# OpenZFS on FSKit — Proof of Concept

This branch contains a proof-of-concept FSKit filesystem extension for
OpenZFS on macOS.  It mounts ZFS pools using Apple's FSKit framework
instead of the legacy IOKit kext (`org.openzfsonosx.zfs`).

Maintained by Jorgen Lundman — [OpenZFS on OS X](https://openzfsonosx.org/)

---

## What Works

The full read path is functional end-to-end:

- Pool probe via vdev label read through `FSBlockDeviceResource`
- Pool import (`spa_import` via pre-opened fd — sandbox-safe)
- Complete FSKit lifecycle: probe → check → activate → mount
- `ls`, `cat`, correct timestamps, ownership, and permissions
- Tested against pools created on Solaris/illumos and Linux

```
/dev/disk4 on /Volumes/tank (zfs, local, nodev, nosuid, noowners, noatime, fskit)

$ ls -la /Volumes/tank/
drwxr-xr-x  3 lundman  staff    4 May 29 09:21 .
-rw-r--r--  1 lundman  staff   11 May 29 09:21 file.txt
drwxr-xr-x  2 lundman  staff    2 May 29 09:21 HelloWorld

$ cat /Volumes/tank/file.txt
HelloWorld
```

---

## Building

### Prerequisites

```sh
brew install automake libtool gawk coreutils
```

### FSKit build

```sh
./autogen.sh
./configure --enable-fskit \
    CPPFLAGS="-I${HOMEBREW_PREFIX}/opt/gettext/include \
              -I${HOMEBREW_PREFIX}/opt/openssl/include" \
    LDFLAGS="-L${HOMEBREW_PREFIX}/opt/gettext/lib/ \
             -L${HOMEBREW_PREFIX}/opt/openssl/lib"
make -j $(($(sysctl -n hw.ncpu)+1))
```

`--enable-fskit` builds the `ZFSFSKit.appex` extension and the `zfsd`
management daemon.  It replaces the `/dev/zfs` ioctl interface with a
UNIX socket transport.

### Install

```sh
sudo scripts/copy_macos.sh          # installs kext (legacy)
# or for FSKit:
sudo cp -R cmd/os/macos/ZFSFSKit/ZFSFSKit.appex \
          /Library/ExtensionKit/Extensions/
```

The extension requires the `com.apple.developer.fskit.fsmodule` entitlement
(currently only available via Apple's developer program or with ADHOC signing
for local testing).

---

## Architecture

The FSKit port embeds libzpool directly in the extension process.  All
ZFS engine operations (pool import, DMU reads, SA attribute lookups) run
in userspace inside the `ZFSFSKit.appex` sandbox.

```
fskitd
  └─ ZFSFSKit.appex (sandboxed)
       ├─ ZFSFileSystem.m   — probe, check, load (spa_import via pre-opened fd)
       ├─ ZFSVolume.m       — VFS ops: getattr, lookup, readdir, read
       └─ zfs_fskit.c       — pure-C bridge to libzpool (DMU, SA, ZAP)

zfsd                        — management daemon (ZFS_IOC_* over UNIX socket)
```

Block device I/O uses the fd that FSKit opens and holds in the extension
process.  DKIOC ioctls blocked by the App Sandbox are replaced by a
path→size registry (`lib/libspl/os/macos/fskit_posix.c`).

---

## Key Technical Findings

Things that were not obvious from the FSKit documentation:

**1. `startCheckWithTask:` must complete asynchronously**

Calling `[task didCompleteWithError:nil]` synchronously causes fskitd to
receive "task completed" before "task started" over XPC, and it rejects
the operation with `FSKitErrorDomain Code=27503 "Task didn't start yet"`.
The fix is a `dispatch_after` with at least a 1 ms delay.

**2. `app-sandbox=true` is required in entitlements**

ExtensionKit rejects the extension without `com.apple.security.app-sandbox=true`,
even though sandboxing a filesystem extension seems counterintuitive.  This
must be paired with `com.apple.developer.fskit.fsmodule=true`.

**3. Container identifier must equal volume identifier**

For `FSUnaryFileSystem`, the `FSContainerIdentifier` returned in
`probeResource:` must exactly match the `FSVolumeIdentifier` used when
constructing the `FSVolume`.  A mismatch causes `loadResource:` to fail
with EAGAIN "unexpected container state".

**4. spa async thread asserts `spa_writeable` in read-only mode**

After `spa_import` with `SPA_MODE_READ`, the spa async thread processes
`SPA_ASYNC_CONFIG_UPDATE`, which calls `vdev_config_dirty()`, which has
`ASSERT(spa_writeable(spa))`.  Fixed in `module/zfs/spa.c` with the same
`spa_writeable()` guard used elsewhere in that file.

**5. FTAG mismatch across function boundaries crashes rrwlock in debug builds**

`FTAG` expands to `__func__`.  When `dmu_objset_hold` and `dmu_objset_rele`
are called from different functions, the hold and release tags differ.  In
debug libzpool, `rrwlock` is in `rr_track_all` mode and asserts when the
hold tag cannot be found in the reader list.  Fix: use a single named tag
constant across paired hold/release sites that span function boundaries.

---

## What's Missing for Production

### Hard blockers

**1. Management plane — no `/dev/zfs` equivalent**

Every ZFS management tool (`zpool`, `zfs`, `zdb`, `zed`) communicates via
`/dev/zfs` ioctls (`ZFS_IOC_*`).  Without an equivalent IPC mechanism:

- No pool create, destroy, scrub, resilver, or status
- No snapshots, clones, send/receive, or property management
- No ZFS event daemon for fault handling

This branch includes a minimal `zfsd` socket daemon as a starting point,
but it is not a production solution.  The mechanism needs to be defined by
Apple as part of the FSKit contract.

**2. Zvols — no virtual block device publication**

ZFS Volumes (zvols) are block devices backed by the pool — used for VM
disks, iSCSI targets, and swap.  The kext uses `IOBlockStorageDevice` to
publish them into the IOKit namespace.  There is no userspace equivalent.
DriverKit's `IOUserBlockStorageDevice` is the closest analog, but IOKit
matching is hardware-triggered and cannot be driven by pool contents
discovered at import time.

**3. N:M — multiple devices per pool, multiple datasets per mount**

- **N devices → 1 pool**: Mirrors and RAIDZ span multiple block devices.
  FSKit's model is one `FSBlockDeviceResource` per activation.  There is
  no multi-resource activation concept.  (This PoC works only because it
  uses a single-vdev file pool.)

- **1 pool → M mounts**: A pool typically contains multiple datasets, each
  with its own mountpoint.  `FSUnaryFileSystem` is explicitly one volume
  per activation.  There is no mechanism for one pool import to produce
  multiple mounted volumes.

### Secondary gaps

- **ARC memory limits** — ZFS's Adaptive Replacement Cache is designed to
  use a significant portion of RAM.  Sandbox memory limits constrain it.

- **Background operations** — Pool scrub and vdev resilver (RAID rebuild)
  are long-running tasks essential for data integrity.  There is no
  mechanism for an FSKit extension to run sustained background work while
  mounted.

- **No unified buffer cache integration** — All reads go through the
  extension process.  `mmap` performance is affected by the lack of kernel
  page cache sharing.

- **NFS/SMB re-export** — Correctness of persistent file IDs, `fsid`
  stability, and server-side locking under FSKit needs validation for the
  NAS use case.

---

## Questions for Apple

1. What is the roadmap for `com.apple.developer.fskit.fsmodule` general
   availability for third-party filesystem developers?

2. Is there a recommended pattern for a filesystem extension to expose a
   management interface to non-sandboxed privileged tools?

3. Is multi-resource activation (multiple `FSBlockDeviceResource` objects
   for one filesystem instance) planned?  Is there a pattern for one
   extension activation to produce multiple mount points?

4. What is the intended path for publishing virtual block devices from a
   filesystem extension (zvol-equivalent)?

5. What is the recommended pattern for long-running background tasks
   (scrub, resilver) while a volume is mounted?

---

## Repository

This is a fork of [openzfs/zfs](https://github.com/openzfs/zfs) maintained
for macOS.  The FSKit work lives on the `FSKit` branch.

OpenZFS is released under a CDDL license.
See the NOTICE, LICENSE and COPYRIGHT files; `UCRL-CODE-235197`
