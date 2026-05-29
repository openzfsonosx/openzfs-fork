/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2025 Jorgen Lundman <lundman@lundman.net>
 *
 * ZFSFileSystem.m — FSKit FSUnaryFileSystem subclass for OpenZFS on macOS.
 *
 * This is the entry point for the ZFS FSKit filesystem extension.
 * It handles probeResource (ZFS label detection) and loadResource (pool import)
 * using the embedded ZFS engine (libzpool).
 *
 * Architecture:
 *  - FSKit calls probeResource: when it sees a new block device; we read the
 *    ZFS vdev label to decide if this disk belongs to a ZFS pool.
 *  - On loadResource: we import the pool (spa_import) and return a ZFSVolume.
 *  - ZFSVolume (see ZFSVolume.m) implements FSVolumeOperations, serving VFS
 *    calls (lookup, getattr, readdir, read) directly from libzpool / DMU.
 *
 * Current status: PoC skeleton — probe and load are stubbed; VFS ops return
 * minimal data for the root directory so Finder can open the volume.
 */

#import <Foundation/Foundation.h>
#import <FSKit/FSKit.h>

/* NSExtensionMain is part of Foundation but has no standalone header
 * on macOS CLI/automake builds.  Forward-declare it directly.
 * (Swift @main / UnaryFileSystemExtension synthesises this for Swift;
 * in ObjC we still need an explicit main() that calls it.)
 */
extern int NSExtensionMain(int argc, char *argv[]);

#include <fcntl.h>
#include <string.h>
#include <sys/syslimits.h>
#include "zfs_fskit.h"
/* fskit_register_device / fskit_unregister_device from fskit_posix.c */
#include <sys/fskit_posix.h>

#import "ZFSVolume.h"

/* ---- ZFSFileSystem ---- */

/*
 * FSManageableResourceMaintenanceOperations is required for all
 * FSUnaryFileSystem implementations that use FSBlockDeviceResource.
 * FSKit will not proceed past the check phase without it.
 *
 * For ZFS, the pool was already imported cleanly via spa_import, so
 * startCheck reports immediate success.  startFormat is not supported.
 */
@interface ZFSFileSystem : FSUnaryFileSystem
    <FSUnaryFileSystemOperations, FSManageableResourceMaintenanceOperations>
@end

@implementation ZFSFileSystem {
	NSString	*_poolName;	/* set on successful loadResource: */
}

/*
 * init — called by NSExtensionMain when it instantiates the principal class.
 * Initialise the ZFS engine here; didFinishLoading is not a real FSKit callback.
 */
- (instancetype)init
{
	self = [super init];
	if (self) {
		NSLog(@"ZFSFileSystem: init — initialising ZFS engine");
		zfs_fskit_init();
	}
	return (self);
}

/*
 * probeResource: — called by FSKit when it sees a block device.
 *
 * We read the vdev label from the first 256 KiB of the device to check for a
 * ZFS magic number.  If the label is valid we return FSMatchResultUsable with
 * the pool name and a UUID derived from the pool GUID.
 *
 * TODO: use the real libzpool vdev label reader (vdev_label_read_config) once
 * the resource read API is wired up.  For now we do a direct pread on the
 * device path via FSBlockDeviceResource.devicePath.
 */
- (void)probeResource:(FSResource *)resource
         replyHandler:(void (^)(FSProbeResult *_Nullable result,
                                NSError *_Nullable error))reply
{
	if (![resource isKindOfClass:[FSBlockDeviceResource class]]) {
		NSLog(@"ZFSFileSystem: probeResource: not a block device, skipping");
		reply([FSProbeResult notRecognizedProbeResult], nil);
		return;
	}

	FSBlockDeviceResource *blk = (FSBlockDeviceResource *)resource;
	NSLog(@"ZFSFileSystem: probeResource: %@  blockSize=%llu  size=%llu",
	    blk.BSDName, (unsigned long long)blk.blockSize,
	    (unsigned long long)blk.blockCount * blk.blockSize);

	/*
	 * Read the first two ZFS vdev labels (256 KB each) through
	 * FSBlockDeviceResource — the only I/O path available in the sandbox.
	 * Direct open("/dev/diskX") is blocked by the App Sandbox profile.
	 *
	 * ZFS vdev label layout (256 KB per label):
	 *   Label 0: offset 0          (tried first)
	 *   Label 1: offset 256 KB     (fallback)
	 *   Labels 2,3: near end       (skipped; needs tail-of-device offset)
	 */
	char poolname[256] = {0};
	uint64_t pool_guid = 0;
	int rc = -1;

	const size_t kLabelSize = 256 * 1024;
	void *labelBuf = malloc(kLabelSize);
	if (!labelBuf) {
		reply(nil, fs_errorForPOSIXError(ENOMEM));
		return;
	}

	off_t labelOffsets[2] = { 0, (off_t)kLabelSize };
	for (int i = 0; i < 2 && rc != 0; i++) {
		NSError *readErr = nil;
		size_t got = [blk readInto:labelBuf
		                startingAt:labelOffsets[i]
		                    length:kLabelSize
		                     error:&readErr];
		if (readErr || got < kLabelSize) {
			NSLog(@"ZFSFileSystem: probeResource: readInto "
			    "label[%d] got %zu/%zu err=%@",
			    i, got, kLabelSize, readErr);
			continue;
		}
		rc = zfs_fskit_probe_buf(labelBuf, got,
		    poolname, sizeof (poolname), &pool_guid);
	}
	free(labelBuf);

	if (rc != 0) {
		NSLog(@"ZFSFileSystem: probeResource: no ZFS label on %@",
		    blk.BSDName);
		reply([FSProbeResult notRecognizedProbeResult], nil);
		return;
	}

	NSLog(@"ZFSFileSystem: probeResource: found pool '%s' guid %llu on %@",
	    poolname, (unsigned long long)pool_guid, blk.BSDName);

	/*
	 * Build a deterministic UUID from the pool GUID so FSKit can
	 * identify this container across reboots.
	 */
	uuid_t uuid;
	memset(uuid, 0, sizeof (uuid));
	memcpy(uuid, &pool_guid, sizeof (pool_guid));
	NSUUID *containerID = [[NSUUID alloc] initWithUUIDBytes:uuid];

	NSString *name = [NSString stringWithUTF8String:poolname];

	/*
	 * FSProbeResult requires an FSContainerIdentifier, which is a subclass
	 * of FSEntityIdentifier.  Wrap our NSUUID in one.
	 */
	FSContainerIdentifier *cid =
	    [[FSContainerIdentifier alloc] initWithUUID:containerID];
	FSProbeResult *result =
	    [FSProbeResult usableProbeResultWithName:name containerID:cid];
	reply(result, nil);
}

/*
 * loadResource: — import the pool and hand FSKit a ZFSVolume.
 *
 * FSKit calls this after a successful probe (or when the user explicitly
 * mounts the volume).  We import the pool with spa_import() and return a
 * ZFSVolume that will serve all subsequent VFS operations.
 */
- (void)loadResource:(FSResource *)resource
             options:(FSTaskOptions *)options
        replyHandler:(void (^)(FSVolume *_Nullable volume,
                               NSError *_Nullable err))reply
{
	if (![resource isKindOfClass:[FSBlockDeviceResource class]]) {
		reply(nil, fs_errorForPOSIXError(EINVAL));
		return;
	}

	FSBlockDeviceResource *blk = (FSBlockDeviceResource *)resource;
	NSLog(@"ZFSFileSystem: loadResource: %@  blockSize=%llu  size=%llu",
	    blk.BSDName,
	    (unsigned long long)blk.blockSize,
	    (unsigned long long)blk.blockCount * blk.blockSize);

	char poolname[256] = {0};
	uint64_t pool_guid = 0;

	/*
	 * Re-read the vdev label through the sandbox-safe FSKit I/O path
	 * (same technique as probeResource:) to recover pool name and GUID.
	 * Direct open("/dev/diskX") is blocked by the App Sandbox.
	 */
	const size_t kLabelSize = 256 * 1024;
	void *labelBuf = malloc(kLabelSize);
	if (!labelBuf) {
		reply(nil, fs_errorForPOSIXError(ENOMEM));
		return;
	}

	int rc = -1;
	off_t labelOffsets[2] = { 0, (off_t)kLabelSize };
	for (int i = 0; i < 2 && rc != 0; i++) {
		NSError *readErr = nil;
		size_t got = [blk readInto:labelBuf
		                startingAt:labelOffsets[i]
		                    length:kLabelSize
		                     error:&readErr];
		if (readErr || got < kLabelSize) {
			NSLog(@"ZFSFileSystem: loadResource: readInto label[%d] "
			    "got %zu/%zu err=%@", i, got, kLabelSize, readErr);
			continue;
		}
		rc = zfs_fskit_probe_buf(labelBuf, got,
		    poolname, sizeof (poolname), &pool_guid);
	}
	free(labelBuf);

	if (rc != 0) {
		NSLog(@"ZFSFileSystem: loadResource: no ZFS label on %@",
		    blk.BSDName);
		reply(nil, fs_errorForPOSIXError(ENODEV));
		return;
	}
	NSLog(@"ZFSFileSystem: loadResource: label re-read OK, "
	    "pool '%s' guid %llu", poolname, (unsigned long long)pool_guid);

	/*
	 * The App Sandbox denies open("/dev/diskX") directly.
	 * FSKit opens the device itself and holds an fd in our process —
	 * it uses the *raw* device (/dev/rdiskX), not the block device.
	 * We scan our fd table for either form, then pass /dev/fd/<N> to
	 * spa_import so the vdev layer re-uses the open fd without a new
	 * open(2) call.
	 */
	const char *bsdname = blk.BSDName.UTF8String;	/* e.g. "disk4s1" */
	char blk_path[PATH_MAX], raw_path[PATH_MAX];
	snprintf(blk_path, sizeof (blk_path), "/dev/%s",  bsdname);
	/* Construct raw path: "diskXsY" → "rdiskXsY" */
	if (strncmp(bsdname, "disk", 4) == 0)
		snprintf(raw_path, sizeof (raw_path), "/dev/r%s", bsdname);
	else
		strlcpy(raw_path, blk_path, sizeof (raw_path));

	int devfd = -1;
	{
		char fpath[PATH_MAX];
		NSLog(@"ZFSFileSystem: loadResource: scanning open fds "
		    "(looking for %s or %s)", blk_path, raw_path);
		for (int fd = 3; fd < 512; fd++) {
			if (fcntl(fd, F_GETPATH, fpath) == 0) {
				if (strncmp(fpath, "/dev/", 5) == 0)
					NSLog(@"ZFSFileSystem: loadResource:   "
					    "fd %d → %s", fd, fpath);
				if (devfd < 0 &&
				    (strcmp(fpath, blk_path) == 0 ||
				     strcmp(fpath, raw_path) == 0))
					devfd = fd;
			}
		}
	}

	if (devfd >= 0) {
		NSLog(@"ZFSFileSystem: loadResource: using FSKit fd %d "
		    "via /dev/fd/%d", devfd, devfd);

		/*
		 * Register the device size in the libspl path→size registry so
		 * fskit_fstat_blk() can answer fstat64_blk() queries when the
		 * sandbox blocks DKIOC ioctls during spa_import.
		 *
		 * fskit_fstat_blk() resolves the vdev fd via fcntl(F_GETPATH) and
		 * looks up the result here.  The kernel may return either the block
		 * form (/dev/diskXsY) or the raw form (/dev/rdiskXsY), so register
		 * both to guarantee a match.
		 *
		 * blockCount * blockSize gives the total device capacity in bytes.
		 */
		uint64_t devbytes =
		    (uint64_t)blk.blockCount * (uint64_t)blk.blockSize;
		NSLog(@"ZFSFileSystem: loadResource: device size = %llu bytes "
		    "(blockCount=%llu * blockSize=%llu)",
		    (unsigned long long)devbytes,
		    (unsigned long long)blk.blockCount,
		    (unsigned long long)blk.blockSize);

		fskit_register_device(raw_path, devbytes);
		if (strcmp(raw_path, blk_path) != 0)
			fskit_register_device(blk_path, devbytes);

		rc = zfs_fskit_pool_import_fd(poolname, pool_guid, devfd);

		/*
		 * Keep the registry entries live: spa uses the open fd for I/O and
		 * any subsequent fstat64_blk call (e.g. during scrub) still needs
		 * to resolve the device size.  We unregister in unloadResource:.
		 */
	} else {
		/* fd not found — fall back to path open (sandbox-denied, for diag) */
		NSLog(@"ZFSFileSystem: loadResource: no pre-opened fd found, "
		    "trying path-based import (expect sandbox deny)");
		rc = zfs_fskit_pool_import(poolname, pool_guid, bsdname);
	}

	if (rc != 0) {
		NSLog(@"ZFSFileSystem: loadResource: pool import failed (rc=%d) "
		    "for pool '%s'", rc, poolname);
		NSError *importErr = fs_errorForPOSIXError(rc);
		self.containerStatus = [FSContainerStatus blockedWithStatus:importErr];
		reply(nil, importErr);
		return;
	}

	NSLog(@"ZFSFileSystem: loadResource: pool '%s' imported OK, "
	    "creating ZFSVolume (guid=%llu)", poolname,
	    (unsigned long long)pool_guid);

	/*
	 * Remember pool name so unloadResource: can export it.
	 */
	_poolName = [NSString stringWithUTF8String:poolname];

	/*
	 * FSFileSystemBase requires that loadResource transitions the container
	 * out of FSContainerStateNotReady before calling reply.  Calling reply
	 * while the container is still notReady causes FSKit to reject the call
	 * with EAGAIN "unexpected container state".
	 *
	 * Set containerStatus = ready BEFORE reply so FSKit's state machine
	 * sees a valid transition.
	 */
	self.containerStatus = [FSContainerStatus ready];

	ZFSVolume *vol = [[ZFSVolume alloc] initWithPoolName:_poolName
	                                            poolGUID:pool_guid];
	reply(vol, nil);
}

/* ---- FSManageableResourceMaintenanceOperations ---- */

/*
 * startCheckWithTask:options:error: — ZFS pools are self-verifying;
 * if spa_import succeeded, the pool is consistent.  Report immediate
 * success so FSKit can proceed to activateWithOptions: → mount.
 */
- (NSProgress * _Nullable)startCheckWithTask:(FSTask *)task
                                     options:(FSTaskOptions *)options
                                       error:(NSError **)error
{
	NSLog(@"ZFSFileSystem: startCheck: ZFS pool is self-consistent "
	    "(pool imported OK) — reporting immediate pass");
	NSProgress *progress = [[NSProgress alloc] initWithParent:nil
	                                                 userInfo:nil];
	progress.totalUnitCount = 1;
	progress.completedUnitCount = 1;

	/*
	 * CRITICAL: do NOT call [task didCompleteWithError:nil] synchronously.
	 *
	 * FSKit sends the "task started" notification to diskarbitrationd only
	 * AFTER startCheckWithTask: returns.  Calling didCompleteWithError:
	 * before we return sends "task completed" before "task started" over
	 * XPC, causing diskarbitrationd to reply:
	 *   FSKitErrorDomain Code=27503 "Task didn't start yet"
	 * When fskitd receives that error it cancels the fskit_helper session
	 * and never spawns the activate/mount instance.
	 *
	 * Fix: schedule the completion on a high-priority background queue with
	 * a 1 ms delay.  This guarantees:
	 *  1. startCheckWithTask: has returned → FSKit can send "task started"
	 *  2. 1 ms gives FSKit time to deliver "started" before "completed"
	 *  3. The block fires well within any XPC session timeout
	 */
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_MSEC),
	    dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
		NSLog(@"ZFSFileSystem: startCheck: didCompleteWithError:nil");
		[task didCompleteWithError:nil];
	});
	return (progress);
}

/*
 * startFormatWithTask:options:error: — creating a new pool is not
 * supported via FSKit (use zpool create instead).
 */
- (NSProgress * _Nullable)startFormatWithTask:(FSTask *)task
                                      options:(FSTaskOptions *)options
                                        error:(NSError **)error
{
	NSLog(@"ZFSFileSystem: startFormat: not supported");
	if (error)
		*error = fs_errorForPOSIXError(ENOTSUP);
	return (nil);
}

/*
 * unloadResource: — export the pool and clean up.
 *
 * Called by FSKit when the extension instance is being torn down (either
 * because the volume was unmounted or because fskitd decided to terminate
 * this instance).  ZFSVolume.deactivateWithOptions: also calls spa_export;
 * this call is a safety net for cases where deactivate was not invoked
 * (e.g. the check instance, which fskitd terminates without deactivating).
 */
- (void)unloadResource:(FSResource *)resource
               options:(FSTaskOptions *)options
          replyHandler:(void (^)(NSError *_Nullable err))reply
{
	NSLog(@"ZFSFileSystem: unloadResource: pool '%@'",
	    _poolName ? _poolName : @"(none)");

	if (_poolName) {
		/* Unregister device size entries we registered in loadResource:. */
		NSString *bsdName =
		    ([resource isKindOfClass:[FSBlockDeviceResource class]])
		    ? ((FSBlockDeviceResource *)resource).BSDName : nil;
		if (bsdName) {
			char blk_path[PATH_MAX], raw_path[PATH_MAX];
			const char *bsdname = bsdName.UTF8String;
			snprintf(blk_path, sizeof (blk_path), "/dev/%s", bsdname);
			if (strncmp(bsdname, "disk", 4) == 0)
				snprintf(raw_path, sizeof (raw_path),
				    "/dev/r%s", bsdname);
			else
				strlcpy(raw_path, blk_path, sizeof (raw_path));
			fskit_unregister_device(raw_path);
			if (strcmp(raw_path, blk_path) != 0)
				fskit_unregister_device(blk_path);
		}

		/* Export the pool (idempotent: safe if already exported). */
		zfs_fskit_pool_export(_poolName.UTF8String);
		_poolName = nil;
	}

	self.containerStatus = [FSContainerStatus notReadyWithStatus:
	    [NSError errorWithDomain:NSPOSIXErrorDomain code:ENODEV userInfo:nil]];
	reply(nil);
}

@end

/* ---- Extension entry point ---- */

/*
 * NSExtensionMain() is the correct entry point for all NSExtension /
 * ExtensionKit extensions (confirmed by nm on Apple's own FSKit agents).
 * It reads EXExtensionPrincipalClass from Info.plist, instantiates
 * ZFSFileSystem, registers it with the FSKit framework, then runs the
 * XPC service event loop indefinitely.  Do NOT manually instantiate the
 * principal class here — NSExtensionMain owns that lifecycle.
 *
 * Our old hand-rolled main() exited immediately, so fskitd would get a
 * dead XPC connection and never call probeResource:.
 */
int
main(int argc, char *argv[])
{
	return (NSExtensionMain(argc, argv));
}
