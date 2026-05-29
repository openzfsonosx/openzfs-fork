if BUILD_FSKIT

#
# ZFSFSKit — OpenZFS FSKit filesystem extension
#
# Builds ZFSFSKit.appex, a macOS system extension that presents ZFS pools
# as FSKit volumes (probeResource / loadResource / FSVolumeOperations).
#
# The Objective-C sources are compiled with ARC; the C bridge (zfs_fskit.c)
# links against the same ZFS libraries as zfsd.
#
# The binary is assembled into an .appex bundle via install-data-local.
#

noinst_PROGRAMS += ZFSFSKit

# FSKIT is defined globally by AC_DEFINE (config.h) when --enable-fskit is
# configured; that activates the fskit_posix.h shim (open/stat/fstat_blk
# redirects) for all translation units including these.
ZFSFSKit_CPPFLAGS  = $(AM_CPPFLAGS) $(LIBZPOOL_CPPFLAGS)
ZFSFSKit_CFLAGS    = $(AM_CFLAGS)
ZFSFSKit_OBJCFLAGS = -fobjc-arc $(AM_CPPFLAGS) $(LIBZPOOL_CPPFLAGS)

ZFSFSKit_SOURCES = \
	%D%/ZFSFileSystem.m \
	%D%/ZFSVolume.m \
	%D%/zfs_fskit.c

# libzpool before libzfs: ensures spa_import / fstat64_blk in libzpool resolve
# fskit_register_device and fskit_fstat_blk to libspl (which libzpool links
# against), not to any shadowed copy in libzfs.
ZFSFSKit_LDADD = \
	libzpool.la \
	libzfs.la \
	libzfs_core.la \
	libzutil.la \
	libnvpair.la \
	libspl.la

ZFSFSKit_LDFLAGS = \
	-lobjc \
	-framework FSKit \
	-framework Foundation \
	-framework IOKit \
	-framework CoreFoundation

#
# Bundle assembly
# ---------------
# ZFSFSKit.appex — ExtensionKit FSKit extension (probe / check / activate / mount
#   via FSKit UserFS callbacks).  Installed to /Library/ExtensionKit/Extensions/
#   by scripts/fskit.sh.
#
# zfs.fs — legacy .fs bundle that diskarbitrationd / fskitd require to route
#   block devices through the ZFS FSKit extension.  Must live at
#   /Library/Filesystems/zfs.fs/ (the well-known third-party .fs location).
#   FSMountExecutable (mount_zfs) is resolved from zfs.fs/Contents/Resources/;
#   the binary itself is built and installed by cmd/os/macos/mount_zfs/Makefile.am
#   (as macos_mount_zfs → mount_zfs) via mount_zfs-install-exec-hook.
#   The plist is installed via fskit-fs-bundle-install-hook below.
#

APPEX_DIR   = ZFSFSKit.appex/Contents/MacOS
APPEX_PLIST = ZFSFSKit.appex/Contents/Info.plist

all-local: $(APPEX_PLIST)

$(APPEX_PLIST): ZFSFSKit $(srcdir)/%D%/Info.plist
	$(MKDIR_P) $(APPEX_DIR)
	$(INSTALL_PROGRAM) ZFSFSKit $(APPEX_DIR)/ZFSFSKit
	$(INSTALL_DATA) $(srcdir)/%D%/Info.plist $(APPEX_PLIST)

# Install the zfs.fs bundle Info.plist alongside the mount_zfs binary that
# mount_zfs-install-exec-hook (in mount_zfs/Makefile.am) already places at
# $(FS_BUNDLEDIR)/Contents/Resources/mount_zfs.
INSTALL_DATA_HOOKS += fskit-fs-bundle-install-hook
fskit-fs-bundle-install-hook:
	$(MKDIR_P) $(FS_BUNDLEDIR)/Contents
	$(INSTALL_DATA) $(srcdir)/%D%/zfs_fs.plist \
	    $(FS_BUNDLEDIR)/Contents/Info.plist

clean-local:
	rm -rf ZFSFSKit.appex

endif # BUILD_FSKIT
