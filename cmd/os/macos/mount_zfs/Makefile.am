sbin_PROGRAMS   += mount_zfs
CPPCHECKTARGETS += mount_zfs

AM_CPPFLAGS += -I$(top_srcdir)/lib/libzfs

mount_zfs_SOURCES = \
	%D%/mount_zfs.c

mount_zfs_LDADD = \
	libzfs.la \
	libzfs_core.la \
	libnvpair.la

mount_zfs_LDADD += $(LTLIBINTL)

INSTALL_DATA_HOOKS += mount_zfs-install-exec-hook
mount_zfs-install-exec-hook:
	cp -f $(DESTDIR)/$(sbindir)/mount_zfs $(FS_BUNDLEDIR)/Contents/Resources/mount_zfs
