if BUILD_FSKIT

sbin_PROGRAMS   += zfsd
CPPCHECKTARGETS += zfsd

zfsd_CPPFLAGS  = $(AM_CPPFLAGS) $(LIBZPOOL_CPPFLAGS)
zfsd_CFLAGS    = $(AM_CFLAGS)

zfsd_SOURCES = \
	%D%/zfsd.c

#
# Same library set as zdb: libzpool gives us the ZFS engine,
# libzfs + libzfs_core give us the higher-level helpers,
# libzutil / libnvpair / libspl round out the support layer.
#
zfsd_LDADD = \
	libzfs.la \
	libzfs_core.la \
	libzpool.la \
	libzutil.la \
	libnvpair.la \
	libspl.la

zfsd_LDFLAGS = -framework IOKit -framework CoreFoundation

endif # BUILD_FSKIT
