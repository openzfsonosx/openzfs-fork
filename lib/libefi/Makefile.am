libefi_la_CFLAGS  = $(AM_CFLAGS) $(LIBRARY_CFLAGS)
libefi_la_CFLAGS += $(LIBUUID_CFLAGS) $(ZLIB_CFLAGS)
libefi_la_CFLAGS += -fvisibility=hidden

noinst_LTLIBRARIES += libefi.la
CPPCHECKTARGETS    += libefi.la


$(info "Here $BUILD_MACOS and $BUILD_LINUX and $CONFIG_USER")

libefi_la_SOURCES =
libefi_la_LDFLAGS =

if BUILD_MACOS
libefi_la_SOURCES += \
	%D%/rdwr_efi_macos.c
libefi_la_LDFLAGS += -framework DiskArbitration -framework CoreServices
endif

if BUILD_LINUX
libefi_la_SOURCES += \
	%D%/rdwr_efi.c
endif

libefi_la_LIBADD = $(LIBUUID_LIBS) $(ZLIB_LIBS)
