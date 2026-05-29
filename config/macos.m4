

AC_DEFUN([ZFS_AC_MACOS_IMPURE_ENABLE], [
	AC_ARG_ENABLE(macos_impure,
		AS_HELP_STRING([--enable-macos-impure],
		[Use XNU Private.exports [[default: no]]]),
		[CPPFLAGS="$CPPFLAGS -DMACOS_IMPURE"],
		[])
])

dnl #
dnl # --enable-fskit
dnl #
dnl # Build the FSKit userland port instead of the legacy IOKit kext.
dnl # When enabled, FSKIT is defined and the socket-based IPC transport
dnl # is used in place of ioctl(/dev/zfs).  Only meaningful on macOS.
dnl #
AC_DEFUN([ZFS_AC_FSKIT], [
	AC_MSG_CHECKING([whether FSKit userland port is enabled])
	AC_ARG_ENABLE([fskit],
		[AS_HELP_STRING([--enable-fskit],
		[Enable FSKit userland port (macOS only) @<:@default: no@:>@])],
		[enable_fskit=$enableval],
		[enable_fskit=no])

	AS_CASE(["x$enable_fskit"],
		["xyes"], [
			AC_DEFINE([FSKIT], [1],
				[Define to 1 to build the FSKit userland port])
			dnl # Override ZFS_DEV: no kext means no /dev/zfs.
			dnl # /dev/null is opened as a dummy fd by libzfs_core_init();
			dnl # lzc_ioctl_fd_os() ignores it and uses the zfsd socket.
			CPPFLAGS="$CPPFLAGS -DZFS_DEV='\"/dev/null\"'"
			AC_MSG_RESULT([yes])
		], ["xno"], [
			AC_MSG_RESULT([no])
		], [
			AC_MSG_ERROR([Unknown option: --enable-fskit=$enable_fskit])
		])

	AM_CONDITIONAL([BUILD_FSKIT], [test "x$enable_fskit" = "xyes"])
])
