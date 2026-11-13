# SPDX-License-Identifier: CDDL-1.0


AC_DEFUN([ZFS_AC_MACOS_IMPURE_ENABLE], [
	AC_ARG_ENABLE(macos_impure,
		AS_HELP_STRING([--enable-macos-impure],
		[Use XNU Private.exports [[default: no]]]),
		[AS_IF([test "x$enableval" = xyes],
		    [CPPFLAGS="$CPPFLAGS -DMACOS_IMPURE"])],
		[])
])



dnl #
dnl # With LTO the Apple linker hands the debug information to dsymutil and
dnl # lldb in temporary objects, which it keeps only if -object_path_lto
dnl # names a place for them.  It names those objects by index and
dnl # architecture alone, and it reads them back while linking, so no two
dnl # links may share a directory: parallel links then overwrite each
dnl # other's objects and fail, or lose their debug information.
dnl #
dnl # Give every link target a directory of its own under lto-objs/.  The
dnl # make functions are expanded once per link, in the recipe.  This must
dnl # run after the last link test, as the shell cannot expand them.
dnl #
AC_DEFUN([ZFS_AC_MACOS_LTO_OBJECT_PATH], [
	AC_MSG_CHECKING([whether to keep LTO objects per link target])
	lto_object_path=no
	AS_IF([test "x$ac_system" = "xmacOS"], [
		AS_CASE([" $CC $CXX $CFLAGS $CXXFLAGS $LDFLAGS "],
		    [*object_path_lto*], [lto_object_path="no, set by user"],
		    [*" -flto"*], [lto_object_path=yes])
	])
	AS_IF([test "x$lto_object_path" = "xyes"], [
		LDFLAGS="$LDFLAGS "'-Wl,-object_path_lto,$(shell d=$(abs_top_builddir)/lto-objs/$(subst /,_,@S|@@); mkdir -p $$d; echo $$d)'
	])
	AC_MSG_RESULT([$lto_object_path])
])

dnl #
dnl # --enable-flto[=thin|full]: compile the C sources of the userland and
dnl # of the kext for link-time optimization.  The flag is added after the
dnl # configure tests have run, so they are not slowed down by it.
dnl #
AC_DEFUN([ZFS_AC_MACOS_LTO], [
	AC_ARG_ENABLE([flto],
		AS_HELP_STRING([--enable-flto@<:@=thin|full@:>@],
		[Build with link-time optimization (macOS) [default: no]]),
		[], [enable_flto=no])

	AC_MSG_CHECKING([whether to build with link-time optimization])
	AS_CASE(["x$enable_flto"],
	    [xno], [lto_flag=""],
	    [xyes|xfull], [lto_flag="-flto"],
	    [xthin], [lto_flag="-flto=thin"],
	    [AC_MSG_RESULT([error])
	    AC_MSG_ERROR([Unknown argument --enable-flto=$enable_flto])])
	AC_MSG_RESULT([${lto_flag:-no}])

	AS_IF([test -n "$lto_flag"], [
		AS_IF([test "x$ac_system" != "xmacOS"], [
			AC_MSG_ERROR([--enable-flto is only supported on macOS])
		])

		AC_MSG_CHECKING([whether $CC can link with $lto_flag])
		CFLAGS="$CFLAGS $lto_flag"
		AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [
			AC_MSG_RESULT([yes])
		], [
			AC_MSG_RESULT([no])
			AC_MSG_ERROR([$CC cannot link with $lto_flag])
		])
	])
])
