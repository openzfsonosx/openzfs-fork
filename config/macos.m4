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
