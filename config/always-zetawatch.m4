dnl # SPDX-License-Identifier: CDDL-1.0
dnl #
dnl # Determine whether to build the ZetaWatch macOS menu bar application
dnl #
AC_DEFUN([ZFS_AC_CONFIG_ALWAYS_ZETAWATCH], [
	AC_ARG_ENABLE(zetawatch,
		AS_HELP_STRING([--enable-zetawatch],
		[Build the ZetaWatch macOS menu bar application @<:@default=no@:>@]),
		[enable_zetawatch=$enableval],
		[enable_zetawatch=no])

	AM_CONDITIONAL([ENABLE_ZETAWATCH], [test "x$enable_zetawatch" = "xyes"])
	AC_MSG_CHECKING(for ZetaWatch support)
	AC_MSG_RESULT([$enable_zetawatch])
])
