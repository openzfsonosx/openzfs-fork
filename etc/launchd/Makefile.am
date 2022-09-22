launchddaemondir = /Library/LaunchDaemons
DAEMON_DIR = $(top_srcdir)/etc/launchd/daemons
launchdscriptdir = ${libexecdir}/zfs/launchd.d
launchdscript_SCRIPTS = \
	zpool-import-all.sh

include $(srcdir)/%D%/daemons/Makefile.am
include $(srcdir)/%D%/launchd.d/Makefile.am
