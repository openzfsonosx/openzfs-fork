pathsddir = $(sysconfdir)/paths.d
pathsd_DATA = zfs

paths_ddir = $(sysconfdir)/etc/paths.d/
dist_paths_d_DATA = \
	zfs

CLEANFILES += $(pathsd_DATA)

zfs: zfs.in

$(pathsd_DATA):
	-$(SED) -e 's,@bindir\@,$(bindir),g' \
		-e 's,@runstatedir\@,$(runstatedir),g' \
		-e 's,@sbindir\@,$(sbindir),g' \
		-e 's,@sysconfdir\@,$(sysconfdir),g' \
		-e 's,@launchddaemondir\@,$(launchddaemondir),g' \
		-e 's,@launchdscriptdir\@,$(launchdscriptdir),g' \
		'$@.in' >'$@'
