pathsddir = $(sysconfdir)/paths.d
pathsd_DATA = zfs-path

paths_ddir = $(sysconfdir)/etc/paths.d/
dist_paths_d_DATA = \
	zfs-path

CLEANFILES += $(pathsd_DATA)

zfs-path: %D%/zfs-path.in

$(pathsd_DATA):
	-$(SED) -e 's,@bindir\@,$(bindir),g' \
		-e 's,@runstatedir\@,$(runstatedir),g' \
		-e 's,@sbindir\@,$(sbindir),g' \
		-e 's,@sysconfdir\@,$(sysconfdir),g' \
		-e 's,@launchddaemondir\@,$(launchddaemondir),g' \
		-e 's,@launchdscriptdir\@,$(launchdscriptdir),g' \
		'$@.in' >'$@'
