
CLEANFILES += $(launchdscript_SCRIPTS)

launch_ddir = $(sysconfdir)/launchd/launchd.d
dist_launch_d_DATA = \
	$(top_srcdir)/%D%/zpool-import-all.sh.in

do_subst = -$(SED) -e 's,@bindir\@,$(bindir),g' \
		-e 's,@runstatedir\@,$(runstatedir),g' \
		-e 's,@sbindir\@,$(sbindir),g' \
		-e 's,@sysconfdir\@,$(sysconfdir),g' \
		-e 's,@launchdscriptdir\@,$(launchdscriptdir),g'

zpool-import-all.sh: %D%/zpool-import-all.sh.in
	$(do_subst) < $(top_srcdir)/%D%/zpool-import-all.sh.in > zpool-import-all.sh
	chmod +x zpool-import-all.sh
