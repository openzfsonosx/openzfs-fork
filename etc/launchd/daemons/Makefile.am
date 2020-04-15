
CLEANFILES += $(launchddaemon_DATA)

launchddaemon_DATA = \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zconfigd.plist \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zed.plist \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zpool-import.plist \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.zpool-import-all.plist \
	$(top_srcdir)/etc/launchd/daemons/org.openzfsonosx.InvariantDisks.plist

dist_launchddaemon_DATA = \
	$(DAEMON_DIR)/org.openzfsonosx.zconfigd.plist.in \
	$(DAEMON_DIR)/org.openzfsonosx.zed.plist.in \
	$(DAEMON_DIR)/org.openzfsonosx.zpool-import.plist.in \
	$(DAEMON_DIR)/org.openzfsonosx.zpool-import-all.plist.in \
	$(DAEMON_DIR)/org.openzfsonosx.InvariantDisks.plist.in

$(DAEMON_DIR)/org.openzfsonosx.zconfigd.plist: $(DAEMON_DIR)/org.openzfsonosx.zconfigd.plist.in
$(DAEMON_DIR)/org.openzfsonosx.zed.plist: $(DAEMON_DIR)/org.openzfsonosx.zed.plist.in
$(DAEMON_DIR)/org.openzfsonosx.zpool-import.plist: $(DAEMON_DIR)/org.openzfsonosx.zpool-import.plist.in
$(DAEMON_DIR)/org.openzfsonosx.zpool-import-all.plist: $(DAEMON_DIR)/org.openzfsonosx.zpool-import-all.plist.in
$(DAEMON_DIR)/org.openzfsonosx.InvariantDisks.plist: $(DAEMON_DIR)/org.openzfsonosx.InvariantDisks.plist.in

$(launchddaemon_DATA):
	-$(SED) -e 's,@bindir\@,$(bindir),g' \
		-e 's,@runstatedir\@,$(runstatedir),g' \
		-e 's,@sbindir\@,$(sbindir),g' \
		-e 's,@sysconfdir\@,$(sysconfdir),g' \
		-e 's,@launchddaemondir\@,$(launchddaemondir),g' \
		-e 's,@launchdscriptdir\@,$(launchdscriptdir),g' \
		'$@.in' >'$@'


