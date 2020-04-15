sbin_PROGRAMS   += zfs_util
CPPCHECKTARGETS += zfs_util

INFO_PLIST = %D%/Info.plist
INFOPLIST_STRINGS = %D%/English.lproj/InfoPlist.strings
PKGINFO = %D%/PkgInfo

zfs_util_SOURCES = \
	%D%/zfs_util.c

zfs_util_LDADD = \
        libzfs.la

zfs_util_LDFLAGS = -static -framework IOKit

# build the /Library/Filesystems/zfs.fs/ bundle

zfs_fs_SOURCES =

bin_PROGRAMS += zfs.fs

dist_noinst_DATA += $(INFO_PLIST) $(INFOPLIST_STRINGS) $(PKGINFO)

zfs.fs$(EXEEXT): zfs_util
	rm -rf zfs.fs
	mkdir -p zfs.fs/Contents/Resources/English.lproj
	cp -f $(PKGINFO) zfs.fs/Contents/
	cp -f $(INFO_PLIST) zfs.fs/Contents/
	cp -f zfs_util zfs.fs/Contents/Resources/
	cp -f $(INFOPLIST_STRINGS) zfs.fs/Contents/Resources/English.lproj/
	/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $(ZFS_META_VERSION)" zfs.fs/Contents/Info.plist
	/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $(ZFS_META_VERSION)" zfs.fs/Contents/Info.plist
	plutil -convert binary1 zfs.fs/Contents/Resources/English.lproj/InfoPlist.strings

install-exec-local:: zfs.fs
	rm -f $(FS_BUNDLEDIR)/Contents/$(PKGINFO)
	rm -f $(FS_BUNDLEDIR)/Contents/$(INFO_PLIST)
	rm -f $(FS_BUNDLEDIR)/Contents/Resources/English.lproj/$(INFOPLIST_STRINGS)
	mkdir -p $(FS_BUNDLEDIR)
	rsync -aH zfs.fs/ $(FS_BUNDLEDIR)/
	ln -fs /usr/bin/true $(FS_BUNDLEDIR)/Contents/Resources/fsck_zfs
	ln -fs /usr/bin/true $(FS_BUNDLEDIR)/Contents/Resources/newfs_zfs
	chown -R root:wheel $(FS_BUNDLEDIR) || echo "Unable to chown root:wheel in $(FS_BUNDLEDIR)"

clean-binPROGRAMS:
	rm -rf zfs.fs/

clean:
	rm -rf zfs.fs

uninstall-hook:
	rm -rf "$(FS_BUNDLEDIR)"
