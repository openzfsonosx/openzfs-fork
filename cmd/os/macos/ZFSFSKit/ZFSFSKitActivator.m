/*
 * ZFSFSKitActivator.m — FSKit module diagnostic / host-app binary for ZFSFSKit.
 *
 * FSKit extensions (ExtensionKit, com.apple.fskit.fsmodule) are NOT System
 * Extensions; OSSystemExtensionManager does not apply to them.  The enabled/
 * disabled state lives in the ExtensionKit extension database and is managed
 * via pluginkit(1) and/or System Settings → Privacy & Security → Extensions.
 *
 * This binary:
 *  - "list"    : calls FSClient to show all installed FSKit modules + enabled state
 *  - (default) : same as list
 *
 * It also serves as the CFBundleExecutable of /Applications/ZFSFSKit.app so
 * that lsd/LaunchServices will scan the bundle for embedded extensions.
 *
 * Build:
 *   clang -fobjc-arc -framework Foundation -framework FSKit \
 *         -o ZFSFSKitActivator \
 *         cmd/os/macos/ZFSFSKit/ZFSFSKitActivator.m
 */

#import <Foundation/Foundation.h>
#import <FSKit/FSKit.h>

int
main(int argc, char *argv[])
{
	@autoreleasepool {
		FSClient *client = [FSClient sharedInstance];
		if (!client) {
			fprintf(stderr, "FSClient.sharedInstance returned nil — "
			    "is FSKit available on this OS?\n");
			return (1);
		}

		dispatch_semaphore_t sem = dispatch_semaphore_create(0);
		__block int rc = 0;

		[client fetchInstalledExtensionsWithCompletionHandler:
		    ^(NSArray<FSModuleIdentity *> *modules, NSError *error) {
			if (error) {
				fprintf(stderr, "fetchInstalledExtensions failed: %s\n",
				    error.localizedDescription.UTF8String);
				rc = 1;
			} else if (!modules || modules.count == 0) {
				printf("No FSKit modules found.\n");
				printf("  Check: sudo pluginkit -v -m -p "
				    "com.apple.fskit.fsmodule\n");
			} else {
				printf("Installed FSKit modules (%lu):\n",
				    (unsigned long)modules.count);
				for (FSModuleIdentity *m in modules) {
					printf("  [%s] %s\n        %s\n",
					    m.isEnabled ? "ENABLED " : "DISABLED",
					    m.bundleIdentifier.UTF8String,
					    m.url.absoluteString.UTF8String);
				}
				printf("\nTo enable a disabled module:\n");
				printf("  sudo pluginkit -e use -i "
				    "<bundleIdentifier>\n");
				printf("  sudo launchctl kickstart -k "
				    "system/com.apple.filesystems.fskitd\n");
			}
			dispatch_semaphore_signal(sem);
		}];

		dispatch_semaphore_wait(sem,
		    dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
		return (rc);
	}
}
