/*
 * mount_zfs — FSKit activation helper stub for OpenZFS.
 *
 * Background
 * ----------
 * In the FSKit pure-UserFS model, the VFS mount point is created by lifs.kext
 * after ZFSFileSystem.loadResource: → ZFSVolume.activateWithOptions: →
 * ZFSVolume.mountWithOptions: complete successfully.
 *
 * diskarbitrationd / fskitd look for FSMountExecutable in the FSPersonalities
 * of the module as a signal that this personality supports mounting.  Without
 * it, fskitd treats the personality as non-mountable and never spawns the
 * activate instance.
 *
 * Once FSMountExecutable is present, fskitd will:
 *   1. Spawn the activate instance (new ZFSFSKit process).
 *   2. Call loadResource: → activateWithOptions: → mountWithOptions: on it.
 *   3. Invoke this helper after the FSKit mount is already in place.
 *
 * Because lifs.kext already created the VFS mount point in step 2, this
 * binary simply logs its arguments (for diagnostics) and exits 0.  It must
 * NOT attempt a duplicate mount(2) call.
 *
 * If fskitd eventually stops calling this helper (Apple may remove the legacy
 * helper invocation for pure-UserFS modules), no change is needed here.
 */

#import <Foundation/Foundation.h>

int
main(int argc, char *argv[])
{
	@autoreleasepool {
		/*
		 * Log the arguments fskitd / diskarbitrationd pass to us.
		 * This helps diagnose the activation flow without printing to
		 * stdout (which may not be connected to a terminal).
		 */
		NSMutableString *args = [NSMutableString string];
		for (int i = 0; i < argc; i++) {
			if (i > 0)
				[args appendString:@" "];
			[args appendFormat:@"'%s'", argv[i]];
		}
		NSLog(@"mount_zfs: called by fskitd/diskarbitrationd with args: %@",
		    args);

		/*
		 * Exit 0: the FSKit framework (lifs.kext) has already completed
		 * the VFS mount via ZFSVolume.mountWithOptions:.  This helper is
		 * a no-op placeholder required by the FSKit module metadata.
		 */
		return (0);
	}
}
