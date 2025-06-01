/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, 2016 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev_file.h>
#include <sys/vdev_impl.h>
#include <sys/vdev_trim.h>
#include <sys/zio.h>
#include <sys/fs/zfs.h>
#include <sys/fm/fs/zfs.h>
#include <sys/abd.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>


#ifdef CLOSE_ON_UNMOUNT
/*
 * This sucks!
 *
 * So vdev_file opens the file on an underlying file-system, which
 * means calling vnode_open("diskimage"), this will then hold a
 * v_usecount during the time that the pool is open (imported).
 * When it comes time to "reboot" the system, it only issues
 * unmount to all mounted file-systems. This is not an export.
 * The pool still has v_usecount on "diskimage", so vflush() of
 * that file-system can not complete, and we hang waiting forever
 * for the usecount to go down (.. and all file-systems to be unmounted)
 *
 * Sadly Apple has left us no way to know when the system is in
 * reboot/shutdown.
 *
 * So now, any unmount request for a dataset, it will run through
 * all the vdevs (in that pool), and if the vdev is one of "vdev_file",
 * we will close the underlying opened file. We do this "dirty".
 *
 * The next call to vdev_file_io_start() will notice the file is
 * not open, and reopen it.
 *
 * In theory, vdev_file pools are not common, and unmounting is not
 * common, so the penalty might not be too bad. Compared to reboots
 * that hang.
 *
 * vdev_disk gets away with it, as all open disks are in /dev/ mount,
 * which is not unmounted at reboot. (virtual filesystem).
 *
 * Linux and FreeBSD appear to get away with it by using
 * file-descriptor equivalent opens, which is flushed at the start of
 * reboots. Apple will not let us open files this way from within the
 * kernel.
 *
 */
static uint32_t vdev_file_close_on_unmount = 1;
ZFS_MODULE_PARAM(zfs_vdev_file, vdev_file_, close_on_unmount, UINT, ZMOD_RW,
	"close vdevs on unmount to avoid reboot hang");

static void
vdev_file_close_all_impl(vdev_t *vd)
{
	if (vd->vdev_ops->vdev_op_leaf) {
		if (vd->vdev_ops == &vdev_file_ops) {
			vdev_file_t *vf;
			vf = vd->vdev_tsd;
			if (vf != NULL) {
				zfs_file_t *fp = vf->vf_file;
				if (fp != NULL) {
					atomic_cas_ptr(&vf->vf_file, fp, NULL);
					if (vf->vf_file == NULL) {
						zfs_file_close(fp);
						printf("closed '%s' "
						    "(close_on_unmount)\n",
						    vd->vdev_path);
					}
				}
			}
		}
		return;
	}

	for (int c = 0; c < vd->vdev_children; c++)
		vdev_file_close_all_impl(vd->vdev_child[c]);
}

void
vdev_file_close_all(objset_t *os)
{
	spa_t *spa = dmu_objset_spa(os);
	if (!vdev_file_close_on_unmount)
		return;
	spa_config_enter(spa, SCL_VDEV, FTAG, RW_READER);
	vdev_file_close_all_impl(spa->spa_root_vdev);
	spa_config_exit(spa, SCL_VDEV, FTAG);
}
#endif
