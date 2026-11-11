// SPDX-License-Identifier: CDDL-1.0
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * https://opensource.org/license/CDDL-1.0.
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, 2019 by Delphix. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2014 Spectra Logic Corporation, All rights reserved.
 * Copyright 2013 Saso Kiselkov. All rights reserved.
 * Copyright (c) 2017 Datto Inc.
 * Copyright (c) 2017, Intel Corporation.
 */

#include <sys/zfs_context.h>
#include <sys/spa_impl.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/unique.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/fm/util.h>
#include <sys/dsl_scan.h>
#include <sys/fs/zfs.h>
#include <sys/kstat.h>
#include <sys/ZFSPool.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_boot.h>
#include <sys/zio.h>
#include <sys/systeminfo.h>
#include <libkern/OSKextLib.h>

#include "zfs_prop.h"

const char *
spa_history_zone(void)
{
	return ("macos");
}

void
spa_import_os(spa_t *spa)
{
	int haslock = 0;
	int error;

	haslock = spa_namespace_held();

	/* Increase open refcount */
	spa_open_ref(spa, FTAG);

	if (haslock) {
		spa_namespace_exit(FTAG);
	}

	/* Create IOKit pool proxy */
	if ((error = spa_iokit_pool_proxy_create(spa)) != 0) {
		printf("%s spa_iokit_pool_proxy_create error %d\n",
		    __func__, error);
		/* spa_create succeeded, ignore proxy error */
	}

	/* Cache vdev info, needs open ref above, and pool proxy */

	if (error == 0 && (error = zfs_boot_update_bootinfo(spa)) != 0) {
		printf("%s update_bootinfo error %d\n", __func__, error);
		/* create succeeded, ignore error from bootinfo */
	}

	/* Drop open refcount */
	if (haslock) {
		spa_namespace_enter(FTAG);
	}

	spa_close(spa, FTAG);
}

/*
 * Shutdown handling.
 *
 * launchd sets kern.willshutdown as soon as it commits to a shutdown,
 * then boots out every daemon, then lets the kernel sync and unmount
 * several seconds later. Storage that lives in user space (disk image
 * helpers, dexts) can be gone by then, and a pool that keeps syncing
 * while its vdevs disappear one by one hits syncing-context VERIFYs
 * (openzfsonosx/openzfs-fork#129).
 *
 * zfs_shutdown_check() is called from points that run early in
 * shutdown (zed closing /dev/zfs at bootout, device loss). Once the
 * shutdown is confirmed it flushes every pool while its storage is
 * still present, so whatever happens to the devices afterwards there
 * is little or nothing left to write.
 */
static volatile uint32_t zfs_shutdown_started = 0;

static void
zfs_shutdown_sync_task(void *arg)
{
	(void) arg;
	printf("ZFS: system shutdown detected, syncing pools\n");
	spa_sync_allpools();
	printf("ZFS: pools synced for shutdown\n");
}

void
zfs_shutdown_check(void)
{
	if (zfs_shutdown_started != 0 || !spl_system_inshutdown())
		return;
	if (atomic_cas_32(&zfs_shutdown_started, 0, 1) != 0)
		return;
	(void) taskq_dispatch(system_taskq, zfs_shutdown_sync_task, NULL,
	    TQ_SLEEP);
}

/*
 * A vdev went away during shutdown: stop the pool instead of letting
 * it process the removal. Removal dirties the config, and the next
 * sync would write labels and ZAPs to a vdev tree that is being torn
 * down underneath it. A suspended pool issues no new transactions,
 * and zfs_vfs_unmount() leaves its filesystems mounted.
 */
void
zfs_shutdown_freeze(spa_t *spa)
{
	if (spa_suspended(spa))
		return;
	printf("ZFS: pool '%s' lost a device during shutdown, "
	    "suspending it\n", spa_name(spa));
	/*
	 * Fail new transactions with EIO instead of blocking them until
	 * the pool resumes (failmode=wait). A process blocked on a
	 * suspended pool can not be killed, and the kernel's final kill
	 * pass waits for every process to exit. This also keeps
	 * failmode=panic from panicking here. In-core only, the pool
	 * property is not changed.
	 */
	spa->spa_failmode = ZIO_FAILURE_MODE_CONTINUE;
	zio_suspend(spa, NULL, ZIO_SUSPEND_IOERR);
}

/*
 * True when waiting for this pool to sync would never return: the
 * system is going down and the pool is suspended.
 */
boolean_t
zfs_shutdown_frozen(spa_t *spa)
{
	return (spa != NULL && spa_suspended(spa) &&
	    spl_system_inshutdown());
}

void
spa_export_os(spa_t *spa)
{
	/* Remove IOKit pool proxy */
	spa_iokit_pool_proxy_destroy(spa);
}

void
spa_activate_os(spa_t *spa)
{
	/* spa_t *spa = (spa_t *)arg; */
	/* Lock kext in kernel while mounted */
	OSKextRetainKextWithLoadTag(OSKextGetCurrentLoadTag());
}

void
spa_deactivate_os(spa_t *spa)
{
	/* spa_t *spa = (spa_t *)arg; */
	OSKextReleaseKextWithLoadTag(OSKextGetCurrentLoadTag());
}
