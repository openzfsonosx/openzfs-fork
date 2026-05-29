/*
 * Copyright (c) 2025 Jorgen Lundman <lundman@lundman.net>
 *
 * zfs_fskit.c — Pure-C bridge: ZFS engine (libzpool) ↔ FSKit ObjC layer.
 *
 * Uses only plain C types; no ObjC, no FSKit headers.
 * The ObjC extension (ZFSFileSystem.m, ZFSVolume.m) calls these functions.
 *
 * SA attribute lookup pattern follows cmd/zdb/zdb.c:
 *   sa_setup(os, sa_attrs, zfs_attr_table, ZPL_END, &sa_attr_table)
 * which gives us a sa_attr_type_t[] indexed by zpl_attr_t.
 */

#ifdef FSKIT

#include "zfs_fskit.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <os/log.h>
/* Route C-level messages into the unified log (visible via `log stream`). */
#define	FSKIT_LOG(fmt, ...) \
	os_log(OS_LOG_DEFAULT, "ZFSFSKit: " fmt, ##__VA_ARGS__)

/*
 * zfs_context.h must come first: it includes <sys/types.h> which (via the
 * SPL include path) provides inode_timespec_t required by xvattr.h, which
 * in turn is pulled in by zfs_acl.h → zfs_znode.h → zfs_sa.h.
 * This is the same pattern used by cmd/zdb/zdb.c.
 */
#include <sys/zfs_context.h>

/*
 * Include order matters:
 * - zfs_znode.h pulls in zfs_acl.h which defines zfs_acl_phys_t
 * - zfs_sa.h uses zfs_acl_phys_t in the deprecated znode_phys_t struct
 * - zfs_sa.h must therefore come after zfs_znode.h
 */
#include <sys/zfs_znode.h>
#include <sys/zfs_sa.h>

#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/zap.h>
#include <sys/sa.h>
#include <sys/sa_impl.h>
#include <sys/nvpair.h>
#include <sys/fs/zfs.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <libzpool.h>
#include <libzfs.h>
#include <libzutil.h>

/* ------------------------------------------------------------------ */
/* Engine initialisation */
/* ------------------------------------------------------------------ */

void
zfs_fskit_init(void)
{
	/*
	 * Read-only mode: the FSKit sandbox provides the block device fd
	 * opened O_RDONLY.  SPA_MODE_WRITE would cause vdev_disk_open to
	 * call open("/dev/fd/<N>", O_RDWR), which the fdesc filesystem
	 * rejects with EINVAL when the underlying fd is read-only.
	 */
	kernel_init(SPA_MODE_READ);
	/*
	 * Enable ZFS internal dprintf tracing when ZFS_DEBUG is set in the
	 * environment.  dprintf_setup dereferences argc, so pass a real int.
	 */
	int fake_argc = 2;
	char *fake_argv[] = { "", "debug=on", NULL };
	dprintf_setup(&fake_argc, fake_argv);
	fprintf(stderr, "zfs_fskit: ZFS engine initialised (read-only)\n");
}

/* ------------------------------------------------------------------ */
/* Probe */
/* ------------------------------------------------------------------ */

int
zfs_fskit_probe_bsd(const char *bsdname,
    char *poolname, size_t poolname_len,
    uint64_t *pool_guid)
{
	nvlist_t *config = NULL;
	nvlist_t *nvroot = NULL;
	char devpath[MAXPATHLEN];

	snprintf(devpath, sizeof (devpath), "/dev/%s", bsdname);

	if (nvlist_alloc(&config, NV_UNIQUE_NAME, 0) != 0)
		return (-1);
	if (nvlist_alloc(&nvroot, NV_UNIQUE_NAME, 0) != 0) {
		nvlist_free(config);
		return (-1);
	}

	fnvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	fnvlist_add_string(nvroot, ZPOOL_CONFIG_PATH, devpath);
	fnvlist_add_uint64(nvroot, ZPOOL_CONFIG_WHOLE_DISK, 0);

	fnvlist_add_string(config, ZPOOL_CONFIG_POOL_NAME, "(probe)");
	fnvlist_add_uint64(config, ZPOOL_CONFIG_POOL_GUID, 0);
	fnvlist_add_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    (uint64_t)POOL_STATE_EXPORTED);
	fnvlist_add_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, nvroot);
	nvlist_free(nvroot);

	nvlist_t *result = spa_tryimport(config);
	nvlist_free(config);

	if (result == NULL)
		return (-1);

	const char *name = NULL;
	uint64_t guid = 0;

	(void) nvlist_lookup_string(result, ZPOOL_CONFIG_POOL_NAME, &name);
	(void) nvlist_lookup_uint64(result, ZPOOL_CONFIG_POOL_GUID, &guid);

	if (name == NULL || guid == 0) {
		nvlist_free(result);
		return (-1);
	}

	strlcpy(poolname, name, poolname_len);
	*pool_guid = guid;
	nvlist_free(result);

	return (0);
}

/*
 * zfs_fskit_probe_buf — parse a ZFS vdev label from a raw memory buffer.
 *
 * ZFS vdev label layout (256 KB total per label):
 *   [  0 KB –   8 KB)  vl_pad1     (zeroed)
 *   [  8 KB –  16 KB)  vl_pad2     (zeroed)
 *   [ 16 KB – 128 KB)  vl_vdev_phys — packed nvlist config
 *   [128 KB – 256 KB)  vl_uberblock_ring
 *
 * The packed nvlist at offset VDEV_SKIP_SIZE (16 KB) contains the pool
 * name and GUID we need for the probe result.
 *
 * We try to unpack starting at VDEV_SKIP_SIZE.  If nvlist_unpack succeeds
 * and returns a valid ZPOOL_CONFIG_POOL_NAME + ZPOOL_CONFIG_POOL_GUID, the
 * device is recognised as a ZFS vdev.
 */
#define	ZFS_PROBE_VDEV_PAD	(8 * 1024)		/* VDEV_PAD_SIZE */
#define	ZFS_PROBE_SKIP		(2 * ZFS_PROBE_VDEV_PAD) /* vdev_phys offset */
#define	ZFS_PROBE_PHYS_SIZE	(112 * 1024)		/* vl_vdev_phys size */
#define	ZFS_PROBE_LABEL_SIZE	(256 * 1024)		/* total label size */

int
zfs_fskit_probe_buf(const void *buf, size_t buf_len,
    char *poolname, size_t poolname_len,
    uint64_t *pool_guid)
{
	if (buf_len < ZFS_PROBE_SKIP + 8)
		return (-1);

	const char *nvdata = (const char *)buf + ZFS_PROBE_SKIP;
	size_t nvlen = (buf_len > ZFS_PROBE_SKIP + ZFS_PROBE_PHYS_SIZE)
	    ? ZFS_PROBE_PHYS_SIZE
	    : (buf_len - ZFS_PROBE_SKIP);

	nvlist_t *config = NULL;
	if (nvlist_unpack((char *)nvdata, nvlen, &config, 0) != 0) {
		fprintf(stderr, "zfs_fskit_probe_buf: nvlist_unpack failed "
		    "(not a ZFS label or checksum mismatch)\n");
		return (-1);
	}

	const char *name = NULL;
	uint64_t guid = 0;
	(void) nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &name);
	(void) nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &guid);

	if (name == NULL || guid == 0) {
		fprintf(stderr, "zfs_fskit_probe_buf: label found but no "
		    "pool name/GUID (incomplete label?)\n");
		nvlist_free(config);
		return (-1);
	}

	strlcpy(poolname, name, poolname_len);
	*pool_guid = guid;
	nvlist_free(config);
	fprintf(stderr, "zfs_fskit_probe_buf: found pool '%s' guid %llu\n",
	    poolname, (unsigned long long)guid);
	return (0);
}

/* ------------------------------------------------------------------ */
/* Import / export */
/* ------------------------------------------------------------------ */

int
zfs_fskit_pool_import(const char *poolname, uint64_t pool_guid,
    const char *bsdname)
{
	char devpath[MAXPATHLEN];
	nvlist_t *config = NULL;
	nvlist_t *nvroot = NULL;

	snprintf(devpath, sizeof (devpath), "/dev/%s", bsdname);

	/*
	 * Sandbox smoke-test: try to open the device before calling spa_import.
	 * If this fails with EPERM/EACCES the sandbox profile blocks direct
	 * device access and we need a different import strategy.
	 */
	{
		int fd = open(devpath, O_RDONLY | O_NONBLOCK);
		if (fd < 0) {
			fprintf(stderr, "zfs_fskit_pool_import: open(%s) "
			    "FAILED errno=%d (%s) — sandbox may block device "
			    "access\n", devpath, errno, strerror(errno));
			/*
			 * Don't bail out — let spa_import try anyway;
			 * its error will be more informative.
			 */
		} else {
			fprintf(stderr, "zfs_fskit_pool_import: open(%s) "
			    "OK (fd=%d) — device access allowed\n",
			    devpath, fd);
			close(fd);
		}
	}

	if (nvlist_alloc(&config, NV_UNIQUE_NAME, 0) != 0)
		return (ENOMEM);
	if (nvlist_alloc(&nvroot, NV_UNIQUE_NAME, 0) != 0) {
		nvlist_free(config);
		return (ENOMEM);
	}

	fnvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	fnvlist_add_string(nvroot, ZPOOL_CONFIG_PATH, devpath);
	fnvlist_add_uint64(nvroot, ZPOOL_CONFIG_WHOLE_DISK, 0);

	fnvlist_add_string(config, ZPOOL_CONFIG_POOL_NAME, poolname);
	fnvlist_add_uint64(config, ZPOOL_CONFIG_POOL_GUID, pool_guid);
	fnvlist_add_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    (uint64_t)POOL_STATE_EXPORTED);
	fnvlist_add_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, nvroot);
	nvlist_free(nvroot);

	/* spa_import takes char* (not const); cast is safe — no mutation */
	int rc = spa_import((char *)(uintptr_t)poolname,
	    config, NULL /* props */, 0 /* flags */);
	nvlist_free(config);

	return (rc);
}

/*
 * update_vdev_paths — recursively replace ZPOOL_CONFIG_PATH in disk vdevs.
 *
 * The config from zpool_read_label / vdev labels has the original device
 * paths (e.g. /dev/disk4s1).  We replace every disk-vdev path with our
 * /dev/fd/<N> fdesc path so that spa_import re-uses the already-open fd
 * rather than attempting a new open(2) that the sandbox may deny.
 */
static void
update_vdev_paths(nvlist_t *vdev, const char *fdpath)
{
	char *type = NULL;
	if (nvlist_lookup_string(vdev, ZPOOL_CONFIG_TYPE, &type) != 0)
		return;

	if (strcmp(type, VDEV_TYPE_DISK) == 0) {
		(void) nvlist_remove_all(vdev, ZPOOL_CONFIG_PATH);
		fnvlist_add_string(vdev, ZPOOL_CONFIG_PATH, fdpath);
		/*
		 * Clear WHOLE_DISK: the raw device is a partition, not a whole
		 * disk — WHOLE_DISK=1 causes ZFS to apply a 4 MiB offset that
		 * skips the vdev labels.
		 */
		(void) nvlist_remove_all(vdev, ZPOOL_CONFIG_WHOLE_DISK);
		fnvlist_add_uint64(vdev, ZPOOL_CONFIG_WHOLE_DISK, 0);
		return;
	}

	/*
	 * File vdevs store the original host path (e.g. /export/pool.img).
	 * Redirect to our pre-opened fd so the pool can be imported regardless
	 * of where the image file lives on this host.
	 */
	if (strcmp(type, VDEV_TYPE_FILE) == 0) {
		(void) nvlist_remove_all(vdev, ZPOOL_CONFIG_PATH);
		fnvlist_add_string(vdev, ZPOOL_CONFIG_PATH, fdpath);
		return;
	}

	nvlist_t **children = NULL;
	uint_t nch = 0;
	if (nvlist_lookup_nvlist_array(vdev, ZPOOL_CONFIG_CHILDREN,
	    &children, &nch) == 0) {
		for (uint_t i = 0; i < nch; i++)
			update_vdev_paths(children[i], fdpath);
	}
	if (nvlist_lookup_nvlist_array(vdev, ZPOOL_CONFIG_L2CACHE,
	    &children, &nch) == 0) {
		for (uint_t i = 0; i < nch; i++)
			update_vdev_paths(children[i], fdpath);
	}
	if (nvlist_lookup_nvlist_array(vdev, ZPOOL_CONFIG_SPARES,
	    &children, &nch) == 0) {
		for (uint_t i = 0; i < nch; i++)
			update_vdev_paths(children[i], fdpath);
	}
}

int
zfs_fskit_pool_import_fd(const char *poolname, uint64_t pool_guid, int devfd)
{
	/*
	 * Sandbox-safe pool import via pre-opened fd.
	 *
	 * Strategy:
	 *  1. dup() FSKit's fd so we own a long-lived copy for vdev I/O.
	 *     The dup is kept open for the lifetime of the imported pool.
	 *
	 *  2. zpool_read_label(devfd) — read the real, COMPLETE vdev config
	 *     directly from the on-disk labels using our pre-opened fd.
	 *     This gives us the full vdev tree with proper GUIDs, IDs, and
	 *     ASIZEs that VDEV_ALLOC_LOAD requires.
	 *
	 *     WHY NOT spa_tryimport WITH A SYNTHETIC CONFIG?
	 *     spa_tryimport calls spa_config_parse with VDEV_ALLOC_LOAD which
	 *     requires ZPOOL_CONFIG_ID and ZPOOL_CONFIG_GUID in EVERY vdev
	 *     entry (vdev.c:847-852).  A hand-built config without those
	 *     fields causes vdev_alloc to return EINVAL, spa_root_vdev stays
	 *     NULL, and spa_tryimport returns NULL.
	 *
	 *  3. Redirect every disk-vdev PATH in the label config to
	 *     /dev/fd/<myfd> so spa_import opens the device via the already-
	 *     open fd rather than by the raw-device path
	 *     (which the App Sandbox may deny).
	 *
	 *  4. spa_import with ZFS_IMPORT_ANY_HOST to handle pools that were
	 *     not cleanly exported (e.g. still held by the IOKit kext).
	 *
	 * Device size:
	 *     DKIOCGETBLOCKCOUNT/SIZE ioctls are blocked by the App Sandbox.
	 *     ZFSFileSystem.m calls fskit_register_device() (libspl) before
	 *     import to populate the path→size registry.  fskit_fstat_blk()
	 *     in libspl resolves any dup'd fd via fcntl(F_GETPATH) and looks
	 *     up the size in that registry when ioctls fail.
	 */

	/*
	 * pool_guid is provided by the caller for diagnostic use; the actual
	 * GUID used for import comes from the on-disk labels via
	 * zpool_read_label, so we don't need to pass it to spa_import.
	 */
	(void) pool_guid;

	int fl = fcntl(devfd, F_GETFL);
	FSKIT_LOG("import_fd: FSKit fd %d flags 0x%x (%s)", devfd,
	    fl < 0 ? 0 : fl,
	    (fl < 0) ? "?" :
	    ((fl & O_ACCMODE) == O_RDWR)  ? "O_RDWR" :
	    ((fl & O_ACCMODE) == O_WRONLY) ? "O_WRONLY" : "O_RDONLY");

	/* ---- Step 1: dup the fd ---- */
	int myfd = dup(devfd);
	if (myfd < 0) {
		FSKIT_LOG("import_fd: dup(%d) failed errno=%d", devfd, errno);
		return (errno);
	}
	char fdpath[64];
	snprintf(fdpath, sizeof (fdpath), "/dev/fd/%d", myfd);

	/* ---- Step 2: read real vdev config from on-disk labels ---- */
	nvlist_t *config = NULL;
	int num_labels = 0;
	FSKIT_LOG("import_fd: zpool_read_label on fd %d for pool '%s'",
	    devfd, poolname);
	int err = zpool_read_label(devfd, &config, &num_labels);
	if (err != 0 || config == NULL) {
		FSKIT_LOG("import_fd: zpool_read_label failed: "
		    "err=%d config=%s num_labels=%d",
		    err, config ? "non-NULL" : "NULL", num_labels);
		close(myfd);
		return (ENODEV);
	}
	FSKIT_LOG("import_fd: zpool_read_label OK: %d label(s)", num_labels);

	/* Log what we found in the label. */
	{
		char *lbl_name = NULL;
		uint64_t lbl_guid = 0;
		nvlist_t *lbl_tree = NULL;
		char *root_type = NULL;
		(void) nvlist_lookup_string(config,
		    ZPOOL_CONFIG_POOL_NAME, &lbl_name);
		(void) nvlist_lookup_uint64(config,
		    ZPOOL_CONFIG_POOL_GUID, &lbl_guid);
		if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &lbl_tree) == 0)
			(void) nvlist_lookup_string(lbl_tree,
			    ZPOOL_CONFIG_TYPE, &root_type);
		FSKIT_LOG("import_fd: label: name='%s' guid=%llu "
		    "vdev_tree.type='%s'",
		    lbl_name ? lbl_name : "?",
		    (unsigned long long)lbl_guid,
		    root_type ? root_type : "?");
	}

	/*
	 * The macOS kext stores VDEV_TREE with the disk vdev at the top level,
	 * without the standard type="root" wrapper that OpenZFS expects.
	 * spa_config_parse (via VDEV_ALLOC_LOAD) requires the outermost vdev to
	 * have type="root" (vdev.c:867: ops != &vdev_root_ops && root==NULL →
	 * EINVAL).  If the label does not have a root wrapper, synthesize one.
	 *
	 * Root-vdev GUIDs are not checked by vdev_validate() — it returns 0
	 * immediately for non-leaf vdevs — so GUID=1 is a safe placeholder
	 * for the synthesized root.
	 */
	{
		nvlist_t *top_vdev = NULL;
		if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &top_vdev) == 0) {
			char *top_type = NULL;
			(void) nvlist_lookup_string(top_vdev,
			    ZPOOL_CONFIG_TYPE, &top_type);
			if (top_type != NULL &&
			    strcmp(top_type, VDEV_TYPE_ROOT) != 0) {
				/*
				 * The root vdev GUID must equal the pool GUID.
				 * spa_ld_parse_config() ASSERTs:
				 *   spa_guid(spa) == ZPOOL_CONFIG_POOL_GUID
				 * spa_guid() returns the root vdev GUID before
				 * the DSL pool is loaded. Read it first to log.
				 */
				uint64_t pool_guid_val = 0;
				(void) nvlist_lookup_uint64(config,
				    ZPOOL_CONFIG_POOL_GUID, &pool_guid_val);
				FSKIT_LOG("import_fd: vdev_tree.type='%s', "
				    "synthesising root wrapper "
				    "(pool_guid=%llu)",
				    top_type,
				    (unsigned long long)pool_guid_val);
				/* Copy disk vdev; normalise id to 0. */
				nvlist_t *disk_copy = fnvlist_dup(top_vdev);
				(void) nvlist_remove(disk_copy,
				    ZPOOL_CONFIG_ID, DATA_TYPE_UINT64);
				fnvlist_add_uint64(disk_copy,
				    ZPOOL_CONFIG_ID, 0);
				/* Build the root vdev wrapper. */
				nvlist_t *root_vdev = fnvlist_alloc();
				fnvlist_add_string(root_vdev,
				    ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT);
				fnvlist_add_uint64(root_vdev,
				    ZPOOL_CONFIG_ID, 0);
				fnvlist_add_uint64(root_vdev,
				    ZPOOL_CONFIG_GUID, pool_guid_val);
				nvlist_t *children[1] = { disk_copy };
				fnvlist_add_nvlist_array(root_vdev,
				    ZPOOL_CONFIG_CHILDREN,
				    (nvlist_t * const *)children, 1);
				fnvlist_free(disk_copy);
				/* Replace VDEV_TREE with wrapped version. */
				fnvlist_remove(config, ZPOOL_CONFIG_VDEV_TREE);
				fnvlist_add_nvlist(config,
				    ZPOOL_CONFIG_VDEV_TREE, root_vdev);
				fnvlist_free(root_vdev);
			}
		}
	}

	/*
	 * Override pool state to EXPORTED so spa_import treats it as a pool
	 * that is not currently active on any host.
	 */
	fnvlist_add_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    (uint64_t)POOL_STATE_EXPORTED);

	/* ---- Step 3: redirect all disk paths to /dev/fd/<myfd> ---- */
	{
		nvlist_t *tree = NULL;
		if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &tree) == 0)
			update_vdev_paths(tree, fdpath);
	}

	/* ---- Step 4: spa_import ---- */
	FSKIT_LOG("import_fd: spa_import via %s for pool '%s'",
	    fdpath, poolname);
	int rc = spa_import((char *)(uintptr_t)poolname,
	    config, NULL, ZFS_IMPORT_ANY_HOST);

	if (rc != 0) {
		nvlist_t *load_info = NULL;
		char *msg = NULL;
		if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_LOAD_INFO,
		    &load_info) == 0)
			(void) nvlist_lookup_string(load_info,
			    ZPOOL_CONFIG_LOAD_INFO, &msg);
		FSKIT_LOG("import_fd: spa_import failed rc=%d msg='%s'",
		    rc, msg ? msg : "(none)");
		nvlist_free(config);
		close(myfd);
	} else {
		nvlist_free(config);
		FSKIT_LOG("import_fd: spa_import OK for pool '%s'", poolname);
		/*
		 * Suspend the spa async thread immediately after import.
		 *
		 * spa_import queues SPA_ASYNC_CONFIG_UPDATE (task 32) and
		 * potentially other async tasks.  In SPA_MODE_READ these tasks
		 * hit ASSERT(spa_writeable(spa)) → SIGABRT when the async
		 * thread processes them.  Suspending the thread prevents it
		 * from running; the suspension is never lifted because this
		 * spa lives only as long as the FSKit mount.
		 */
		spa_t *spa = NULL;
		if (spa_open(poolname, &spa, FTAG) == 0) {
			spa_async_suspend(spa);
			spa_close(spa, FTAG);
		}
		/* myfd stays open — ZFS holds it for vdev I/O. */
	}

	return (rc);
}

void
zfs_fskit_pool_export(const char *poolname)
{
	(void) spa_export(poolname, NULL, B_TRUE /* force */, B_FALSE);
}

/* ------------------------------------------------------------------ */
/* Root object lookup */
/* ------------------------------------------------------------------ */

int
zfs_fskit_root_obj(const char *poolname, uint64_t *root_obj_out)
{
	objset_t *os;
	int error;

	error = dmu_objset_hold(poolname, FTAG, &os);
	if (error != 0) {
		FSKIT_LOG("root_obj: objset_hold('%s') -> %d",
		    poolname, error);
		return (error);
	}

	FSKIT_LOG("root_obj: objset_hold OK type=%d (DMU_OST_ZFS=%d)",
	    dmu_objset_type(os), DMU_OST_ZFS);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ,
	    sizeof (uint64_t), 1, root_obj_out);

	if (error != 0) {
		FSKIT_LOG("root_obj: zap_lookup(MASTER_NODE_OBJ,'%s') -> %d; "
		    "dumping master node ZAP:", ZFS_ROOT_OBJ, error);
		zap_cursor_t zc;
		zap_attribute_t *za = zap_attribute_alloc();
		zap_cursor_init(&zc, os, MASTER_NODE_OBJ);
		int nkeys = 0;
		while (zap_cursor_retrieve(&zc, za) == 0) {
			FSKIT_LOG("root_obj:   key='%s'", za->za_name);
			zap_cursor_advance(&zc);
			nkeys++;
		}
		zap_cursor_fini(&zc);
		zap_attribute_free(za);
		if (nkeys == 0) {
			/* Check whether dnode 1 exists at all. */
			dnode_t *dn = NULL;
			int dnerr = dnode_hold(os, MASTER_NODE_OBJ, FTAG, &dn);
			if (dnerr != 0) {
				FSKIT_LOG("root_obj: dnode_hold(1) -> %d "
				    "(dnode is FREE/unallocated)", dnerr);
			} else {
				FSKIT_LOG("root_obj: dnode1 type=%u "
				    "nlevels=%u ZAP empty",
				    dn->dn_type, dn->dn_nlevels);
				dnode_rele(dn, FTAG);
			}
		}
	} else {
		FSKIT_LOG("root_obj: root_obj=%llu",
		    (unsigned long long)*root_obj_out);
	}

	dmu_objset_rele(os, FTAG);
	return (error);
}

/* ------------------------------------------------------------------ */
/* SA setup / teardown helpers (pattern from cmd/zdb/zdb.c) */
/* ------------------------------------------------------------------ */

/*
 * Open a ZFS dataset objset and initialise the SA attribute table.
 * On success *osp and *sa_table_out are set; caller must close with
 * close_dataset_sa().
 */
/*
 * open_dataset_sa — open a ZFS dataset objset and initialise the SA table.
 *
 * sa_setup() fills in a sa_attr_type_t* array indexed by zpl_attr_t.
 * Its last argument is sa_attr_type_t** (pointer-to-pointer), so we
 * take sa_attr_type_t** here and pass it straight through.
 */
/*
 * Tag for dmu_objset_hold/rele pairs that span open_dataset_sa and
 * close_dataset_sa.  FTAG (__func__) would differ between the two
 * functions, causing the rrwlock linked-reader tracking to assert in
 * debug builds (ASSERT(!rrl->rr_track_all) in rrw_exit when the hold
 * tag is not found in the reader list).
 */
static const void *const ds_sa_tag = "zfs_fskit_sa";

static int
open_dataset_sa(const char *poolname, objset_t **osp,
    sa_attr_type_t **sa_table_out)
{
	int error;

	*sa_table_out = NULL;

	error = dmu_objset_hold(poolname, ds_sa_tag, osp);
	if (error != 0)
		return (error);

	if (dmu_objset_type(*osp) != DMU_OST_ZFS) {
		dmu_objset_rele(*osp, ds_sa_tag);
		*osp = NULL;
		return (ENOTSUP);
	}

	uint64_t sa_attrs = 0, version = 0;
	(void) zap_lookup(*osp, MASTER_NODE_OBJ, ZPL_VERSION_STR,
	    8, 1, &version);
	if (version >= ZPL_VERSION_SA) {
		(void) zap_lookup(*osp, MASTER_NODE_OBJ, ZFS_SA_ATTRS,
		    8, 1, &sa_attrs);
	}

	/* sa_setup writes the allocated table pointer into *sa_table_out */
	error = sa_setup(*osp, sa_attrs, zfs_attr_table, ZPL_END,
	    sa_table_out);
	if (error != 0) {
		*sa_table_out = NULL;
		dmu_objset_rele(*osp, ds_sa_tag);
		*osp = NULL;
	}
	return (error);
}

static void
close_dataset_sa(objset_t *os)
{
	if (os->os_sa != NULL)
		sa_tear_down(os);
	dmu_objset_rele(os, ds_sa_tag);
}

/* ------------------------------------------------------------------ */
/* Internal: fill zfs_item_attrs_t from an SA handle */
/* ------------------------------------------------------------------ */

static void
fill_attrs_from_sa(sa_handle_t *hdl, uint64_t obj,
    sa_attr_type_t *sa_table, zfs_item_attrs_t *attrs)
{
	uint64_t mode = 0, size = 0, uid = 0, gid = 0, flags = 0, nlink = 1;
	uint64_t atime[2] = {0}, mtime[2] = {0}, ctime[2] = {0};
	uint64_t crtime[2] = {0};

	(void) sa_lookup(hdl, sa_table[ZPL_MODE],   &mode,   sizeof (mode));
	(void) sa_lookup(hdl, sa_table[ZPL_SIZE],   &size,   sizeof (size));
	(void) sa_lookup(hdl, sa_table[ZPL_UID],    &uid,    sizeof (uid));
	(void) sa_lookup(hdl, sa_table[ZPL_GID],    &gid,    sizeof (gid));
	(void) sa_lookup(hdl, sa_table[ZPL_FLAGS],  &flags,  sizeof (flags));
	(void) sa_lookup(hdl, sa_table[ZPL_LINKS],  &nlink,  sizeof (nlink));
	(void) sa_lookup(hdl, sa_table[ZPL_ATIME],  atime,   sizeof (atime));
	(void) sa_lookup(hdl, sa_table[ZPL_MTIME],  mtime,   sizeof (mtime));
	(void) sa_lookup(hdl, sa_table[ZPL_CTIME],  ctime,   sizeof (ctime));
	(void) sa_lookup(hdl, sa_table[ZPL_CRTIME], crtime,  sizeof (crtime));

	attrs->mode   = (uint32_t)mode;
	attrs->size   = size;
	attrs->uid    = (uint32_t)uid;
	attrs->gid    = (uint32_t)gid;
	attrs->flags  = (uint32_t)flags;
	attrs->nlink  = (nlink > 0) ? (uint32_t)nlink : 1;
	attrs->obj_id = obj;

	attrs->atime.tv_sec  = (time_t)atime[0];
	attrs->atime.tv_nsec = (long)atime[1];
	attrs->mtime.tv_sec  = (time_t)mtime[0];
	attrs->mtime.tv_nsec = (long)mtime[1];
	attrs->ctime.tv_sec  = (time_t)ctime[0];
	attrs->ctime.tv_nsec = (long)ctime[1];
	attrs->btime.tv_sec  = (time_t)crtime[0];
	attrs->btime.tv_nsec = (long)crtime[1];
}

/* ------------------------------------------------------------------ */
/* VFS ops */
/* ------------------------------------------------------------------ */

int
zfs_fskit_getattr(const char *poolname, uint64_t obj,
    zfs_item_attrs_t *attrs)
{
	objset_t *os = NULL;
	sa_attr_type_t *sa_table = NULL;
	sa_handle_t *hdl = NULL;
	int rc;

	rc = open_dataset_sa(poolname, &os, &sa_table);
	if (rc != 0)
		return (rc);
	if (sa_table == NULL) {
		close_dataset_sa(os);
		return (ENOTSUP);
	}

	rc = sa_handle_get(os, obj, NULL, SA_HDL_SHARED, &hdl);
	if (rc != 0) {
		close_dataset_sa(os);
		return (rc);
	}

	memset(attrs, 0, sizeof (*attrs));
	fill_attrs_from_sa(hdl, obj, sa_table, attrs);

	sa_handle_destroy(hdl);
	close_dataset_sa(os);
	return (0);
}

int
zfs_fskit_lookup(const char *poolname, uint64_t dir_obj,
    const char *name, uint64_t *child_obj)
{
	objset_t *os;
	int rc;

	rc = dmu_objset_hold(poolname, FTAG, &os);
	if (rc != 0)
		return (rc);

	uint64_t raw_val = 0;
	rc = zap_lookup(os, dir_obj, name, 8, 1, &raw_val);
	dmu_objset_rele(os, FTAG);

	if (rc == 0)
		*child_obj = ZFS_DIRENT_OBJ(raw_val);

	return (rc);
}

int
zfs_fskit_read(const char *poolname, uint64_t obj,
    off_t offset, size_t length, void *buf, size_t *actual_out)
{
	*actual_out = 0;

	/* Get the logical file size from SA so we can clamp the read. */
	zfs_item_attrs_t attrs = {};
	int rc = zfs_fskit_getattr(poolname, obj, &attrs);
	if (rc != 0)
		return (rc);

	uint64_t file_size = attrs.size;

	if (offset < 0 || (uint64_t)offset >= file_size)
		return (0);	/* past EOF — not an error, bytes = 0 */

	if ((uint64_t)offset + length > file_size)
		length = (size_t)(file_size - (uint64_t)offset);

	if (length == 0)
		return (0);

	objset_t *os;
	rc = dmu_objset_hold(poolname, FTAG, &os);
	if (rc != 0)
		return (rc);

	rc = dmu_read(os, obj, (uint64_t)offset, length, buf,
	    DMU_READ_PREFETCH);
	dmu_objset_rele(os, FTAG);

	if (rc == 0)
		*actual_out = length;
	return (rc);
}

int
zfs_fskit_readdir_next(const char *poolname, uint64_t dir_obj,
    uint64_t cookie, zfs_dirent_t *ent, zfs_item_attrs_t *attrs_out)
{
	objset_t *os = NULL;
	sa_attr_type_t *sa_table = NULL;
	zap_cursor_t zc;
	zap_attribute_t *za;
	int rc;

	rc = open_dataset_sa(poolname, &os, &sa_table);
	if (rc != 0)
		return (rc);

	za = zap_attribute_alloc();
	if (za == NULL) {
		close_dataset_sa(os);
		return (ENOMEM);
	}

	/*
	 * cookie == 0  → FSDirectoryCookieInitial, start from the beginning.
	 * cookie  > 0  → resume from serialised ZAP cursor position.
	 */
	if (cookie == 0)
		zap_cursor_init(&zc, os, dir_obj);
	else
		zap_cursor_init_serialized(&zc, os, dir_obj, cookie);

	rc = zap_cursor_retrieve(&zc, za);
	if (rc != 0) {
		/* ENOENT = end of directory. */
		zap_cursor_fini(&zc);
		zap_attribute_free(za);
		close_dataset_sa(os);
		return (rc);
	}

	zap_cursor_advance(&zc);
	ent->next_cookie = zap_cursor_serialize(&zc);
	zap_cursor_fini(&zc);

	uint64_t child_obj = ZFS_DIRENT_OBJ(za->za_first_integer);
	strlcpy(ent->name, za->za_name, sizeof (ent->name));
	ent->obj_id = child_obj;
	ent->is_dir = 0;

	if (attrs_out != NULL && sa_table != NULL) {
		sa_handle_t *hdl = NULL;
		if (sa_handle_get(os, child_obj, NULL,
		    SA_HDL_SHARED, &hdl) == 0) {
			memset(attrs_out, 0, sizeof (*attrs_out));
			fill_attrs_from_sa(hdl, child_obj, sa_table, attrs_out);
			ent->is_dir = S_ISDIR(attrs_out->mode);
			sa_handle_destroy(hdl);
		}
	}

	zap_attribute_free(za);
	close_dataset_sa(os);
	return (0);
}

#endif /* FSKIT */
