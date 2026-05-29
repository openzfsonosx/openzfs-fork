/*
 * Copyright (c) 2025 Jorgen Lundman <lundman@lundman.net>
 *
 * zfs_fskit.h — Pure-C interface between the ObjC FSKit layer and libzpool.
 *
 * All functions use plain C types only (no ObjC, no FSKit headers).
 * The ObjC layer (ZFSFileSystem.m, ZFSVolume.m) calls these helpers,
 * which in turn call into libzpool / DMU / SA directly.
 */

#ifndef ZFS_FSKIT_H
#define	ZFS_FSKIT_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <sys/types.h>	/* off_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Plain-C attribute snapshot for a ZFS item */
/* ------------------------------------------------------------------ */

typedef struct zfs_item_attrs {
	uint32_t	mode;		/* S_IFXXX | permissions */
	uint64_t	size;		/* file size in bytes */
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	flags;		/* BSD UF_ flags */
	uint32_t	nlink;		/* hard link count */
	uint64_t	obj_id;		/* DMU object number */
	struct timespec	atime;
	struct timespec	mtime;
	struct timespec	ctime;
	struct timespec btime;	/* birth time */
} zfs_item_attrs_t;

/* A single directory entry returned by zfs_fskit_readdir_next(). */
typedef struct zfs_dirent {
	char		name[256];	/* entry name (NUL-terminated) */
	uint64_t	obj_id;		/* child DMU object number */
	uint64_t	next_cookie;	/* opaque cursor for the next call */
	int		is_dir;		/* 1 if directory, 0 otherwise */
} zfs_dirent_t;

/* ------------------------------------------------------------------ */
/* Engine lifecycle */
/* ------------------------------------------------------------------ */

/*
 * Initialise the ZFS engine (kernel_init).
 * Must be called once before any other zfs_fskit_* functions.
 */
void zfs_fskit_init(void);

/* ------------------------------------------------------------------ */
/* Pool probe / import / export */
/* ------------------------------------------------------------------ */

/*
 * Probe a BSD disk name (e.g. "disk2s1") for a ZFS vdev label.
 * Opens the device directly — only works outside the App Sandbox.
 * Returns 0 and fills poolname / pool_guid on success.
 * Returns -1 if no valid ZFS label is found.
 */
int zfs_fskit_probe_bsd(const char *_Nonnull bsdname,
    char *_Nonnull poolname, size_t poolname_len,
    uint64_t *_Nonnull pool_guid);

/*
 * Probe a ZFS vdev label from a raw buffer.
 *
 * Use this inside the FSKit App Sandbox where direct device open is blocked.
 * The caller reads the device through FSBlockDeviceResource.readInto:
 * and passes the resulting bytes here.
 *
 * buf      — raw bytes read from the START of the vdev (at least 256 KB).
 * buf_len  — number of valid bytes in buf (must be >= 256 * 1024).
 *
 * Tries all four vdev labels (two at the start, two at the end — the
 * end-of-device labels require end_offset to be non-zero).
 * end_offset  — byte offset of the END of the device
 *               (blockCount * blockSize); pass 0 to skip the tail labels.
 *
 * Returns 0 and fills poolname / pool_guid on success.
 * Returns -1 if no valid ZFS label is found.
 */
int zfs_fskit_probe_buf(const void *_Nonnull buf, size_t buf_len,
    char *_Nonnull poolname, size_t poolname_len,
    uint64_t *_Nonnull pool_guid);

/*
 * Import a pool by name + GUID from a single vdev device path.
 * Returns 0 on success, errno on failure.
 */
int zfs_fskit_pool_import(const char *_Nonnull poolname,
    uint64_t pool_guid,
    const char *_Nonnull bsdname);

/*
 * Import a pool using a pre-opened file descriptor.
 *
 * FSKit sandbox blocks open("/dev/diskX") in loadResource.  However FSKit
 * itself opens the device and holds an fd in our process.  This function
 * accepts that fd and passes /dev/fd/<fd> to spa_import so the vdev layer
 * uses the already-open descriptor rather than opening by path.
 *
 * Returns 0 on success, errno on failure.
 */
int zfs_fskit_pool_import_fd(const char *_Nonnull poolname,
    uint64_t pool_guid,
    int devfd);

/*
 * Force-export a pool.
 */
void zfs_fskit_pool_export(const char *_Nonnull poolname);

/* ------------------------------------------------------------------ */
/* Root object lookup */
/* ------------------------------------------------------------------ */

/*
 * Look up the DMU object number of the root directory for a pool/dataset.
 * Reads the "ROOT" key from the master node ZAP (object 1).
 * Returns 0 on success; *root_obj_out is filled with the object number.
 */
int zfs_fskit_root_obj(const char *_Nonnull poolname,
    uint64_t *_Nonnull root_obj_out);

/* ------------------------------------------------------------------ */
/* VFS operations */
/* ------------------------------------------------------------------ */

/*
 * Fill in *attrs for ZFS object 'obj' in dataset 'poolname'.
 * Returns 0 on success, errno on failure.
 */
int zfs_fskit_getattr(const char *_Nonnull poolname,
    uint64_t obj,
    zfs_item_attrs_t *_Nonnull attrs);

/*
 * Look up a directory entry by name.
 * Sets *child_obj to the ZFS object number of the found entry.
 * Returns 0 on success, ENOENT if not found.
 */
int zfs_fskit_lookup(const char *_Nonnull poolname,
    uint64_t dir_obj,
    const char *_Nonnull name,
    uint64_t *_Nonnull child_obj);

/*
 * Read one directory entry starting at 'cookie'.
 *   cookie == 0  → start from the beginning (FSDirectoryCookieInitial)
 *   cookie  > 0  → resume from the serialised ZAP cursor position
 *
 * On success (0): *ent is filled; ent->next_cookie holds the value to
 *   pass on the next call.
 * Returns ENOENT when there are no more entries.
 * If attrs_out is non-NULL, the entry's attributes are filled too.
 */
int zfs_fskit_readdir_next(const char *_Nonnull poolname,
    uint64_t dir_obj,
    uint64_t cookie,
    zfs_dirent_t *_Nonnull ent,
    zfs_item_attrs_t *_Nullable attrs_out);

/*
 * Read up to 'length' bytes of file data at 'offset' into 'buf'.
 * Clamps to the logical file size (ZPL_SIZE from SA); reads past EOF
 * set *actual_out = 0 without error.
 * Returns 0 on success, errno on I/O error.
 */
int zfs_fskit_read(const char *_Nonnull poolname,
    uint64_t obj,
    off_t offset,
    size_t length,
    void *_Nonnull buf,
    size_t *_Nonnull actual_out);

#ifdef __cplusplus
}
#endif

#endif /* ZFS_FSKIT_H */
