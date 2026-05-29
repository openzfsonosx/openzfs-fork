/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2025 Jorgen Lundman <lundman@lundman.net>
 *
 * fskit_posix.c — Sandbox-safe POSIX wrappers for FSKit builds.
 *
 * Pattern modelled on the Windows port's wosix.c: intercept the POSIX
 * calls that the App Sandbox blocks on device paths and substitute
 * safe equivalents.  For all other paths the real syscall is invoked.
 *
 * This file is compiled into libspl (active for any binary built
 * with --enable-fskit: zpool, zdb, ZFSFSKit, …).
 *
 * Device-size registry
 * --------------------
 * DKIOCGETBLOCKCOUNT / DKIOCGETBLOCKSIZE are blocked by the FSKit
 * App Sandbox.  To make fstat_blk() work, the caller registers each
 * device with its known size before calling spa_import:
 *
 *   fskit_register_device("/dev/rdisk4s1", totalBytes);
 *   spa_import(...);
 *   fskit_unregister_device("/dev/rdisk4s1");
 *
 * Inside fskit_fstat_blk(), when ioctls fail, fcntl(F_GETPATH) resolves
 * the fd (possibly a dup'd copy) back to the underlying device path and
 * the registry is consulted.  Both /dev/diskXsY and /dev/rdiskXsY forms
 * are tried so the lookup succeeds regardless of which path form the
 * kernel returns.
 *
 * The registry lives here in libspl so that ALL binaries in an FSKit
 * build share the same lookup — including libzpool.dylib's spa_import
 * path which resolves fstat64_blk → fskit_fstat_blk to THIS library
 * via Mach-O two-level namespace.
 *
 * IMPORTANT: the system-header includes below MUST come before any
 * fskit_posix.h inclusion so we can #undef the macro overrides and call
 * the real functions without recursion.
 */

/*
 * Pull in system headers directly.  Because this file is compiled with
 * the libspl include paths active, <sys/stat.h> and <sys/fcntl.h> would
 * normally resolve to the libspl overrides, which in turn include
 * fskit_posix.h and install the open/stat macro redirects.  We include
 * the headers first (to get struct stat, O_* constants, etc.) and then
 * immediately #undef the macros so our implementations can call the real
 * POSIX functions without infinite recursion.
 */
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/disk.h>	/* DKIOCGETBLOCKSIZE, DKIOCGETBLOCKCOUNT */
#include <sys/param.h>	/* MAXPATHLEN */
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>	/* sscanf, snprintf */
#include <errno.h>
#include <string.h>	/* strlcpy, strncmp */
#include <pthread.h>
#include <os/log.h>

/*
 * Undo any macro overrides that fskit_posix.h may have installed via
 * the headers included above.  After this point, open/stat/etc. name
 * the real POSIX functions again.
 */
#ifdef open
#undef open
#endif
#ifdef open64
#undef open64
#endif
#ifdef stat
#undef stat
#endif
#ifdef stat64
#undef stat64
#endif
#ifdef lstat
#undef lstat
#endif
#ifdef lstat64
#undef lstat64
#endif
#ifdef fstat
#undef fstat
#endif
#ifdef fstat64
#undef fstat64
#endif
#ifdef ioctl
#undef ioctl
#endif

/* ------------------------------------------------------------------ */
/* Debug logging                                                        */
/* ------------------------------------------------------------------ */

#define	FPOSIX_LOG(fmt, ...) \
	os_log_debug(OS_LOG_DEFAULT, \
	    "ZFSFSKit fskit_posix: " fmt, ##__VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Path → size registry                                                 */
/* ------------------------------------------------------------------ */

#define	FSKIT_DEV_MAX	32	/* enough for any realistic pool topology */

typedef struct {
	char		path[MAXPATHLEN];
	uint64_t	size_bytes;
} fskit_dev_entry_t;

static fskit_dev_entry_t	fskit_dev_table[FSKIT_DEV_MAX];
static int			fskit_dev_count = 0;
static pthread_mutex_t		fskit_dev_lock  = PTHREAD_MUTEX_INITIALIZER;

/*
 * fskit_register_device — register a device path with its byte size.
 *
 * path       — real device path returned by fcntl(F_GETPATH) on FSKit's fd,
 *              e.g. "/dev/rdisk4s1" or "/dev/disk4s1".
 * size_bytes — blockCount * physicalBlockSize from FSBlockDeviceResource.
 *
 * Called by ZFSFileSystem.m before spa_import.  Register both the raw
 * (/dev/rdiskXsY) and block (/dev/diskXsY) forms to guarantee a match
 * regardless of which form F_GETPATH returns for the dup'd vdev fd.
 */
void
fskit_register_device(const char *path, uint64_t size_bytes)
{
	pthread_mutex_lock(&fskit_dev_lock);

	/* Update an existing entry if present. */
	for (int i = 0; i < fskit_dev_count; i++) {
		if (strncmp(fskit_dev_table[i].path, path, MAXPATHLEN) == 0) {
			fskit_dev_table[i].size_bytes = size_bytes;
			pthread_mutex_unlock(&fskit_dev_lock);
			FPOSIX_LOG("register_device: updated '%s' → %llu bytes",
			    path, (unsigned long long)size_bytes);
			return;
		}
	}

	/* Add a new entry. */
	if (fskit_dev_count < FSKIT_DEV_MAX) {
		strlcpy(fskit_dev_table[fskit_dev_count].path, path, MAXPATHLEN);
		fskit_dev_table[fskit_dev_count].size_bytes = size_bytes;
		fskit_dev_count++;
		FPOSIX_LOG("register_device: added '%s' → %llu bytes",
		    path, (unsigned long long)size_bytes);
	} else {
		FPOSIX_LOG("register_device: table full, dropped '%s'", path);
	}

	pthread_mutex_unlock(&fskit_dev_lock);
}

/*
 * fskit_unregister_device — remove a device from the registry.
 */
void
fskit_unregister_device(const char *path)
{
	pthread_mutex_lock(&fskit_dev_lock);

	for (int i = 0; i < fskit_dev_count; i++) {
		if (strncmp(fskit_dev_table[i].path, path, MAXPATHLEN) == 0) {
			/* Compact the table. */
			for (int j = i; j < fskit_dev_count - 1; j++)
				fskit_dev_table[j] = fskit_dev_table[j + 1];
			fskit_dev_count--;
			FPOSIX_LOG("unregister_device: removed '%s'", path);
			pthread_mutex_unlock(&fskit_dev_lock);
			return;
		}
	}

	FPOSIX_LOG("unregister_device: '%s' not found", path);
	pthread_mutex_unlock(&fskit_dev_lock);
}

/*
 * registry_lookup — look up a device path and return its size.
 * Returns 0 if not found.  Caller must NOT hold fskit_dev_lock.
 */
static uint64_t
registry_lookup(const char *path)
{
	uint64_t sz = 0;

	pthread_mutex_lock(&fskit_dev_lock);
	for (int i = 0; i < fskit_dev_count; i++) {
		if (strncmp(fskit_dev_table[i].path, path, MAXPATHLEN) == 0) {
			sz = fskit_dev_table[i].size_bytes;
			break;
		}
	}
	pthread_mutex_unlock(&fskit_dev_lock);
	return (sz);
}

/* ------------------------------------------------------------------ */
/* fskit_open — sandbox-safe open(2) / open64(2).                      */
/* ------------------------------------------------------------------ */

/*
 * The FSKit App Sandbox blocks open(2) on raw device paths even when
 * the caller has a valid pre-opened fd.  When vdev_file_open or any
 * other libzpool caller tries to open "/dev/fd/N", the sandbox sees
 * the underlying "/dev/rdiskNsM" path and denies it.
 *
 * For /dev/fd/N paths we call dup(N) instead: duplicating an existing
 * fd is always permitted because it does not create a new resource
 * reference visible to the sandbox.  For all other paths we fall
 * through to the real open(2).
 */
int
fskit_open(const char *path, int flags, ...)
{
	int n;

	if (sscanf(path, "/dev/fd/%d", &n) == 1 && n >= 0) {
		int fd = dup(n);
		FPOSIX_LOG("open: '%s' → dup(%d) = %d", path, n, fd);
		return (fd);
	}

	va_list ap;
	va_start(ap, flags);
	mode_t mode = (mode_t)va_arg(ap, int); /* mode_t promotes to int */
	va_end(ap);

	int fd = open(path, flags, mode);
	FPOSIX_LOG("open: '%s' flags=0x%x → %d", path, flags, fd);
	return (fd);
}

/* ------------------------------------------------------------------ */
/* fskit_stat — sandbox-safe stat(2) / stat64(2).                      */
/* ------------------------------------------------------------------ */

/*
 * Path-based stat on a /dev/fd/N path may be denied by the sandbox
 * because the kernel resolves it to the underlying device path for the
 * access check.  For /dev/fd/N paths we substitute fstat(N, st), which
 * is always allowed (the fd is already open).  All other paths use the
 * real stat(2).
 */
int
fskit_stat(const char *path, struct fskit_stat *st)
{
	int n, rc;

	if (sscanf(path, "/dev/fd/%d", &n) == 1 && n >= 0) {
		rc = fstat(n, (struct stat *)st);
		FPOSIX_LOG("stat: '%s' → fstat(%d) = %d", path, n, rc);
		return (rc);
	}

	rc = stat(path, (struct stat *)st);
	FPOSIX_LOG("stat: '%s' → %d", path, rc);
	return (rc);
}

/* ------------------------------------------------------------------ */
/* fskit_fstat                                                          */
/* ------------------------------------------------------------------ */

int
fskit_fstat(int fd, struct fskit_stat *st)
{
	int rc = fstat(fd, (struct stat *)st);
	FPOSIX_LOG("fstat(%d) → %d", fd, rc);
	return (rc);
}

/* ------------------------------------------------------------------ */
/* fskit_fstat_blk — sandbox-safe fstat_blk replacement.               */
/* ------------------------------------------------------------------ */

/*
 * Strategy:
 *  1. Call fstat() to populate mode / inode / basic size.
 *  2. For plain files, st_size is already set; return immediately.
 *  3. For block/char devices, try DKIOC ioctls first (succeed outside
 *     the sandbox or with a permissive profile).
 *  4. On ioctl failure, use fcntl(F_GETPATH) to resolve the fd to its
 *     underlying device path (works on dup'd fds too), then look that
 *     path up in the registry.  Also try the sibling path form
 *     (/dev/diskX ↔ /dev/rdiskX) in case F_GETPATH returns a different
 *     form than what was registered.
 */
int
fskit_fstat_blk(int fd, struct fskit_stat *st)
{
	FPOSIX_LOG("fstat_blk(%d): entered", fd);

	if (fstat(fd, (struct stat *)st) == -1) {
		FPOSIX_LOG("fstat_blk(%d): fstat failed errno=%d", fd, errno);
		return (-1);
	}

	/* Regular files already have st_size set correctly. */
	if (!(st->st_mode & (S_IFBLK | S_IFCHR))) {
		FPOSIX_LOG("fstat_blk(%d): not a device, size=%llu",
		    fd, (unsigned long long)st->st_size);
		return (0);
	}

	/* Try ioctls — succeed outside the sandbox or with permissive profile. */
	{
		uint32_t blksize = 0;
		uint64_t blkcnt  = 0;

		if (ioctl(fd, DKIOCGETBLOCKSIZE,  &blksize) == 0 &&
		    ioctl(fd, DKIOCGETBLOCKCOUNT, &blkcnt)  == 0 &&
		    blksize > 0 && blkcnt > 0) {
			st->st_size = (off_t)((uint64_t)blksize * blkcnt);
			FPOSIX_LOG("fstat_blk(%d): DKIOC ok, size=%llu",
			    fd, (unsigned long long)st->st_size);
			return (0);
		}
	}

	/*
	 * DKIOC blocked by App Sandbox.
	 * Resolve fd → device path via F_GETPATH and look up the registry
	 * populated by ZFSFileSystem.m via fskit_register_device() before import.
	 * F_GETPATH works on dup'd fds — it returns the underlying device path.
	 */
	{
		char path[MAXPATHLEN];

		if (fcntl(fd, F_GETPATH, path) == 0) {
			uint64_t sz = registry_lookup(path);
			if (sz > 0) {
				st->st_size = (off_t)sz;
				FPOSIX_LOG("fstat_blk(%d): DKIOC blocked, "
				    "registry hit '%s' → %llu bytes",
				    fd, path, (unsigned long long)sz);
				return (0);
			}

			/*
			 * Try the sibling path form: /dev/diskXsY ↔ /dev/rdiskXsY.
			 * The kernel may return the block form when we registered the
			 * raw form (or vice versa).
			 */
			char alt[MAXPATHLEN];
			alt[0] = '\0';
			if (strncmp(path, "/dev/rdisk", 10) == 0) {
				/* raw → block: /dev/rdiskXsY → /dev/diskXsY */
				snprintf(alt, sizeof (alt), "/dev/%s", path + 6);
			} else if (strncmp(path, "/dev/disk", 9) == 0) {
				/* block → raw: /dev/diskXsY → /dev/rdiskXsY */
				snprintf(alt, sizeof (alt), "/dev/r%s", path + 5);
			}

			if (alt[0] != '\0') {
				sz = registry_lookup(alt);
				if (sz > 0) {
					st->st_size = (off_t)sz;
					FPOSIX_LOG("fstat_blk(%d): DKIOC blocked, "
					    "registry hit (alt) '%s' → %llu bytes",
					    fd, alt, (unsigned long long)sz);
					return (0);
				}
			}

			FPOSIX_LOG("fstat_blk(%d): DKIOC blocked, "
			    "path '%s' not in registry → -1", fd, path);
		} else {
			FPOSIX_LOG("fstat_blk(%d): DKIOC blocked, "
			    "F_GETPATH failed errno=%d → -1", fd, errno);
		}
	}

	return (-1);
}
