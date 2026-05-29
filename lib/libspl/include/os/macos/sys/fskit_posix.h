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
 * fskit_posix.h — FSKit shim for POSIX calls blocked by the App Sandbox.
 *
 * Include this LAST (after all system headers) to redirect POSIX calls
 * that the FSKit sandbox denies to FSKit-aware, sandbox-safe
 * implementations in lib/libspl/os/macos/fskit_posix.c.
 *
 * Pattern modelled on the Windows port's wosix.h.  Only the calls that
 * the FSKit sandbox actually blocks need to be listed here; everything
 * else passes through unmodified.
 *
 * Active when FSKIT is defined (build-wide via --enable-fskit / AC_DEFINE)
 * -------------------------------------------------------------------------
 *   open / open64  → fskit_open    dup(N) for /dev/fd/N, real open otherwise
 *   stat / stat64  → fskit_stat    fstat(N) for /dev/fd/N, real stat otherwise
 *   fstat          → fskit_fstat
 *   fstat64_blk    → fskit_fstat_blk
 *                    Tries DKIOC ioctls; if blocked by sandbox falls back to
 *                    fcntl(F_GETPATH) + the path→size registry populated by
 *                    ZFSFileSystem.m via fskit_register_device() before import.
 *
 * The registry (fskit_register_device / fskit_unregister_device) is also
 * implemented in libspl so it is accessible from all binaries in an FSKit
 * build, including libzpool.dylib which resolves fstat64_blk to this library
 * via Mach-O two-level namespace.
 *
 * IMPORTANT: this file must be included AFTER <sys/stat.h>, <sys/fcntl.h>
 * and any other header that declares the symbols being redirected, so
 * that every call site sees the correct prototype before the name is
 * macro-replaced.  stat.h and fcntl.h already include it last.
 */

#ifndef _FSKIT_POSIX_H
#define	_FSKIT_POSIX_H

#include <stdint.h>	/* uint64_t */
#include <sys/stat.h>	/* struct stat */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef FSKIT_NO_POSIX_WRAPPER

#ifdef FSKIT

/* Work around that upstream uses gcc99 to compile */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wnested-anon-types"
	/* keep the struct type before we #define */
	struct fskit_stat {
		struct stat __os;
	};
#pragma clang diagnostic pop

#define	st_mode  __os.st_mode
#define	st_size  __os.st_size
#define	st_ino   __os.st_ino
#define	st_dev   __os.st_dev
#define	st_uid   __os.st_uid
#define	st_gid   __os.st_gid
#define	st_atime __os.st_atime
#define	st_mtime __os.st_mtime
#define	st_ctime __os.st_ctime

/*
 * POSIX shim functions — implemented in lib/libspl/os/macos/fskit_posix.c.
 *
 * fskit_open     — dup(N) for /dev/fd/N, real open() for everything else.
 * fskit_stat     — fstat(N) for /dev/fd/N, real stat() for everything else.
 * fskit_fstat_blk — DKIOC ioctls; falls back to F_GETPATH + registry.
 *
 * Device-size registry:
 *   ZFSFileSystem.m calls fskit_register_device() before spa_tryimport /
 *   spa_import and fskit_unregister_device() after import completes.
 *   Register both /dev/rdiskXsY and /dev/diskXsY forms so the lookup
 *   succeeds regardless of which form F_GETPATH returns for the dup'd fd.
 *
 *   path       — real device path, e.g. "/dev/rdisk4s1"
 *   size_bytes — blockCount * physicalBlockSize
 */
extern int  fskit_open(const char *path, int flags, ...);
extern int  fskit_stat(const char *path, struct fskit_stat *st);
extern int  fskit_fstat(int fd, struct fskit_stat *st);
extern int  fskit_fstat_blk(int fd, struct fskit_stat *st);
extern void fskit_register_device(const char *path, uint64_t size_bytes);
extern void fskit_unregister_device(const char *path);

#undef	open
#define	open		fskit_open
#undef	open64
#define	open64		fskit_open

#undef	stat
#define	stat		fskit_stat
#undef	fstat
#define	fstat		fskit_fstat
#undef	stat64
#define	stat64		fskit_stat
#undef	fstat64_blk
#define	fstat64_blk	fskit_fstat_blk

#endif /* FSKIT */

#endif /* FSKIT_NO_POSIX_WRAPPER */

#ifdef __cplusplus
}
#endif

#endif /* _FSKIT_POSIX_H */
