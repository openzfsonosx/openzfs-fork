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
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2013, 2020 Jorgen Lundman <lundman@lundman.net>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/zfs_ioctl.h>
#include <os/macos/zfs/sys/zfs_ioctl_compat.h>
#include <err.h>
#include <libzfs_core.h>
#include "libzfs_core_impl.h"

#ifdef FSKIT

/*
 * FSKit / userland port: replace ioctl() with a UNIX domain socket to zfsd.
 *
 * libzfs_core_init() opens /dev/null as a dummy fd so the refcount logic
 * in libzfs_core.c stays intact.  All real I/O uses the static g_sock_fd
 * managed here; the fd parameter of lzc_ioctl_fd_os() is ignored.
 * The socket is connected lazily on first use and reconnected on error.
 *
 * Wire protocol — request (client → zfsd):
 *   uint32_t  magic       ZFS_SOCK_MAGIC
 *   uint32_t  ioc         ZFS_IOC_* value
 *   zfs_cmd_t zc          cmd struct; nvlist pointer fields zeroed, sizes kept
 *   uint32_t  conf_len    bytes of zc_nvlist_conf data following (0 = none)
 *   uint32_t  src_len     bytes of zc_nvlist_src  data following (0 = none)
 *   uint8_t   conf[]      conf_len bytes of packed nvlist
 *   uint8_t   src[]       src_len  bytes of packed nvlist
 *
 * Wire protocol — reply (zfsd → client):
 *   uint32_t  magic       ZFS_SOCK_MAGIC
 *   int32_t   err         errno on error, 0 on success
 *   zfs_cmd_t zc          updated cmd struct; nvlist pointer fields zeroed
 *   uint32_t  dst_len     actual bytes of zc_nvlist_dst data following
 *   uint8_t   dst[]       dst_len bytes of packed nvlist
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define	ZFS_SOCK_PATH	"/var/run/zfs.sock"
#define	ZFS_SOCK_MAGIC	0x5A465344U	/* 'ZFSD' */

static int		g_sock_fd  = -1;
static pthread_mutex_t	g_sock_lock = PTHREAD_MUTEX_INITIALIZER;

static int
fskit_sock_connect(void)
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (-1);

	memset(&addr, 0, sizeof (addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, ZFS_SOCK_PATH, sizeof (addr.sun_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
		close(fd);
		return (-1);
	}
	return (fd);
}

static int
fskit_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = write(fd, p, len);
		if (n <= 0)
			return (-1);
		p   += n;
		len -= (size_t)n;
	}
	return (0);
}

static int
fskit_read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = read(fd, p, len);
		if (n <= 0)
			return (-1);
		p   += n;
		len -= (size_t)n;
	}
	return (0);
}

/*
 * The fd parameter is a /dev/null dummy; we ignore it and use g_sock_fd.
 */
int
lzc_ioctl_fd_os(int fd __attribute__((unused)), unsigned long request,
    zfs_cmd_t *zc)
{
	uint32_t	magic, ioc, conf_len, src_len, dst_len;
	int32_t		srv_err;
	zfs_cmd_t	zc_wire;
	void		*conf_buf, *src_buf, *dst_buf;
	size_t		dst_buf_size;
	int		ret = 0;

	/* Save caller's nvlist pointers/sizes before zeroing for wire */
	conf_buf = (void *)(uintptr_t)zc->zc_nvlist_conf;
	conf_len = (uint32_t)zc->zc_nvlist_conf_size;
	src_buf = (void *)(uintptr_t)zc->zc_nvlist_src;
	src_len = (uint32_t)zc->zc_nvlist_src_size;
	dst_buf = (void *)(uintptr_t)zc->zc_nvlist_dst;
	dst_buf_size = zc->zc_nvlist_dst_size;

	/* Wire copy: zero pointer fields (sizes stay for daemon) */
	zc_wire = *zc;
	zc_wire.zc_nvlist_conf = 0;
	zc_wire.zc_nvlist_src  = 0;
	zc_wire.zc_nvlist_dst  = 0;

	magic = ZFS_SOCK_MAGIC;
	ioc   = (uint32_t)request;

	pthread_mutex_lock(&g_sock_lock);

	/* Lazy connect / reconnect after previous error */
	if (g_sock_fd < 0) {
		g_sock_fd = fskit_sock_connect();
		if (g_sock_fd < 0) {
			ret = -1;
			errno = ENOENT;		/* zfsd not running */
			goto out;
		}
	}

	/* ---- Send request ---- */
	if (fskit_write_all(g_sock_fd, &magic, sizeof (magic)) < 0 ||
	    fskit_write_all(g_sock_fd, &ioc, sizeof (ioc)) < 0 ||
	    fskit_write_all(g_sock_fd, &zc_wire, sizeof (zc_wire)) < 0 ||
	    fskit_write_all(g_sock_fd, &conf_len, sizeof (conf_len)) < 0 ||
	    fskit_write_all(g_sock_fd, &src_len, sizeof (src_len)) < 0)
		goto ioerr;

	if (conf_len > 0 && conf_buf != NULL &&
	    fskit_write_all(g_sock_fd, conf_buf, conf_len) < 0)
		goto ioerr;

	if (src_len > 0 && src_buf != NULL &&
	    fskit_write_all(g_sock_fd, src_buf, src_len) < 0)
		goto ioerr;

	/* ---- Receive reply ---- */
	if (fskit_read_all(g_sock_fd, &magic,   sizeof (magic))   < 0 ||
	    fskit_read_all(g_sock_fd, &srv_err, sizeof (srv_err)) < 0 ||
	    fskit_read_all(g_sock_fd, &zc_wire, sizeof (zc_wire)) < 0 ||
	    fskit_read_all(g_sock_fd, &dst_len, sizeof (dst_len)) < 0)
		goto ioerr;

	if (magic != ZFS_SOCK_MAGIC) {
		errno = EPROTO;
		goto ioerr;
	}

	/* Merge server's zc back, restoring our pointer fields */
	zc_wire.zc_nvlist_conf = zc->zc_nvlist_conf;
	zc_wire.zc_nvlist_src  = zc->zc_nvlist_src;
	zc_wire.zc_nvlist_dst  = zc->zc_nvlist_dst;
	*zc = zc_wire;
	zc->zc_nvlist_dst_size = dst_len;

	if (dst_len > 0) {
		if (dst_buf == NULL || dst_len > dst_buf_size) {
			/*
			 * Drain bytes to keep the protocol in sync, then
			 * return ENOMEM — the libzfs_core retry convention
			 * for "grow your dst buffer".  zc_nvlist_dst_size is
			 * already set to dst_len so the caller knows the size.
			 */
			uint8_t	drain[512];
			uint32_t rem = dst_len;
			while (rem > 0) {
				uint32_t n = (rem < sizeof (drain)) ?
				    rem : (uint32_t)sizeof (drain);
				if (fskit_read_all(g_sock_fd, drain, n) < 0)
					goto ioerr;
				rem -= n;
			}
			ret = -1;
			errno = ENOMEM;
			goto out;
		}
		if (fskit_read_all(g_sock_fd, dst_buf, dst_len) < 0)
			goto ioerr;
	}

	if (srv_err != 0) {
		ret = -1;
		errno = srv_err;
	}
	goto out;

ioerr:
	{
		int saved = errno;
		close(g_sock_fd);
		g_sock_fd = -1;
		errno = saved ? saved : EIO;
	}
	ret = -1;

out:
	pthread_mutex_unlock(&g_sock_lock);
	return (ret);
}

#else	/* !FSKIT — legacy kext ioctl path */

static int
zcmd_ioctl_compat(int fd, int request, zfs_cmd_t *zc, const int cflag)
{
	int ret;
	void *zc_c;
	unsigned long ncmd;
	zfs_iocparm_t zp;

	switch (cflag) {
	case ZFS_CMD_COMPAT_NONE:
		ncmd = _IOWR('Z', request, zfs_iocparm_t);
		zp.zfs_cmd = (uint64_t)zc;
		zp.zfs_cmd_size = sizeof (zfs_cmd_t);
		zp.zfs_ioctl_version = ZFS_IOCVER_ZOF;
		zp.zfs_ioc_error = 0;

		ret = ioctl(fd, ncmd, &zp);

		/*
		 * If ioctl worked, get actual rc from kernel, which goes
		 * into errno, and return -1 if not-zero.
		 */
		if (ret == 0) {
			errno = zp.zfs_ioc_error;
			if (zp.zfs_ioc_error != 0)
				ret = -1;
		}
		return (ret);

	default:
		abort();
		return (EINVAL);
	}

	/* Pass-through ioctl, rarely used if at all */

	ret = ioctl(fd, ncmd, zc_c);
	ASSERT0(ret);

	zfs_cmd_compat_get(zc, (caddr_t)zc_c, cflag);
	free(zc_c);

	return (ret);
}

/*
 * This is the macOS version of ioctl().  Because the XNU kernel
 * handles copyin() and copyout(), we must return success from the
 * ioctl() handler (or it will not copyout() for userland),
 * and instead embed the error return value in the zc structure.
 */
int
lzc_ioctl_fd_os(int fd, unsigned long request, zfs_cmd_t *zc)
{
	size_t oldsize;
	int ret, cflag = ZFS_CMD_COMPAT_NONE;

	oldsize = zc->zc_nvlist_dst_size;
	ret = zcmd_ioctl_compat(fd, request, zc, cflag);

	if (ret == 0 && oldsize < zc->zc_nvlist_dst_size) {
		ret = -1;
		errno = ENOMEM;
	}

	return (ret);
}

#endif	/* FSKIT */
