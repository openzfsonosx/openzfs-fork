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
 * Copyright (c) 2025 Jorgen Lundman <lundman@lundman.net>
 *
 * zfsd — ZFS userland daemon for the macOS FSKit port.
 *
 * Replaces the /dev/zfs ioctl channel.  libzfs / libzfs_core connect here
 * via a UNIX domain socket instead of talking to the kext.  The ZFS engine
 * (libzpool: spa, dmu, zio, arc …) runs entirely inside this process.
 *
 * Wire protocol matches libzfs_core/os/macos/libzfs_core_ioctl.c.
 *
 * Request  (client → zfsd):
 *   uint32_t  magic       ZFS_SOCK_MAGIC
 *   uint32_t  ioc         ZFS_IOC_* value
 *   zfs_cmd_t zc          nvlist pointer fields zeroed, sizes intact
 *   uint32_t  conf_len    bytes of zc_nvlist_conf data following
 *   uint32_t  src_len     bytes of zc_nvlist_src  data following
 *   uint8_t   conf[]
 *   uint8_t   src[]
 *
 * Reply    (zfsd → client):
 *   uint32_t  magic       ZFS_SOCK_MAGIC
 *   int32_t   err         errno (0 = success)
 *   zfs_cmd_t zc          nvlist pointer fields zeroed
 *   uint32_t  dst_len     actual bytes of zc_nvlist_dst data following
 *   uint8_t   dst[]
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/nvpair.h>
#include <sys/spa.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libzfs.h>
#include <libzpool.h>
#include <zfs_comutil.h>

#define	ZFS_SOCK_PATH	"/var/run/zfs.sock"
#define	ZFS_SOCK_MAGIC	0x5A465344U	/* 'ZFSD' */
#define	ZFS_SOCK_BACKLOG	16

/* ---- I/O helpers ---- */

static int
write_all(int fd, const void *buf, size_t len)
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
read_all(int fd, void *buf, size_t len)
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

/* ---- nvlist helpers ---- */

/*
 * Read a packed nvlist of 'len' bytes from 'buf' into *nvlp.
 * Returns 0 on success, errno on failure.
 */
static int
zfsd_nvlist_unpack(const void *buf, uint32_t len, nvlist_t **nvlp)
{
	if (len == 0) {
		*nvlp = NULL;
		return (0);
	}
	return (nvlist_unpack((char *)(uintptr_t)buf, len, nvlp, 0));
}

/*
 * Pack nvl into a freshly allocated buffer; caller must free() it.
 * Returns packed size in *lenp.
 */
static int
zfsd_nvlist_pack(nvlist_t *nvl, void **bufp, size_t *lenp)
{
	if (nvl == NULL) {
		*bufp = NULL;
		*lenp = 0;
		return (0);
	}
	return (nvlist_pack(nvl, (char **)bufp, lenp, NV_ENCODE_NATIVE, 0));
}

/*
 * Dispatch handlers.
 * Each handler receives unpacked nvlists and returns an error code.
 * On success, *out_nvl is packed and sent back as zc_nvlist_dst.
 */

static int
zfsd_pool_create(zfs_cmd_t *zc, nvlist_t *conf_nvl, nvlist_t *src_nvl,
    nvlist_t **out_nvl __attribute__((unused)))
{
	if (conf_nvl == NULL)
		return (EINVAL);
	return (spa_create(zc->zc_name, conf_nvl, src_nvl, NULL, NULL));
}

static int
zfsd_pool_destroy(zfs_cmd_t *zc, nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl __attribute__((unused)),
    nvlist_t **out_nvl __attribute__((unused)))
{
	return (spa_destroy(zc->zc_name));
}

static int
zfsd_pool_import(zfs_cmd_t *zc, nvlist_t *conf_nvl,
    nvlist_t *src_nvl, nvlist_t **out_nvl __attribute__((unused)))
{
	if (conf_nvl == NULL)
		return (EINVAL);
	return (spa_import(zc->zc_name, conf_nvl, src_nvl,
	    zc->zc_cookie /* flags */));
}

static int
zfsd_pool_export(zfs_cmd_t *zc, nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl __attribute__((unused)), nvlist_t **out_nvl)
{
	nvlist_t *oldconfig = NULL;
	int error;

	error = spa_export(zc->zc_name, &oldconfig,
	    zc->zc_cookie /* force */, zc->zc_guid /* hardforce */);
	if (error == 0 && oldconfig != NULL)
		*out_nvl = oldconfig;
	return (error);
}

static int
zfsd_pool_configs(zfs_cmd_t *zc, nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl __attribute__((unused)), nvlist_t **out_nvl)
{
	nvlist_t *pools = NULL;
	uint64_t generation = zc->zc_cookie;
	int error;

	error = spa_all_configs(&generation, &pools);
	if (error == 0) {
		zc->zc_cookie = generation;
		*out_nvl = pools;
	}
	return (error);
}

static int
zfsd_pool_stats(zfs_cmd_t *zc, nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl __attribute__((unused)), nvlist_t **out_nvl)
{
	nvlist_t *config = NULL;
	int error;

	error = spa_get_stats(zc->zc_name, &config,
	    zc->zc_value, sizeof (zc->zc_value));
	if (error == 0)
		*out_nvl = config;
	return (error);
}

static int
zfsd_pool_tryimport(zfs_cmd_t *zc __attribute__((unused)),
    nvlist_t *conf_nvl, nvlist_t *src_nvl __attribute__((unused)),
    nvlist_t **out_nvl)
{
	if (conf_nvl == NULL)
		return (EINVAL);
	*out_nvl = spa_tryimport(conf_nvl);
	return (*out_nvl ? 0 : EINVAL);
}

static int
zfsd_pool_get_props(zfs_cmd_t *zc,
    nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl __attribute__((unused)), nvlist_t **out_nvl)
{
	spa_t *spa;
	nvlist_t *props = NULL;
	int error;

	error = spa_open(zc->zc_name, &spa, FTAG);
	if (error != 0)
		return (error);

	props = fnvlist_alloc();
	spa_prop_get(spa, props);
	spa_close(spa, FTAG);
	*out_nvl = props;
	return (0);
}

static int
zfsd_objset_stats(zfs_cmd_t *zc,
    nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl __attribute__((unused)),
    nvlist_t **out_nvl)
{
	objset_t *os;
	nvlist_t *nv = NULL;
	int error;

	error = dmu_objset_hold(zc->zc_name, FTAG, &os);
	if (error == 0) {
		dmu_objset_fast_stat(os, &zc->zc_objset_stats);
		/*
		 * Return the full property nvlist (same as kernel).
		 * libzfs calls zcmd_read_dst_nvlist() on the result,
		 * which fails if we return nothing.
		 */
		if (!zc->zc_simple) {
			error = dsl_prop_get_all(os, &nv);
			if (error == 0) {
				dmu_objset_stats(os, nv);
				*out_nvl = nv;
			}
		}
		dmu_objset_rele(os, FTAG);
	}
	return (error);
}

/*
 * ZFS_IOC_LOG_HISTORY — record a command-line string in the pool history.
 * The message is in src_nvl["message"]; the pool name comes from kernel TSD
 * which we don't replicate here.  For the FSKit PoC we accept the call and
 * return success so callers (zpool_log_history) don't fail.
 */
static int
zfsd_log_history(zfs_cmd_t *zc __attribute__((unused)),
    nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl, nvlist_t **out_nvl __attribute__((unused)))
{
	if (src_nvl != NULL) {
		const char *msg = NULL;
		(void) nvlist_lookup_string(src_nvl, "message", &msg);
		if (msg != NULL)
			fprintf(stderr, "zfsd: history: %s\n", msg);
	}
	return (0);
}

static int
zfsd_dataset_list_next(zfs_cmd_t *zc,
    nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl __attribute__((unused)), nvlist_t **out_nvl)
{
	objset_t *os;
	char *p;
	size_t orig_len = strlen(zc->zc_name);
	int error;

top:
	error = dmu_objset_hold(zc->zc_name, FTAG, &os);
	if (error != 0) {
		if (error == ENOENT)
			error = ESRCH;
		return (error);
	}

	/* Append '/' separator so dmu_dir_list_next fills in the child name */
	p = strrchr(zc->zc_name, '/');
	if (p == NULL || p[1] != '\0')
		(void) strlcat(zc->zc_name, "/", sizeof (zc->zc_name));
	p = zc->zc_name + strlen(zc->zc_name);

	do {
		error = dmu_dir_list_next(os,
		    sizeof (zc->zc_name) - (p - zc->zc_name), p,
		    NULL, &zc->zc_cookie);
		if (error == ENOENT)
			error = ESRCH;
	} while (error == 0 && zfs_dataset_name_hidden(zc->zc_name));

	dmu_objset_rele(os, FTAG);

	if (error == 0 && strchr(zc->zc_name, '$') == NULL) {
		/* Fill in stats and props for the found child dataset */
		error = zfsd_objset_stats(zc, NULL, NULL, out_nvl);
		if (error == ENOENT) {
			/* Lost a race with destroy; try the next one */
			zc->zc_name[orig_len] = '\0';
			goto top;
		}
	}
	return (error);
}

static int
zfsd_snapshot_list_next(zfs_cmd_t *zc,
    nvlist_t *conf_nvl __attribute__((unused)),
    nvlist_t *src_nvl, nvlist_t **out_nvl)
{
	objset_t	*os, *ossnap;
	dsl_dataset_t	*ds;
	uint64_t	 min_txg = 0, max_txg = 0;
	int		 error;

	/* Optional txg filter from src_nvl */
	if (src_nvl != NULL) {
		(void) nvlist_lookup_uint64(src_nvl, SNAP_ITER_MIN_TXG,
		    &min_txg);
		(void) nvlist_lookup_uint64(src_nvl, SNAP_ITER_MAX_TXG,
		    &max_txg);
	}

	error = dmu_objset_hold(zc->zc_name, FTAG, &os);
	if (error != 0)
		return (error == ENOENT ? ESRCH : error);

	if (strlcat(zc->zc_name, "@", sizeof (zc->zc_name)) >=
	    ZFS_MAX_DATASET_NAME_LEN) {
		dmu_objset_rele(os, FTAG);
		return (ESRCH);
	}

	while (error == 0) {
		error = dmu_snapshot_list_next(os,
		    sizeof (zc->zc_name) - strlen(zc->zc_name),
		    zc->zc_name + strlen(zc->zc_name),
		    &zc->zc_obj, &zc->zc_cookie, NULL);
		if (error == ENOENT) {
			error = ESRCH;
			break;
		} else if (error != 0) {
			break;
		}

		error = dsl_dataset_hold_obj(dmu_objset_pool(os),
		    zc->zc_obj, FTAG, &ds);
		if (error != 0)
			break;

		/* Optional txg range filter */
		if ((min_txg != 0 && dsl_get_creationtxg(ds) < min_txg) ||
		    (max_txg != 0 && dsl_get_creationtxg(ds) > max_txg)) {
			dsl_dataset_rele(ds, FTAG);
			*(strchr(zc->zc_name, '@') + 1) = '\0';
			continue;
		}

		if (zc->zc_simple) {
			dsl_dataset_fast_stat(ds, &zc->zc_objset_stats);
			dsl_dataset_rele(ds, FTAG);
			break;
		}

		error = dmu_objset_from_ds(ds, &ossnap);
		if (error == 0) {
			nvlist_t *nv = NULL;
			dmu_objset_fast_stat(ossnap, &zc->zc_objset_stats);
			if (dsl_prop_get_all(ossnap, &nv) == 0) {
				dmu_objset_stats(ossnap, nv);
				*out_nvl = nv;
			}
		}
		dsl_dataset_rele(ds, FTAG);
		break;
	}

	dmu_objset_rele(os, FTAG);
	if (error != 0) {
		char *at = strchr(zc->zc_name, '@');
		if (at != NULL)
			*at = '\0';
	}
	return (error);
}

/* ---- dispatch table ---- */

typedef int (*zfsd_handler_t)(zfs_cmd_t *, nvlist_t *, nvlist_t *,
    nvlist_t **);

static const struct {
	uint32_t	ioc;
	zfsd_handler_t	fn;
	const char	*name;
} zfsd_dispatch_cmd[] = {
	{ ZFS_IOC_POOL_CREATE, zfsd_pool_create, "POOL_CREATE" },
	{ ZFS_IOC_POOL_DESTROY, zfsd_pool_destroy, "POOL_DESTROY" },
	{ ZFS_IOC_POOL_IMPORT, zfsd_pool_import, "POOL_IMPORT" },
	{ ZFS_IOC_POOL_EXPORT, zfsd_pool_export, "POOL_EXPORT" },
	{ ZFS_IOC_POOL_CONFIGS, zfsd_pool_configs, "POOL_CONFIGS" },
	{ ZFS_IOC_POOL_STATS, zfsd_pool_stats, "POOL_STATS" },
	{ ZFS_IOC_POOL_TRYIMPORT, zfsd_pool_tryimport, "POOL_TRYIMPORT" },
	{ ZFS_IOC_POOL_GET_PROPS, zfsd_pool_get_props, "POOL_GET_PROPS" },
	{ ZFS_IOC_OBJSET_STATS, zfsd_objset_stats, "OBJSET_STATS" },
	{ ZFS_IOC_DATASET_LIST_NEXT, zfsd_dataset_list_next,
	    "DATASET_LIST_NEXT" },
	{ ZFS_IOC_SNAPSHOT_LIST_NEXT, zfsd_snapshot_list_next,
	    "SNAPSHOT_LIST_NEXT" },
	{ ZFS_IOC_LOG_HISTORY, zfsd_log_history, "LOG_HISTORY" },
	{ 0, NULL, NULL }
};

static void
zfsd_dispatch(int client_fd, uint32_t ioc, zfs_cmd_t *zc,
    void *conf_buf, uint32_t conf_len,
    void *src_buf,  uint32_t src_len)
{
	nvlist_t	*conf_nvl = NULL, *src_nvl = NULL, *out_nvl = NULL;
	void		*dst_buf = NULL;
	size_t		dst_len = 0;
	uint32_t	magic = ZFS_SOCK_MAGIC;
	int32_t		err = 0;
	zfs_cmd_t	zc_reply;

	/* Unpack incoming nvlists */
	if (zfsd_nvlist_unpack(conf_buf, conf_len, &conf_nvl) != 0 ||
	    zfsd_nvlist_unpack(src_buf,  src_len,  &src_nvl)  != 0) {
		err = EINVAL;
		goto reply;
	}

	/* Find and call handler */
	err = ENOTSUP;
	for (int i = 0; zfsd_dispatch_cmd[i].fn != NULL; i++) {
		if (zfsd_dispatch_cmd[i].ioc == ioc) {
			fprintf(stderr, "zfsd: ioc %s\n",
			    zfsd_dispatch_cmd[i].name);
			err = zfsd_dispatch_cmd[i].fn(zc, conf_nvl, src_nvl,
			    &out_nvl);
			break;
		}
	}
	if (err == ENOTSUP)
		fprintf(stderr, "zfsd: UNHANDLED ioc 0x%x\n", ioc);

	if (err == 0 && out_nvl != NULL)
		(void) zfsd_nvlist_pack(out_nvl, &dst_buf, &dst_len);

reply:
	/* Build reply: zero pointer fields, keep the rest */
	zc_reply = *zc;
	zc_reply.zc_nvlist_conf = 0;
	zc_reply.zc_nvlist_src  = 0;
	zc_reply.zc_nvlist_dst  = 0;

	uint32_t dst_len32 = (uint32_t)dst_len;

	(void) write_all(client_fd, &magic, sizeof (magic));
	(void) write_all(client_fd, &err, sizeof (err));
	(void) write_all(client_fd, &zc_reply,  sizeof (zc_reply));
	(void) write_all(client_fd, &dst_len32, sizeof (dst_len32));
	if (dst_len32 > 0 && dst_buf != NULL)
		(void) write_all(client_fd, dst_buf, dst_len32);

	free(dst_buf);
	nvlist_free(conf_nvl);
	nvlist_free(src_nvl);
	nvlist_free(out_nvl);
}

/* ---- per-client thread ---- */

static void *
zfsd_client_thread(void *arg)
{
	int client_fd = (int)(intptr_t)arg;

	for (;;) {
		uint32_t  magic, ioc, conf_len, src_len;
		zfs_cmd_t zc;

		/* Read fixed header */
		if (read_all(client_fd, &magic, sizeof (magic)) < 0 ||
		    read_all(client_fd, &ioc, sizeof (ioc)) < 0 ||
		    read_all(client_fd, &zc, sizeof (zc)) < 0 ||
		    read_all(client_fd, &conf_len, sizeof (conf_len)) < 0 ||
		    read_all(client_fd, &src_len, sizeof (src_len)) < 0)
			break;

		if (magic != ZFS_SOCK_MAGIC) {
			fprintf(stderr, "zfsd: bad magic 0x%x\n", magic);
			break;
		}

		/* Read variable nvlist payloads */
		void *conf_buf = NULL, *src_buf = NULL;

		if (conf_len > 0) {
			conf_buf = malloc(conf_len);
			if (conf_buf == NULL ||
			    read_all(client_fd, conf_buf, conf_len) < 0) {
				free(conf_buf);
				break;
			}
		}
		if (src_len > 0) {
			src_buf = malloc(src_len);
			if (src_buf == NULL ||
			    read_all(client_fd, src_buf, src_len) < 0) {
				free(conf_buf);
				free(src_buf);
				break;
			}
		}

		zfsd_dispatch(client_fd, ioc, &zc,
		    conf_buf, conf_len, src_buf, src_len);

		free(conf_buf);
		free(src_buf);
	}

	close(client_fd);
	return (NULL);
}

/* ---- main ---- */

int
main(int argc __attribute__((unused)), char *argv[] __attribute__((unused)))
{
	struct sockaddr_un addr;
	int listen_fd;

	/* Ignore SIGPIPE — we handle write errors inline */
	signal(SIGPIPE, SIG_IGN);

	/* Initialise the ZFS engine (same as zdb/ztest) */
	kernel_init(SPA_MODE_READ | SPA_MODE_WRITE);

	fprintf(stderr, "zfsd: ZFS engine initialised\n");

	/* Create listening socket */
	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("zfsd: socket");
		return (1);
	}

	(void) unlink(ZFS_SOCK_PATH);	/* remove stale socket */

	memset(&addr, 0, sizeof (addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, ZFS_SOCK_PATH, sizeof (addr.sun_path));

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
		perror("zfsd: bind");
		return (1);
	}

	/* Only root should talk to us */
	(void) chmod(ZFS_SOCK_PATH, 0600);

	if (listen(listen_fd, ZFS_SOCK_BACKLOG) < 0) {
		perror("zfsd: listen");
		return (1);
	}

	fprintf(stderr, "zfsd: listening on %s\n", ZFS_SOCK_PATH);

	for (;;) {
		int client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			perror("zfsd: accept");
			break;
		}

		/* Detached thread per client — fine for PoC */
		pthread_t tid;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&tid, &attr, zfsd_client_thread,
		    (void *)(intptr_t)client_fd);
		pthread_attr_destroy(&attr);
	}

	kernel_fini();
	close(listen_fd);
	(void) unlink(ZFS_SOCK_PATH);
	return (0);
}
