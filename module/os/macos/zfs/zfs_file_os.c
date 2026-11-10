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

#include <IOKit/IOLib.h>
#include <sys/zfs_context.h>
#include <sys/zfs_file.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/zfs_ioctl.h>

#define	FILE_FD_NOTUSED -1

/*
 * Open file
 *
 * path - fully qualified path to file
 * flags - file attributes O_READ / O_WRITE / O_EXCL
 * fpp - pointer to return file pointer
 *
 * Returns 0 on success underlying error on failure.
 */
noinline int
zfs_file_open(const char *path, int flags, int mode, cred_t *cr,
    zfs_file_t **fpp)
{
	struct vnode *vp = NULL;
	vfs_context_t vctx;
	int error;

	if (!(flags & O_CREAT) && (flags & O_WRONLY))
		flags |= O_EXCL;

	vctx = vfs_context_create((vfs_context_t)0);
	error = vnode_open(path, flags, mode, 0, &vp, vctx);
	if (error == 0 && vp != NULL) {
		struct spl_fileproc *zf;
		zf = kmem_zalloc(sizeof (*zf), KM_SLEEP);
		zf->f_vnode = vp;
		zf->f_fd = FILE_FD_NOTUSED;

		/* Optional, implemented O_APPEND: set offset to file size. */
		if (flags & O_APPEND)
			zf->f_ioflags |= IO_APPEND;

		/* O_TRUNC is broken */
		if (flags & O_TRUNC) {
			struct vnode_attr va;

			VATTR_INIT(&va);
			VATTR_SET(&va, va_data_size, 0);
			error = vnode_setattr(vp, &va, vctx);
		}

		*fpp = zf;
	}
	(void) vfs_context_rele(vctx);

	return (error);
}

void
zfs_file_close(zfs_file_t *zfp)
{
	struct spl_fileproc *fp = zfp;
	vfs_context_t vctx;

	if (fp == NULL)
		return;

	vctx = vfs_context_create((vfs_context_t)0);
	vnode_close(fp->f_vnode, fp->f_writes ? FWASWRITTEN : 0, vctx);
	(void) vfs_context_rele(vctx);

	kmem_free(fp, sizeof (*fp));
}

static int
zfs_file_write_impl(zfs_file_t *zfp, const void *buf, size_t count,
    loff_t *off, ssize_t *resid)
{
	struct spl_fileproc *fp = zfp;
	int error;
	ssize_t local_resid = count;

	if (fp == NULL)
		return (EIO);

	/* If we came with a 'fd' use it, as it can handle pipes. */
again:
	if (fp->f_fd == FILE_FD_NOTUSED)
		error = zfs_vn_rdwr(UIO_WRITE, fp->f_vnode, (caddr_t)buf, count,
		    *off, UIO_SYSSPACE, fp->f_ioflags, RLIM64_INFINITY,
		    kcred, &local_resid);
	else
		error = spl_vn_rdwr(UIO_WRITE, fp, (caddr_t)buf, count,
		    *off, UIO_SYSSPACE, fp->f_ioflags, RLIM64_INFINITY,
		    kcred, &local_resid);

	/*
	 * We need to handle partial writes and restarts. The test
	 * zfs_send/zfs_send_sparse is really good at triggering this.
	 */
	if (error == EAGAIN) {
		/*
		 * No progress at all, sleep a bit so we don't busycpu
		 * Unfortunately, pipe_select() and fo_select(), are static,
		 * and VNOP_SELECT is not exported. So we have no choice
		 * but to static sleep until APPLE exports something for us
		 */
		if (local_resid == count)
			IOSleepWithLeeway(2, 1);

		buf += count - local_resid;
		*off += count - local_resid;
		count -= count - local_resid;
		goto again;
	}

	if (error != 0)
		return (SET_ERROR(error));

	fp->f_writes = 1;

	if (resid != NULL)
		*resid = local_resid;
	else if (local_resid != 0)
		return (SET_ERROR(EIO));

	*off += count - local_resid;

	return (0);
}

/*
 * Stateful write - use os internal file pointer to determine where to
 * write and update on successful completion.
 *
 * fp -  pointer to file (pipe, socket, etc) to write to
 * buf - buffer to write
 * count - # of bytes to write
 * resid -  pointer to count of unwritten bytes  (if short write)
 *
 * Returns 0 on success errno on failure.
 */
int
zfs_file_write(zfs_file_t *zfp, const void *buf, size_t count, ssize_t *resid)
{
	struct spl_fileproc *fp = zfp;
	loff_t off = fp->f_offset;
	ssize_t rc;

	rc = zfs_file_write_impl(fp, buf, count, &off, resid);
	if (rc == 0)
		fp->f_offset = off;

	return (SET_ERROR(rc));
}

/*
 * Stateless write - os internal file pointer is not updated.
 *
 * fp -  pointer to file (pipe, socket, etc) to write to
 * buf - buffer to write
 * count - # of bytes to write
 * off - file offset to write to (only valid for seekable types)
 * resid -  pointer to count of unwritten bytes
 *
 * Returns 0 on success errno on failure.
 */
int
zfs_file_pwrite(zfs_file_t *fp, const void *buf, size_t count, loff_t off,
    uint8_t ashift, ssize_t *resid)
{
	(void) ashift;
	return (zfs_file_write_impl(fp, buf, count, &off, resid));
}

static ssize_t
zfs_file_read_impl(zfs_file_t *zfp, void *buf, size_t count, loff_t *off,
    ssize_t *resid)
{
	struct spl_fileproc *fp = zfp;
	int error;
	ssize_t local_resid = count;

	if (fp == NULL)
		return (EIO);

	/* If we have realvp, it's faster to call its spl_vn_rdwr */
again:
	if (fp->f_fd == FILE_FD_NOTUSED)
		error = zfs_vn_rdwr(UIO_READ, fp->f_vnode, buf, count,
		    *off, UIO_SYSSPACE, 0, RLIM64_INFINITY,
		    kcred, &local_resid);
	else
		error = spl_vn_rdwr(UIO_READ, fp, buf, count,
		    *off, UIO_SYSSPACE, 0, RLIM64_INFINITY,
		    kcred, &local_resid);

	/*
	 * We need to handle partial reads and restarts.
	 */
	if (error == EAGAIN) {
		/* No progress at all, sleep a bit so we don't busycpu */
		if (local_resid == count)
			IOSleepWithLeeway(2, 1);
		buf += count - local_resid;
		*off += count - local_resid;
		count -= count - local_resid;
		goto again;
	}

	if (error)
		return (SET_ERROR(error));

	*off += count - local_resid;
	if (resid != NULL)
		*resid = local_resid;

	return (SET_ERROR(0));
}

/*
 * Stateful read - use os internal file pointer to determine where to
 * read and update on successful completion.
 *
 * fp -  pointer to file (pipe, socket, etc) to read from
 * buf - buffer to write
 * count - # of bytes to read
 * resid -  pointer to count of unread bytes (if short read)
 *
 * Returns 0 on success errno on failure.
 */
int
zfs_file_read(zfs_file_t *zfp, void *buf, size_t count, ssize_t *resid)
{
	struct spl_fileproc *fp = zfp;
	loff_t off = fp->f_offset;
	int rc;

	rc = zfs_file_read_impl(fp, buf, count, &off, resid);
	if (rc == 0)
		fp->f_offset = off;
	return (rc);
}

/*
 * Stateless read - os internal file pointer is not updated.
 *
 * fp -  pointer to file (pipe, socket, etc) to read from
 * buf - buffer to write
 * count - # of bytes to write
 * off - file offset to read from (only valid for seekable types)
 * resid -  pointer to count of unwritten bytes (if short read)
 *
 * Returns 0 on success errno on failure.
 */
int
zfs_file_pread(zfs_file_t *fp, void *buf, size_t count, loff_t off,
    ssize_t *resid)
{
	return (zfs_file_read_impl(fp, buf, count, &off, resid));
}

/*
 * lseek - set / get file pointer
 *
 * fp -  pointer to file (pipe, socket, etc) to read from
 * offp - value to seek to, returns current value plus passed offset
 * whence - see man pages for standard lseek whence values
 *
 * Returns 0 on success errno on failure (ESPIPE for non seekable types)
 */
int
zfs_file_seek(zfs_file_t *zfp, loff_t *offp, int whence)
{
	struct spl_fileproc *fp = zfp;

	if (*offp < 0 || *offp > MAXOFFSET_T)
		return (EINVAL);

	if (fp == NULL)
		return (EIO);

	switch (whence) {
		case SEEK_SET:
			fp->f_offset = *offp;
			break;
		case SEEK_CUR:
			fp->f_offset += *offp;
			*offp = fp->f_offset;
			break;
		case SEEK_END:
			/* Implement this if eventually needed: get filesize */
			VERIFY0(whence == SEEK_END);
			break;
	}

	return (0);
}

/*
 * Get file attributes
 *
 * filp - file pointer
 * zfattr - pointer to file attr structure
 *
 * Currently only used for fetching size and file mode.
 *
 * Returns 0 on success or error code of underlying getattr call on failure.
 */
int
zfs_file_getattr(zfs_file_t *zfp, zfs_file_attr_t *zfattr)
{
	struct spl_fileproc *filp = zfp;
	vfs_context_t vctx;
	int rc;
	vattr_t vap;

	if (filp == NULL)
		return (EIO);

	VATTR_INIT(&vap);
	VATTR_WANTED(&vap, va_size);
	VATTR_WANTED(&vap, va_mode);

	vctx = vfs_context_create((vfs_context_t)0);
	rc = vnode_getattr(filp->f_vnode, &vap, vctx);
	(void) vfs_context_rele(vctx);

	if (rc)
		return (rc);

	zfattr->zfa_size = vap.va_size;
	zfattr->zfa_mode = vap.va_mode;

	return (0);
}

/*
 * Sync file to disk
 *
 * filp - file pointer
 * flags - O_SYNC and or O_DSYNC
 *
 * Returns 0 on success or error code of underlying sync call on failure.
 */
int
zfs_file_fsync(zfs_file_t *zfp, int flags)
{
	struct spl_fileproc *filp = zfp;
	vfs_context_t vctx;
	int rc;

	if (filp == NULL)
		return (EIO);

	vctx = vfs_context_create((vfs_context_t)0);
	rc = VNOP_FSYNC(filp->f_vnode, (flags == FSYNC), vctx);
	(void) vfs_context_rele(vctx);
	return (rc);
}

/*
 * fallocate - allocate or free space on disk
 *
 * fp - file pointer
 * mode (non-standard options for hole punching etc)
 * offset - offset to start allocating or freeing from
 * len - length to free / allocate
 *
 * OPTIONAL
 */
int
zfs_file_deallocate(zfs_file_t *zfp, loff_t offset, loff_t len)
{
	struct spl_fileproc *fp = zfp;
	int rc;
	struct flock flck = { 0 };

	if (fp == NULL)
		return (EIO);

	flck.l_type = F_FREESP;
	flck.l_start = offset;
	flck.l_len = len;
	flck.l_whence = 0;

	rc = VOP_SPACE(fp->f_vnode, F_FREESP, &flck,
	    0, 0, kcred, NULL);

	return (rc);
}

/*
 * Request current file pointer offset
 *
 * fp - pointer to file
 *
 * Returns current file offset.
 */
loff_t
zfs_file_off(zfs_file_t *zfp)
{
	struct spl_fileproc *fp = zfp;

	if (fp == NULL)
		return (-EIO);

	return (fp->f_offset);
}

/*
 * Request file pointer private data
 *
 * fp - pointer to file
 *
 * Returns pointer to file private data.
 */
extern kmutex_t zfsdev_state_lock;
dev_t zfsdev_get_dev(void);

void *
zfs_file_private(zfs_file_t *fp)
{
	dev_t dev;
	void *zs;

	dev = zfsdev_get_dev();
	dprintf("%s: fetching dev x%x\n", __func__, dev);
	if (dev == 0)
		return (NULL);

	mutex_enter(&zfsdev_state_lock);
	zs = zfsdev_get_state(minor(dev), ZST_ALL);
	mutex_exit(&zfsdev_state_lock);
	dprintf("%s: searching minor %d %p\n", __func__, minor(dev), zs);

	return (zs);
}

/*
 * unlink file
 *
 * path - fully qualified file path
 *
 * Returns 0 on success.
 *
 * OPTIONAL
 */
int
zfs_file_unlink(const char *path)
{
	return (EOPNOTSUPP);
}

/*
 * XNU gives us no way to reach a userland fd's file offset, so getf()
 * starts every fd at 0. That is fine for a pipe, but "zfs send > file"
 * and "zfs recv < file" share one regular file between userland and the
 * kernel: userland has already written (or read) the stream header, and
 * a -R stream is several kernel sends back to back.
 *
 * So libzfs_core passes the fd's offset in zc_fd_offset, the ioctl
 * points zfs_file_offset_set() at it while it runs, zfs_file_get() starts
 * a regular file there, and zfs_file_put() hands back where the kernel
 * stopped, for userland to lseek() to.
 */
static uint_t zfs_file_offset_tsd = 0;

static boolean_t
zfs_file_is_regular(struct spl_fileproc *fp)
{
	return (fp->f_vnode != NULL && vnode_isreg(fp->f_vnode));
}

/*
 * Get reference to file pointer
 *
 * fd - input file descriptor
 *
 * Returns pointer to file struct or NULL
 */
zfs_file_t *
zfs_file_get(int fd)
{
	struct spl_fileproc *fp = getf(fd);
	uint64_t *offp = tsd_get(zfs_file_offset_tsd);

	if (fp != NULL && offp != NULL && zfs_file_is_regular(fp))
		fp->f_offset = *offp;

	return (fp);
}

/*
 * Drop reference to file pointer
 *
 * fp - input file struct pointer
 */
void
zfs_file_put(zfs_file_t *zfp)
{
	struct spl_fileproc *fp = zfp;
	uint64_t *offp = tsd_get(zfs_file_offset_tsd);

	if (offp != NULL && zfs_file_is_regular(fp))
		*offp = fp->f_offset;

	releasefp(fp);
}

void
zfs_file_offset_set(uint64_t *offp)
{
	(void) tsd_set(zfs_file_offset_tsd, offp);
}

void
zfs_file_offset_init(void)
{
	tsd_create(&zfs_file_offset_tsd, NULL);
}

void
zfs_file_offset_fini(void)
{
	tsd_destroy(&zfs_file_offset_tsd);
}
