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
 *
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */

#ifndef _SPL_FCNTL_H
#define	_SPL_FCNTL_H

#include <TargetConditionals.h>
#include <AvailabilityMacros.h>
#if !defined(MAC_OS_X_VERSION_10_9) ||	\
	(MAC_OS_X_VERSION_MIN_REQUIRED <= MAC_OS_X_VERSION_10_9)
#include <i386/types.h>
#endif

#include_next <sys/fcntl.h>

#define	F_FREESP		11

#define	O_LARGEFILE		0
#define	O_RSYNC			0

/*
 * macOS has no O_DIRECT open(2) flag; the equivalent is per-fd, via
 * fcntl(F_NOCACHE), which reaches VNOP_READ/VNOP_WRITE as IO_NOCACHE and is
 * translated to this bit by zfs_ioflags().
 *
 * There is no spare bit to take: counting the kernel-only definitions,
 * XNU's bsd/sys/fcntl.h allocates every bit from 0x1 (FREAD) to 0x80000000
 * (O_POPUP). Any value we pick therefore shares one. That is safe because
 * this is a ZFS-private namespace - zfs_ioflags() builds the int from
 * scratch out of IO_* inputs, and it never holds an XNU oflag or fg_flag.
 * The invariant that does matter, that it not collide with the flags
 * zfs_ioflags() itself sets, is asserted there.
 *
 * We deliberately reuse FNOCACHE's value rather than an arbitrary bit, so
 * that if the two namespaces ever do meet they agree instead of conflict.
 * Note this is only the kernel SPL; userland has its own O_DIRECT 0 in
 * lib/libspl/include/os/macos/poll.h, which cmd/zpool passes to open(2).
 */
#define	O_DIRECT		0x00040000	/* == FNOCACHE */

#endif /* _SPL_FCNTL_H */
