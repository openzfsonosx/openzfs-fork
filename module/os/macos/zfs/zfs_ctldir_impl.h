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

#ifndef _ZFS_CTLDIR_IMPL_H
#define	_ZFS_CTLDIR_IMPL_H

#define	IGNORE_MAX 5

/* Keep concurrent writers in bounds without resetting the counter. */
#define	IGNORE_ADD(pid, tid, time) do {				\
	uint32_t i = (atomic_inc_32_nv(&ignore_next) - 1U) % IGNORE_MAX; \
	ignore_lookups_pid[i] = (pid); \
	ignore_lookups_tid[i] = (tid); \
	ignore_lookups_time[i] = (time); \
	} while (0)

#endif /* _ZFS_CTLDIR_IMPL_H */
