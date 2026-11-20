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

#include <stdint.h>
#include <string.h>
#include "unit.h"
#include "../../module/os/macos/zfs/zfs_ctldir_impl.h"

static uint32_t ignore_next;
static int ignore_lookups_pid[IGNORE_MAX];
static void *ignore_lookups_tid[IGNORE_MAX];
static uint64_t ignore_lookups_time[IGNORE_MAX];
static int interleave;

static uint32_t
atomic_inc_32_nv(uint32_t *counter)
{
	uint32_t ticket = ++*counter;

	/* Another caller enters before the first increment returns. */
	if (interleave) {
		interleave = 0;
		IGNORE_ADD(2, NULL, 0);
	}
	return (ticket);
}

static MunitResult
ignore_interleaved(const MunitParameter params[], void *data)
{
	(void) params, (void) data;

	memset(ignore_lookups_pid, 0, sizeof (ignore_lookups_pid));
	ignore_next = IGNORE_MAX - 1;
	interleave = 1;
	IGNORE_ADD(1, NULL, 0);
	unit_eq(ignore_lookups_pid[IGNORE_MAX - 1], 1);
	unit_eq(ignore_lookups_pid[0], 2);
	return (MUNIT_OK);
}

static MunitResult
ignore_wrap(const MunitParameter params[], void *data)
{
	(void) params, (void) data;
	/* Unsigned rollover repeats slot zero; every slot stays in bounds. */
	const unsigned int slots[] = {3, 4, 0, 0, 1, 2};

	ignore_next = UINT32_MAX - 2;
	interleave = 0;
	for (size_t n = 0; n < sizeof (slots) / sizeof (slots[0]); n++) {
		IGNORE_ADD((int)n + 1, NULL, 0);
		unit_eq(ignore_lookups_pid[slots[n]], (int)n + 1);
	}
	return (MUNIT_OK);
}

static const MunitTest zfsctl_tests[] = {
	UNIT_TEST("ignore_interleaved", ignore_interleaved),
	UNIT_TEST("ignore_wrap", ignore_wrap),
	{ 0 },
};

static const MunitSuite zfsctl_suite = {
	"zfsctl.", zfsctl_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

int
main(int argc, char **argv)
{
	return (munit_suite_main(&zfsctl_suite, NULL, argc, argv));
}
