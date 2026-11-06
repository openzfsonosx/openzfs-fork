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

/*
 * SPL boot log.
 *
 * Messages printed while the kext loads are easy to lose: on a busy boot
 * the kernel's os_log queue can overflow before logd drains it, and the
 * kernel message buffer (dmesg) is a ring that later traffic overwrites.
 * zfs_dbgmsg() is no help either, as it is not set up until ZFS module
 * init, well after spl_start() has done its work.
 *
 * spl_bootlog() prints a message exactly as printf() would, and also
 * appends it, with a seconds-since-boot timestamp, to a small static
 * buffer that lives as long as the kext is loaded.  The buffer needs no
 * allocation and no SPL subsystem, so it can be used from the very first
 * line of spl_start().  It keeps the *first* SPL_BOOTLOG_SIZE bytes:
 * once full, further messages are still printed but are only counted.
 *
 * The buffer is exported as a raw kstat once kstats exist:
 *
 *	sysctl kstat.spl.misc.bootlog.verbose=1 \
 *	    kstat.spl.misc.bootlog.bootlog \
 *	    kstat.spl.misc.bootlog.verbose=0
 *
 * (like zfs dbgmsg, raw kstats only produce output while verbose is set)
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kstat.h>
#include <sys/mutex.h>
#include <kern/clock.h>
#include <stdarg.h>

#define	SPL_BOOTLOG_SIZE	(16 * 1024)
#define	SPL_BOOTLOG_LINE	256
#define	SPL_BOOTLOG_STAMP	24

static char spl_bootlog_buf[SPL_BOOTLOG_SIZE];
static size_t spl_bootlog_len;
static uint64_t spl_bootlog_msgs;
static uint64_t spl_bootlog_dropped;

/*
 * Writers may run before lck_grp_alloc_init() or the SPL mutex subsystem
 * is usable, so the buffer is guarded by a bare test-and-set flag.  The
 * critical section is a bounds check and a copy of at most
 * SPL_BOOTLOG_STAMP + SPL_BOOTLOG_LINE bytes, and there are only a few
 * dozen messages in a boot, so spinning is acceptable.
 */
static volatile int spl_bootlog_busy;

static kstat_t *spl_bootlog_ksp;
static kmutex_t spl_bootlog_kstat_lock;

static void
spl_bootlog_lock(void)
{
	while (__atomic_test_and_set(&spl_bootlog_busy, __ATOMIC_ACQUIRE))
		;
}

static void
spl_bootlog_unlock(void)
{
	__atomic_clear(&spl_bootlog_busy, __ATOMIC_RELEASE);
}

static void
spl_bootlog_append(const char *msg, size_t msglen)
{
	char stamp[SPL_BOOTLOG_STAMP];
	uint64_t ns;
	size_t stamplen, need;
	boolean_t addnl;

	absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
	stamplen = snprintf(stamp, sizeof (stamp), "[%6llu.%06llu] ",
	    (u_longlong_t)(ns / NANOSEC),
	    (u_longlong_t)((ns % NANOSEC) / 1000));
	if (stamplen >= sizeof (stamp))
		stamplen = sizeof (stamp) - 1;

	addnl = (msglen == 0 || msg[msglen - 1] != '\n');
	need = stamplen + msglen + (addnl ? 1 : 0);

	spl_bootlog_lock();
	if (spl_bootlog_len + need > SPL_BOOTLOG_SIZE) {
		spl_bootlog_dropped++;
	} else {
		char *p = spl_bootlog_buf + spl_bootlog_len;

		memcpy(p, stamp, stamplen);
		memcpy(p + stamplen, msg, msglen);
		if (addnl)
			p[stamplen + msglen] = '\n';
		spl_bootlog_len += need;
		spl_bootlog_msgs++;
	}
	spl_bootlog_unlock();
}

void
spl_vbootlog(const char *fmt, va_list ap)
{
	char line[SPL_BOOTLOG_LINE];
	int n;

	n = vsnprintf(line, sizeof (line), fmt, ap);
	if (n < 0)
		return;
	if (n >= (int)sizeof (line)) {
		/* truncated: keep it on one line */
		n = sizeof (line) - 1;
		line[n - 1] = '\n';
	}

	printf("%s", line);
	spl_bootlog_append(line, n);
}

void
spl_bootlog(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	spl_vbootlog(fmt, ap);
	va_end(ap);
}

static int
spl_bootlog_kstat_headers(char *buf, size_t size)
{
	uint64_t msgs, dropped;
	size_t len;

	spl_bootlog_lock();
	len = spl_bootlog_len;
	msgs = spl_bootlog_msgs;
	dropped = spl_bootlog_dropped;
	spl_bootlog_unlock();

	(void) snprintf(buf, size,
	    "%llu messages, %lu of %lu bytes, %llu dropped (buffer full)\n",
	    (u_longlong_t)msgs, (unsigned long)len,
	    (unsigned long)SPL_BOOTLOG_SIZE, (u_longlong_t)dropped);

	return (0);
}

static int
spl_bootlog_kstat_data(char *buf, size_t size, void *data)
{
	size_t len;

	spl_bootlog_lock();
	len = spl_bootlog_len;
	spl_bootlog_unlock();

	/* the caller doubles the buffer, up to KSTAT_RAW_MAX, on ENOMEM */
	if (len + 1 > size)
		return (ENOMEM);

	/* text before len is never rewritten, so it can be copied unlocked */
	memcpy(buf, data, len);
	buf[len] = '\0';

	return (0);
}

static void *
spl_bootlog_kstat_addr(kstat_t *ksp, loff_t n)
{
	return (n == 0 ? spl_bootlog_buf : NULL);
}

void
spl_bootlog_kstat_init(void)
{
	mutex_init(&spl_bootlog_kstat_lock, "spl_bootlog_kstat_lock",
	    MUTEX_DEFAULT, NULL);

	spl_bootlog_ksp = kstat_create("spl", 0, "bootlog", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VIRTUAL);
	if (spl_bootlog_ksp != NULL) {
		spl_bootlog_ksp->ks_lock = &spl_bootlog_kstat_lock;
		spl_bootlog_ksp->ks_ndata = 1;
		spl_bootlog_ksp->ks_private = NULL;
		kstat_set_raw_ops(spl_bootlog_ksp, spl_bootlog_kstat_headers,
		    spl_bootlog_kstat_data, spl_bootlog_kstat_addr);
		kstat_install(spl_bootlog_ksp);
	}
}

void
spl_bootlog_kstat_fini(void)
{
	if (spl_bootlog_ksp != NULL) {
		kstat_delete(spl_bootlog_ksp);
		spl_bootlog_ksp = NULL;
	}
	mutex_destroy(&spl_bootlog_kstat_lock);
}
