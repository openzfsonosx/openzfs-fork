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
 *
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/processor.h>
#include <sys/sysmacros.h>

extern int cpu_number(void);

#if defined(__x86_64__)

#include <i386/cpuid.h>
#include <sys/simd_x86.h>

#elif defined(__aarch64__)

#include <sys/simd_aarch64.h>

static uint64_t _spl_cpuid_id_aa64isar0_el1 = 0ULL;
static uint64_t _spl_cpuid_id_aa64isar1_el1 = 0ULL;

#else

#define	_spl_cpuid(func, a, b, c, d)				\
	a = b = c = d = 0

#endif

#if defined(__aarch64__)
/*
 * Map this CPU's MPIDR_EL1 to a dense id in [0, max_ncpus).
 *
 * xnu's own cpu_number() would do, but on arm64 it (and
 * ml_get_cpu_number(), ml_get_topology_info()) is only in
 * Private.arm64.exports, so we cannot link against it.
 *
 * Apple Silicon MPIDR_EL1:
 *   Aff0: core number within its cluster
 *   Aff1: physical cluster number; on Ultra parts the second die's
 *         clusters have their own numbers (M3 Ultra: E 0, P 1-2,
 *         E 8, P 9-10).  xnu board_config.h allows up to 10 on
 *         T6031 and 18 on T6050 (M5 Pro/Max/Ultra).
 *   Aff2: core type bit; not needed -- xnu itself identifies a CPU
 *         by MPIDR & 0xFFFF (osfmk/arm64/start.s), so Aff1:Aff0 is
 *         unique.
 *
 * Each CPU's "reg" property in IODeviceTree:/cpus is that same
 * Aff1:Aff0 value, and "cpu-id" is the logical number xnu gives it.
 * spl_cpuid_init() (called from spl_start(), before kmem is set up)
 * walks the device tree via spl_cpuid_dt_walk() in spl-cpus.cpp and
 * fills spl_cpuid_slot[], so getcpuid() returns the same number as
 * xnu's cpu_number() from boot.
 *
 * If the walk fails, ids are handed out on first sight of each MPIDR
 * instead.  Either way every id returned is < max_ncpus; anything
 * unexpected (an affinity field too wide for the table, a CPU missing
 * from the table) falls back to a modulus.  Callers tolerate a shared
 * id -- they lock -- they just contend.
 */
#define	CPUID_AFF0_BITS		4
#define	CPUID_AFF1_BITS		5
#define	CPUID_NKEYS		(1U << (CPUID_AFF0_BITS + CPUID_AFF1_BITS))
#define	CPUID_SLOT_FREE		0
#define	CPUID_SLOT_BUSY		0xffff

static uint16_t spl_cpuid_slot[CPUID_NKEYS];	/* id + 1, or FREE/BUSY */
static uint32_t spl_cpuid_next = 0;		/* first-sight mode */
static int spl_cpuid_from_dt = 0;		/* table is authoritative */

extern int spl_cpuid_dt_walk(void);

static inline int
spl_cpuid_key(uint64_t mpidr, uint32_t *key)
{
	uint32_t aff0 = (uint32_t)(mpidr & 0xff);
	uint32_t aff1 = (uint32_t)((mpidr >> 8) & 0xff);

	if ((aff0 >> CPUID_AFF0_BITS) != 0 || (aff1 >> CPUID_AFF1_BITS) != 0)
		return (0);
	*key = (aff1 << CPUID_AFF0_BITS) | aff0;
	return (1);
}

static inline uint32_t
spl_cpuid_fallback(uint64_t mpidr)
{
	return ((uint32_t)((mpidr & 0xff) + ((mpidr >> 8) & 0xff) * 8) %
	    max_ncpus);
}

/*
 * Called by spl_cpuid_dt_walk() for each device-tree CPU node.
 * Returns 0 if the entry was recorded, nonzero if it was skipped.
 */
int
spl_cpuid_dt_add(uint32_t reg, uint32_t cpu_id, char cluster_type)
{
	uint32_t key;

	if (cpu_id >= max_ncpus) {
		/* e.g. cpus= boot-arg: this CPU will never run */
		return (1);
	}
	if (!spl_cpuid_key(reg, &key)) {
		printf("SPL: cpu-id %u reg 0x%x out of table range\n",
		    cpu_id, reg);
		return (2);
	}
	if (spl_cpuid_slot[key] != CPUID_SLOT_FREE) {
		printf("SPL: cpu-id %u reg 0x%x duplicates cpu-id %u\n",
		    cpu_id, reg, spl_cpuid_slot[key] - 1);
		return (3);
	}
	for (uint32_t k = 0; k < CPUID_NKEYS; k++) {
		if (spl_cpuid_slot[k] == cpu_id + 1) {
			printf("SPL: cpu-id %u appears twice\n", cpu_id);
			return (4);
		}
	}
	spl_cpuid_slot[key] = (uint16_t)(cpu_id + 1);
#ifdef DEBUG
	printf("SPL: cpu-id %2u reg 0x%04x cluster %u core %u type %c\n",
	    cpu_id, reg, (reg >> 8) & 0xff, reg & 0xff,
	    cluster_type ? cluster_type : '?');
#endif
	return (0);
}

void
spl_cpuid_init(void)
{
	int n = spl_cpuid_dt_walk();

	if (n > 0) {
		printf("SPL: cpu ids from IODeviceTree: %d of %u cpus\n",
		    n, max_ncpus);
		__atomic_store_n(&spl_cpuid_from_dt, 1, __ATOMIC_RELEASE);
		return;
	}

	/* walk failed or found nothing usable: discard any partial table */
	for (uint32_t k = 0; k < CPUID_NKEYS; k++)
		spl_cpuid_slot[k] = CPUID_SLOT_FREE;
	printf("SPL: IODeviceTree cpu walk failed (%d), "
	    "assigning cpu ids on first use\n", n);
}

/*
 * For the spl_misc kstat: 1 if cpu ids came from IODeviceTree,
 * 0 if assigned on first use (or not arm64).
 */
uint64_t
spl_cpuid_source(void)
{
	return (__atomic_load_n(&spl_cpuid_from_dt, __ATOMIC_ACQUIRE) ? 1 : 0);
}

static uint32_t
spl_cpuid_assign(uint64_t mpidr, uint16_t *slot)
{
	uint16_t v = CPUID_SLOT_FREE;

	if (__atomic_compare_exchange_n(slot, &v, CPUID_SLOT_BUSY, 0,
	    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
		uint32_t id = __atomic_fetch_add(&spl_cpuid_next, 1,
		    __ATOMIC_RELAXED);
		if (id >= max_ncpus)
			id %= max_ncpus;
		__atomic_store_n(slot, (uint16_t)(id + 1), __ATOMIC_RELEASE);
		return (id);
	}

	/*
	 * Someone else is assigning this slot.  Don't spin: the assigner
	 * may be the thread we interrupted on this very CPU.  A shared
	 * id for this one call is harmless.
	 */
	if (v == CPUID_SLOT_BUSY)
		return (spl_cpuid_fallback(mpidr));
	return ((uint32_t)v - 1);
}
#endif

#if !defined(__aarch64__)
uint64_t
spl_cpuid_source(void)
{
	return (0);
}
#endif

uint32_t
getcpuid(void)
{
#if defined(__aarch64__)
	uint64_t mpidr_el1;
	uint32_t key;

	if (max_ncpus <= 1)
		return (0);

	asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));

	if (!spl_cpuid_key(mpidr_el1, &key))
		return (spl_cpuid_fallback(mpidr_el1));

	uint16_t v = __atomic_load_n(&spl_cpuid_slot[key], __ATOMIC_ACQUIRE);

	if (__builtin_expect(v != CPUID_SLOT_FREE && v != CPUID_SLOT_BUSY, 1))
		return ((uint32_t)v - 1);

	if (__atomic_load_n(&spl_cpuid_from_dt, __ATOMIC_ACQUIRE))
		return (spl_cpuid_fallback(mpidr_el1)); /* not in the DT? */

	return (spl_cpuid_assign(mpidr_el1, &spl_cpuid_slot[key]));
#else
	return ((uint32_t)cpu_number());
#endif
}

#if defined(__aarch64__)

/* 4,5,6,7 -> GET_BITS(4, 8) */
#define	GET_BITS(S, F, T) \
		((S) >> (F)) & ((1 << ((T) - (F))) - 1)

uint64_t
spl_cpuid_id_aa64isar0_el1(void)
{
	static int first_time = 1;

	if (first_time == 1) {
		first_time = 0;
		uint64_t value;
		uint32_t aes, sha1, sha2, sha3;

		asm volatile("mrs %0, ID_AA64ISAR0_EL1" :
		    "=r"(value) ::);

		_spl_cpuid_id_aa64isar0_el1 = value;

		printf("cpu_features0: 0x%016llx \n",
		    _spl_cpuid_id_aa64isar0_el1);

		aes = GET_BITS(_spl_cpuid_id_aa64isar0_el1, 4, 8);
		sha1 = GET_BITS(_spl_cpuid_id_aa64isar0_el1, 8, 12);
		sha2 = GET_BITS(_spl_cpuid_id_aa64isar0_el1, 12, 16);
		sha3 = GET_BITS(_spl_cpuid_id_aa64isar0_el1, 32, 36);

		printf("cpu_features0: %s%s%s%s%s%s\n",
		    aes & 3 ? "AES " : "",
		    aes & 2 ? "PMULL " : "",
		    sha1    ? "SHA1 " : "",
		    sha2    ? "SHA256 " : "",
		    sha2 & 2 ? "SHA512 " : "",
		    sha3    ? "SHA3 " : "");
	}

	return (_spl_cpuid_id_aa64isar0_el1);
}

uint64_t
spl_cpuid_id_aa64isar1_el1(void)
{
	static int first_time = 1;

	if (first_time == 1) {
		first_time = 0;
		uint64_t value;
		uint32_t bf16, i8mm;

		asm volatile("mrs %0, ID_AA64ISAR1_EL1" :
		    "=r"(value) ::);

		_spl_cpuid_id_aa64isar1_el1 = value;

		printf("cpu_features: 0x%016llx \n",
		    _spl_cpuid_id_aa64isar1_el1);

		bf16 = GET_BITS(_spl_cpuid_id_aa64isar1_el1, 44, 48);
		i8mm = GET_BITS(_spl_cpuid_id_aa64isar1_el1, 52, 56);

		printf("cpu_features1: %s%s\n",
		    bf16 ? "BF16 " : "",
		    i8mm ? "I8MM " : "");
	}

	return (_spl_cpuid_id_aa64isar1_el1);
}

#endif /* aarch64 */

int
spl_processor_init(void)
{

#if defined(__aarch64__)
	spl_cpuid_id_aa64isar0_el1();
	spl_cpuid_id_aa64isar1_el1();
#endif

#if defined(__x86)
	printf("CPUID: %s%s%s%s%s%s%s\n",
	    zfs_osxsave_available() ? "osxsave " : "",
	    zfs_sse_available() ? "sse " : "",
	    zfs_sse2_available() ? "sse2 " : "",
	    zfs_sse3_available() ? "sse3 " : "",
	    zfs_ssse3_available() ? "ssse3 " : "",
	    zfs_sse4_1_available() ? "sse4.1 " : "",
	    zfs_sse4_2_available() ? "sse4.2 " : "");
	printf("CPUID: %s%s%s%s%s%s%s\n",
	    zfs_avx_available() ? "avx " : "",
	    zfs_avx2_available() ? "avx2 " : "",
	    zfs_aes_available() ? "aes " : "",
	    zfs_pclmulqdq_available() ? "pclmulqdq " : "",
	    zfs_avx512f_available() ? "avx512f " : "",
	    zfs_movbe_available() ? "movbe " : "",
	    zfs_shani_available() ? "sha-ni " : "");
#endif

	return (0);
}
