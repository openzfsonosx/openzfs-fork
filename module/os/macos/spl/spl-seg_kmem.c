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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>

#include <sys/atomic.h>

#include <sys/vmem.h>
#include <sys/vmem_impl.h>

#include <sys/time.h>
#include <sys/timer.h>
#include <sys/condvar.h>

#include <stdbool.h>

/*
 * seg_kmem is the primary kernel memory segment driver.  It
 * maps the kernel heap [kernelheap, ekernelheap), module text,
 * and all memory which was allocated before the VM was initialized
 * into kas.
 *
 * Pages which belong to seg_kmem are hashed into &kvp vnode at
 * an offset equal to (u_offset_t)virt_addr, and have p_lckcnt >= 1.
 * They must never be paged out since segkmem_fault() is a no-op to
 * prevent recursive faults.
 *
 * Currently, seg_kmem pages are sharelocked (p_sharelock == 1) on
 * __x86 and are unlocked (p_sharelock == 0) on __sparc.  Once __x86
 * supports relocation the #ifdef kludges can be removed.
 *
 * seg_kmem pages may be subject to relocation by page_relocate(),
 * provided that the HAT supports it; if this is so, segkmem_reloc
 * will be set to a nonzero value. All boot time allocated memory as
 * well as static memory is considered off limits to relocation.
 * Pages are "relocatable" if p_state does not have P_NORELOC set, so
 * we request P_NORELOC pages for memory that isn't safe to relocate.
 *
 * The kernel heap is logically divided up into four pieces:
 *
 *   heap32_arena is for allocations that require 32-bit absolute
 *   virtual addresses (e.g. code that uses 32-bit pointers/offsets).
 *
 *   heap_core is for allocations that require 2GB *relative*
 *   offsets; in other words all memory from heap_core is within
 *   2GB of all other memory from the same arena. This is a requirement
 *   of the addressing modes of some processors in supervisor code.
 *
 *   heap_arena is the general heap arena.
 *
 *   static_arena is the static memory arena.  Allocations from it
 *   are not subject to relocation so it is safe to use the memory
 *   physical address as well as the virtual address (e.g. the VA to
 *   PA translations are static).  Caches may import from static_arena;
 *   all other static memory allocations should use static_alloc_arena.
 *
 * On some platforms which have limited virtual address space, seg_kmem
 * may share [kernelheap, ekernelheap) with seg_kp; if this is so,
 * segkp_bitmap is non-NULL, and each bit represents a page of virtual
 * address space which is actually seg_kp mapped.
 */

/*
 * Rough stubbed Port for XNU.
 *
 * Copyright (c) 2014 Brendon Humphrey (brendon.humphrey@mac.com)
 */

#ifdef _KERNEL
#define	XNU_KERNEL_PRIVATE
#include <mach/vm_types.h>
extern vm_map_t kernel_map;

/*
 * These extern prototypes has to be carefully checked against XNU source
 * in case Apple changes them. They are not defined in the "allowed" parts
 * of the kernel.framework
 */
typedef uint8_t vm_tag_t;

/*
 * Tag we use to identify memory we have allocated
 *
 * (VM_KERN_MEMORY_KEXT - mach_vm_statistics.h)
 */
#define	SPL_TAG	6

#endif /* _KERNEL */

typedef int page_t;

void *segkmem_alloc(vmem_t *vmp, size_t size, int vmflag);
void segkmem_free(vmem_t *vmp, const void *inaddr, size_t size);

/* Total memory held allocated */
uint64_t segkmem_total_mem_allocated = 0;

/* primary kernel heap arena */
vmem_t *heap_arena;

/* qcaches abd */
vmem_t *abd_arena;
vmem_t *abd_subpage_arena;

#ifdef _KERNEL
uint64_t stat_osif_malloc_success = 0;
uint64_t stat_osif_malloc_fail = 0;
uint64_t stat_osif_free = 0;
uint64_t stat_osif_malloc_bytes = 0;
uint64_t stat_osif_free_bytes = 0;
uint64_t stat_osif_malloc_sub128k = 0;
uint64_t stat_osif_malloc_sub64k = 0;
uint64_t stat_osif_malloc_sub32k = 0;
uint64_t stat_osif_malloc_page = 0;
uint64_t stat_osif_malloc_subpage = 0;
#endif

void *
osif_malloc(uint64_t size)
{
#ifdef _KERNEL
	// vm_offset_t tr = NULL;
	void *tr = NULL;
	kern_return_t kr = -1;

	if (size < PAGESIZE)
		atomic_inc_64(&stat_osif_malloc_subpage);
	else if (size == PAGESIZE)
		atomic_inc_64(&stat_osif_malloc_page);
	else if (size < 32768)
		atomic_inc_64(&stat_osif_malloc_sub32k);
	else if (size < 65536)
		atomic_inc_64(&stat_osif_malloc_sub64k);
	else if (size < 131072)
		atomic_inc_64(&stat_osif_malloc_sub128k);

	/*
	 * On Intel and ARM we can deal with eight-byte-aligned pointers from
	 * IOMallocAligned().  Larger alignment may be faster, but may also
	 * cause problems when we have a system with very large RAM that we
	 * want to use for ARC and other zfs purposes.
	 */
	const uint64_t align = 8;

	tr = IOMallocAligned(size, align);
	if (tr != NULL)
		kr = KERN_SUCCESS;

	if (kr == KERN_SUCCESS) {
		atomic_inc_64(&stat_osif_malloc_success);
		atomic_add_64(&segkmem_total_mem_allocated, size);
		atomic_add_64(&spl_shared_mem_allocated, size);
		atomic_add_64(&stat_osif_malloc_bytes, size);
		return ((void *)tr);
	} else {
		/*
		 * Apple documentation says IOMallocAligned()
		 * may return NULL.  Make a note of these and
		 * bubble the result upwards to deal with,
		 * which may result in a kmem allocator returning
		 * NULL, or potentially a panic if VM_PANIC is set.
		 *
		 * The only places VM_PANIC is set are in vmem_init() and if
		 * in the call to vmem_populate is called because the
		 * VMC_POPULATOR flag is given vmem_create(), so only very
		 * early in vmem initialization.
		 */
		atomic_inc_64(&stat_osif_malloc_fail);
		return (NULL);
	}
#else
	return (malloc(size));
#endif
}

void
osif_free(const void *buf, uint64_t size)
{
#ifdef _KERNEL
	IOFreeAligned((void *)buf, size);
	atomic_inc_64(&stat_osif_free);
	atomic_sub_64(&segkmem_total_mem_allocated, size);
	atomic_sub_64(&spl_shared_mem_allocated, size);
	atomic_add_64(&stat_osif_free_bytes, size);
#else
	free(buf);
#endif /* _KERNEL */
}

/*
 * Configure vmem, such that the heap arena is fed,
 * and drains to the kernel low level allocator.
 */
void
kernelheap_init()
{
	heap_arena = vmem_init("heap", NULL, 0,
#if defined(__arm64__)
	    4096,
#else
	    PAGESIZE,
#endif
	    segkmem_alloc,
	    segkmem_free);
}


void
kernelheap_fini(void)
{
	vmem_fini(heap_arena);
}

void *
segkmem_alloc(vmem_t *vmp, size_t size, int maybe_unmasked_vmflag)
{
	return (osif_malloc(size));
}

void
segkmem_free(vmem_t *vmp, const void *inaddr, size_t size)
{
	osif_free(inaddr, size);
	// since this is mainly called by spl_root_arena and free_arena,
	// do we really want to wake up a waiter, just because we have
	// transferred from one to the other?
	// we already have vmem_add_a_gibibyte waking up waiters
	// so specializing here seems wasteful
	// (originally included in vmem_experiments)
	// cv_signal(&vmp->vm_cv);
}

/*
 * OSX does not use separate heaps for the ZIO buffers,
 * the ZFS code is structured such that the zio caches will
 * fallback to using the kmem_default arena same
 * as all the other caches.
 */

// smd: we nevertheless plumb in an arena with heap as parent, so that
// we can track stats and maintain the VM_ / qc settings differently

/*
 * The smallest exchange with IOMallocData must be bigger
 * than KHEAP_MAX_SIZE (32k on Apple Silicon, 16k on X86_64)
 * in order to avoid being channeled into a zone:
 *
 * osfmk/vm/vm_kern_xnu.h (kalloc and wrappers like IOMalloc* are backed by
 * zone memory for sizes below KHEAP_MAX_SIZE)
 *
 * osfmk/kern/kalloc.c ("Allocations of size greater than KHEAP_MAX_SIZE, are
 * allocated from the VM.")
 *
 * The trade-off here is between lots of IOMallocData/IOFreeData calls and abd
 * chunks pinning an ABD_DATA_MIN_IMPORT amount of memory when only occupying
 * a ~PAGESIZE fraction.
 *
 * VMEM allocations smaller than ABD_DATA_MIN_IMPORT will use parent
 * spl_vmem_heap.
 */
#define	ABD_DATA_ZONE_MAX	(32 * 1024)	/* >= KHEAP_MAX_SIZE */
#define	ABD_DATA_MIN_IMPORT	(2 * 32 * 1024)	/* bigger => fewer kallocs */

extern vmem_t *spl_heap_arena;

/*
 * we have kstats for these even if the mechanism is compiled out.
 */
uint64_t spl_abd_data_throttles = 0;
uint64_t spl_abd_data_throttle_timeouts = 0;

#ifdef SPL_HAVE_IOMALLOCDATA

/*
 * Imports to this arena are driven by ARC growth, and at present the main
 * check on importing up to ABD_DATA_THROTTLE_PCT is arc_no_grow() and
 * spl_free_set_pressure_additive().
 *
 * Above ABD_DATA_THROTTLE_PCT VM_SLEEP imports trigger pressure and then go
 * for a series of brief sleeps, giving the ARC reclaim thread and reaping up
 * to a second to free ABD chunk spans.  This is deliberately simpler than the
 * xnu_alloc_throttled() mechanism for the bucket arenas, principally because
 * it is a backstop that is only very rarely if ever used (it would take a
 * very full ABD chunk cache, including cache fragmentation, and probably also
 * a large burst of dirty or transient data demanding ABD chunks).
 */

#define	ABD_DATA_THROTTLE_PCT		110ULL
#define	ABD_DATA_THROTTLE_SLEEP_MS	10ULL
#define	ABD_DATA_THROTTLE_MAX_LOOPS	100ULL

static void
abd_data_throttle(size_t size, int vmflag)
{
	if ((vmflag & (VM_NOSLEEP | VM_PUSHPAGE | VM_PANIC)) != 0)
		return;

	const uint64_t ceiling = (spl_data_private_memory *
	    ABD_DATA_THROTTLE_PCT) / 100ULL;

	if (spl_private_mem_allocated + size <= ceiling)
		return;

	atomic_inc_64(&spl_abd_data_throttles);

	for (int i = 0; i < ABD_DATA_THROTTLE_MAX_LOOPS; i++) {
		const uint64_t want = spl_private_mem_allocated + size;
		if (want <= ceiling)
			return;
		spl_set_arc_no_grow(B_TRUE);
		spl_free_set_pressure_additive((int64_t)(want - ceiling));
		IOSleepWithLeeway(ABD_DATA_THROTTLE_SLEEP_MS, 1);
	}

	atomic_inc_64(&spl_abd_data_throttle_timeouts);
}

static void *
abd_data_import(vmem_t *vmp, size_t size, int vmflag)
{
	const boolean_t usedata = spl_use_iomallocdata();
	boolean_t oom = B_FALSE;

	if (usedata && size > ABD_DATA_ZONE_MAX) {
		/*
		 * stop ARC growth if we will cross the
		 * limit of what kext private data
		 * we should allocate
		 */
		if (spl_private_mem_allocated + size >
		    spl_data_private_memory) {
			oom = B_TRUE;
			spl_set_arc_no_grow(B_TRUE);
			spl_free_set_pressure_additive(size);
		}

		/*
		 * honour vmflag, fail if we would cross the limit,
		 * rather than sleep as below
		 */
		if ((vmflag & (VM_NOSLEEP | VM_ABORT)) != 0 && oom) {
			return (NULL);
		}

		abd_data_throttle(size, vmflag);

		void *p = IOMallocData(size);
		if (p != NULL) {
			atomic_add_64(&segkmem_total_mem_allocated, size);
			atomic_add_64(&spl_private_mem_allocated, size);
		}
		return (p);
	}
	return (vmem_alloc_impl(spl_heap_arena, size, vmflag));
}

static void
abd_data_release(vmem_t *vmp, const void *p, size_t size)
{
	const boolean_t usedata = spl_use_iomallocdata();

	if (usedata && size > ABD_DATA_ZONE_MAX) {
		if (spl_private_mem_allocated >
		    spl_data_private_memory + size) {
			spl_free_set_pressure_additive(size);
		}
		IOFreeData((void *)p, size);
		atomic_sub_64(&segkmem_total_mem_allocated, size);
		atomic_sub_64(&spl_private_mem_allocated, size);
		return;
	}
	vmem_free_impl(spl_heap_arena, p, size);
}

#endif

void
segkmem_abd_init()
{
	/*
	 * OpenZFS does not segregate the abd kmem cache out of the general
	 * heap, leading to large numbers of short-lived slabs exchanged
	 * between the kmem cache and it's parent.  XNU absorbs this with a a
	 * large minimum request to the parent vmem_caches on large-memory
	 * MacOS systems.
	 *
	 * Additionally, on modern macOS, ABD chunks are segregated into the
	 * kext's private wired map, rather than the kernel's shared wired map.
	 */

	extern vmem_t *spl_heap_arena;

#if defined(__arm64__)
#define	BIG_SLAB (PAGESIZE * 4)
#else
#define	BIG_SLAB (PAGESIZE * 16)
#endif

#define	SMALL_RAM_MACHINE (4ULL * 1024ULL * 1024ULL * 1024ULL)

	const boolean_t usedata = spl_use_iomallocdata();
	vmem_alloc_t *importer;
	vmem_free_t *releaser;
	size_t span_size;

	if (spl_total_memory >= SMALL_RAM_MACHINE)
		span_size = MAX(BIG_SLAB, ABD_DATA_MIN_IMPORT);
	else
		span_size = MAX(PAGESIZE, ABD_DATA_MIN_IMPORT);

	if (usedata) {
#ifdef	SPL_HAVE_IOMALLOCDATA
		importer = abd_data_import;
		releaser = abd_data_release;
#else
		importer = vmem_alloc_impl;
		releaser = vmem_free_impl;
#endif
	} else {
		importer = vmem_alloc_impl;
		releaser = vmem_free_impl;
	}

	abd_arena = vmem_create("abd_cache", NULL, 0,
	    sizeof (void *),
	    importer, releaser,
	    spl_heap_arena,
	    span_size,
	    VM_SLEEP | VMC_NO_QCACHE);

	VERIFY3P(abd_arena, !=, NULL);

	if (usedata) {
#ifdef SPL_HAVE_IOMALLOCDATA
		/*
		 * If we are using abd_data_import / abd_data_release,
		 * make self self's parent, as with the bucket arenas'
		 * b->vm_source = b;
		 *
		 * spl_heap_arena was just a nominal parent at create time.
		 */

		abd_arena->vm_source = abd_arena;
#endif
	}

	/*
	 * We also have a child arena for sub-page allocations, so as to avoid
	 * memory waste, while segregating small ABDs for visibility and
	 * fragmentation control.
	 *
	 * This approach presently assumes SPA_MINBLOCKSIZE is 512 and that
	 * PAGESIZE is an even multiple of at least several SPA_MINBLOCKSIZE.
	 * This will be _Static_assert-ed in abd_os.c.
	 */

	abd_subpage_arena = vmem_create("abd_subpage_cache", NULL, 0,
	    sizeof (void *),
	    vmem_alloc_impl, vmem_free_impl,
	    abd_arena,
	    PAGESIZE, VM_SLEEP | VMC_NO_QCACHE);

	VERIFY3P(abd_subpage_arena, !=, NULL);
}

void
segkmem_abd_fini(void)
{
	if (abd_subpage_arena) {
		vmem_destroy(abd_subpage_arena);
	}

	if (abd_arena) {
		vmem_destroy(abd_arena);
	}
}
