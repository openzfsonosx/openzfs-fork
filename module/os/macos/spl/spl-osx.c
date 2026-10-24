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
 * Copyright (C) 2013, 2020 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/thread.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/taskq.h>
#include <kern/processor.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/processor.h>

#define	_task_user_
#include <IOKit/IOLib.h>

#include <sys/systeminfo.h>

static utsname_t utsname_static = { { 0 } };

unsigned int max_ncpus = 0;
unsigned int boot_ncpus = 0;
unsigned int num_ecores = 0;
uint64_t spl_total_memory = 0;
uint64_t spl_real_total_memory = 0;
uint64_t spl_data_private_memory = 0;
uint64_t spl_data_shared_memory = 0;
uint64_t spl_private_mem_allocated = 0;
uint64_t spl_shared_mem_allocated = 0;

// Size in bytes of the memory allocated in seg_kmem
extern uint64_t		segkmem_total_mem_allocated;

extern int bsd_hostname(char *, size_t, size_t *);
static char spl_hostname[MAXHOSTNAMELEN];

/*
 * __attribute__((destructor)) built with a non-Apple clang leaves
 * __cxa_atexit() unresolved at kext load time; the kernel never runs
 * those registrations, so a stub that does nothing is enough.
 */
#ifdef _KERNEL
int
__cxa_atexit(void (*f)(void *), void *p, void *d)
{
	(void) f, (void) p, (void) d;
	return (0);
}
#endif

utsname_t *
utsname(void)
{
	return (&utsname_static);
}

/*
 * Solaris delay is in ticks (hz) and Darwin uses microsecs
 * 1 HZ is 10 milliseconds
 */
void
osx_delay(clock_t ticks)
{
	ASSERT3U(ticks, <, SEC_TO_TICK(60));

	// ticks are 10 msec units
	int64_t ticks_to_go = (int64_t)ticks;
	// zfs_lbolt() is in 10 mec units
	int64_t start_tick = (int64_t)zfs_lbolt();
	int64_t end_tick = start_tick + (int64_t)ticks_to_go;

	do {
		/*
		 * IOSleepWithLeeway takes() (milliseconds, lw_ms) where the
		 * leeway in milliseconds lw_ms ultimately results in an
		 * interval and deadline being given to
		 * _clock_delay_until_deadline_with_leeway() to schedule a lax
		 * (TIMEOUT_URGENCY_LEEWAY) wakeup and then does a
		 * thread_block().
		 *
		 * Without the leeway, a strict deadline is scheduled before
		 * the thread_block().
		 *
		 * Both of these options are gentle compared to a spin wait,
		 * which will happen if the interval given to
		 * _clock..._leeway(int, dead, lee) is less than the threshold
		 * from ml_delay_should_spin.
		 *
		 * The threshold is short on ARM and is related to CPU idle
		 * latency.  On i386 it appears to be 10 microseconds by
		 * default, so also short compared to one tick, which is at
		 * least ten milliseconds.
		 *
		 * We will always IOSleepWithLeeway a minimum amount, even if
		 * we are invoked with delay(zero-or-negative-value);
		 */

		bool forced_sleep = false;

		ASSERT3U(ticks_to_go, <, SEC_TO_TICK(60));
		unsigned milliseconds_remaining = ticks_to_go * 10;

		if (milliseconds_remaining < 2) {
			milliseconds_remaining = 2;
			forced_sleep = true;
		}

		ASSERT3U(milliseconds_remaining, <=, 1000 * 60);

		IOSleepWithLeeway(milliseconds_remaining, 1);

		if (forced_sleep)
			break;

		int64_t cur_tick = (int64_t)zfs_lbolt();
		ticks_to_go = (end_tick - cur_tick);

	} while (ticks_to_go > 0);
}


uint32_t
zone_get_hostid(void *zone)
{
	size_t len;
	uint32_t myhostid = 0;

	len = sizeof (myhostid);
	sysctlbyname("kern.hostid", &myhostid, &len, NULL, 0);
	return (myhostid);
}

extern void *(*__ihook_malloc)(size_t size);
extern void (*__ihook_free)(void *);

const char *
spl_panicstr(void)
{
	return (NULL);
}

extern int get_system_inshutdown(void);

int
spl_system_inshutdown(void)
{
	// return (get_system_inshutdown());
	return (1);
}

#include <mach-o/loader.h>
typedef struct mach_header_64	kernel_mach_header_t;
#include <mach-o/nlist.h>
typedef struct nlist_64			kernel_nlist_t;

typedef struct segment_command_64 kernel_segment_command_t;

typedef struct _loaded_kext_summary {
	char		name[KMOD_MAX_NAME];
	uuid_t		uuid;
	uint64_t	address;
	uint64_t	size;
	uint64_t	version;
	uint32_t	loadTag;
	uint32_t	flags;
	uint64_t	reference_list;
} OSKextLoadedKextSummary;

typedef struct _loaded_kext_summary_header {
    uint32_t version;
    uint32_t entry_size;
    uint32_t numSummaries;
    uint32_t reserved; /* explicit alignment for gdb  */
    OSKextLoadedKextSummary summaries[0];
} OSKextLoadedKextSummaryHeader;

extern OSKextLoadedKextSummaryHeader *gLoadedKextSummaries;

typedef struct _cframe_t {
	struct _cframe_t	*prev;
	uintptr_t			caller;
#if PRINT_ARGS_FROM_STACK_FRAME
	unsigned			args[0];
#endif
} cframe_t;

extern kernel_mach_header_t _mh_execute_header;

extern kmod_info_t *kmod; /* the list of modules */

extern addr64_t  kvtophys(vm_offset_t va);

static int __maybe_unused
panic_print_macho_symbol_name(kernel_mach_header_t *mh, vm_address_t search,
    const char *module_name)
{
	kernel_nlist_t			*sym = NULL;
	struct load_command		*cmd;
	kernel_segment_command_t	*orig_ts = NULL, *orig_le = NULL;
	struct symtab_command		*orig_st = NULL;
	unsigned int			i;
	char				*strings, *bestsym = NULL;
	vm_address_t			bestaddr __maybe_unused = 0;
	vm_address_t 			diff, curdiff;

	/*
	 * Assume that if it's loaded and linked into the kernel,
	 * it's a valid Mach-O
	 */
	cmd = (struct load_command *)&mh[1];
	for (i = 0; i < mh->ncmds; i++) {
		if (cmd->cmd == LC_SEGMENT_64) {
			kernel_segment_command_t *orig_sg =
			    (kernel_segment_command_t *)cmd;

			if (strncmp(SEG_TEXT, orig_sg->segname,
			    sizeof (orig_sg->segname)) == 0)
				orig_ts = orig_sg;
			else if (strncmp(SEG_LINKEDIT, orig_sg->segname,
			    sizeof (orig_sg->segname)) == 0)
				orig_le = orig_sg;
			/* pre-Lion i386 kexts have a single unnamed segment */
			else if (strncmp("", orig_sg->segname,
			    sizeof (orig_sg->segname)) == 0)
				orig_ts = orig_sg;
		} else if (cmd->cmd == LC_SYMTAB)
			orig_st = (struct symtab_command *)cmd;

		cmd = (struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
	}

	if ((orig_ts == NULL) || (orig_st == NULL) || (orig_le == NULL))
		return (0);

	if ((search < orig_ts->vmaddr) ||
	    (search >= orig_ts->vmaddr + orig_ts->vmsize)) {
		/* search out of range for this mach header */
		return (0);
	}

	sym = (kernel_nlist_t *)(uintptr_t)(orig_le->vmaddr +
	    orig_st->symoff - orig_le->fileoff);
	strings = (char *)(uintptr_t)(orig_le->vmaddr +
	    orig_st->stroff - orig_le->fileoff);
	diff = search;

	for (i = 0; i < orig_st->nsyms; i++) {
		if (sym[i].n_type & N_STAB) continue;

		if (sym[i].n_value <= search) {
			curdiff = search - (vm_address_t)sym[i].n_value;
			if (curdiff < diff) {
				diff = curdiff;
				bestaddr = sym[i].n_value;
				bestsym = strings + sym[i].n_un.n_strx;
			}
		}
	}

	if (bestsym != NULL) {
		if (diff != 0) {
			printf("%s : %s + 0x%lx", module_name, bestsym,
			    (unsigned long)diff);
		} else {
			printf("%s : %s", module_name, bestsym);
		}
		return (1);
	}
	return (0);
}


static void __maybe_unused
panic_print_kmod_symbol_name(vm_address_t search)
{
#if 0	// gLoadedKextSummaries is no longer available
	uint_t i;
	if (gLoadedKextSummaries == NULL)
		return;
	for (i = 0; i < gLoadedKextSummaries->numSummaries; ++i) {
		OSKextLoadedKextSummary *summary =
		    gLoadedKextSummaries->summaries + i;

		if ((search >= summary->address) &&
		    (search < (summary->address + summary->size))) {
			kernel_mach_header_t *header =
			    (kernel_mach_header_t *)(uintptr_t)summary->address;
			if (panic_print_macho_symbol_name(header, search,
			    summary->name) == 0) {
				printf("%s + %llu", summary->name,
				    (unsigned long)search - summary->address);
			}
			break;
		}
	}
#endif
}


static void
panic_print_symbol_name(vm_address_t search)
{
	/* try searching in the kernel */
#if 0
	if (panic_print_macho_symbol_name(&_mh_execute_header,
	    search, "mach_kernel") == 0) {
		/* that failed, now try to search for the right kext */
		panic_print_kmod_symbol_name(search);
	}
#endif
}


void
spl_backtrace(char *thesignal)
{
	void *stackptr = NULL;

	printf("SPL: backtrace \"%s\"\n", thesignal);

#if defined(__i386__)
	__asm__ volatile("movl %%ebp, %0" : "=m" (stackptr));
#elif defined(__x86_64__)
	__asm__ volatile("movq %%rbp, %0" : "=m" (stackptr));
#endif

	int frame_index;
	int nframes = 16;
	cframe_t *frame = (cframe_t *)stackptr;

	for (frame_index = 0; frame_index < nframes; frame_index++) {
		vm_offset_t curframep = (vm_offset_t)frame;
		if (!curframep)
			break;
		if (curframep & 0x3) {
			printf("SPL: Unaligned frame\n");
			break;
		}
#if 0
		// no kvtophys() available now. Used to verify only?
		// pmap_find_phys(kernel_pmap, curframep) ?
		if (!kvtophys(curframep) ||
		    !kvtophys(curframep + sizeof (cframe_t) - 1)) {
			printf("SPL: No mapping exists for frame pointer\n");
			break;
		}
#endif
		printf("SPL: %p : 0x%lx ", frame, frame->caller);
		panic_print_symbol_name((vm_address_t)frame->caller);
		printf("\n");
		frame = frame->prev;
	}
}

int
getpcstack(uintptr_t *pcstack, int pcstack_limit)
{
	int  depth = 0;
	void *stackptr = NULL;

#if defined(__i386__)
	__asm__ volatile("movl %%ebp, %0" : "=m" (stackptr));
#elif defined(__x86_64__)
	__asm__ volatile("movq %%rbp, %0" : "=m" (stackptr));
#endif

	int frame_index;
	int nframes = pcstack_limit;
	cframe_t *frame = (cframe_t *)stackptr;

	for (frame_index = 0; frame_index < nframes; frame_index++) {
		vm_offset_t curframep = (vm_offset_t)frame;
		if (!curframep)
			break;
		if (curframep & 0x3) {
			break;
		}
#if 0
		if (!kvtophys(curframep) ||
		    !kvtophys(curframep + sizeof (cframe_t) - 1)) {
			break;
		}
#endif
		pcstack[depth++] = frame->caller;
		frame = frame->prev;
	}

	return (depth);
}

void
print_symbol(uintptr_t symbol)
{
	printf("SPL: ");
	panic_print_symbol_name((vm_address_t)(symbol));
	printf("\n");
}

int
ddi_copyin(const void *from, void *to, size_t len, int flags)
{
	int ret = 0;

	/* Fake ioctl() issued by kernel, 'from' is a kernel address */
	if (flags & FKIOCTL)
		memcpy(to, from, len);
	else
		ret = copyin((user_addr_t)from, (void *)to, len);

	return (ret);
}

int
ddi_copyout(const void *from, void *to, size_t len, int flags)
{
	int ret = 0;

	/* Fake ioctl() issued by kernel, 'from' is a kernel address */
	if (flags & FKIOCTL) {
		memcpy(to, from, len);
	} else {
		ret = copyout(from, (user_addr_t)to, len);
	}

	return (ret);
}

/*
 * Technically, this call does not exist in illumos, but we use it for
 * consistency.
 */
int
ddi_copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done)
{
	int ret;
	size_t local_done;

#undef copyinstr
	ret = copyinstr((user_addr_t)uaddr, kaddr, len, &local_done);
	if (done != NULL)
		*done = local_done;
	return (ret);
}

/*
 * If the kext can use IOMallocData(), return true.
 *
 * This will put ABD chunks into this kext's private wired memory which is
 * instrumented in "/usr/bin/zprint org.openzfsonosx.zfs", rather than in the
 * kernel's shared wired map, where memory backed by IOMallocAligned() is
 * found.  ABD chunks are by far the largest consumer of memory by this kext
 * so long as abd_scatter_enabled is true (default) and abd_scatter_min_size
 * is sensible (see module/os/macos/abd_os.c).
 *
 * The shared wired map *must* be used for data that will be exported from the
 * kext via a remapping, which is any memory we pass to IOKit objects, the
 * uio*() and UPL functions, and so forth. The private wired map is only
 * reliably safe when the data is (from our kext's persepective) a blob whose
 * contents don't depend on any memory address versus whether memory addresses
 * (pointers, mutexes, etc) might in the allocated data.  ABD chunks are
 * paradigmatic of "blob" data that is never shared, since chunk ABD are
 * copied into (shared-map) linear ABDs before "export" from our private map
 * (see e.g. the use of abd_borrow_buf_copy() and abd_borrow_buf() in
 * module/os/macos/zfs/vdev_disk.c*).
 *
 * Most allocations are backed by IOMallocAligned(), which allocates in the
 * shared wired map.  On small-memory machines we run the risk of being out of
 * memory, signalled by a NULL from IOMallocAligned().  While we can deal with
 * that, other kexts and kernel consumers can freak out leading to panics and
 * other unexpected behaviours.  Consequently, there are several mechanisms in
 * the kext to avoid using too much system memory.
 *
 * Small IOMallocData allocations (generally less than 32KiB) will go
 * to the kernel-global zones allocator, which is counterproductive for our
 * vmem and kmem allocators, as it adds unnecessary work by the zones
 * infrastructure, and because we have to be careful not to run any zone out
 * of memory.  Those are better backed by kmem+vmem+IOMallocAligned(), and
 * this is implemented in spl-seg_kmem.c
 *
 * The return value of spl_use_iomallocdata(), which much be invariant from
 * kext start time, influences the amount of memory the kext will try to use.
 * If B_FALSE, we should use less than 80% of 1/7 of the total physical system
 * memory. Even if there is ample wire-able space available, the constraint is
 * the size of the kernel shared map. Controlling the maximum ARC size is the
 * principal mechanism to respect this, so we can be a good neighbour to other
 * parts of the kernel and other kexts.
 *
 * If B_TRUE, then most kext data is in the kernel private map space, which
 * is a different ~ 1/7 of total system memory. In general we must assume that
 * it is shared with other kexts, but practically all consumers of this space
 * will wait for memory to become available, so we can let ABD chunks occupy a
 * large fraction this memory space. Controlling the size of the ABD chunk
 * arena then becomes the principal mechanism, however we do that within the
 * context of a ceiling on the ARC size.
 *
 * B_TRUE therefore allows for a larger ARC size (as ARC mainly holds
 * references to ABD chunks) while nearly eliminating risk of exhausting the
 * kernel shared map's VA map or its memory size.
 *
 */
boolean_t
spl_use_iomallocdata(void)
{
#ifdef SPL_HAVE_IOMALLOCDATA
	return (B_TRUE);
#else
	return (B_FALSE);
#endif
}

kern_return_t
spl_start(kmod_info_t *ki, void *d)
{
	printf("SPL: loading\n");

	int ncpus;
	size_t len = sizeof (ncpus);

	/*
	 * Boot load time is excessively early, so we have to wait
	 * until certain subsystems are available. Surely there is
	 * a more elegant way to do this wait?
	 */

	while (current_proc() == NULL) {
		printf("SPL: waiting for kernel init...\n");
		delay(hz>>1);
	}

	/*
	 * special purpose xnu-style locks, separate from the spl-mutex.c
	 * system, where those are available either late or may require
	 * memory or thread allocation
	 */
	spl_mtx_lck_attr  = lck_attr_alloc_init();
	spl_mtx_grp_attr = lck_grp_attr_alloc_init();
	spl_mtx_grp = lck_grp_alloc_init("spl-mutex", spl_mtx_grp_attr);

	while (1) {
		len = sizeof (spl_real_total_memory);
		sysctlbyname("hw.memsize", &spl_real_total_memory, &len,
		    NULL, 0);
		if (spl_real_total_memory != 0) break;

		printf("SPL: waiting for sysctl...\n");
		delay(hz>>1);
	}

	sysctlbyname("hw.logicalcpu_max", &max_ncpus, &len, NULL, 0);
	if (!max_ncpus) max_ncpus = 1;

#if defined(__arm64__)
	num_ecores = (max_ncpus > 4) ? 4 : 0;
	num_ecores += (max_ncpus > 16) ? 4 : 0;
	boot_ncpus = MAX(1, (int)max_ncpus - (int)num_ecores);
#else
	boot_ncpus = max_ncpus;
#endif

	/*
	 * set up kext's notions of RAM availability
	 */

	if (spl_use_iomallocdata()) {
		/*
		 * This is a modern macOS where we expect to have ABD chunks
		 * in the kext's private map, which is shared with other maps
		 */

		/*
		 * kernel private wired memory and kernel shared wire memory
		 * are each 2/7 of physical memory, but we want to be good
		 * neighbours and only use 1/7 of each
		 */
		spl_data_private_memory = spl_real_total_memory / 7;
		spl_data_shared_memory = spl_real_total_memory / 7;
	} else {
		spl_data_private_memory = 0;
		spl_data_shared_memory = spl_real_total_memory / 7;

		/*
		 * Small pre-macOS-15 Macs are constrained by physical RAM
		 * rather than the shared VA map space.  The kernel's memory
		 * pressure signals are sufficient to control for this case.
		 * Consequently, use more of the shared map than the half
		 * we otherwise take.
		 */

#define	SPL_SMALL_RAM	(16ULL * 1024ULL * 1024ULL * 1024ULL)

		if (spl_real_total_memory <= SPL_SMALL_RAM)
			spl_data_shared_memory =
			    spl_real_total_memory / 5; // instead of /7
	}

	spl_total_memory = (spl_data_shared_memory * 80ULL / 100ULL) +
	    spl_data_private_memory;

	physmem = spl_total_memory / PAGE_SIZE;

#if defined(__arm64__)

	/*
	 * Large Apple Silicon, such as full-of-RAM Mac Studios, typically
	 * will run out of kernel virtual address map space before running out
	 * of wireable memory.  Since there is plenty of wireable memory and
	 * other memory available, we will not see memory pressure signalled
	 * by the kernel.  If we keep allocating naively until we see pressure,
	 * we will reach the point at which we deprive other consumers of kernel
	 * memory allocations, triggering undesired behaviour like subsystem
	 * aborts or system panics.
	 *
	 * There are two VA maps of interest, each of which is sized to
	 * approximately 2/7 of physical RAM: the kernel shared map and the
	 * kext private map, which is a further 2/7 of physical RAM but
	 * shared among many consumers such as other kexts.
	 *
	 * We need to avoid using more than about half of each of these two
	 * maps in order to be good neighbours.
	 *
	 * Empirically, on a 512GiB M3 Mac Studio, we can safely use about
	 * 60 GiB of the shared memory map, while on a 128 GiB M1 Mac Studio,
	 * we can safely use about 26 GiB of the shared memory map.  These
	 * are not hard and fast data to clamp on, however, and a smaller
	 * ARC on a smaller-RAM machine is tolerable.
	 *
	 * Here is a dynamic memory cap set to spl_total_memory that
	 * will be used to avoid growing our memory consumption above that
	 * threshold.   For the moment it only controls the total memory use,
	 * rather than specifically the shared memory map.  In future, there
	 * should be a cap for each of these two memory maps on systems with
	 * IOMallocData().
	 *
	 * The initial setting for the dynamic memory cap is presently
	 * strictly tautologous, but attracts the eyeballs.  Presently it can
	 * be set to this point and smaller by an administrator using sysctl,
	 * and the value is subject to automatic deflation.
	 */

	extern _Atomic uint64_t spl_dynamic_memory_cap;

	if (spl_real_total_memory >= 64LL*1024LL*1024LL*1024LL)
		spl_dynamic_memory_cap = spl_total_memory;

#endif

	len = sizeof (utsname_static.sysname);
	sysctlbyname("kern.ostype", &utsname_static.sysname, &len, NULL, 0);

	/*
	 * For some reason, (CTLFLAG_KERN is not set) looking up hostname
	 * returns 1. So we set it to uuid just to give it *something*.
	 * As it happens, ZFS sets the nodename on init.
	 */
	len = sizeof (utsname_static.nodename);
	sysctlbyname("kern.uuid", &utsname_static.nodename, &len, NULL, 0);

	len = sizeof (utsname_static.release);
	sysctlbyname("kern.osrelease", &utsname_static.release, &len, NULL, 0);

	len = sizeof (utsname_static.version);
	sysctlbyname("kern.version", &utsname_static.version, &len, NULL, 0);

	strlcpy(spl_hostname, "noname", sizeof (spl_hostname));
	// Private.exports
	// bsd_hostname(spl_hostname, sizeof (spl_hostname), &len);

	strlcpy(utsname_static.nodename, spl_hostname,
	    sizeof (utsname_static.nodename));

	spl_mutex_subsystem_init();
	spl_kmem_init(spl_total_memory);
	spl_vnode_init();
	spl_kmem_thread_init();
	spl_kmem_mp_init();

	spl_processor_init();

	return (KERN_SUCCESS);
}

kern_return_t
spl_stop(kmod_info_t *ki, void *d)
{
	spl_kmem_thread_fini();
	spl_vnode_fini();
	spl_taskq_fini();
	spl_rwlock_fini();
	spl_tsd_fini();
	spl_kmem_fini();
	spl_kstat_fini();
	spl_mutex_subsystem_fini();

	lck_attr_free(spl_mtx_lck_attr);
	spl_mtx_lck_attr = NULL;
	lck_grp_attr_free(spl_mtx_grp_attr);
	spl_mtx_grp_attr = NULL;
	lck_grp_free(spl_mtx_grp);
	spl_mtx_grp = NULL;

	return (KERN_SUCCESS);
}
