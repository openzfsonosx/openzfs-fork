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
 * Read the CPU topology from IODeviceTree:/cpus for getcpuid().
 *
 * Each child of /cpus is one CPU, carrying (as native-endian data):
 *   "reg"          MPIDR_EL1 Aff1:Aff0 -- what xnu matches against
 *                  MPIDR & 0xFFFF to find a CPU's cpu_data
 *   "cpu-id"       the logical CPU number xnu uses
 *   "cluster-type" 'E', 'M' or 'P'
 *
 * The C side (spl-processor.c) owns the table; we just enumerate.
 */

#include <IOKit/IORegistryEntry.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSIterator.h>
#include <string.h>

extern "C" {
int spl_cpuid_dt_walk(void);
#if defined(__aarch64__)
int spl_cpuid_dt_add(uint32_t reg, uint32_t cpu_id, char cluster_type);
#endif
}

#if defined(__aarch64__)
static bool
spl_dt_number(IORegistryEntry *e, const char *key, uint64_t *out)
{
	OSData *d = OSDynamicCast(OSData, e->getProperty(key));

	if (d == NULL)
		return (false);

	unsigned int len = d->getLength();
	if (len != sizeof (uint32_t) && len != sizeof (uint64_t))
		return (false);

	uint64_t v = 0;	/* little-endian: a 4-byte cell lands in the low half */
	memcpy(&v, d->getBytesNoCopy(), len);
	*out = v;
	return (true);
}
#endif

/*
 * Returns the number of CPUs recorded, or a negative value if the
 * device tree could not be read or was inconsistent.
 */
int
spl_cpuid_dt_walk(void)
{
#if defined(__aarch64__)
	IORegistryEntry *cpus = IORegistryEntry::fromPath("/cpus",
	    gIODTPlane);

	if (cpus == NULL)
		return (-1);

	OSIterator *it = cpus->getChildIterator(gIODTPlane);
	if (it == NULL) {
		cpus->release();
		return (-2);
	}

	int recorded = 0, bad = 0;
	OSObject *obj;

	while ((obj = it->getNextObject()) != NULL) {
		IORegistryEntry *cpu = OSDynamicCast(IORegistryEntry, obj);
		uint64_t reg, cpu_id;
		char type = 0;

		if (cpu == NULL)
			continue;
		if (!spl_dt_number(cpu, "reg", &reg) ||
		    !spl_dt_number(cpu, "cpu-id", &cpu_id)) {
			bad++;
			continue;
		}

		OSData *t = OSDynamicCast(OSData,
		    cpu->getProperty("cluster-type"));
		if (t != NULL && t->getLength() > 0)
			type = *(const char *)t->getBytesNoCopy();

		switch (spl_cpuid_dt_add((uint32_t)reg, (uint32_t)cpu_id,
		    type)) {
		case 0:
			recorded++;
			break;
		case 1:
			break;		/* beyond max_ncpus: not running */
		default:
			bad++;
			break;
		}
	}

	it->release();
	cpus->release();

	return (bad != 0 ? -3 : recorded);
#else
	return (-1);
#endif
}
