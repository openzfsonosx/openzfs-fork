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

#ifndef _SIMD_AARCH64_H
#define	_SIMD_AARCH64_H

#include <sys/isa_defs.h>

#define	kfpu_init()		(0)
#define	kfpu_fini()		do {} while (0)

#define	kfpu_begin()  ((void)0)
#define	kfpu_end()    ((void)0)
#define	kfpu_allowed()		1


#if defined(__aarch64__)

#include <sys/types.h>

#if defined(_KERNEL)

extern uint64_t spl_cpuid_id_aa64isar0_el1(void);
extern uint64_t spl_cpuid_id_aa64isar1_el1(void);

#endif
#endif
#endif /* _SIMD_AARCH64_H */
