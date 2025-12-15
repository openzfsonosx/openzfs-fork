/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
#ifndef _SPL_DISP_H
#define	_SPL_DISP_H

#define	KPREEMPT_SYNC		(-1)

#define	kpreempt(unused)	(void) thread_block(THREAD_CONTINUE_NULL)

/*
 * XNU doesn't export _disable_preemption() or _enable_preemption() so we use
 * ml_set_interrupts_enabled() instead.
 */
extern boolean_t ml_set_interrupts_enabled(boolean_t);

#define	kpreempt_disable()	ml_set_interrupts_enabled(false)
#define	kpreempt_enable()	ml_set_interrupts_enabled(true)

#endif
