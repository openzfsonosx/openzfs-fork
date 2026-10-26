// SPDX-License-Identifier: OpenSSL-standalone AND Apache-2.0
/*
 * ====================================================================
 * Copyright (c) 1998-2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#define _ASM
#include <sys/asm_linkage.h>

#if defined(__aarch64__)

.arch	armv8-a+crypto

/*
 *
 * OpenSSL interface:
 * 2025/06/01 lundman Add to macOS
 *
 *
 */

// #define	AARCH64_VALID_CALL_TARGET hint	#34
#define AARCH64_VALID_JUMP_CALL_TARGET bti jc
#define AARCH64_VALID_CALL_TARGET      bti c
#define AARCH64_VALID_JUMP_TARGET      bti j


ENTRY_ALIGN(gcm_init_v8, 16)
	AARCH64_VALID_CALL_TARGET
	ld1	{v17.2d},[x1]		//load input H
	movi	v19.16b,#0xe1
	shl	v19.2d,v19.2d,#57		//0xc2.0
	ext	v3.16b,v17.16b,v17.16b,#8
	ushr	v18.2d,v19.2d,#63
	dup	v17.4s,v17.s[1]
	ext	v16.16b,v18.16b,v19.16b,#8		//t0=0xc2....01
	ushr	v18.2d,v3.2d,#63
	sshr	v17.4s,v17.4s,#31		//broadcast carry bit
	and	v18.16b,v18.16b,v16.16b
	shl	v3.2d,v3.2d,#1
	ext	v18.16b,v18.16b,v18.16b,#8
	and	v16.16b,v16.16b,v17.16b
	orr	v3.16b,v3.16b,v18.16b		//H<<<=1
	eor	v20.16b,v3.16b,v16.16b		//twisted H
	st1	{v20.2d},[x0],#16		//store Htable[0]

	//calculate H^2
	ext	v16.16b,v20.16b,v20.16b,#8		//Karatsuba pre-processing
	pmull	v0.1q,v20.1d,v20.1d
	eor	v16.16b,v16.16b,v20.16b
	pmull2	v2.1q,v20.2d,v20.2d
	pmull	v1.1q,v16.1d,v16.1d

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
	pmull	v18.1q,v0.1d,v19.1d		//1st phase

	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase
	pmull	v0.1q,v0.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v22.16b,v0.16b,v18.16b

	ext	v17.16b,v22.16b,v22.16b,#8		//Karatsuba pre-processing
	eor	v17.16b,v17.16b,v22.16b
	ext	v21.16b,v16.16b,v17.16b,#8		//pack Karatsuba pre-processed
	st1	{v21.2d,v22.2d},[x0],#32	//store Htable[1..2]
	//calculate H^3 and H^4
	pmull	v0.1q,v20.1d, v22.1d
	pmull	v5.1q,v22.1d,v22.1d
	pmull2	v2.1q,v20.2d, v22.2d
	pmull2	v7.1q,v22.2d,v22.2d
	pmull	v1.1q,v16.1d,v17.1d
	pmull	v6.1q,v17.1d,v17.1d

	ext	v16.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	ext	v17.16b,v5.16b,v7.16b,#8
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v16.16b
	eor	v4.16b,v5.16b,v7.16b
	eor	v6.16b,v6.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
	pmull	v18.1q,v0.1d,v19.1d		//1st phase
	eor	v6.16b,v6.16b,v4.16b
	pmull	v4.1q,v5.1d,v19.1d

	ins	v2.d[0],v1.d[1]
	ins	v7.d[0],v6.d[1]
	ins	v1.d[1],v0.d[0]
	ins	v6.d[1],v5.d[0]
	eor	v0.16b,v1.16b,v18.16b
	eor	v5.16b,v6.16b,v4.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase
	ext	v4.16b,v5.16b,v5.16b,#8
	pmull	v0.1q,v0.1d,v19.1d
	pmull	v5.1q,v5.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v4.16b,v4.16b,v7.16b
	eor	v23.16b, v0.16b,v18.16b		//H^3
	eor	v25.16b,v5.16b,v4.16b		//H^4

	ext	v16.16b,v23.16b, v23.16b,#8		//Karatsuba pre-processing
	ext	v17.16b,v25.16b,v25.16b,#8
	ext	v18.16b,v22.16b,v22.16b,#8
	eor	v16.16b,v16.16b,v23.16b
	eor	v17.16b,v17.16b,v25.16b
	eor	v18.16b,v18.16b,v22.16b
	ext	v24.16b,v16.16b,v17.16b,#8		//pack Karatsuba pre-processed
	st1	{v23.2d,v24.2d,v25.2d},[x0],#48		//store Htable[3..5]

	//calculate H^5 and H^6
	pmull	v0.1q,v22.1d, v23.1d
	pmull	v5.1q,v23.1d,v23.1d
	pmull2	v2.1q,v22.2d, v23.2d
	pmull2	v7.1q,v23.2d,v23.2d
	pmull	v1.1q,v16.1d,v18.1d
	pmull	v6.1q,v16.1d,v16.1d

	ext	v16.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	ext	v17.16b,v5.16b,v7.16b,#8
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v16.16b
	eor	v4.16b,v5.16b,v7.16b
	eor	v6.16b,v6.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
	pmull	v18.1q,v0.1d,v19.1d		//1st phase
	eor	v6.16b,v6.16b,v4.16b
	pmull	v4.1q,v5.1d,v19.1d

	ins	v2.d[0],v1.d[1]
	ins	v7.d[0],v6.d[1]
	ins	v1.d[1],v0.d[0]
	ins	v6.d[1],v5.d[0]
	eor	v0.16b,v1.16b,v18.16b
	eor	v5.16b,v6.16b,v4.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase
	ext	v4.16b,v5.16b,v5.16b,#8
	pmull	v0.1q,v0.1d,v19.1d
	pmull	v5.1q,v5.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v4.16b,v4.16b,v7.16b
	eor	v26.16b,v0.16b,v18.16b		//H^5
	eor	v28.16b,v5.16b,v4.16b		//H^6

	ext	v16.16b,v26.16b, v26.16b,#8		//Karatsuba pre-processing
	ext	v17.16b,v28.16b,v28.16b,#8
	ext	v18.16b,v22.16b,v22.16b,#8
	eor	v16.16b,v16.16b,v26.16b
	eor	v17.16b,v17.16b,v28.16b
	eor	v18.16b,v18.16b,v22.16b
	ext	v27.16b,v16.16b,v17.16b,#8		//pack Karatsuba pre-processed
	st1	{v26.2d,v27.2d,v28.2d},[x0],#48		//store Htable[6..8]

	//calculate H^7 and H^8
	pmull	v0.1q,v22.1d,v26.1d
	pmull	v5.1q,v22.1d,v28.1d
	pmull2	v2.1q,v22.2d,v26.2d
	pmull2	v7.1q,v22.2d,v28.2d
	pmull	v1.1q,v16.1d,v18.1d
	pmull	v6.1q,v17.1d,v18.1d

	ext	v16.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	ext	v17.16b,v5.16b,v7.16b,#8
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v16.16b
	eor	v4.16b,v5.16b,v7.16b
	eor	v6.16b,v6.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
	pmull	v18.1q,v0.1d,v19.1d		//1st phase
	eor	v6.16b,v6.16b,v4.16b
	pmull	v4.1q,v5.1d,v19.1d

	ins	v2.d[0],v1.d[1]
	ins	v7.d[0],v6.d[1]
	ins	v1.d[1],v0.d[0]
	ins	v6.d[1],v5.d[0]
	eor	v0.16b,v1.16b,v18.16b
	eor	v5.16b,v6.16b,v4.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase
	ext	v4.16b,v5.16b,v5.16b,#8
	pmull	v0.1q,v0.1d,v19.1d
	pmull	v5.1q,v5.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v4.16b,v4.16b,v7.16b
	eor	v29.16b,v0.16b,v18.16b		//H^7
	eor	v31.16b,v5.16b,v4.16b		//H^8

	ext	v16.16b,v29.16b,v29.16b,#8		//Karatsuba pre-processing
	ext	v17.16b,v31.16b,v31.16b,#8
	eor	v16.16b,v16.16b,v29.16b
	eor	v17.16b,v17.16b,v31.16b
	ext	v30.16b,v16.16b,v17.16b,#8		//pack Karatsuba pre-processed
	st1	{v29.2d,v30.2d,v31.2d},[x0]		//store Htable[9..11]
	ret
SET_SIZE(gcm_init_v8)

// This call is currently not used, since we use ghash call instead.
ENTRY_ALIGN(gcm_gmult_v8, 16)
	AARCH64_VALID_CALL_TARGET
	ld1	{v17.2d},[x0]		//load Xi
	movi	v19.16b,#0xe1
	ld1	{v20.2d,v21.2d},[x1]	//load twisted H, ...
	shl	v19.2d,v19.2d,#57
#ifndef __AARCH64EB__
	rev64	v17.16b,v17.16b
#endif
	ext	v3.16b,v17.16b,v17.16b,#8

	pmull	v0.1q,v20.1d,v3.1d		//H.lo·Xi.lo
	eor	v17.16b,v17.16b,v3.16b		//Karatsuba pre-processing
	pmull2	v2.1q,v20.2d,v3.2d		//H.hi·Xi.hi
	pmull	v1.1q,v21.1d,v17.1d		//(H.lo+H.hi)·(Xi.lo+Xi.hi)

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
	pmull	v18.1q,v0.1d,v19.1d		//1st phase of reduction

	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
	pmull	v0.1q,v0.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b

#ifndef __AARCH64EB__
	rev64	v0.16b,v0.16b
#endif
	ext	v0.16b,v0.16b,v0.16b,#8
	st1	{v0.2d},[x0]		//write out Xi

	ret
SET_SIZE(gcm_gmult_v8)


ENTRY_ALIGN(gcm_ghash_v8, 16)
	AARCH64_VALID_CALL_TARGET
	cmp	x3,#64
	b.hs	Lgcm_ghash_v8_4x
	ld1	{v0.2d},[x0]		//load [rotated] Xi
						//"[rotated]" means that
						//loaded value would have
						//to be rotated in order to
						//make it appear as in
						//algorithm specification
	subs	x3,x3,#32		//see if x3 is 32 or larger
	mov	x12,#16		//x12 is used as post-
						//increment for input pointer;
						//as loop is modulo-scheduled
						//x12 is zeroed just in time
						//to preclude overstepping
						//inp[len], which means that
						//last block[s] are actually
						//loaded twice, but last
						//copy is not processed
	ld1	{v20.2d,v21.2d},[x1],#32	//load twisted H, ..., H^2
	movi	v19.16b,#0xe1
	ld1	{v22.2d},[x1]
	csel	x12,xzr,x12,eq			//is it time to zero x12?
	ext	v0.16b,v0.16b,v0.16b,#8		//rotate Xi
	ld1	{v16.2d},[x2],#16	//load [rotated] I[0]
	shl	v19.2d,v19.2d,#57		//compose 0xc2.0 constant
#ifndef __AARCH64EB__
	rev64	v16.16b,v16.16b
	rev64	v0.16b,v0.16b
#endif
	ext	v3.16b,v16.16b,v16.16b,#8		//rotate I[0]
	b.lo	Lodd_tail_v8		//x3 was less than 32
	ld1	{v17.2d},[x2],x12	//load [rotated] I[1]
#ifndef __AARCH64EB__
	rev64	v17.16b,v17.16b
#endif
	ext	v7.16b,v17.16b,v17.16b,#8
	eor	v3.16b,v3.16b,v0.16b		//I[i]^=Xi
	pmull	v4.1q,v20.1d,v7.1d		//H·Ii+1
	eor	v17.16b,v17.16b,v7.16b		//Karatsuba pre-processing
	pmull2	v6.1q,v20.2d,v7.2d
	b	Loop_mod2x_v8

.align	4
Loop_mod2x_v8:
	ext	v18.16b,v3.16b,v3.16b,#8
	subs	x3,x3,#32		//is there more data?
	pmull	v0.1q,v22.1d,v3.1d		//H^2.lo·Xi.lo
	csel	x12,xzr,x12,lo			//is it time to zero x12?

	pmull	v5.1q,v21.1d,v17.1d
	eor	v18.16b,v18.16b,v3.16b		//Karatsuba pre-processing
	pmull2	v2.1q,v22.2d,v3.2d		//H^2.hi·Xi.hi
	eor	v0.16b,v0.16b,v4.16b		//accumulate
	pmull2	v1.1q,v21.2d,v18.2d		//(H^2.lo+H^2.hi)·(Xi.lo+Xi.hi)
	ld1	{v16.2d},[x2],x12	//load [rotated] I[i+2]

	eor	v2.16b,v2.16b,v6.16b
	csel	x12,xzr,x12,eq			//is it time to zero x12?
	eor	v1.16b,v1.16b,v5.16b

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	ld1	{v17.2d},[x2],x12	//load [rotated] I[i+3]
#ifndef __AARCH64EB__
	rev64	v16.16b,v16.16b
#endif
	eor	v1.16b,v1.16b,v18.16b
	pmull	v18.1q,v0.1d,v19.1d		//1st phase of reduction

#ifndef __AARCH64EB__
	rev64	v17.16b,v17.16b
#endif
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	ext	v7.16b,v17.16b,v17.16b,#8
	ext	v3.16b,v16.16b,v16.16b,#8
	eor	v0.16b,v1.16b,v18.16b
	pmull	v4.1q,v20.1d,v7.1d		//H·Ii+1
	eor	v3.16b,v3.16b,v2.16b		//accumulate v3.16b early

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
	pmull	v0.1q,v0.1d,v19.1d
	eor	v3.16b,v3.16b,v18.16b
	eor	v17.16b,v17.16b,v7.16b		//Karatsuba pre-processing
	eor	v3.16b,v3.16b,v0.16b
	pmull2	v6.1q,v20.2d,v7.2d
	b.hs	Loop_mod2x_v8		//there was at least 32 more bytes

	eor	v2.16b,v2.16b,v18.16b
	ext	v3.16b,v16.16b,v16.16b,#8		//re-construct v3.16b
	adds	x3,x3,#32		//re-construct x3
	eor	v0.16b,v0.16b,v2.16b		//re-construct v0.16b
	b.eq	Ldone_v8		//is x3 zero?
Lodd_tail_v8:
	ext	v18.16b,v0.16b,v0.16b,#8
	eor	v3.16b,v3.16b,v0.16b		//inp^=Xi
	eor	v17.16b,v16.16b,v18.16b		//v17.16b is rotated inp^Xi

	pmull	v0.1q,v20.1d,v3.1d		//H.lo·Xi.lo
	eor	v17.16b,v17.16b,v3.16b		//Karatsuba pre-processing
	pmull2	v2.1q,v20.2d,v3.2d		//H.hi·Xi.hi
	pmull	v1.1q,v21.1d,v17.1d		//(H.lo+H.hi)·(Xi.lo+Xi.hi)

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
	pmull	v18.1q,v0.1d,v19.1d		//1st phase of reduction

	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
	pmull	v0.1q,v0.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b

Ldone_v8:
#ifndef __AARCH64EB__
	rev64	v0.16b,v0.16b
#endif
	ext	v0.16b,v0.16b,v0.16b,#8
	st1	{v0.2d},[x0]		//write out Xi

	ret
SET_SIZE(gcm_ghash_v8)

ENTRY_ALIGN(gcm_ghash_v8_4x, 16)
Lgcm_ghash_v8_4x:
	ld1	{v0.2d},[x0]		//load [rotated] Xi
	ld1	{v20.2d,v21.2d,v22.2d},[x1],#48	//load twisted H, ..., H^2
	movi	v19.16b,#0xe1
	ld1	{v26.2d,v27.2d,v28.2d},[x1]	//load twisted H^3, ..., H^4
	shl	v19.2d,v19.2d,#57		//compose 0xc2.0 constant

	ld1	{v4.2d,v5.2d,v6.2d,v7.2d},[x2],#64
#ifndef __AARCH64EB__
	rev64	v0.16b,v0.16b
	rev64	v5.16b,v5.16b
	rev64	v6.16b,v6.16b
	rev64	v7.16b,v7.16b
	rev64	v4.16b,v4.16b
#endif
	ext	v25.16b,v7.16b,v7.16b,#8
	ext	v24.16b,v6.16b,v6.16b,#8
	ext	v23.16b,v5.16b,v5.16b,#8

	pmull	v29.1q,v20.1d,v25.1d		//H·Ii+3
	eor	v7.16b,v7.16b,v25.16b
	pmull2	v31.1q,v20.2d,v25.2d
	pmull	v30.1q,v21.1d,v7.1d

	pmull	v16.1q,v22.1d,v24.1d		//H^2·Ii+2
	eor	v6.16b,v6.16b,v24.16b
	pmull2	v24.1q,v22.2d,v24.2d
	pmull2	v6.1q,v21.2d,v6.2d

	eor	v29.16b,v29.16b,v16.16b
	eor	v31.16b,v31.16b,v24.16b
	eor	v30.16b,v30.16b,v6.16b

	pmull	v7.1q,v26.1d,v23.1d		//H^3·Ii+1
	eor	v5.16b,v5.16b,v23.16b
	pmull2	v23.1q,v26.2d,v23.2d
	pmull	v5.1q,v27.1d,v5.1d

	eor	v29.16b,v29.16b,v7.16b
	eor	v31.16b,v31.16b,v23.16b
	eor	v30.16b,v30.16b,v5.16b

	subs	x3,x3,#128
	b.lo	Ltail4x

	b	Loop4x

.align	4
Loop4x:
	eor	v16.16b,v4.16b,v0.16b
	ld1	{v4.2d,v5.2d,v6.2d,v7.2d},[x2],#64
	ext	v3.16b,v16.16b,v16.16b,#8
#ifndef __AARCH64EB__
	rev64	v5.16b,v5.16b
	rev64	v6.16b,v6.16b
	rev64	v7.16b,v7.16b
	rev64	v4.16b,v4.16b
#endif

	pmull	v0.1q,v28.1d,v3.1d		//H^4·(Xi+Ii)
	eor	v16.16b,v16.16b,v3.16b
	pmull2	v2.1q,v28.2d,v3.2d
	ext	v25.16b,v7.16b,v7.16b,#8
	pmull2	v1.1q,v27.2d,v16.2d

	eor	v0.16b,v0.16b,v29.16b
	eor	v2.16b,v2.16b,v31.16b
	ext	v24.16b,v6.16b,v6.16b,#8
	eor	v1.16b,v1.16b,v30.16b
	ext	v23.16b,v5.16b,v5.16b,#8

	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	pmull	v29.1q,v20.1d,v25.1d		//H·Ii+3
	eor	v7.16b,v7.16b,v25.16b
	eor	v1.16b,v1.16b,v17.16b
	pmull2	v31.1q,v20.2d,v25.2d
	eor	v1.16b,v1.16b,v18.16b
	pmull	v30.1q,v21.1d,v7.1d

	pmull	v18.1q,v0.1d,v19.1d		//1st phase of reduction
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	pmull	v16.1q,v22.1d,v24.1d		//H^2·Ii+2
	eor	v6.16b,v6.16b,v24.16b
	pmull2	v24.1q,v22.2d,v24.2d
	eor	v0.16b,v1.16b,v18.16b
	pmull2	v6.1q,v21.2d,v6.2d

	eor	v29.16b,v29.16b,v16.16b
	eor	v31.16b,v31.16b,v24.16b
	eor	v30.16b,v30.16b,v6.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
	pmull	v0.1q,v0.1d,v19.1d
	pmull	v7.1q,v26.1d,v23.1d		//H^3·Ii+1
	eor	v5.16b,v5.16b,v23.16b
	eor	v18.16b,v18.16b,v2.16b
	pmull2	v23.1q,v26.2d,v23.2d
	pmull	v5.1q,v27.1d,v5.1d

	eor	v0.16b,v0.16b,v18.16b
	eor	v29.16b,v29.16b,v7.16b
	eor	v31.16b,v31.16b,v23.16b
	ext	v0.16b,v0.16b,v0.16b,#8
	eor	v30.16b,v30.16b,v5.16b

	subs	x3,x3,#64
	b.hs	Loop4x

Ltail4x:
	eor	v16.16b,v4.16b,v0.16b
	ext	v3.16b,v16.16b,v16.16b,#8

	pmull	v0.1q,v28.1d,v3.1d		//H^4·(Xi+Ii)
	eor	v16.16b,v16.16b,v3.16b
	pmull2	v2.1q,v28.2d,v3.2d
	pmull2	v1.1q,v27.2d,v16.2d

	eor	v0.16b,v0.16b,v29.16b
	eor	v2.16b,v2.16b,v31.16b
	eor	v1.16b,v1.16b,v30.16b

	adds	x3,x3,#64
	b.eq	Ldone4x

	cmp	x3,#32
	b.lo	Lone
	b.eq	Ltwo
Lthree:
	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	ld1	{v4.2d,v5.2d,v6.2d},[x2]
	eor	v1.16b,v1.16b,v18.16b
#ifndef	__AARCH64EB__
	rev64	v5.16b,v5.16b
	rev64	v6.16b,v6.16b
	rev64	v4.16b,v4.16b
#endif

	pmull	v18.1q,v0.1d,v19.1d		//1st phase of reduction
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	ext	v24.16b,v6.16b,v6.16b,#8
	ext	v23.16b,v5.16b,v5.16b,#8
	eor	v0.16b,v1.16b,v18.16b

	pmull	v29.1q,v20.1d,v24.1d		//H·Ii+2
	eor	v6.16b,v6.16b,v24.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
	pmull	v0.1q,v0.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	pmull2	v31.1q,v20.2d,v24.2d
	pmull	v30.1q,v21.1d,v6.1d
	eor	v0.16b,v0.16b,v18.16b
	pmull	v7.1q,v22.1d,v23.1d		//H^2·Ii+1
	eor	v5.16b,v5.16b,v23.16b
	ext	v0.16b,v0.16b,v0.16b,#8

	pmull2	v23.1q,v22.2d,v23.2d
	eor	v16.16b,v4.16b,v0.16b
	pmull2	v5.1q,v21.2d,v5.2d
	ext	v3.16b,v16.16b,v16.16b,#8

	eor	v29.16b,v29.16b,v7.16b
	eor	v31.16b,v31.16b,v23.16b
	eor	v30.16b,v30.16b,v5.16b

	pmull	v0.1q,v26.1d,v3.1d		//H^3·(Xi+Ii)
	eor	v16.16b,v16.16b,v3.16b
	pmull2	v2.1q,v26.2d,v3.2d
	pmull	v1.1q,v27.1d,v16.1d

	eor	v0.16b,v0.16b,v29.16b
	eor	v2.16b,v2.16b,v31.16b
	eor	v1.16b,v1.16b,v30.16b
	b	Ldone4x

.align	4
Ltwo:
	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	ld1	{v4.2d,v5.2d},[x2]
	eor	v1.16b,v1.16b,v18.16b
#ifndef	__AARCH64EB__
	rev64	v5.16b,v5.16b
	rev64	v4.16b,v4.16b
#endif

	pmull	v18.1q,v0.1d,v19.1d		//1st phase of reduction
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	ext	v23.16b,v5.16b,v5.16b,#8
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
	pmull	v0.1q,v0.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b
	ext	v0.16b,v0.16b,v0.16b,#8

	pmull	v29.1q,v20.1d,v23.1d		//H·Ii+1
	eor	v5.16b,v5.16b,v23.16b

	eor	v16.16b,v4.16b,v0.16b
	ext	v3.16b,v16.16b,v16.16b,#8

	pmull2	v31.1q,v20.2d,v23.2d
	pmull	v30.1q,v21.1d,v5.1d

	pmull	v0.1q,v22.1d,v3.1d		//H^2·(Xi+Ii)
	eor	v16.16b,v16.16b,v3.16b
	pmull2	v2.1q,v22.2d,v3.2d
	pmull2	v1.1q,v21.2d,v16.2d

	eor	v0.16b,v0.16b,v29.16b
	eor	v2.16b,v2.16b,v31.16b
	eor	v1.16b,v1.16b,v30.16b
	b	Ldone4x

.align	4
Lone:
	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	ld1	{v4.2d},[x2]
	eor	v1.16b,v1.16b,v18.16b
#ifndef	__AARCH64EB__
	rev64	v4.16b,v4.16b
#endif

	pmull	v18.1q,v0.1d,v19.1d		//1st phase of reduction
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
	pmull	v0.1q,v0.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b
	ext	v0.16b,v0.16b,v0.16b,#8

	eor	v16.16b,v4.16b,v0.16b
	ext	v3.16b,v16.16b,v16.16b,#8

	pmull	v0.1q,v20.1d,v3.1d
	eor	v16.16b,v16.16b,v3.16b
	pmull2	v2.1q,v20.2d,v3.2d
	pmull	v1.1q,v21.1d,v16.1d

Ldone4x:
	ext	v17.16b,v0.16b,v2.16b,#8		//Karatsuba post-processing
	eor	v18.16b,v0.16b,v2.16b
	eor	v1.16b,v1.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b

	pmull	v18.1q,v0.1d,v19.1d		//1st phase of reduction
	ins	v2.d[0],v1.d[1]
	ins	v1.d[1],v0.d[0]
	eor	v0.16b,v1.16b,v18.16b

	ext	v18.16b,v0.16b,v0.16b,#8		//2nd phase of reduction
	pmull	v0.1q,v0.1d,v19.1d
	eor	v18.16b,v18.16b,v2.16b
	eor	v0.16b,v0.16b,v18.16b
	ext	v0.16b,v0.16b,v0.16b,#8

#ifndef __AARCH64EB__
	rev64	v0.16b,v0.16b
#endif
	st1	{v0.2d},[x0]		//write out Xi

	ret
SET_SIZE(gcm_ghash_v8_4x)

#if defined(__APPLE__)
.arch_extension sha3

/*
 * Apple M1-M5 AES-128-GCM fused kernels derived from OpenSSL 3.6.3's
 * aes-gcm-armv8-unroll8_64 implementation.
 *
 * Interface: (input, bit_length, output, Xi_with_inline_Htable, counter,
 * key_schedule).  Xi is followed by 16 reserved bytes and the 256-byte
 * gcm_init_v8 table.  The counter is updated in place.
 *
 * Copyright 2020-2023 The OpenSSL Project Authors. All Rights Reserved.
 * Written by Xiaokang Qian for OpenSSL, derived from AArch64cryptolib
 * by Samuel Lee. The OpenSSL version used here is Apache-2.0 licensed.
 * See THIRDPARTYLICENSE.openssl and THIRDPARTYLICENSE.openssl.descrip.
 */
ENTRY_ALIGN(aes_gcm_enc_128_eor3_zfs, 16)
	AARCH64_VALID_CALL_TARGET
	cbz	x1, Lgcm_enc_ret
	stp	d8, d9, [sp, #-80]!
	lsr	x9, x1, #3
	mov	x16, x4
	mov	x8, x5
	stp	d10, d11, [sp, #16]
	stp	d12, d13, [sp, #32]
	stp	d14, d15, [sp, #48]
	mov	x5, #0xc200000000000000
	stp	x5, xzr, [sp, #64]
	add	x10, sp, #64

	mov	x15, #0x100000000	// set up counter increment
	movi	v31.16b, #0x0
	mov	v31.d[1], x15
	mov	x5, x9
	ld1	{ v0.16b}, [x16]	// CTR block 0

	sub	x5, x5, #1	// byte_len - 1

	// number of bytes to be processed in main loop (at least 1 byte must be
	// handled by tail)
	and	x5, x5, #0xffffffffffffff80

	rev32	v30.16b, v0.16b	// set up reversed counter

	add	v30.4s, v30.4s, v31.4s	// CTR block 0

	rev32	v1.16b, v30.16b	// CTR block 1
	add	v30.4s, v30.4s, v31.4s	// CTR block 1

	rev32	v2.16b, v30.16b	// CTR block 2
	add	v30.4s, v30.4s, v31.4s	// CTR block 2

	rev32	v3.16b, v30.16b	// CTR block 3
	add	v30.4s, v30.4s, v31.4s	// CTR block 3

	rev32	v4.16b, v30.16b	// CTR block 4
	add	v30.4s, v30.4s, v31.4s	// CTR block 4

	rev32	v5.16b, v30.16b	// CTR block 5
	add	v30.4s, v30.4s, v31.4s	// CTR block 5
	ldp	q26, q27, [x8, #0]	// load rk0, rk1

	rev32	v6.16b, v30.16b	// CTR block 6
	add	v30.4s, v30.4s, v31.4s	// CTR block 6

	rev32	v7.16b, v30.16b	// CTR block 7
	add	v30.4s, v30.4s, v31.4s	// CTR block 7

	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 0
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 0
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 0

	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 0
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 0
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 0

	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 0
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 0
	ldp	q28, q26, [x8, #32]	// load rk2, rk3

	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 1

	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 1
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 1
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 1

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 1
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 1
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 1

	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 2
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 1
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 2

	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 2
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 2
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 2

	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 2
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 2
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 2

	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 3

	ldp	q27, q28, [x8, #64]	// load rk4, rk5
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 3
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 3

	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 3
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 3
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 3

	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 3

	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 4
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 3
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 4

	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 4
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 4
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 4

	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 4
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 4
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 4

	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 5
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 5
	ldp	q26, q27, [x8, #96]	// load rk6, rk7

	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 5
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 5
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 5

	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 5
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 5
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 5

	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 6
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 6
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 6

	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 6
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 6
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 6

	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 6
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 6
	ldp	q28, q26, [x8, #128]	// load rk8, rk9

	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 7

	ld1	{ v19.16b}, [x3]
	ext	v19.16b, v19.16b, v19.16b, #8
	rev64	v19.16b, v19.16b

	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 7

	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 7
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 7
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 7

	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 7
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 7
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 7

	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 8
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 8
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 8

	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 8
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 8
	ldr	q27, [x8, #160]	// load rk10

	aese	v3.16b, v26.16b	// AES block 8k+11 - round 9
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 8
	aese	v2.16b, v26.16b	// AES block 8k+10 - round 9

	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 8
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 8
	aese	v6.16b, v26.16b	// AES block 8k+14 - round 9

	aese	v4.16b, v26.16b	// AES block 8k+12 - round 9
	add	x5, x5, x0
	aese	v0.16b, v26.16b	// AES block 8k+8 - round 9

	aese	v7.16b, v26.16b	// AES block 8k+15 - round 9
	aese	v5.16b, v26.16b	// AES block 8k+13 - round 9
	aese	v1.16b, v26.16b	// AES block 8k+9 - round 9

	add	x4, x0, x1, lsr #3	// end_input_ptr
	cmp	x0, x5	// check if we have <= 8 blocks
	b.ge	Lgcm_enc_tail	// handle tail

	ldp	q8, q9, [x0], #32	// AES block 0, 1 - load plaintext

	ldp	q10, q11, [x0], #32	// AES block 2, 3 - load plaintext

	ldp	q12, q13, [x0], #32	// AES block 4, 5 - load plaintext

	ldp	q14, q15, [x0], #32	// AES block 6, 7 - load plaintext
	cmp	x0, x5	// check if we have <= 8 blocks

	eor3	v8.16b, v8.16b, v0.16b, v27.16b	// AES block 0 - result
	rev32	v0.16b, v30.16b	// CTR block 8
	add	v30.4s, v30.4s, v31.4s	// CTR block 8

	eor3	v9.16b, v9.16b, v1.16b, v27.16b	// AES block 1 - result
	stp	q8, q9, [x2], #32	// AES block 0, 1 - store result

	rev32	v1.16b, v30.16b	// CTR block 9
	eor3	v13.16b, v13.16b, v5.16b, v27.16b	// AES block 5 - result
	add	v30.4s, v30.4s, v31.4s	// CTR block 9

	eor3	v10.16b, v10.16b, v2.16b, v27.16b	// AES block 2 - result
	eor3	v14.16b, v14.16b, v6.16b, v27.16b	// AES block 6 - result
	eor3	v12.16b, v12.16b, v4.16b, v27.16b	// AES block 4 - result

	rev32	v2.16b, v30.16b	// CTR block 10
	add	v30.4s, v30.4s, v31.4s	// CTR block 10

	eor3	v11.16b, v11.16b, v3.16b, v27.16b	// AES block 3 - result
	eor3	v15.16b, v15.16b, v7.16b,v27.16b	// AES block 7 - result
	stp	q10, q11, [x2], #32	// AES block 2, 3 - store result

	rev32	v3.16b, v30.16b	// CTR block 11
	add	v30.4s, v30.4s, v31.4s	// CTR block 11
	stp	q12, q13, [x2], #32	// AES block 4, 5 - store result

	stp	q14, q15, [x2], #32	// AES block 6, 7 - store result

	rev32	v4.16b, v30.16b	// CTR block 12
	add	v30.4s, v30.4s, v31.4s	// CTR block 12
	b.ge	Lgcm_enc_prepretail	// do prepretail

Lgcm_enc_main_loop:	// main loop start
	rev32	v5.16b, v30.16b	// CTR block 8k+13
	ldr	q20, [x3, #128]	// load h5l | h5h
	ext	v20.16b, v20.16b, v20.16b, #8
	ldr	q22, [x3, #160]	// load h6l | h6h
	ext	v22.16b, v22.16b, v22.16b, #8
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+13

	rev64	v9.16b, v9.16b	// GHASH block 8k+1
	rev64	v8.16b, v8.16b	// GHASH block 8k
	ldr	q23, [x3, #176]	// load h7l | h7h
	ext	v23.16b, v23.16b, v23.16b, #8
	ldr	q25, [x3, #208]	// load h8l | h8h
	ext	v25.16b, v25.16b, v25.16b, #8

	rev32	v6.16b, v30.16b	// CTR block 8k+14
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+14
	ext	v19.16b, v19.16b, v19.16b, #8	// PRE 0

	ldr	q21, [x3, #144]	// load h6k | h5k
	ldr	q24, [x3, #192]	// load h8k | h7k
	// GHASH block 8k+5 (t0, t1, t2 and t3 free)
	rev64	v13.16b, v13.16b
	rev64	v11.16b, v11.16b	// GHASH block 8k+3

	ldp	q26, q27, [x8, #0]	// load rk0, rk1
	eor	v8.16b, v8.16b, v19.16b	// PRE 1
	rev32	v7.16b, v30.16b	// CTR block 8k+15

	// GHASH block 8k+7 (t0, t1, t2 and t3 free)
	rev64	v15.16b, v15.16b

	pmull2	v16.1q, v9.2d, v23.2d	// GHASH block 8k+1 - high
	rev64	v10.16b, v10.16b	// GHASH block 8k+2
	pmull2	v17.1q, v8.2d, v25.2d	// GHASH block 8k - high

	pmull	v23.1q, v9.1d, v23.1d	// GHASH block 8k+1 - low
	trn1	v18.2d, v9.2d, v8.2d	// GHASH block 8k, 8k+1 - mid
	pmull	v19.1q, v8.1d, v25.1d	// GHASH block 8k - low

	trn2	v8.2d, v9.2d, v8.2d	// GHASH block 8k, 8k+1 - mid
	pmull2	v29.1q, v10.2d, v22.2d	// GHASH block 8k+2 - high
	pmull2	v9.1q, v11.2d, v20.2d	// GHASH block 8k+3 - high

	eor	v19.16b, v19.16b, v23.16b	// GHASH block 8k+1 - low
	ldr	q23, [x3, #80]	// load h3l | h3h
	ext	v23.16b, v23.16b, v23.16b, #8
	ldr	q25, [x3, #112]	// load h3l | h3h
	ext	v25.16b, v25.16b, v25.16b, #8
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 0

	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 0
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 0
	eor	v17.16b, v17.16b, v16.16b	// GHASH block 8k+1 - high

	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+15
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 0
	eor	v8.16b, v8.16b, v18.16b	// GHASH block 8k, 8k+1 - mid

	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 0
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 1
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 0

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 1
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 0
	pmull	v22.1q, v10.1d, v22.1d	// GHASH block 8k+2 - low

	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 1
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 0
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 1

	// GHASH block 8k+2, 8k+3 - high
	eor3	v17.16b, v17.16b, v29.16b,v9.16b
	trn1	v29.2d, v11.2d, v10.2d	// GHASH block 8k+2, 8k+3 - mid
	trn2	v10.2d, v11.2d, v10.2d	// GHASH block 8k+2, 8k+3 - mid

	ldp	q28, q26, [x8, #32]	// load rk2, rk3
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 1
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 1

	pmull	v20.1q, v11.1d, v20.1d	// GHASH block 8k+3 - low
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 1
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 1

	pmull2	v18.1q, v8.2d, v24.2d	// GHASH block 8k - mid
	eor	v10.16b, v10.16b, v29.16b	// GHASH block 8k+2, 8k+3 - mid
	pmull	v24.1q, v8.1d, v24.1d	// GHASH block 8k+1 - mid

	// GHASH block 8k+6 (t0, t1, and t2 free)
	rev64	v14.16b, v14.16b
	// GHASH block 8k+2, 8k+3 - low
	eor3	v19.16b, v19.16b, v22.16b, v20.16b

	pmull2	v29.1q, v10.2d, v21.2d	// GHASH block 8k+2 - mid
	eor	v18.16b, v18.16b, v24.16b	// GHASH block 8k+1 - mid
	pmull	v21.1q, v10.1d, v21.1d	// GHASH block 8k+3 - mid

	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 2
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 2
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 2

	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 2
	// GHASH block 8k+2, 8k+3 - mid
	eor3	v18.16b, v18.16b, v21.16b, v29.16b
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 2

	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 2
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 2
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 2

	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 3
	ldr	q21, [x3, #48]	// load h2k | h1k
	ldr	q24, [x3, #96]	// load h4k | h3k
	// GHASH block 8k+4 (t0, t1, and t2 free)
	rev64	v12.16b, v12.16b

	ldp	q27, q28, [x8, #64]	// load rk4, rk5
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 3
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 3

	ldr	q20, [x3, #32]	// load h1l | h1h
	ext	v20.16b, v20.16b, v20.16b, #8
	ldr	q22, [x3, #64]	// load h1l | h1h
	ext	v22.16b, v22.16b, v22.16b, #8
	pmull2	v8.1q, v12.2d, v25.2d	// GHASH block 8k+4 - high
	pmull	v25.1q, v12.1d, v25.1d	// GHASH block 8k+4 - low

	trn1	v16.2d, v13.2d, v12.2d	// GHASH block 8k+4, 8k+5 - mid
	trn2	v12.2d, v13.2d, v12.2d	// GHASH block 8k+4, 8k+5 - mid

	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 3
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 3

	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 3
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 3

	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 3
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 4

	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 4
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 4
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 4

	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 4
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 4
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 4

	pmull2	v10.1q, v13.2d, v23.2d	// GHASH block 8k+5 - high
	eor	v12.16b, v12.16b, v16.16b	// GHASH block 8k+4, 8k+5 - mid
	pmull	v23.1q, v13.1d, v23.1d	// GHASH block 8k+5 - low

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 4
	ldp	q26, q27, [x8, #96]	// load rk6, rk7
	trn1	v13.2d, v15.2d, v14.2d	// GHASH block 8k+6, 8k+7 - mid

	pmull2	v16.1q, v12.2d, v24.2d	// GHASH block 8k+4 - mid
	pmull	v24.1q, v12.1d, v24.1d	// GHASH block 8k+5 - mid
	pmull2	v11.1q, v14.2d, v22.2d	// GHASH block 8k+6 - high

	pmull2	v12.1q, v15.2d, v20.2d	// GHASH block 8k+7 - high
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 5
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 5

	pmull	v22.1q, v14.1d, v22.1d	// GHASH block 8k+6 - low
	// GHASH block 8k+4, 8k+5 - high
	eor3	v17.16b, v17.16b, v8.16b, v10.16b
	trn2	v14.2d, v15.2d, v14.2d	// GHASH block 8k+6, 8k+7 - mid

	// GHASH block 8k+4, 8k+5 - low
	eor3	v19.16b, v19.16b, v25.16b, v23.16b
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 5

	eor	v14.16b, v14.16b, v13.16b	// GHASH block 8k+6, 8k+7 - mid
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 5
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 5

	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 5
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 5
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 5

	// GHASH block 8k+4, 8k+5 - mid
	eor3	v18.16b, v18.16b, v24.16b, v16.16b
	ldr	d16, [x10]	// MODULO - load modulo constant
	pmull	v20.1q, v15.1d, v20.1d	// GHASH block 8k+7 - low

	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 6
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 6

	pmull2	v13.1q, v14.2d, v21.2d	// GHASH block 8k+6 - mid
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 6
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 6

	pmull	v21.1q, v14.1d, v21.1d	// GHASH block 8k+7 - mid
	// GHASH block 8k+6, 8k+7 - low
	eor3	v19.16b, v19.16b, v22.16b, v20.16b
	ldp	q8, q9, [x0], #32	// AES block 8k+8, 8k+9 - load plaintext

	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 6
	rev32	v20.16b, v30.16b	// CTR block 8k+16
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+16

	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 6
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 6
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 6

	// GHASH block 8k+6, 8k+7 - mid
	eor3	v18.16b, v18.16b, v21.16b, v13.16b
	ldp	q28, q26, [x8, #128]	// load rk8, rk9
	// GHASH block 8k+6, 8k+7 - high
	eor3	v17.16b, v17.16b, v11.16b, v12.16b

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 7
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 7
	// AES block 8k+10, 8k+11 - load plaintext
	ldp	q10, q11, [x0], #32

	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 7
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 7
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 7

	pmull	v21.1q, v17.1d, v16.1d	// MODULO - top 64b align with mid
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 7
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 7

	rev32	v22.16b, v30.16b	// CTR block 8k+17
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 7

	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 8
	// AES block 8k+12, 8k+13 - load plaintext
	ldp	q12, q13, [x0], #32
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+17

	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 8
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 8
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 8

	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 8
	// MODULO - karatsuba tidy up
	eor3	v18.16b, v18.16b, v17.16b, v19.16b
	ldr	q27, [x8, #160]	// load rk10

	ext	v29.16b, v17.16b, v17.16b, #8	// MODULO - other top alignment
	rev32	v23.16b, v30.16b	// CTR block 8k+18
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+18
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 8

	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 8
	// MODULO - fold into mid
	eor3	v18.16b, v18.16b, v29.16b, v21.16b
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 8

	aese	v2.16b, v26.16b	// AES block 8k+10 - round 9
	aese	v4.16b, v26.16b	// AES block 8k+12 - round 9
	aese	v1.16b, v26.16b	// AES block 8k+9 - round 9

	// AES block 8k+14, 8k+15 - load plaintext
	ldp	q14, q15, [x0], #32
	rev32	v25.16b, v30.16b	// CTR block 8k+19
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+19

	cmp	x0, x5	// .LOOP CONTROL
	eor3	v12.16b, v12.16b, v4.16b, v27.16b	// AES block 4 - result
	aese	v7.16b, v26.16b	// AES block 8k+15 - round 9

	aese	v6.16b, v26.16b	// AES block 8k+14 - round 9
	aese	v3.16b, v26.16b	// AES block 8k+11 - round 9

	// AES block 8k+10 - result
	eor3	v10.16b, v10.16b, v2.16b, v27.16b

	mov	v2.16b, v23.16b	// CTR block 8k+18
	aese	v0.16b, v26.16b	// AES block 8k+8 - round 9

	rev32	v4.16b, v30.16b	// CTR block 8k+20
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+20

	eor3	v15.16b, v15.16b, v7.16b, v27.16b	// AES block 7 - result
	aese	v5.16b, v26.16b	// AES block 8k+13 - round 9
	pmull	v17.1q, v18.1d, v16.1d	// MODULO - mid 64b align with low

	eor3	v9.16b, v9.16b, v1.16b, v27.16b	// AES block 8k+9 - result
	// AES block 8k+11 - result
	eor3	v11.16b, v11.16b, v3.16b, v27.16b
	mov	v3.16b, v25.16b	// CTR block 8k+19

	ext	v21.16b, v18.16b, v18.16b, #8	// MODULO - other mid alignment
	eor3	v13.16b, v13.16b, v5.16b, v27.16b	// AES block 5 - result
	mov	v1.16b, v22.16b	// CTR block 8k+17

	eor3	v8.16b, v8.16b, v0.16b, v27.16b	// AES block 8k+8 - result
	mov	v0.16b, v20.16b	// CTR block 8k+16
	stp	q8, q9, [x2], #32	// AES block 8k+8, 8k+9 - store result

	stp	q10, q11, [x2], #32	// AES block 8k+10, 8k+11 - store result
	eor3	v14.16b, v14.16b, v6.16b, v27.16b	// AES block 6 - result

	stp	q12, q13, [x2], #32	// AES block 8k+12, 8k+13 - store result
	// MODULO - fold into low
	eor3	v19.16b, v19.16b, v17.16b, v21.16b

	stp	q14, q15, [x2], #32	// AES block 8k+14, 8k+15 - store result
	b.lt	Lgcm_enc_main_loop

Lgcm_enc_prepretail:	// PREPRETAIL
	rev32	v5.16b, v30.16b	// CTR block 8k+13
	ldr	q23, [x3, #176]	// load h7l | h7h
	ext	v23.16b, v23.16b, v23.16b, #8
	ldr	q25, [x3, #208]	// load h8l | h8h
	ext	v25.16b, v25.16b, v25.16b, #8
	ext	v19.16b, v19.16b, v19.16b, #8	// PRE 0

	ldr	q20, [x3, #128]	// load h5l | h5h
	ext	v20.16b, v20.16b, v20.16b, #8
	ldr	q22, [x3, #160]	// load h6l | h6h
	ext	v22.16b, v22.16b, v22.16b, #8
	rev64	v8.16b, v8.16b	// GHASH block 8k
	rev64	v9.16b, v9.16b	// GHASH block 8k+1

	ldr	q21, [x3, #144]	// load h6k | h5k
	ldr	q24, [x3, #192]	// load h6k | h5k
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+13
	rev64	v11.16b, v11.16b	// GHASH block 8k+3

	rev64	v10.16b, v10.16b	// GHASH block 8k+2
	eor	v8.16b, v8.16b, v19.16b	// PRE 1

	rev32	v6.16b, v30.16b	// CTR block 8k+14

	pmull2	v16.1q, v9.2d, v23.2d	// GHASH block 8k+1 - high
	pmull	v19.1q, v8.1d, v25.1d	// GHASH block 8k - low
	pmull2	v17.1q, v8.2d, v25.2d	// GHASH block 8k - high

	// GHASH block 8k+5 (t0, t1, t2 and t3 free)
	rev64	v13.16b, v13.16b
	trn1	v18.2d, v9.2d, v8.2d	// GHASH block 8k, 8k+1 - mid

	pmull	v23.1q, v9.1d, v23.1d	// GHASH block 8k+1 - low
	eor	v17.16b, v17.16b, v16.16b	// GHASH block 8k+1 - high
	trn2	v8.2d, v9.2d, v8.2d	// GHASH block 8k, 8k+1 - mid

	eor	v19.16b, v19.16b, v23.16b	// GHASH block 8k+1 - low
	eor	v8.16b, v8.16b, v18.16b	// GHASH block 8k, 8k+1 - mid

	ldp	q26, q27, [x8, #0]	// load rk0, rk1
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+14

	pmull2	v18.1q, v8.2d, v24.2d	// GHASH block 8k - mid
	pmull	v24.1q, v8.1d, v24.1d	// GHASH block 8k+1 - mid

	// GHASH block 8k+4 (t0, t1, and t2 free)
	rev64	v12.16b, v12.16b
	// GHASH block 8k+7 (t0, t1, t2 and t3 free)
	rev64	v15.16b, v15.16b

	eor	v18.16b, v18.16b, v24.16b	// GHASH block 8k+1 - mid

	rev32	v7.16b, v30.16b	// CTR block 8k+15

	// GHASH block 8k+6 (t0, t1, and t2 free)
	rev64	v14.16b, v14.16b

	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 0

	pmull2	v9.1q, v11.2d, v20.2d	// GHASH block 8k+3 - high
	pmull2	v29.1q, v10.2d, v22.2d	// GHASH block 8k+2 - high

	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 0
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 0

	pmull	v22.1q, v10.1d, v22.1d	// GHASH block 8k+2 - low
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 0

	// GHASH block 8k+2, 8k+3 - high
	eor3	v17.16b, v17.16b, v29.16b, v9.16b
	trn1	v29.2d, v11.2d, v10.2d	// GHASH block 8k+2, 8k+3 - mid
	trn2	v10.2d, v11.2d, v10.2d	// GHASH block 8k+2, 8k+3 - mid

	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 0
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 0

	eor	v10.16b, v10.16b, v29.16b	// GHASH block 8k+2, 8k+3 - mid
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 0
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 0

	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 1
	pmull	v20.1q, v11.1d, v20.1d	// GHASH block 8k+3 - low

	ldr	q23, [x3, #80]	// load h3l | h3h
	ext	v23.16b, v23.16b, v23.16b, #8
	ldr	q25, [x3, #112]	// load h4l | h4h
	ext	v25.16b, v25.16b, v25.16b, #8

	ldp	q28, q26, [x8, #32]	// load rk2, rk3
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 1
	pmull2	v29.1q, v10.2d, v21.2d	// GHASH block 8k+2 - mid

	// GHASH block 8k+2, 8k+3 - low
	eor3	v19.16b, v19.16b, v22.16b, v20.16b
	pmull	v21.1q, v10.1d, v21.1d	// GHASH block 8k+3 - mid

	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 1
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 1

	// GHASH block 8k+2, 8k+3 - mid
	eor3	v18.16b, v18.16b, v21.16b, v29.16b
	ldr	q21, [x3, #48]	// load h2k | h1k
	ldr	q24, [x3, #96]	// load h4k | h3k
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 1

	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 1
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 1

	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 2
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 2
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 2

	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 2
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 1
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 2

	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 3
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 2

	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 2
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 2
	ldp	q27, q28, [x8, #64]	// load rk4, rk5

	ldr	q20, [x3, #32]	// load h1l | h1h
	ext	v20.16b, v20.16b, v20.16b, #8
	ldr	q22, [x3, #64]	// load h1l | h1h
	ext	v22.16b, v22.16b, v22.16b, #8
	trn1	v16.2d, v13.2d, v12.2d	// GHASH block 8k+4, 8k+5 - mid
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 3

	pmull2	v8.1q, v12.2d, v25.2d	// GHASH block 8k+4 - high
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 3
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 3

	pmull	v25.1q, v12.1d, v25.1d	// GHASH block 8k+4 - low
	trn2	v12.2d, v13.2d, v12.2d	// GHASH block 8k+4, 8k+5 - mid
	pmull2	v10.1q, v13.2d, v23.2d	// GHASH block 8k+5 - high

	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 3
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+15

	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 3
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 3
	eor	v12.16b, v12.16b, v16.16b	// GHASH block 8k+4, 8k+5 - mid

	pmull	v23.1q, v13.1d, v23.1d	// GHASH block 8k+5 - low
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 3
	pmull2	v11.1q, v14.2d, v22.2d	// GHASH block 8k+6 - high

	trn1	v13.2d, v15.2d, v14.2d	// GHASH block 8k+6, 8k+7 - mid
	pmull	v22.1q, v14.1d, v22.1d	// GHASH block 8k+6 - low
	trn2	v14.2d, v15.2d, v14.2d	// GHASH block 8k+6, 8k+7 - mid

	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 4
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 4
	// GHASH block 8k+4, 8k+5 - high
	eor3	v17.16b, v17.16b, v8.16b, v10.16b

	// GHASH block 8k+4, 8k+5 - low
	eor3	v19.16b, v19.16b, v25.16b, v23.16b
	eor	v14.16b, v14.16b, v13.16b	// GHASH block 8k+6, 8k+7 - mid
	pmull2	v16.1q, v12.2d, v24.2d	// GHASH block 8k+4 - mid

	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 5
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 4
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 4

	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 4
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 4

	pmull	v24.1q, v12.1d, v24.1d	// GHASH block 8k+5 - mid
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 4
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 4

	pmull2	v12.1q, v15.2d, v20.2d	// GHASH block 8k+7 - high
	ldp	q26, q27, [x8, #96]	// load rk6, rk7
	pmull	v20.1q, v15.1d, v20.1d	// GHASH block 8k+7 - low

	// GHASH block 8k+4, 8k+5 - mid
	eor3	v18.16b, v18.16b, v24.16b, v16.16b
	pmull2	v13.1q, v14.2d, v21.2d	// GHASH block 8k+6 - mid
	pmull	v21.1q, v14.1d, v21.1d	// GHASH block 8k+7 - mid

	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 5
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 5
	ldr	d16, [x10]	// MODULO - load modulo constant

	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 5
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 5

	// GHASH block 8k+6, 8k+7 - high
	eor3	v17.16b, v17.16b, v11.16b, v12.16b
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 5
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 5

	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 5
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 6

	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 6
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 6
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 6

	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 6
	// GHASH block 8k+6, 8k+7 - low
	eor3	v19.16b, v19.16b, v22.16b, v20.16b
	// GHASH block 8k+6, 8k+7 - mid
	eor3	v18.16b, v18.16b, v21.16b, v13.16b

	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 6
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 6
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 6

	pmull	v21.1q, v17.1d, v16.1d	// MODULO - top 64b align with mid
	// MODULO - karatsuba tidy up
	eor3	v18.16b, v18.16b, v17.16b, v19.16b
	ldp	q28, q26, [x8, #128]	// load rk8, rk9

	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 7
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 7
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 7
	ext	v29.16b, v17.16b, v17.16b, #8	// MODULO - other top alignment

	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 7
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 7
	// MODULO - fold into mid
	eor3	v18.16b, v18.16b, v29.16b, v21.16b

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 7
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 7

	pmull	v17.1q, v18.1d, v16.1d	// MODULO - mid 64b align with low
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 7

	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 8
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 8
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 8
	ext	v18.16b, v18.16b, v18.16b, #8	// MODULO - other mid alignment

	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 8
	// MODULO - fold into low
	eor3	v19.16b, v19.16b, v17.16b, v18.16b
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 8

	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 8
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 8
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 8

	ldr	q27, [x8, #160]	// load rk10
	aese	v6.16b, v26.16b	// AES block 8k+14 - round 9
	aese	v2.16b, v26.16b	// AES block 8k+10 - round 9

	aese	v0.16b, v26.16b	// AES block 8k+8 - round 9
	aese	v1.16b, v26.16b	// AES block 8k+9 - round 9

	aese	v3.16b, v26.16b	// AES block 8k+11 - round 9
	aese	v5.16b, v26.16b	// AES block 8k+13 - round 9

	aese	v4.16b, v26.16b	// AES block 8k+12 - round 9
	aese	v7.16b, v26.16b	// AES block 8k+15 - round 9
Lgcm_enc_tail:	// TAIL

	// main_end_input_ptr is number of bytes left to process
	sub	x5, x4, x0
	ldr	q8, [x0], #16	// AES block 8k+8 - load plaintext

	mov	v29.16b, v27.16b
	ldp	q20, q21, [x3, #128]	// load h5l | h5h
	ext	v20.16b, v20.16b, v20.16b, #8

	eor3	v9.16b, v8.16b, v0.16b, v29.16b	// AES block 8k+8 - result
	ext	v16.16b, v19.16b, v19.16b, #8	// prepare final partial tag
	ldp	q22, q23, [x3, #160]	// load h6l | h6h
	ext	v22.16b, v22.16b, v22.16b, #8
	ext	v23.16b, v23.16b, v23.16b, #8

	ldp	q24, q25, [x3, #192]	// load h8k | h7k
	ext	v25.16b, v25.16b, v25.16b, #8
	cmp	x5, #112
	b.gt	Lgcm_enc_blocks_more_than_7

	mov	v7.16b, v6.16b
	mov	v6.16b, v5.16b
	movi	v17.8b, #0

	cmp	x5, #96
	sub	v30.4s, v30.4s, v31.4s
	mov	v5.16b, v4.16b

	mov	v4.16b, v3.16b
	mov	v3.16b, v2.16b
	mov	v2.16b, v1.16b

	movi	v19.8b, #0
	movi	v18.8b, #0
	b.gt	Lgcm_enc_blocks_more_than_6

	mov	v7.16b, v6.16b
	cmp	x5, #80

	sub	v30.4s, v30.4s, v31.4s
	mov	v6.16b, v5.16b
	mov	v5.16b, v4.16b

	mov	v4.16b, v3.16b
	mov	v3.16b, v1.16b
	b.gt	Lgcm_enc_blocks_more_than_5

	cmp	x5, #64
	sub	v30.4s, v30.4s, v31.4s

	mov	v7.16b, v6.16b
	mov	v6.16b, v5.16b

	mov	v5.16b, v4.16b
	mov	v4.16b, v1.16b
	b.gt	Lgcm_enc_blocks_more_than_4

	mov	v7.16b, v6.16b
	sub	v30.4s, v30.4s, v31.4s
	mov	v6.16b, v5.16b

	mov	v5.16b, v1.16b
	cmp	x5, #48
	b.gt	Lgcm_enc_blocks_more_than_3

	sub	v30.4s, v30.4s, v31.4s
	mov	v7.16b, v6.16b
	mov	v6.16b, v1.16b

	cmp	x5, #32
	ldr	q24, [x3, #96]	// load h4k | h3k
	b.gt	Lgcm_enc_blocks_more_than_2

	cmp	x5, #16

	sub	v30.4s, v30.4s, v31.4s
	mov	v7.16b, v1.16b
	b.gt	Lgcm_enc_blocks_more_than_1

	ldr	q21, [x3, #48]	// load h2k | h1k
	sub	v30.4s, v30.4s, v31.4s
	b	Lgcm_enc_blocks_less_than_1
Lgcm_enc_blocks_more_than_7:	// blocks left > 7
	st1	{ v9.16b}, [x2], #16	// AES final-7 block - store result

	rev64	v8.16b, v9.16b	// GHASH final-7 block
	ldr	q9, [x0], #16	// AES final-6 block - load plaintext

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v27.d[0], v8.d[1]	// GHASH final-7 block - mid

	pmull2	v17.1q, v8.2d, v25.2d	// GHASH final-7 block - high

	ins	v18.d[0], v24.d[1]	// GHASH final-7 block - mid

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-7 block - mid
	movi	v16.8b, #0	// suppress further partial tag feed in

	eor3	v9.16b, v9.16b, v1.16b, v29.16b	// AES final-6 block - result

	pmull	v18.1q, v27.1d, v18.1d	// GHASH final-7 block - mid
	pmull	v19.1q, v8.1d, v25.1d	// GHASH final-7 block - low
Lgcm_enc_blocks_more_than_6:	// blocks left > 6

	st1	{ v9.16b}, [x2], #16	// AES final-6 block - store result

	rev64	v8.16b, v9.16b	// GHASH final-6 block
	ldr	q9, [x0], #16	// AES final-5 block - load plaintext

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v27.d[0], v8.d[1]	// GHASH final-6 block - mid

	eor3	v9.16b, v9.16b, v2.16b, v29.16b	// AES final-5 block - result
	pmull	v26.1q, v8.1d, v23.1d	// GHASH final-6 block - low

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-6 block - mid
	movi	v16.8b, #0	// suppress further partial tag feed in

	pmull	v27.1q, v27.1d, v24.1d	// GHASH final-6 block - mid
	pmull2	v28.1q, v8.2d, v23.2d	// GHASH final-6 block - high

	eor	v19.16b, v19.16b, v26.16b	// GHASH final-6 block - low

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-6 block - mid
	eor	v17.16b, v17.16b, v28.16b	// GHASH final-6 block - high
Lgcm_enc_blocks_more_than_5:	// blocks left > 5

	st1	{ v9.16b}, [x2], #16	// AES final-5 block - store result

	rev64	v8.16b, v9.16b	// GHASH final-5 block

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v27.d[0], v8.d[1]	// GHASH final-5 block - mid
	ldr	q9, [x0], #16	// AES final-4 block - load plaintext
	pmull2	v28.1q, v8.2d, v22.2d	// GHASH final-5 block - high

	eor	v17.16b, v17.16b, v28.16b	// GHASH final-5 block - high

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-5 block - mid

	ins	v27.d[1], v27.d[0]	// GHASH final-5 block - mid

	eor3	v9.16b, v9.16b, v3.16b, v29.16b	// AES final-4 block - result
	pmull	v26.1q, v8.1d, v22.1d	// GHASH final-5 block - low
	movi	v16.8b, #0	// suppress further partial tag feed in

	pmull2	v27.1q, v27.2d, v21.2d	// GHASH final-5 block - mid
	eor	v19.16b, v19.16b, v26.16b	// GHASH final-5 block - low

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-5 block - mid
Lgcm_enc_blocks_more_than_4:	// blocks left > 4

	st1	{ v9.16b}, [x2], #16	// AES final-4 block - store result

	rev64	v8.16b, v9.16b	// GHASH final-4 block

	ldr	q9, [x0], #16	// AES final-3 block - load plaintext

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v27.d[0], v8.d[1]	// GHASH final-4 block - mid
	movi	v16.8b, #0	// suppress further partial tag feed in
	pmull2	v28.1q, v8.2d, v20.2d	// GHASH final-4 block - high

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-4 block - mid

	pmull	v26.1q, v8.1d, v20.1d	// GHASH final-4 block - low

	eor	v17.16b, v17.16b, v28.16b	// GHASH final-4 block - high
	pmull	v27.1q, v27.1d, v21.1d	// GHASH final-4 block - mid

	eor	v19.16b, v19.16b, v26.16b	// GHASH final-4 block - low

	eor3	v9.16b, v9.16b, v4.16b, v29.16b	// AES final-3 block - result
	eor	v18.16b, v18.16b, v27.16b	// GHASH final-4 block - mid
Lgcm_enc_blocks_more_than_3:	// blocks left > 3

	st1	{ v9.16b}, [x2], #16	// AES final-3 block - store result

	ldr	q25, [x3, #112]	// load h4l | h4h
	ext	v25.16b, v25.16b, v25.16b, #8

	rev64	v8.16b, v9.16b	// GHASH final-3 block

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag
	movi	v16.8b, #0	// suppress further partial tag feed in

	ins	v27.d[0], v8.d[1]	// GHASH final-3 block - mid
	ldr	q24, [x3, #96]	// load h4k | h3k
	pmull	v26.1q, v8.1d, v25.1d	// GHASH final-3 block - low

	ldr	q9, [x0], #16	// AES final-2 block - load plaintext

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-3 block - mid

	ins	v27.d[1], v27.d[0]	// GHASH final-3 block - mid
	eor	v19.16b, v19.16b, v26.16b	// GHASH final-3 block - low

	eor3	v9.16b, v9.16b, v5.16b, v29.16b	// AES final-2 block - result

	pmull2	v27.1q, v27.2d, v24.2d	// GHASH final-3 block - mid
	pmull2	v28.1q, v8.2d, v25.2d	// GHASH final-3 block - high

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-3 block - mid
	eor	v17.16b, v17.16b, v28.16b	// GHASH final-3 block - high
Lgcm_enc_blocks_more_than_2:	// blocks left > 2

	st1	{ v9.16b}, [x2], #16	// AES final-2 block - store result

	rev64	v8.16b, v9.16b	// GHASH final-2 block

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ldr	q9, [x0], #16	// AES final-1 block - load plaintext

	ins	v27.d[0], v8.d[1]	// GHASH final-2 block - mid
	ldr	q23, [x3, #80]	// load h3l | h3h
	ext	v23.16b, v23.16b, v23.16b, #8
	movi	v16.8b, #0	// suppress further partial tag feed in

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-2 block - mid
	eor3	v9.16b, v9.16b, v6.16b, v29.16b	// AES final-1 block - result

	pmull2	v28.1q, v8.2d, v23.2d	// GHASH final-2 block - high

	pmull	v26.1q, v8.1d, v23.1d	// GHASH final-2 block - low
	pmull	v27.1q, v27.1d, v24.1d	// GHASH final-2 block - mid

	eor	v17.16b, v17.16b, v28.16b	// GHASH final-2 block - high

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-2 block - mid
	eor	v19.16b, v19.16b, v26.16b	// GHASH final-2 block - low
Lgcm_enc_blocks_more_than_1:	// blocks left > 1

	st1	{ v9.16b}, [x2], #16	// AES final-1 block - store result

	ldr	q22, [x3, #64]	// load h2l | h2h
	ext	v22.16b, v22.16b, v22.16b, #8
	rev64	v8.16b, v9.16b	// GHASH final-1 block
	ldr	q9, [x0], #16	// AES final block - load plaintext

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	movi	v16.8b, #0	// suppress further partial tag feed in
	ins	v27.d[0], v8.d[1]	// GHASH final-1 block - mid
	eor3	v9.16b, v9.16b, v7.16b, v29.16b	// AES final block - result

	pmull2	v28.1q, v8.2d, v22.2d	// GHASH final-1 block - high

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-1 block - mid

	ldr	q21, [x3, #48]	// load h2k | h1k

	ins	v27.d[1], v27.d[0]	// GHASH final-1 block - mid

	pmull	v26.1q, v8.1d, v22.1d	// GHASH final-1 block - low
	pmull2	v27.1q, v27.2d, v21.2d	// GHASH final-1 block - mid

	eor	v17.16b, v17.16b, v28.16b	// GHASH final-1 block - high

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-1 block - mid
	eor	v19.16b, v19.16b, v26.16b	// GHASH final-1 block - low
Lgcm_enc_blocks_less_than_1:	// blocks left <= 1

	rev32	v30.16b, v30.16b
	str	q30, [x16]	// store the updated counter
	and	x1, x1, #127	// bit_length %= 128

	sub	x1, x1, #128	// bit_length -= 128

	neg	x1, x1	// bit_length = 128 - #bits in input (in range [1,128])

	mvn	x6, xzr	// temp0_x = 0xffffffffffffffff
	// load existing bytes where the possibly partial last block is to be
	// stored
	ld1	{ v26.16b}, [x2]
	and	x1, x1, #127	// bit_length %= 128

	lsr	x6, x6, x1	// temp0_x is mask for top 64b of last block
	mvn	x7, xzr	// temp1_x = 0xffffffffffffffff
	cmp	x1, #64

	csel	x13, x7, x6, lt
	csel	x14, x6, xzr, lt

	mov	v0.d[1], x14
	mov	v0.d[0], x13	// ctr0b is mask for last block

	// possibly partial last block has zeroes in highest bits
	and	v9.16b, v9.16b, v0.16b

	rev64	v8.16b, v9.16b	// GHASH final block

	// insert existing bytes in top end of result before storing
	bif	v9.16b, v26.16b, v0.16b
	st1	{ v9.16b}, [x2]	// store all 16B

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v16.d[0], v8.d[1]	// GHASH final block - mid

	eor	v16.8b, v16.8b, v8.8b	// GHASH final block - mid
	ldr	q20, [x3, #32]	// load h1l | h1h
	ext	v20.16b, v20.16b, v20.16b, #8

	pmull	v16.1q, v16.1d, v21.1d	// GHASH final block - mid

	pmull2	v28.1q, v8.2d, v20.2d	// GHASH final block - high
	eor	v18.16b, v18.16b, v16.16b	// GHASH final block - mid
	ldr	d16, [x10]	// MODULO - load modulo constant

	pmull	v26.1q, v8.1d, v20.1d	// GHASH final block - low

	eor	v17.16b, v17.16b, v28.16b	// GHASH final block - high

	eor	v19.16b, v19.16b, v26.16b	// GHASH final block - low

	ext	v21.16b, v17.16b, v17.16b, #8	// MODULO - other top alignment
	pmull	v29.1q, v17.1d, v16.1d	// MODULO - top 64b align with mid

	// MODULO - karatsuba tidy up
	eor3	v18.16b, v18.16b, v17.16b, v19.16b

	// MODULO - fold into mid
	eor3	v18.16b, v18.16b, v29.16b, v21.16b

	pmull	v17.1q, v18.1d, v16.1d	// MODULO - mid 64b align with low
	ext	v21.16b, v18.16b, v18.16b, #8	// MODULO - other mid alignment

	// MODULO - fold into low
	eor3	v19.16b, v19.16b, v17.16b, v21.16b
	ext	v19.16b, v19.16b, v19.16b, #8
	rev64	v19.16b, v19.16b
	st1	{ v19.16b }, [x3]
	mov	x0, x9

	ldp	d10, d11, [sp, #16]
	ldp	d12, d13, [sp, #32]
	ldp	d14, d15, [sp, #48]
	ldp	d8, d9, [sp], #80
	ret

Lgcm_enc_ret:
	mov	w0, #0x0
	ret
	nop
SET_SIZE(aes_gcm_enc_128_eor3_zfs)

ENTRY_ALIGN(aes_gcm_dec_128_eor3_zfs, 16)
	AARCH64_VALID_CALL_TARGET
	cbz	x1, Lgcm_dec_ret
	stp	d8, d9, [sp, #-80]!
	lsr	x9, x1, #3
	mov	x16, x4
	mov	x8, x5
	stp	d10, d11, [sp, #16]
	stp	d12, d13, [sp, #32]
	stp	d14, d15, [sp, #48]
	mov	x5, #0xc200000000000000
	stp	x5, xzr, [sp, #64]
	add	x10, sp, #64

	mov	x5, x9
	ld1	{ v0.16b}, [x16]	// CTR block 0

	ldp	q26, q27, [x8, #0]	// load rk0, rk1
	sub	x5, x5, #1	// byte_len - 1

	mov	x15, #0x100000000	// set up counter increment
	movi	v31.16b, #0x0
	mov	v31.d[1], x15
	ld1	{ v19.16b}, [x3]
	ext	v19.16b, v19.16b, v19.16b, #8
	rev64	v19.16b, v19.16b

	rev32	v30.16b, v0.16b	// set up reversed counter

	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 0

	add	v30.4s, v30.4s, v31.4s	// CTR block 0

	rev32	v1.16b, v30.16b	// CTR block 1
	add	v30.4s, v30.4s, v31.4s	// CTR block 1

	// number of bytes to be processed in main loop (at least 1 byte must be
	// handled by tail)
	and	x5, x5, #0xffffffffffffff80

	rev32	v2.16b, v30.16b	// CTR block 2
	add	v30.4s, v30.4s, v31.4s	// CTR block 2
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 0

	rev32	v3.16b, v30.16b	// CTR block 3
	add	v30.4s, v30.4s, v31.4s	// CTR block 3

	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 1
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 1

	rev32	v4.16b, v30.16b	// CTR block 4
	add	v30.4s, v30.4s, v31.4s	// CTR block 4

	rev32	v5.16b, v30.16b	// CTR block 5
	add	v30.4s, v30.4s, v31.4s	// CTR block 5

	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 0

	rev32	v6.16b, v30.16b	// CTR block 6
	add	v30.4s, v30.4s, v31.4s	// CTR block 6
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 0

	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 0
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 0

	rev32	v7.16b, v30.16b	// CTR block 7

	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 0
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 1

	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 0

	ldp	q28, q26, [x8, #32]	// load rk2, rk3

	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 1
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 1

	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 1
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 1

	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 2
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 2
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 1

	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 2
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 2
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 2

	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 2
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 2
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 2

	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 3
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 3

	ldp	q27, q28, [x8, #64]	// load rk4, rk5
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 3

	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 3
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 3

	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 3
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 3

	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 4
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 4
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 3

	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 4
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 4
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 4

	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 4
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 4
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 4

	ldp	q26, q27, [x8, #96]	// load rk6, rk7
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 5
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 5

	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 5
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 5

	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 5
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 5

	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 5

	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 6
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 6
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 5

	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 6
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 6
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 6

	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 6
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 6
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 6

	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 7
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 7
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 7

	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 7
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 7
	ldp	q28, q26, [x8, #128]	// load rk8, rk9

	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 7
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 7
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 7

	add	x5, x5, x0
	add	v30.4s, v30.4s, v31.4s	// CTR block 7

	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 6 - round 8
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 0 - round 8

	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 1 - round 8
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 7 - round 8
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 3 - round 8

	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 5 - round 8
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 2 - round 8
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 4 - round 8

	aese	v0.16b, v26.16b	// AES block 0 - round 9
	aese	v1.16b, v26.16b	// AES block 1 - round 9
	aese	v6.16b, v26.16b	// AES block 6 - round 9

	ldr	q27, [x8, #160]	// load rk10
	aese	v4.16b, v26.16b	// AES block 4 - round 9
	aese	v3.16b, v26.16b	// AES block 3 - round 9

	aese	v2.16b, v26.16b	// AES block 2 - round 9
	aese	v5.16b, v26.16b	// AES block 5 - round 9
	aese	v7.16b, v26.16b	// AES block 7 - round 9

	add	x4, x0, x1, lsr #3	// end_input_ptr
	cmp	x0, x5	// check if we have <= 8 blocks
	b.ge	Lgcm_dec_tail	// handle tail

	ldp	q8, q9, [x0], #32	// AES block 0, 1 - load ciphertext

	eor3	v0.16b, v8.16b, v0.16b, v27.16b	// AES block 0 - result
	eor3	v1.16b, v9.16b, v1.16b, v27.16b	// AES block 1 - result
	stp	q0, q1, [x2], #32	// AES block 0, 1 - store result

	rev32	v0.16b, v30.16b	// CTR block 8
	add	v30.4s, v30.4s, v31.4s	// CTR block 8
	ldp	q10, q11, [x0], #32	// AES block 2, 3 - load ciphertext

	ldp	q12, q13, [x0], #32	// AES block 4, 5 - load ciphertext

	rev32	v1.16b, v30.16b	// CTR block 9
	add	v30.4s, v30.4s, v31.4s	// CTR block 9
	ldp	q14, q15, [x0], #32	// AES block 6, 7 - load ciphertext

	eor3	v3.16b, v11.16b, v3.16b, v27.16b	// AES block 3 - result
	eor3	v2.16b, v10.16b, v2.16b, v27.16b	// AES block 2 - result
	stp	q2, q3, [x2], #32	// AES block 2, 3 - store result

	rev32	v2.16b, v30.16b	// CTR block 10
	add	v30.4s, v30.4s, v31.4s	// CTR block 10

	eor3	v6.16b, v14.16b, v6.16b, v27.16b	// AES block 6 - result

	rev32	v3.16b, v30.16b	// CTR block 11
	add	v30.4s, v30.4s, v31.4s	// CTR block 11

	eor3	v4.16b, v12.16b, v4.16b, v27.16b	// AES block 4 - result
	eor3	v5.16b, v13.16b, v5.16b, v27.16b	// AES block 5 - result
	stp	q4, q5, [x2], #32	// AES block 4, 5 - store result

	eor3	v7.16b, v15.16b, v7.16b, v27.16b	// AES block 7 - result
	stp	q6, q7, [x2], #32	// AES block 6, 7 - store result
	rev32	v4.16b, v30.16b	// CTR block 12

	cmp	x0, x5	// check if we have <= 8 blocks
	add	v30.4s, v30.4s, v31.4s	// CTR block 12
	b.ge	Lgcm_dec_prepretail	// do prepretail

Lgcm_dec_main_loop:	// main loop start
	ldr	q23, [x3, #176]	// load h7l | h7h
	ext	v23.16b, v23.16b, v23.16b, #8
	ldr	q25, [x3, #208]	// load h8l | h8h
	ext	v25.16b, v25.16b, v25.16b, #8

	rev64	v9.16b, v9.16b	// GHASH block 8k+1
	rev64	v8.16b, v8.16b	// GHASH block 8k
	ext	v19.16b, v19.16b, v19.16b, #8	// PRE 0

	rev64	v14.16b, v14.16b	// GHASH block 8k+6
	ldr	q20, [x3, #128]	// load h5l | h5h
	ext	v20.16b, v20.16b, v20.16b, #8
	ldr	q22, [x3, #160]	// load h6l | h6h
	ext	v22.16b, v22.16b, v22.16b, #8

	eor	v8.16b, v8.16b, v19.16b	// PRE 1
	rev32	v5.16b, v30.16b	// CTR block 8k+13
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+13

	rev64	v10.16b, v10.16b	// GHASH block 8k+2
	rev64	v12.16b, v12.16b	// GHASH block 8k+4
	ldp	q26, q27, [x8, #0]	// load rk0, rk1

	rev32	v6.16b, v30.16b	// CTR block 8k+14
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+14
	ldr	q21, [x3, #144]	// load h6k | h5k
	ldr	q24, [x3, #192]	// load h8k | h7k

	pmull2	v16.1q, v9.2d, v23.2d	// GHASH block 8k+1 - high
	pmull2	v17.1q, v8.2d, v25.2d	// GHASH block 8k - high
	rev64	v11.16b, v11.16b	// GHASH block 8k+3

	rev32	v7.16b, v30.16b	// CTR block 8k+15
	trn1	v18.2d, v9.2d, v8.2d	// GHASH block 8k, 8k+1 - mid
	rev64	v13.16b, v13.16b	// GHASH block 8k+5

	pmull	v23.1q, v9.1d, v23.1d	// GHASH block 8k+1 - low
	pmull	v19.1q, v8.1d, v25.1d	// GHASH block 8k - low
	trn2	v8.2d, v9.2d, v8.2d	// GHASH block 8k, 8k+1 - mid

	pmull2	v29.1q, v10.2d, v22.2d	// GHASH block 8k+2 - high
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 0
	pmull2	v9.1q, v11.2d, v20.2d	// GHASH block 8k+3 - high

	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 0
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 0
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 0

	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 0
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 0
	eor	v17.16b, v17.16b, v16.16b	// GHASH block 8k+1 - high

	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 0
	eor	v8.16b, v8.16b, v18.16b	// GHASH block 8k, 8k+1 - mid
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 0

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 1
	eor	v19.16b, v19.16b, v23.16b	// GHASH block 8k+1 - low
	// GHASH block 8k+2, 8k+3 - high
	eor3	v17.16b, v17.16b, v29.16b, v9.16b

	ldp	q28, q26, [x8, #32]	// load rk2, rk3
	trn1	v29.2d, v11.2d, v10.2d	// GHASH block 8k+2, 8k+3 - mid
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 1

	pmull	v22.1q, v10.1d, v22.1d	// GHASH block 8k+2 - low
	trn2	v10.2d, v11.2d, v10.2d	// GHASH block 8k+2, 8k+3 - mid
	pmull2	v18.1q, v8.2d, v24.2d	// GHASH block 8k - mid

	ldr	q23, [x3, #80]	// load h3l | h3h
	ext	v23.16b, v23.16b, v23.16b, #8
	ldr	q25, [x3, #112]	// load h4l | h4h
	ext	v25.16b, v25.16b, v25.16b, #8
	pmull	v24.1q, v8.1d, v24.1d	// GHASH block 8k+1 - mid
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 1

	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 1
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 1
	pmull	v20.1q, v11.1d, v20.1d	// GHASH block 8k+3 - low

	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 1
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 1
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 1

	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 2
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 2
	// GHASH block 8k+2, 8k+3 - low
	eor3	v19.16b, v19.16b, v22.16b, v20.16b

	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 2
	eor	v10.16b, v10.16b, v29.16b	// GHASH block 8k+2, 8k+3 - mid
	ldr	q20, [x3, #32]	// load h1l | h1h
	ext	v20.16b, v20.16b, v20.16b, #8
	ldr	q22, [x3, #64]	// load h2l | h2h
	ext	v22.16b, v22.16b, v22.16b, #8

	eor	v18.16b, v18.16b, v24.16b	// GHASH block 8k+1 - mid
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 2
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 2

	trn1	v16.2d, v13.2d, v12.2d	// GHASH block 8k+4, 8k+5 - mid
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 2
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 2

	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 2
	pmull2	v29.1q, v10.2d, v21.2d	// GHASH block 8k+2 - mid
	pmull	v21.1q, v10.1d, v21.1d	// GHASH block 8k+3 - mid

	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 3
	rev64	v15.16b, v15.16b	// GHASH block 8k+7
	pmull2	v8.1q, v12.2d, v25.2d	// GHASH block 8k+4 - high

	ldp	q27, q28, [x8, #64]	// load rk4, rk5
	pmull	v25.1q, v12.1d, v25.1d	// GHASH block 8k+4 - low
	// GHASH block 8k+2, 8k+3 - mid
	eor3	v18.16b, v18.16b, v21.16b, v29.16b

	ldr	q21, [x3, #48]	// load h2k | h1k
	ldr	q24, [x3, #96]	// load h4k | h3k
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 3
	trn2	v12.2d, v13.2d, v12.2d	// GHASH block 8k+4, 8k+5 - mid

	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 3
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 3
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 3

	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 3
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 3
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 3

	pmull2	v10.1q, v13.2d, v23.2d	// GHASH block 8k+5 - high
	pmull	v23.1q, v13.1d, v23.1d	// GHASH block 8k+5 - low
	pmull2	v11.1q, v14.2d, v22.2d	// GHASH block 8k+6 - high

	pmull	v22.1q, v14.1d, v22.1d	// GHASH block 8k+6 - low
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 4
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 4

	eor	v12.16b, v12.16b, v16.16b	// GHASH block 8k+4, 8k+5 - mid
	trn1	v13.2d, v15.2d, v14.2d	// GHASH block 8k+6, 8k+7 - mid
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 4

	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 4
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 4
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 4

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 4
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 4
	trn2	v14.2d, v15.2d, v14.2d	// GHASH block 8k+6, 8k+7 - mid

	ldp	q26, q27, [x8, #96]	// load rk6, rk7
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 5
	pmull2	v16.1q, v12.2d, v24.2d	// GHASH block 8k+4 - mid

	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 5
	eor	v14.16b, v14.16b, v13.16b	// GHASH block 8k+6, 8k+7 - mid
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 5

	pmull	v24.1q, v12.1d, v24.1d	// GHASH block 8k+5 - mid
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 5
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 5

	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 5
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 5
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 5

	pmull2	v12.1q, v15.2d, v20.2d	// GHASH block 8k+7 - high
	// GHASH block 8k+4, 8k+5 - mid
	eor3	v18.16b, v18.16b, v24.16b, v16.16b
	// GHASH block 8k+4, 8k+5 - low
	eor3	v19.16b, v19.16b, v25.16b, v23.16b

	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 6
	// GHASH block 8k+4, 8k+5 - high
	eor3	v17.16b, v17.16b, v8.16b, v10.16b
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 6

	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 6
	pmull2	v13.1q, v14.2d, v21.2d	// GHASH block 8k+6 - mid
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 6

	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 6
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 6
	pmull	v20.1q, v15.1d, v20.1d	// GHASH block 8k+7 - low

	pmull	v21.1q, v14.1d, v21.1d	// GHASH block 8k+7 - mid
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 6
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+15

	// GHASH block 8k+6, 8k+7 - high
	eor3	v17.16b, v17.16b, v11.16b, v12.16b
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 6
	ldp	q28, q26, [x8, #128]	// load rk8, rk9

	ldr	d16, [x10]	// MODULO - load modulo constant
	// GHASH block 8k+6, 8k+7 - low
	eor3	v19.16b, v19.16b, v22.16b, v20.16b
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 7

	rev32	v20.16b, v30.16b	// CTR block 8k+16
	// GHASH block 8k+6, 8k+7 - mid
	eor3	v18.16b, v18.16b, v21.16b, v13.16b
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+16

	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 7
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 7
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 7

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 7
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 7
	rev32	v22.16b, v30.16b	// CTR block 8k+17

	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 7
	ext	v21.16b, v17.16b, v17.16b, #8	// MODULO - other top alignment
	pmull	v29.1q, v17.1d, v16.1d	// MODULO - top 64b align with mid

	// MODULO - karatsuba tidy up
	eor3	v18.16b, v18.16b, v17.16b, v19.16b
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 7
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+17

	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 8
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 8
	// AES block 8k+8, 8k+9 - load ciphertext
	ldp	q8, q9, [x0], #32

	// AES block 8k+10, 8k+11 - load ciphertext
	ldp	q10, q11, [x0], #32
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 8
	rev32	v23.16b, v30.16b	// CTR block 8k+18

	// AES block 8k+12, 8k+13 - load ciphertext
	ldp	q12, q13, [x0], #32
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 8
	// MODULO - fold into mid
	eor3	v18.16b, v18.16b, v29.16b, v21.16b

	// AES block 8k+14, 8k+15 - load ciphertext
	ldp	q14, q15, [x0], #32
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 8
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+18

	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 8
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 8
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 8

	aese	v0.16b, v26.16b	// AES block 8k+8 - round 9
	aese	v1.16b, v26.16b	// AES block 8k+9 - round 9
	ldr	q27, [x8, #160]	// load rk10

	aese	v6.16b, v26.16b	// AES block 8k+14 - round 9
	pmull	v17.1q, v18.1d, v16.1d	// MODULO - mid 64b align with low
	aese	v2.16b, v26.16b	// AES block 8k+10 - round 9

	aese	v7.16b, v26.16b	// AES block 8k+15 - round 9
	aese	v4.16b, v26.16b	// AES block 8k+12 - round 9
	ext	v21.16b, v18.16b, v18.16b, #8	// MODULO - other mid alignment

	rev32	v25.16b, v30.16b	// CTR block 8k+19
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+19

	aese	v3.16b, v26.16b	// AES block 8k+11 - round 9
	aese	v5.16b, v26.16b	// AES block 8k+13 - round 9
	eor3	v1.16b, v9.16b, v1.16b, v27.16b	// AES block 8k+9 - result

	eor3	v0.16b, v8.16b, v0.16b, v27.16b	// AES block 8k+8 - result
	// AES block 8k+15 - result
	eor3	v7.16b, v15.16b, v7.16b, v27.16b
	// AES block 8k+14 - result
	eor3	v6.16b, v14.16b, v6.16b, v27.16b

	// AES block 8k+10 - result
	eor3	v2.16b, v10.16b, v2.16b, v27.16b
	stp	q0, q1, [x2], #32	// AES block 8k+8, 8k+9 - store result
	mov	v1.16b, v22.16b	// CTR block 8k+17

	// AES block 8k+12 - result
	eor3	v4.16b, v12.16b, v4.16b, v27.16b
	// MODULO - fold into low
	eor3	v19.16b, v19.16b, v17.16b, v21.16b
	mov	v0.16b, v20.16b	// CTR block 8k+16

	// AES block 8k+11 - result
	eor3	v3.16b, v11.16b, v3.16b, v27.16b
	cmp	x0, x5	// .LOOP CONTROL
	stp	q2, q3, [x2], #32	// AES block 8k+10, 8k+11 - store result

	// AES block 8k+13 - result
	eor3	v5.16b, v13.16b, v5.16b, v27.16b
	mov	v2.16b, v23.16b	// CTR block 8k+18

	stp	q4, q5, [x2], #32	// AES block 8k+12, 8k+13 - store result
	rev32	v4.16b, v30.16b	// CTR block 8k+20
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+20

	stp	q6, q7, [x2], #32	// AES block 8k+14, 8k+15 - store result
	mov	v3.16b, v25.16b	// CTR block 8k+19
	b.lt	Lgcm_dec_main_loop

Lgcm_dec_prepretail:	// PREPRETAIL
	rev64	v11.16b, v11.16b	// GHASH block 8k+3
	ext	v19.16b, v19.16b, v19.16b, #8	// PRE 0
	rev64	v8.16b, v8.16b	// GHASH block 8k

	rev64	v10.16b, v10.16b	// GHASH block 8k+2
	rev32	v5.16b, v30.16b	// CTR block 8k+13
	ldp	q26, q27, [x8, #0]	// load rk0, rk1

	ldr	q23, [x3, #176]	// load h7l | h7h
	ext	v23.16b, v23.16b, v23.16b, #8
	ldr	q25, [x3, #208]	// load h8l | h8h
	ext	v25.16b, v25.16b, v25.16b, #8
	eor	v8.16b, v8.16b, v19.16b	// PRE 1
	rev64	v9.16b, v9.16b	// GHASH block 8k+1

	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+13
	ldr	q20, [x3, #128]	// load h5l | h5h
	ext	v20.16b, v20.16b, v20.16b, #8
	ldr	q22, [x3, #160]	// load h6l | h6h
	ext	v22.16b, v22.16b, v22.16b, #8
	rev64	v13.16b, v13.16b	// GHASH block 8k+5

	rev64	v12.16b, v12.16b	// GHASH block 8k+4

	rev64	v14.16b, v14.16b	// GHASH block 8k+6

	ldr	q21, [x3, #144]	// load h6k | h5k
	ldr	q24, [x3, #192]	// load h8k | h7k
	rev32	v6.16b, v30.16b	// CTR block 8k+14
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+14

	pmull2	v16.1q, v9.2d, v23.2d	// GHASH block 8k+1 - high
	pmull	v19.1q, v8.1d, v25.1d	// GHASH block 8k - low
	pmull2	v17.1q, v8.2d, v25.2d	// GHASH block 8k - high

	trn1	v18.2d, v9.2d, v8.2d	// GHASH block 8k, 8k+1 - mid
	trn2	v8.2d, v9.2d, v8.2d	// GHASH block 8k, 8k+1 - mid
	pmull2	v29.1q, v10.2d, v22.2d	// GHASH block 8k+2 - high

	pmull	v23.1q, v9.1d, v23.1d	// GHASH block 8k+1 - low
	pmull2	v9.1q, v11.2d, v20.2d	// GHASH block 8k+3 - high
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 0

	eor	v17.16b, v17.16b, v16.16b	// GHASH block 8k+1 - high
	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 0
	eor	v8.16b, v8.16b, v18.16b	// GHASH block 8k, 8k+1 - mid

	pmull	v22.1q, v10.1d, v22.1d	// GHASH block 8k+2 - low
	rev32	v7.16b, v30.16b	// CTR block 8k+15
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 0

	// GHASH block 8k+2, 8k+3 - high
	eor3	v17.16b, v17.16b, v29.16b, v9.16b
	trn1	v29.2d, v11.2d, v10.2d	// GHASH block 8k+2, 8k+3 - mid
	trn2	v10.2d, v11.2d, v10.2d	// GHASH block 8k+2, 8k+3 - mid

	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 0
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 0
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 0

	pmull2	v18.1q, v8.2d, v24.2d	// GHASH block 8k - mid
	pmull	v24.1q, v8.1d, v24.1d	// GHASH block 8k+1 - mid
	pmull	v20.1q, v11.1d, v20.1d	// GHASH block 8k+3 - low

	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 1
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 0
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 0

	eor	v19.16b, v19.16b, v23.16b	// GHASH block 8k+1 - low
	eor	v10.16b, v10.16b, v29.16b	// GHASH block 8k+2, 8k+3 - mid
	eor	v18.16b, v18.16b, v24.16b	// GHASH block 8k+1 - mid

	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 1
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 1
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 1

	ldp	q28, q26, [x8, #32]	// load rk2, rk3
	// GHASH block 8k+2, 8k+3 - low
	eor3	v19.16b, v19.16b, v22.16b, v20.16b
	pmull2	v29.1q, v10.2d, v21.2d	// GHASH block 8k+2 - mid

	ldr	q23, [x3, #80]	// load h3l | h3h
	ext	v23.16b, v23.16b, v23.16b, #8
	ldr	q25, [x3, #112]	// load h4l | h4h
	ext	v25.16b, v25.16b, v25.16b, #8
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 1
	pmull	v21.1q, v10.1d, v21.1d	// GHASH block 8k+3 - mid

	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 1
	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 1
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 1

	ldr	q20, [x3, #32]	// load h1l | h1h
	ext	v20.16b, v20.16b, v20.16b, #8
	ldr	q22, [x3, #64]	// load h2l | h2h
	ext	v22.16b, v22.16b, v22.16b, #8
	// GHASH block 8k+2, 8k+3 - mid
	eor3	v18.16b, v18.16b, v21.16b, v29.16b

	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 2
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 2
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 2

	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 2
	trn1	v16.2d, v13.2d, v12.2d	// GHASH block 8k+4, 8k+5 - mid
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 2

	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 2
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 2
	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 2

	pmull2	v8.1q, v12.2d, v25.2d	// GHASH block 8k+4 - high
	pmull	v25.1q, v12.1d, v25.1d	// GHASH block 8k+4 - low
	trn2	v12.2d, v13.2d, v12.2d	// GHASH block 8k+4, 8k+5 - mid

	ldp	q27, q28, [x8, #64]	// load rk4, rk5
	rev64	v15.16b, v15.16b	// GHASH block 8k+7
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 3

	ldr	q21, [x3, #48]	// load h2k | h1k
	ldr	q24, [x3, #96]	// load h4k | h3k
	pmull2	v10.1q, v13.2d, v23.2d	// GHASH block 8k+5 - high
	pmull	v23.1q, v13.1d, v23.1d	// GHASH block 8k+5 - low

	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 3
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 3
	trn1	v13.2d, v15.2d, v14.2d	// GHASH block 8k+6, 8k+7 - mid

	pmull2	v11.1q, v14.2d, v22.2d	// GHASH block 8k+6 - high
	pmull	v22.1q, v14.1d, v22.1d	// GHASH block 8k+6 - low
	trn2	v14.2d, v15.2d, v14.2d	// GHASH block 8k+6, 8k+7 - mid

	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 3
	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 3
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 3

	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 3
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 3
	eor	v12.16b, v12.16b, v16.16b	// GHASH block 8k+4, 8k+5 - mid

	// GHASH block 8k+4, 8k+5 - high
	eor3	v17.16b, v17.16b, v8.16b, v10.16b
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 4
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 4

	eor	v14.16b, v14.16b, v13.16b	// GHASH block 8k+6, 8k+7 - mid
	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 4
	pmull2	v16.1q, v12.2d, v24.2d	// GHASH block 8k+4 - mid

	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 4
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 4
	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 4

	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 4
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 4
	pmull	v24.1q, v12.1d, v24.1d	// GHASH block 8k+5 - mid

	pmull2	v12.1q, v15.2d, v20.2d	// GHASH block 8k+7 - high
	pmull2	v13.1q, v14.2d, v21.2d	// GHASH block 8k+6 - mid
	pmull	v21.1q, v14.1d, v21.1d	// GHASH block 8k+7 - mid

	ldp	q26, q27, [x8, #96]	// load rk6, rk7
	// GHASH block 8k+4, 8k+5 - mid
	eor3	v18.16b, v18.16b, v24.16b, v16.16b
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 5

	ldr	d16, [x10]	// MODULO - load modulo constant
	pmull	v20.1q, v15.1d, v20.1d	// GHASH block 8k+7 - low
	// GHASH block 8k+4, 8k+5 - low
	eor3	v19.16b, v19.16b, v25.16b, v23.16b

	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 5
	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 5
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 5

	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 5
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 5
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 5

	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 5
	// GHASH block 8k+6, 8k+7 - mid
	eor3	v18.16b, v18.16b, v21.16b, v13.16b
	// GHASH block 8k+6, 8k+7 - low
	eor3	v19.16b, v19.16b, v22.16b, v20.16b

	aese	v4.16b, v26.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 6
	aese	v1.16b, v26.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 6
	aese	v2.16b, v26.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 6

	// GHASH block 8k+6, 8k+7 - high
	eor3	v17.16b, v17.16b, v11.16b, v12.16b
	aese	v5.16b, v26.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 6
	aese	v0.16b, v26.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 6

	aese	v3.16b, v26.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 6
	aese	v6.16b, v26.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 6
	aese	v7.16b, v26.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 6

	aese	v4.16b, v27.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 7
	// MODULO - karatsuba tidy up
	eor3	v18.16b, v18.16b, v17.16b, v19.16b
	ldp	q28, q26, [x8, #128]	// load rk8, rk9

	pmull	v29.1q, v17.1d, v16.1d	// MODULO - top 64b align with mid
	aese	v3.16b, v27.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 7
	ext	v21.16b, v17.16b, v17.16b, #8	// MODULO - other top alignment

	aese	v5.16b, v27.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 7
	aese	v6.16b, v27.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 7
	aese	v0.16b, v27.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 7

	aese	v7.16b, v27.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 7
	aese	v1.16b, v27.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 7
	aese	v2.16b, v27.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 7

	// MODULO - fold into mid
	eor3	v18.16b, v18.16b, v29.16b, v21.16b
	ldr	q27, [x8, #160]	// load rk10

	aese	v3.16b, v28.16b
	aesmc	v3.16b, v3.16b	// AES block 8k+11 - round 8
	aese	v0.16b, v28.16b
	aesmc	v0.16b, v0.16b	// AES block 8k+8 - round 8

	pmull	v17.1q, v18.1d, v16.1d	// MODULO - mid 64b align with low
	aese	v6.16b, v28.16b
	aesmc	v6.16b, v6.16b	// AES block 8k+14 - round 8
	ext	v21.16b, v18.16b, v18.16b, #8	// MODULO - other mid alignment

	aese	v2.16b, v28.16b
	aesmc	v2.16b, v2.16b	// AES block 8k+10 - round 8
	aese	v1.16b, v28.16b
	aesmc	v1.16b, v1.16b	// AES block 8k+9 - round 8
	aese	v7.16b, v28.16b
	aesmc	v7.16b, v7.16b	// AES block 8k+15 - round 8

	aese	v6.16b, v26.16b	// AES block 8k+14 - round 9
	aese	v5.16b, v28.16b
	aesmc	v5.16b, v5.16b	// AES block 8k+13 - round 8
	aese	v4.16b, v28.16b
	aesmc	v4.16b, v4.16b	// AES block 8k+12 - round 8

	// MODULO - fold into low
	eor3	v19.16b, v19.16b, v17.16b, v21.16b
	add	v30.4s, v30.4s, v31.4s	// CTR block 8k+15
	aese	v2.16b, v26.16b	// AES block 8k+10 - round 9

	aese	v3.16b, v26.16b	// AES block 8k+11 - round 9
	aese	v5.16b, v26.16b	// AES block 8k+13 - round 9
	aese	v0.16b, v26.16b	// AES block 8k+8 - round 9

	aese	v4.16b, v26.16b	// AES block 8k+12 - round 9
	aese	v1.16b, v26.16b	// AES block 8k+9 - round 9
	aese	v7.16b, v26.16b	// AES block 8k+15 - round 9

Lgcm_dec_tail:	// TAIL

	mov	v29.16b, v27.16b
	// main_end_input_ptr is number of bytes left to process
	sub	x5, x4, x0

	cmp	x5, #112

	ldp	q24, q25, [x3, #192]	// load h8k | h7k
	ext	v25.16b, v25.16b, v25.16b, #8
	ldr	q9, [x0], #16	// AES block 8k+8 - load ciphertext

	ldp	q20, q21, [x3, #128]	// load h5l | h5h
	ext	v20.16b, v20.16b, v20.16b, #8
	ext	v16.16b, v19.16b, v19.16b, #8	// prepare final partial tag

	ldp	q22, q23, [x3, #160]	// load h6l | h6h
	ext	v22.16b, v22.16b, v22.16b, #8
	ext	v23.16b, v23.16b, v23.16b, #8

	// AES block 8k+8 - result
	eor3	v12.16b, v9.16b, v0.16b, v29.16b
	b.gt	Lgcm_dec_blocks_more_than_7

	cmp	x5, #96
	mov	v7.16b, v6.16b
	movi	v19.8b, #0

	movi	v17.8b, #0
	mov	v6.16b, v5.16b
	mov	v5.16b, v4.16b

	mov	v4.16b, v3.16b
	mov	v3.16b, v2.16b
	mov	v2.16b, v1.16b

	movi	v18.8b, #0
	sub	v30.4s, v30.4s, v31.4s
	b.gt	Lgcm_dec_blocks_more_than_6

	cmp	x5, #80
	sub	v30.4s, v30.4s, v31.4s

	mov	v7.16b, v6.16b
	mov	v6.16b, v5.16b
	mov	v5.16b, v4.16b

	mov	v4.16b, v3.16b
	mov	v3.16b, v1.16b
	b.gt	Lgcm_dec_blocks_more_than_5

	cmp	x5, #64

	mov	v7.16b, v6.16b
	mov	v6.16b, v5.16b
	mov	v5.16b, v4.16b

	mov	v4.16b, v1.16b
	sub	v30.4s, v30.4s, v31.4s
	b.gt	Lgcm_dec_blocks_more_than_4

	sub	v30.4s, v30.4s, v31.4s
	mov	v7.16b, v6.16b
	mov	v6.16b, v5.16b

	mov	v5.16b, v1.16b
	cmp	x5, #48
	b.gt	Lgcm_dec_blocks_more_than_3

	sub	v30.4s, v30.4s, v31.4s
	mov	v7.16b, v6.16b
	cmp	x5, #32

	ldr	q24, [x3, #96]	// load h4k | h3k
	mov	v6.16b, v1.16b
	b.gt	Lgcm_dec_blocks_more_than_2

	cmp	x5, #16

	mov	v7.16b, v1.16b
	sub	v30.4s, v30.4s, v31.4s
	b.gt	Lgcm_dec_blocks_more_than_1

	sub	v30.4s, v30.4s, v31.4s
	ldr	q21, [x3, #48]	// load h2k | h1k
	b	Lgcm_dec_blocks_less_than_1
Lgcm_dec_blocks_more_than_7:	// blocks left > 7
	rev64	v8.16b, v9.16b	// GHASH final-7 block

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v18.d[0], v24.d[1]	// GHASH final-7 block - mid

	pmull	v19.1q, v8.1d, v25.1d	// GHASH final-7 block - low
	ins	v27.d[0], v8.d[1]	// GHASH final-7 block - mid

	movi	v16.8b, #0	// suppress further partial tag feed in
	ldr	q9, [x0], #16	// AES final-6 block - load ciphertext

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-7 block - mid

	pmull2	v17.1q, v8.2d, v25.2d	// GHASH final-7 block - high
	st1	{ v12.16b}, [x2], #16	// AES final-7 block - store result
	// AES final-6 block - result
	eor3	v12.16b, v9.16b, v1.16b, v29.16b

	pmull	v18.1q, v27.1d, v18.1d	// GHASH final-7 block - mid
Lgcm_dec_blocks_more_than_6:	// blocks left > 6

	rev64	v8.16b, v9.16b	// GHASH final-6 block

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v27.d[0], v8.d[1]	// GHASH final-6 block - mid

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-6 block - mid

	pmull	v26.1q, v8.1d, v23.1d	// GHASH final-6 block - low
	ldr	q9, [x0], #16	// AES final-5 block - load ciphertext
	movi	v16.8b, #0	// suppress further partial tag feed in

	pmull	v27.1q, v27.1d, v24.1d	// GHASH final-6 block - mid
	st1	{ v12.16b}, [x2], #16	// AES final-6 block - store result
	pmull2	v28.1q, v8.2d, v23.2d	// GHASH final-6 block - high

	eor	v19.16b, v19.16b, v26.16b	// GHASH final-6 block - low
	eor	v17.16b, v17.16b, v28.16b	// GHASH final-6 block - high

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-6 block - mid
	// AES final-5 block - result
	eor3	v12.16b, v9.16b, v2.16b, v29.16b
Lgcm_dec_blocks_more_than_5:	// blocks left > 5

	rev64	v8.16b, v9.16b	// GHASH final-5 block

	ldr	q9, [x0], #16	// AES final-4 block - load ciphertext
	st1	{ v12.16b}, [x2], #16	// AES final-5 block - store result

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v27.d[0], v8.d[1]	// GHASH final-5 block - mid

	// AES final-4 block - result
	eor3	v12.16b, v9.16b, v3.16b, v29.16b

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-5 block - mid

	ins	v27.d[1], v27.d[0]	// GHASH final-5 block - mid
	pmull	v26.1q, v8.1d, v22.1d	// GHASH final-5 block - low
	movi	v16.8b, #0	// suppress further partial tag feed in

	pmull2	v27.1q, v27.2d, v21.2d	// GHASH final-5 block - mid
	pmull2	v28.1q, v8.2d, v22.2d	// GHASH final-5 block - high
	eor	v19.16b, v19.16b, v26.16b	// GHASH final-5 block - low

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-5 block - mid
	eor	v17.16b, v17.16b, v28.16b	// GHASH final-5 block - high
Lgcm_dec_blocks_more_than_4:	// blocks left > 4

	rev64	v8.16b, v9.16b	// GHASH final-4 block

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag
	ldr	q9, [x0], #16	// AES final-3 block - load ciphertext

	ins	v27.d[0], v8.d[1]	// GHASH final-4 block - mid
	movi	v16.8b, #0	// suppress further partial tag feed in
	pmull2	v28.1q, v8.2d, v20.2d	// GHASH final-4 block - high

	pmull	v26.1q, v8.1d, v20.1d	// GHASH final-4 block - low

	eor	v17.16b, v17.16b, v28.16b	// GHASH final-4 block - high

	st1	{ v12.16b}, [x2], #16	// AES final-4 block - store result
	eor	v27.8b, v27.8b, v8.8b	// GHASH final-4 block - mid

	// AES final-3 block - result
	eor3	v12.16b, v9.16b, v4.16b, v29.16b
	eor	v19.16b, v19.16b, v26.16b	// GHASH final-4 block - low

	pmull	v27.1q, v27.1d, v21.1d	// GHASH final-4 block - mid

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-4 block - mid
Lgcm_dec_blocks_more_than_3:	// blocks left > 3

	st1	{ v12.16b}, [x2], #16	// AES final-3 block - store result
	rev64	v8.16b, v9.16b	// GHASH final-3 block

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	ins	v27.d[0], v8.d[1]	// GHASH final-3 block - mid

	ldr	q25, [x3, #112]	// load h4l | h4h
	ext	v25.16b, v25.16b, v25.16b, #8
	ldr	q24, [x3, #96]	// load h4k | h3k

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-3 block - mid

	ldr	q9, [x0], #16	// AES final-2 block - load ciphertext

	ins	v27.d[1], v27.d[0]	// GHASH final-3 block - mid
	pmull	v26.1q, v8.1d, v25.1d	// GHASH final-3 block - low
	pmull2	v28.1q, v8.2d, v25.2d	// GHASH final-3 block - high

	movi	v16.8b, #0	// suppress further partial tag feed in
	// AES final-2 block - result
	eor3	v12.16b, v9.16b, v5.16b, v29.16b
	eor	v19.16b, v19.16b, v26.16b	// GHASH final-3 block - low

	pmull2	v27.1q, v27.2d, v24.2d	// GHASH final-3 block - mid

	eor	v17.16b, v17.16b, v28.16b	// GHASH final-3 block - high
	eor	v18.16b, v18.16b, v27.16b	// GHASH final-3 block - mid
Lgcm_dec_blocks_more_than_2:	// blocks left > 2

	rev64	v8.16b, v9.16b	// GHASH final-2 block

	st1	{ v12.16b}, [x2], #16	// AES final-2 block - store result

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag
	ldr	q23, [x3, #80]	// load h3l | h3h
	ext	v23.16b, v23.16b, v23.16b, #8
	movi	v16.8b, #0	// suppress further partial tag feed in

	ins	v27.d[0], v8.d[1]	// GHASH final-2 block - mid

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-2 block - mid

	pmull	v26.1q, v8.1d, v23.1d	// GHASH final-2 block - low

	pmull2	v28.1q, v8.2d, v23.2d	// GHASH final-2 block - high
	pmull	v27.1q, v27.1d, v24.1d	// GHASH final-2 block - mid
	ldr	q9, [x0], #16	// AES final-1 block - load ciphertext

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-2 block - mid

	eor	v19.16b, v19.16b, v26.16b	// GHASH final-2 block - low

	// AES final-1 block - result
	eor3	v12.16b, v9.16b, v6.16b, v29.16b
	eor	v17.16b, v17.16b, v28.16b	// GHASH final-2 block - high
Lgcm_dec_blocks_more_than_1:	// blocks left > 1

	st1	{ v12.16b}, [x2], #16	// AES final-1 block - store result
	rev64	v8.16b, v9.16b	// GHASH final-1 block

	ldr	q22, [x3, #64]	// load h2l | h2h
	ext	v22.16b, v22.16b, v22.16b, #8

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	movi	v16.8b, #0	// suppress further partial tag feed in

	ins	v27.d[0], v8.d[1]	// GHASH final-1 block - mid

	ldr	q9, [x0], #16	// AES final block - load ciphertext
	pmull2	v28.1q, v8.2d, v22.2d	// GHASH final-1 block - high

	eor	v27.8b, v27.8b, v8.8b	// GHASH final-1 block - mid
	eor	v17.16b, v17.16b, v28.16b	// GHASH final-1 block - high
	ldr	q21, [x3, #48]	// load h2k | h1k

	ins	v27.d[1], v27.d[0]	// GHASH final-1 block - mid
	// AES final block - result
	eor3	v12.16b, v9.16b, v7.16b, v29.16b

	pmull	v26.1q, v8.1d, v22.1d	// GHASH final-1 block - low

	pmull2	v27.1q, v27.2d, v21.2d	// GHASH final-1 block - mid

	eor	v19.16b, v19.16b, v26.16b	// GHASH final-1 block - low

	eor	v18.16b, v18.16b, v27.16b	// GHASH final-1 block - mid
Lgcm_dec_blocks_less_than_1:	// blocks left <= 1

	and	x1, x1, #127	// bit_length %= 128

	sub	x1, x1, #128	// bit_length -= 128

	neg	x1, x1	// bit_length = 128 - #bits in input (in range [1,128])

	mvn	x6, xzr	// temp0_x = 0xffffffffffffffff
	and	x1, x1, #127	// bit_length %= 128

	lsr	x6, x6, x1	// temp0_x is mask for top 64b of last block
	cmp	x1, #64
	mvn	x7, xzr	// temp1_x = 0xffffffffffffffff

	csel	x13, x7, x6, lt
	csel	x14, x6, xzr, lt

	mov	v0.d[1], x14
	mov	v0.d[0], x13	// ctr0b is mask for last block

	ldr	q20, [x3, #32]	// load h1l | h1h
	ext	v20.16b, v20.16b, v20.16b, #8
	// load existing bytes where the possibly partial last block is to be
	// stored
	ld1	{ v26.16b}, [x2]

	// possibly partial last block has zeroes in highest bits
	and	v9.16b, v9.16b, v0.16b

	rev64	v8.16b, v9.16b	// GHASH final block

	eor	v8.16b, v8.16b, v16.16b	// feed in partial tag

	pmull2	v28.1q, v8.2d, v20.2d	// GHASH final block - high
	ins	v16.d[0], v8.d[1]	// GHASH final block - mid

	eor	v17.16b, v17.16b, v28.16b	// GHASH final block - high
	eor	v16.8b, v16.8b, v8.8b	// GHASH final block - mid

	// insert existing bytes in top end of result before storing
	bif	v12.16b, v26.16b, v0.16b

	pmull	v16.1q, v16.1d, v21.1d	// GHASH final block - mid
	st1	{ v12.16b}, [x2]	// store all 16B

	pmull	v26.1q, v8.1d, v20.1d	// GHASH final block - low

	eor	v18.16b, v18.16b, v16.16b	// GHASH final block - mid
	ldr	d16, [x10]	// MODULO - load modulo constant

	eor	v19.16b, v19.16b, v26.16b	// GHASH final block - low

	eor	v14.16b, v17.16b, v19.16b	// MODULO - karatsuba tidy up

	pmull	v21.1q, v17.1d, v16.1d	// MODULO - top 64b align with mid
	ext	v17.16b, v17.16b, v17.16b, #8	// MODULO - other top alignment

	eor	v18.16b, v18.16b, v14.16b	// MODULO - karatsuba tidy up

	// MODULO - fold into mid
	eor3	v18.16b, v18.16b, v17.16b, v21.16b

	pmull	v17.1q, v18.1d, v16.1d	// MODULO - mid 64b align with low
	ext	v18.16b, v18.16b, v18.16b, #8	// MODULO - other mid alignment

	// MODULO - fold into low
	eor3	v19.16b, v19.16b, v18.16b, v17.16b
	ext	v19.16b, v19.16b, v19.16b, #8
	rev64	v19.16b, v19.16b
	st1	{ v19.16b }, [x3]
	rev32	v30.16b, v30.16b

	str	q30, [x16]	// store the updated counter

	mov	x0, x9

	ldp	d10, d11, [sp, #16]
	ldp	d12, d13, [sp, #32]
	ldp	d14, d15, [sp, #48]
	ldp	d8, d9, [sp], #80
	ret
Lgcm_dec_ret:
	mov	w0, #0x0
	ret
SET_SIZE(aes_gcm_dec_128_eor3_zfs)
#endif /* __APPLE__ */


SECTION_STATIC
.byte	71,72,65,83,72,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
.align	2
#endif
