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

/*
 * Apple M1-M5 AES-128-GCM fused kernels derived from OpenSSL 3.6.3's
 * aes-gcm-armv8-unroll8_64 implementation.  The opaque words preserve the
 * audited instruction schedule while avoiding an assembler dependency on
 * ARMv8.2 SHA3/EOR3 mnemonics in older KDK toolchains.
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
	.long	0xb40079a1, 0x6dbb27e8, 0xd343fc29, 0xaa0403f0
	.long	0xaa0503e8, 0x6d012fea, 0x6d0237ec, 0x6d033fee
	.long	0xd2f84005, 0xa9047fe5, 0x910103ea, 0xd2c0002f
	.long	0x4f00e41f, 0x4e181dff, 0xaa0903e5, 0x4c407200
	.long	0xd10004a5, 0x9279e0a5, 0x6e20081e, 0x4ebf87de
	.long	0x6e200bc1, 0x4ebf87de, 0x6e200bc2, 0x4ebf87de
	.long	0x6e200bc3, 0x4ebf87de, 0x6e200bc4, 0x4ebf87de
	.long	0x6e200bc5, 0x4ebf87de, 0xad406d1a, 0x6e200bc6
	.long	0x4ebf87de, 0x6e200bc7, 0x4ebf87de, 0x4e284b44
	.long	0x4e286884, 0x4e284b46, 0x4e2868c6, 0x4e284b43
	.long	0x4e286863, 0x4e284b40, 0x4e286800, 0x4e284b41
	.long	0x4e286821, 0x4e284b42, 0x4e286842, 0x4e284b47
	.long	0x4e2868e7, 0x4e284b45, 0x4e2868a5, 0xad41691c
	.long	0x4e284b63, 0x4e286863, 0x4e284b67, 0x4e2868e7
	.long	0x4e284b65, 0x4e2868a5, 0x4e284b64, 0x4e286884
	.long	0x4e284b62, 0x4e286842, 0x4e284b66, 0x4e2868c6
	.long	0x4e284b60, 0x4e286800, 0x4e284b85, 0x4e2868a5
	.long	0x4e284b61, 0x4e286821, 0x4e284b80, 0x4e286800
	.long	0x4e284b82, 0x4e286842, 0x4e284b83, 0x4e286863
	.long	0x4e284b87, 0x4e2868e7, 0x4e284b81, 0x4e286821
	.long	0x4e284b86, 0x4e2868c6, 0x4e284b84, 0x4e286884
	.long	0x4e284b42, 0x4e286842, 0xad42711b, 0x4e284b45
	.long	0x4e2868a5, 0x4e284b40, 0x4e286800, 0x4e284b44
	.long	0x4e286884, 0x4e284b43, 0x4e286863, 0x4e284b46
	.long	0x4e2868c6, 0x4e284b47, 0x4e2868e7, 0x4e284b66
	.long	0x4e2868c6, 0x4e284b41, 0x4e286821, 0x4e284b65
	.long	0x4e2868a5, 0x4e284b67, 0x4e2868e7, 0x4e284b64
	.long	0x4e286884, 0x4e284b60, 0x4e286800, 0x4e284b61
	.long	0x4e286821, 0x4e284b62, 0x4e286842, 0x4e284b63
	.long	0x4e286863, 0x4e284b87, 0x4e2868e7, 0x4e284b80
	.long	0x4e286800, 0xad436d1a, 0x4e284b81, 0x4e286821
	.long	0x4e284b83, 0x4e286863, 0x4e284b82, 0x4e286842
	.long	0x4e284b84, 0x4e286884, 0x4e284b85, 0x4e2868a5
	.long	0x4e284b86, 0x4e2868c6, 0x4e284b44, 0x4e286884
	.long	0x4e284b43, 0x4e286863, 0x4e284b42, 0x4e286842
	.long	0x4e284b47, 0x4e2868e7, 0x4e284b46, 0x4e2868c6
	.long	0x4e284b45, 0x4e2868a5, 0x4e284b40, 0x4e286800
	.long	0x4e284b41, 0x4e286821, 0xad44691c, 0x4e284b65
	.long	0x4e2868a5, 0x4c407073, 0x6e134273, 0x4e200a73
	.long	0x4e284b67, 0x4e2868e7, 0x4e284b64, 0x4e286884
	.long	0x4e284b63, 0x4e286863, 0x4e284b66, 0x4e2868c6
	.long	0x4e284b61, 0x4e286821, 0x4e284b62, 0x4e286842
	.long	0x4e284b60, 0x4e286800, 0x4e284b83, 0x4e286863
	.long	0x4e284b86, 0x4e2868c6, 0x4e284b82, 0x4e286842
	.long	0x4e284b87, 0x4e2868e7, 0x4e284b80, 0x4e286800
	.long	0x3dc0291b, 0x4e284b43, 0x4e284b84, 0x4e286884
	.long	0x4e284b42, 0x4e284b85, 0x4e2868a5, 0x4e284b81
	.long	0x4e286821, 0x4e284b46, 0x4e284b44, 0x8b0000a5
	.long	0x4e284b40, 0x4e284b47, 0x4e284b45, 0x4e284b41
	.long	0x8b410c04, 0xeb05001f, 0x5400462a, 0xacc12408
	.long	0xacc12c0a, 0xacc1340c, 0xacc13c0e, 0xeb05001f
	.long	0xce006d08, 0x6e200bc0, 0x4ebf87de, 0xce016d29
	.long	0xac812448, 0x6e200bc1, 0xce056dad, 0x4ebf87de
	.long	0xce026d4a, 0xce066dce, 0xce046d8c, 0x6e200bc2
	.long	0x4ebf87de, 0xce036d6b, 0xce076def, 0xac812c4a
	.long	0x6e200bc3, 0x4ebf87de, 0xac81344c, 0xac813c4e
	.long	0x6e200bc4, 0x4ebf87de, 0x5400236a, 0x6e200bc5
	.long	0x3dc02074, 0x6e144294, 0x3dc02876, 0x6e1642d6
	.long	0x4ebf87de, 0x4e200929, 0x4e200908, 0x3dc02c77
	.long	0x6e1742f7, 0x3dc03479, 0x6e194339, 0x6e200bc6
	.long	0x4ebf87de, 0x6e134273, 0x3dc02475, 0x3dc03078
	.long	0x4e2009ad, 0x4e20096b, 0xad406d1a, 0x6e331d08
	.long	0x6e200bc7, 0x4e2009ef, 0x4ef7e130, 0x4e20094a
	.long	0x4ef9e111, 0x0ef7e137, 0x4ec82932, 0x0ef9e113
	.long	0x4ec86928, 0x4ef6e15d, 0x4ef4e169, 0x6e371e73
	.long	0x3dc01477, 0x6e1742f7, 0x3dc01c79, 0x6e194339
	.long	0x4e284b45, 0x4e2868a5, 0x4e284b41, 0x4e286821
	.long	0x4e284b44, 0x4e286884, 0x6e301e31, 0x4ebf87de
	.long	0x4e284b42, 0x4e286842, 0x6e321d08, 0x4e284b46
	.long	0x4e2868c6, 0x4e284b61, 0x4e286821, 0x4e284b40
	.long	0x4e286800, 0x4e284b62, 0x4e286842, 0x4e284b43
	.long	0x4e286863, 0x0ef6e156, 0x4e284b65, 0x4e2868a5
	.long	0x4e284b47, 0x4e2868e7, 0x4e284b60, 0x4e286800
	.long	0xce1d2631, 0x4eca297d, 0x4eca696a, 0xad41691c
	.long	0x4e284b64, 0x4e286884, 0x4e284b63, 0x4e286863
	.long	0x0ef4e174, 0x4e284b67, 0x4e2868e7, 0x4e284b66
	.long	0x4e2868c6, 0x4ef8e112, 0x6e3d1d4a, 0x0ef8e118
	.long	0x4e2009ce, 0xce165273, 0x4ef5e15d, 0x6e381e52
	.long	0x0ef5e155, 0x4e284b85, 0x4e2868a5, 0x4e284b84
	.long	0x4e286884, 0x4e284b82, 0x4e286842, 0x4e284b81
	.long	0x4e286821, 0xce157652, 0x4e284b86, 0x4e2868c6
	.long	0x4e284b80, 0x4e286800, 0x4e284b83, 0x4e286863
	.long	0x4e284b87, 0x4e2868e7, 0x4e284b46, 0x4e2868c6
	.long	0x3dc00c75, 0x3dc01878, 0x4e20098c, 0xad42711b
	.long	0x4e284b42, 0x4e286842, 0x4e284b41, 0x4e286821
	.long	0x3dc00874, 0x6e144294, 0x3dc01076, 0x6e1642d6
	.long	0x4ef9e188, 0x0ef9e199, 0x4ecc29b0, 0x4ecc69ac
	.long	0x4e284b40, 0x4e286800, 0x4e284b43, 0x4e286863
	.long	0x4e284b47, 0x4e2868e7, 0x4e284b44, 0x4e286884
	.long	0x4e284b45, 0x4e2868a5, 0x4e284b60, 0x4e286800
	.long	0x4e284b67, 0x4e2868e7, 0x4e284b63, 0x4e286863
	.long	0x4e284b64, 0x4e286884, 0x4e284b65, 0x4e2868a5
	.long	0x4e284b66, 0x4e2868c6, 0x4e284b61, 0x4e286821
	.long	0x4ef7e1aa, 0x6e301d8c, 0x0ef7e1b7, 0x4e284b62
	.long	0x4e286842, 0xad436d1a, 0x4ece29ed, 0x4ef8e190
	.long	0x0ef8e198, 0x4ef6e1cb, 0x4ef4e1ec, 0x4e284b82
	.long	0x4e286842, 0x4e284b85, 0x4e2868a5, 0x0ef6e1d6
	.long	0xce082a31, 0x4ece69ee, 0xce195e73, 0x4e284b86
	.long	0x4e2868c6, 0x6e2d1dce, 0x4e284b87, 0x4e2868e7
	.long	0x4e284b81, 0x4e286821, 0x4e284b83, 0x4e286863
	.long	0x4e284b84, 0x4e286884, 0x4e284b80, 0x4e286800
	.long	0xce184252, 0xfd400150, 0x0ef4e1f4, 0x4e284b47
	.long	0x4e2868e7, 0x4e284b45, 0x4e2868a5, 0x4ef5e1cd
	.long	0x4e284b41, 0x4e286821, 0x4e284b42, 0x4e286842
	.long	0x0ef5e1d5, 0xce165273, 0xacc12408, 0x4e284b43
	.long	0x4e286863, 0x6e200bd4, 0x4ebf87de, 0x4e284b44
	.long	0x4e286884, 0x4e284b40, 0x4e286800, 0x4e284b46
	.long	0x4e2868c6, 0xce153652, 0xad44691c, 0xce0b3231
	.long	0x4e284b62, 0x4e286842, 0x4e284b67, 0x4e2868e7
	.long	0xacc12c0a, 0x4e284b65, 0x4e2868a5, 0x4e284b66
	.long	0x4e2868c6, 0x4e284b61, 0x4e286821, 0x0ef0e235
	.long	0x4e284b60, 0x4e286800, 0x4e284b64, 0x4e286884
	.long	0x6e200bd6, 0x4e284b63, 0x4e286863, 0x4e284b85
	.long	0x4e2868a5, 0xacc1340c, 0x4ebf87de, 0x4e284b82
	.long	0x4e286842, 0x4e284b81, 0x4e286821, 0x4e284b87
	.long	0x4e2868e7, 0x4e284b84, 0x4e286884, 0xce114e52
	.long	0x3dc0291b, 0x6e11423d, 0x6e200bd7, 0x4ebf87de
	.long	0x4e284b83, 0x4e286863, 0x4e284b80, 0x4e286800
	.long	0xce1d5652, 0x4e284b86, 0x4e2868c6, 0x4e284b42
	.long	0x4e284b44, 0x4e284b41, 0xacc13c0e, 0x6e200bd9
	.long	0x4ebf87de, 0xeb05001f, 0xce046d8c, 0x4e284b47
	.long	0x4e284b46, 0x4e284b43, 0xce026d4a, 0x4eb71ee2
	.long	0x4e284b40, 0x6e200bc4, 0x4ebf87de, 0xce076def
	.long	0x4e284b45, 0x0ef0e251, 0xce016d29, 0xce036d6b
	.long	0x4eb91f23, 0x6e124255, 0xce056dad, 0x4eb61ec1
	.long	0xce006d08, 0x4eb41e80, 0xac812448, 0xac812c4a
	.long	0xce066dce, 0xac81344c, 0xce115673, 0xac813c4e
	.long	0x54ffdceb, 0x6e200bc5, 0x3dc02c77, 0x6e1742f7
	.long	0x3dc03479, 0x6e194339, 0x6e134273, 0x3dc02074
	.long	0x6e144294, 0x3dc02876, 0x6e1642d6, 0x4e200908
	.long	0x4e200929, 0x3dc02475, 0x3dc03078, 0x4ebf87de
	.long	0x4e20096b, 0x4e20094a, 0x6e331d08, 0x6e200bc6
	.long	0x4ef7e130, 0x0ef9e113, 0x4ef9e111, 0x4e2009ad
	.long	0x4ec82932, 0x0ef7e137, 0x6e301e31, 0x4ec86928
	.long	0x6e371e73, 0x6e321d08, 0xad406d1a, 0x4ebf87de
	.long	0x4ef8e112, 0x0ef8e118, 0x4e20098c, 0x4e2009ef
	.long	0x6e381e52, 0x6e200bc7, 0x4e2009ce, 0x4e284b42
	.long	0x4e286842, 0x4ef4e169, 0x4ef6e15d, 0x4e284b46
	.long	0x4e2868c6, 0x4e284b43, 0x4e286863, 0x0ef6e156
	.long	0x4e284b41, 0x4e286821, 0xce1d2631, 0x4eca297d
	.long	0x4eca696a, 0x4e284b45, 0x4e2868a5, 0x4e284b47
	.long	0x4e2868e7, 0x6e3d1d4a, 0x4e284b44, 0x4e286884
	.long	0x4e284b40, 0x4e286800, 0x4e284b63, 0x4e286863
	.long	0x0ef4e174, 0x3dc01477, 0x6e1742f7, 0x3dc01c79
	.long	0x6e194339, 0xad41691c, 0x4e284b65, 0x4e2868a5
	.long	0x4ef5e15d, 0xce165273, 0x0ef5e155, 0x4e284b61
	.long	0x4e286821, 0x4e284b60, 0x4e286800, 0xce157652
	.long	0x3dc00c75, 0x3dc01878, 0x4e284b62, 0x4e286842
	.long	0x4e284b64, 0x4e286884, 0x4e284b67, 0x4e2868e7
	.long	0x4e284b85, 0x4e2868a5, 0x4e284b82, 0x4e286842
	.long	0x4e284b83, 0x4e286863, 0x4e284b81, 0x4e286821
	.long	0x4e284b66, 0x4e2868c6, 0x4e284b84, 0x4e286884
	.long	0x4e284b45, 0x4e2868a5, 0x4e284b80, 0x4e286800
	.long	0x4e284b86, 0x4e2868c6, 0x4e284b87, 0x4e2868e7
	.long	0xad42711b, 0x3dc00874, 0x6e144294, 0x3dc01076
	.long	0x6e1642d6, 0x4ecc29b0, 0x4e284b40, 0x4e286800
	.long	0x4ef9e188, 0x4e284b46, 0x4e2868c6, 0x4e284b43
	.long	0x4e286863, 0x0ef9e199, 0x4ecc69ac, 0x4ef7e1aa
	.long	0x4e284b42, 0x4e286842, 0x4ebf87de, 0x4e284b47
	.long	0x4e2868e7, 0x4e284b41, 0x4e286821, 0x6e301d8c
	.long	0x0ef7e1b7, 0x4e284b44, 0x4e286884, 0x4ef6e1cb
	.long	0x4ece29ed, 0x0ef6e1d6, 0x4ece69ee, 0x4e284b61
	.long	0x4e286821, 0x4e284b63, 0x4e286863, 0xce082a31
	.long	0xce195e73, 0x6e2d1dce, 0x4ef8e190, 0x4e284b81
	.long	0x4e286821, 0x4e284b66, 0x4e2868c6, 0x4e284b60
	.long	0x4e286800, 0x4e284b67, 0x4e2868e7, 0x4e284b62
	.long	0x4e286842, 0x0ef8e198, 0x4e284b64, 0x4e286884
	.long	0x4e284b65, 0x4e2868a5, 0x4ef4e1ec, 0xad436d1a
	.long	0x0ef4e1f4, 0xce184252, 0x4ef5e1cd, 0x0ef5e1d5
	.long	0x4e284b80, 0x4e286800, 0x4e284b87, 0x4e2868e7
	.long	0xfd400150, 0x4e284b82, 0x4e286842, 0x4e284b84
	.long	0x4e286884, 0xce0b3231, 0x4e284b85, 0x4e2868a5
	.long	0x4e284b86, 0x4e2868c6, 0x4e284b83, 0x4e286863
	.long	0x4e284b44, 0x4e286884, 0x4e284b45, 0x4e2868a5
	.long	0x4e284b42, 0x4e286842, 0x4e284b40, 0x4e286800
	.long	0x4e284b43, 0x4e286863, 0xce165273, 0xce153652
	.long	0x4e284b46, 0x4e2868c6, 0x4e284b41, 0x4e286821
	.long	0x4e284b47, 0x4e2868e7, 0x0ef0e235, 0xce114e52
	.long	0xad44691c, 0x4e284b63, 0x4e286863, 0x4e284b66
	.long	0x4e2868c6, 0x4e284b61, 0x4e286821, 0x6e11423d
	.long	0x4e284b65, 0x4e2868a5, 0x4e284b60, 0x4e286800
	.long	0xce1d5652, 0x4e284b62, 0x4e286842, 0x4e284b67
	.long	0x4e2868e7, 0x0ef0e251, 0x4e284b64, 0x4e286884
	.long	0x4e284b87, 0x4e2868e7, 0x4e284b82, 0x4e286842
	.long	0x4e284b81, 0x4e286821, 0x6e124252, 0x4e284b86
	.long	0x4e2868c6, 0xce114a73, 0x4e284b84, 0x4e286884
	.long	0x4e284b83, 0x4e286863, 0x4e284b80, 0x4e286800
	.long	0x4e284b85, 0x4e2868a5, 0x3dc0291b, 0x4e284b46
	.long	0x4e284b42, 0x4e284b40, 0x4e284b41, 0x4e284b43
	.long	0x4e284b45, 0x4e284b44, 0x4e284b47, 0xcb000085
	.long	0x3cc10408, 0x4ebb1f7d, 0xad445474, 0x6e144294
	.long	0xce007509, 0x6e134270, 0xad455c76, 0x6e1642d6
	.long	0x6e1742f7, 0xad466478, 0x6e194339, 0xf101c0bf
	.long	0x540005ec, 0x4ea61cc7, 0x4ea51ca6, 0x0f00e411
	.long	0xf10180bf, 0x6ebf87de, 0x4ea41c85, 0x4ea31c64
	.long	0x4ea21c43, 0x4ea11c22, 0x0f00e413, 0x0f00e412
	.long	0x540005ec, 0x4ea61cc7, 0xf10140bf, 0x6ebf87de
	.long	0x4ea51ca6, 0x4ea41c85, 0x4ea31c64, 0x4ea11c23
	.long	0x540006ac, 0xf10100bf, 0x6ebf87de, 0x4ea61cc7
	.long	0x4ea51ca6, 0x4ea41c85, 0x4ea11c24, 0x540007ac
	.long	0x4ea61cc7, 0x6ebf87de, 0x4ea51ca6, 0x4ea11c25
	.long	0xf100c0bf, 0x540008ac, 0x6ebf87de, 0x4ea61cc7
	.long	0x4ea11c26, 0xf10080bf, 0x3dc01878, 0x54000a2c
	.long	0xf10040bf, 0x6ebf87de, 0x4ea11c27, 0x54000bac
	.long	0x3dc00c75, 0x6ebf87de, 0x1400006c, 0x4c9f7049
	.long	0x4e200928, 0x3cc10409, 0x6e301d08, 0x6e08451b
	.long	0x4ef9e111, 0x6e084712, 0x2e281f7b, 0x0f00e410
	.long	0xce017529, 0x0ef2e372, 0x0ef9e113, 0x4c9f7049
	.long	0x4e200928, 0x3cc10409, 0x6e301d08, 0x6e08451b
	.long	0xce027529, 0x0ef7e11a, 0x2e281f7b, 0x0f00e410
	.long	0x0ef8e37b, 0x4ef7e11c, 0x6e3a1e73, 0x6e3b1e52
	.long	0x6e3c1e31, 0x4c9f7049, 0x4e200928, 0x6e301d08
	.long	0x6e08451b, 0x3cc10409, 0x4ef6e11c, 0x6e3c1e31
	.long	0x2e281f7b, 0x6e18077b, 0xce037529, 0x0ef6e11a
	.long	0x0f00e410, 0x4ef5e37b, 0x6e3a1e73, 0x6e3b1e52
	.long	0x4c9f7049, 0x4e200928, 0x3cc10409, 0x6e301d08
	.long	0x6e08451b, 0x0f00e410, 0x4ef4e11c, 0x2e281f7b
	.long	0x0ef4e11a, 0x6e3c1e31, 0x0ef5e37b, 0x6e3a1e73
	.long	0xce047529, 0x6e3b1e52, 0x4c9f7049, 0x3dc01c79
	.long	0x6e194339, 0x4e200928, 0x6e301d08, 0x0f00e410
	.long	0x6e08451b, 0x3dc01878, 0x0ef9e11a, 0x3cc10409
	.long	0x2e281f7b, 0x6e18077b, 0x6e3a1e73, 0xce057529
	.long	0x4ef8e37b, 0x4ef9e11c, 0x6e3b1e52, 0x6e3c1e31
	.long	0x4c9f7049, 0x4e200928, 0x6e301d08, 0x3cc10409
	.long	0x6e08451b, 0x3dc01477, 0x6e1742f7, 0x0f00e410
	.long	0x2e281f7b, 0xce067529, 0x4ef7e11c, 0x0ef7e11a
	.long	0x0ef8e37b, 0x6e3c1e31, 0x6e3b1e52, 0x6e3a1e73
	.long	0x4c9f7049, 0x3dc01076, 0x6e1642d6, 0x4e200928
	.long	0x3cc10409, 0x6e301d08, 0x0f00e410, 0x6e08451b
	.long	0xce077529, 0x4ef6e11c, 0x2e281f7b, 0x3dc00c75
	.long	0x6e18077b, 0x0ef6e11a, 0x4ef5e37b, 0x6e3c1e31
	.long	0x6e3b1e52, 0x6e3a1e73, 0x6e200bde, 0x3d80021e
	.long	0x92401821, 0xd1020021, 0xcb0103e1, 0xaa3f03e6
	.long	0x4c40705a, 0x92401821, 0x9ac124c6, 0xaa3f03e7
	.long	0xf101003f, 0x9a86b0ed, 0x9a9fb0ce, 0x4e181dc0
	.long	0x4e081da0, 0x4e201d29, 0x4e200928, 0x6ee01f49
	.long	0x4c007049, 0x6e301d08, 0x6e084510, 0x2e281e10
	.long	0x3dc00874, 0x6e144294, 0x0ef5e210, 0x4ef4e11c
	.long	0x6e301e52, 0xfd400150, 0x0ef4e11a, 0x6e3c1e31
	.long	0x6e3a1e73, 0x6e114235, 0x0ef0e23d, 0xce114e52
	.long	0xce1d5652, 0x0ef0e251, 0x6e124255, 0xce115673
	.long	0x6e134273, 0x4e200a73, 0x4c007073, 0xaa0903e0
	.long	0x6d412fea, 0x6d4237ec, 0x6d433fee, 0x6cc527e8
	.long	0xd65f03c0, 0x52800000, 0xd65f03c0, 0xd503201f
SET_SIZE(aes_gcm_enc_128_eor3_zfs)

ENTRY_ALIGN(aes_gcm_dec_128_eor3_zfs, 16)
	AARCH64_VALID_CALL_TARGET
	.long	0xb40079c1, 0x6dbb27e8, 0xd343fc29, 0xaa0403f0
	.long	0xaa0503e8, 0x6d012fea, 0x6d0237ec, 0x6d033fee
	.long	0xd2f84005, 0xa9047fe5, 0x910103ea, 0xaa0903e5
	.long	0x4c407200, 0xad406d1a, 0xd10004a5, 0xd2c0002f
	.long	0x4f00e41f, 0x4e181dff, 0x4c407073, 0x6e134273
	.long	0x4e200a73, 0x6e20081e, 0x4e284b40, 0x4e286800
	.long	0x4ebf87de, 0x6e200bc1, 0x4ebf87de, 0x9279e0a5
	.long	0x6e200bc2, 0x4ebf87de, 0x4e284b41, 0x4e286821
	.long	0x6e200bc3, 0x4ebf87de, 0x4e284b60, 0x4e286800
	.long	0x4e284b61, 0x4e286821, 0x6e200bc4, 0x4ebf87de
	.long	0x6e200bc5, 0x4ebf87de, 0x4e284b42, 0x4e286842
	.long	0x6e200bc6, 0x4ebf87de, 0x4e284b45, 0x4e2868a5
	.long	0x4e284b43, 0x4e286863, 0x4e284b44, 0x4e286884
	.long	0x6e200bc7, 0x4e284b46, 0x4e2868c6, 0x4e284b62
	.long	0x4e286842, 0x4e284b47, 0x4e2868e7, 0xad41691c
	.long	0x4e284b66, 0x4e2868c6, 0x4e284b65, 0x4e2868a5
	.long	0x4e284b64, 0x4e286884, 0x4e284b67, 0x4e2868e7
	.long	0x4e284b87, 0x4e2868e7, 0x4e284b80, 0x4e286800
	.long	0x4e284b63, 0x4e286863, 0x4e284b86, 0x4e2868c6
	.long	0x4e284b82, 0x4e286842, 0x4e284b85, 0x4e2868a5
	.long	0x4e284b84, 0x4e286884, 0x4e284b83, 0x4e286863
	.long	0x4e284b81, 0x4e286821, 0x4e284b46, 0x4e2868c6
	.long	0x4e284b42, 0x4e286842, 0xad42711b, 0x4e284b45
	.long	0x4e2868a5, 0x4e284b40, 0x4e286800, 0x4e284b47
	.long	0x4e2868e7, 0x4e284b43, 0x4e286863, 0x4e284b41
	.long	0x4e286821, 0x4e284b60, 0x4e286800, 0x4e284b67
	.long	0x4e2868e7, 0x4e284b44, 0x4e286884, 0x4e284b66
	.long	0x4e2868c6, 0x4e284b61, 0x4e286821, 0x4e284b63
	.long	0x4e286863, 0x4e284b65, 0x4e2868a5, 0x4e284b64
	.long	0x4e286884, 0x4e284b62, 0x4e286842, 0xad436d1a
	.long	0x4e284b82, 0x4e286842, 0x4e284b83, 0x4e286863
	.long	0x4e284b86, 0x4e2868c6, 0x4e284b81, 0x4e286821
	.long	0x4e284b87, 0x4e2868e7, 0x4e284b85, 0x4e2868a5
	.long	0x4e284b84, 0x4e286884, 0x4e284b43, 0x4e286863
	.long	0x4e284b42, 0x4e286842, 0x4e284b80, 0x4e286800
	.long	0x4e284b45, 0x4e2868a5, 0x4e284b44, 0x4e286884
	.long	0x4e284b41, 0x4e286821, 0x4e284b40, 0x4e286800
	.long	0x4e284b47, 0x4e2868e7, 0x4e284b46, 0x4e2868c6
	.long	0x4e284b63, 0x4e286863, 0x4e284b64, 0x4e286884
	.long	0x4e284b61, 0x4e286821, 0x4e284b67, 0x4e2868e7
	.long	0x4e284b65, 0x4e2868a5, 0xad44691c, 0x4e284b66
	.long	0x4e2868c6, 0x4e284b62, 0x4e286842, 0x4e284b60
	.long	0x4e286800, 0x8b0000a5, 0x4ebf87de, 0x4e284b86
	.long	0x4e2868c6, 0x4e284b80, 0x4e286800, 0x4e284b81
	.long	0x4e286821, 0x4e284b87, 0x4e2868e7, 0x4e284b83
	.long	0x4e286863, 0x4e284b85, 0x4e2868a5, 0x4e284b82
	.long	0x4e286842, 0x4e284b84, 0x4e286884, 0x4e284b40
	.long	0x4e284b41, 0x4e284b46, 0x3dc0291b, 0x4e284b44
	.long	0x4e284b43, 0x4e284b42, 0x4e284b45, 0x4e284b47
	.long	0x8b410c04, 0xeb05001f, 0x5400462a, 0xacc12408
	.long	0xce006d00, 0xce016d21, 0xac810440, 0x6e200bc0
	.long	0x4ebf87de, 0xacc12c0a, 0xacc1340c, 0x6e200bc1
	.long	0x4ebf87de, 0xacc13c0e, 0xce036d63, 0xce026d42
	.long	0xac810c42, 0x6e200bc2, 0x4ebf87de, 0xce066dc6
	.long	0x6e200bc3, 0x4ebf87de, 0xce046d84, 0xce056da5
	.long	0xac811444, 0xce076de7, 0xac811c46, 0x6e200bc4
	.long	0xeb05001f, 0x4ebf87de, 0x5400236a, 0x3dc02c77
	.long	0x6e1742f7, 0x3dc03479, 0x6e194339, 0x4e200929
	.long	0x4e200908, 0x6e134273, 0x4e2009ce, 0x3dc02074
	.long	0x6e144294, 0x3dc02876, 0x6e1642d6, 0x6e331d08
	.long	0x6e200bc5, 0x4ebf87de, 0x4e20094a, 0x4e20098c
	.long	0xad406d1a, 0x6e200bc6, 0x4ebf87de, 0x3dc02475
	.long	0x3dc03078, 0x4ef7e130, 0x4ef9e111, 0x4e20096b
	.long	0x6e200bc7, 0x4ec82932, 0x4e2009ad, 0x0ef7e137
	.long	0x0ef9e113, 0x4ec86928, 0x4ef6e15d, 0x4e284b44
	.long	0x4e286884, 0x4ef4e169, 0x4e284b46, 0x4e2868c6
	.long	0x4e284b45, 0x4e2868a5, 0x4e284b47, 0x4e2868e7
	.long	0x4e284b43, 0x4e286863, 0x4e284b42, 0x4e286842
	.long	0x6e301e31, 0x4e284b41, 0x4e286821, 0x6e321d08
	.long	0x4e284b40, 0x4e286800, 0x4e284b62, 0x4e286842
	.long	0x6e371e73, 0xce1d2631, 0xad41691c, 0x4eca297d
	.long	0x4e284b67, 0x4e2868e7, 0x0ef6e156, 0x4eca696a
	.long	0x4ef8e112, 0x3dc01477, 0x6e1742f7, 0x3dc01c79
	.long	0x6e194339, 0x0ef8e118, 0x4e284b66, 0x4e2868c6
	.long	0x4e284b64, 0x4e286884, 0x4e284b65, 0x4e2868a5
	.long	0x0ef4e174, 0x4e284b63, 0x4e286863, 0x4e284b60
	.long	0x4e286800, 0x4e284b61, 0x4e286821, 0x4e284b87
	.long	0x4e2868e7, 0x4e284b82, 0x4e286842, 0xce165273
	.long	0x4e284b84, 0x4e286884, 0x6e3d1d4a, 0x3dc00874
	.long	0x6e144294, 0x3dc01076, 0x6e1642d6, 0x6e381e52
	.long	0x4e284b81, 0x4e286821, 0x4e284b83, 0x4e286863
	.long	0x4ecc29b0, 0x4e284b85, 0x4e2868a5, 0x4e284b80
	.long	0x4e286800, 0x4e284b86, 0x4e2868c6, 0x4ef5e15d
	.long	0x0ef5e155, 0x4e284b47, 0x4e2868e7, 0x4e2009ef
	.long	0x4ef9e188, 0xad42711b, 0x0ef9e199, 0xce157652
	.long	0x3dc00c75, 0x3dc01878, 0x4e284b42, 0x4e286842
	.long	0x4ecc69ac, 0x4e284b44, 0x4e286884, 0x4e284b43
	.long	0x4e286863, 0x4e284b41, 0x4e286821, 0x4e284b40
	.long	0x4e286800, 0x4e284b46, 0x4e2868c6, 0x4e284b45
	.long	0x4e2868a5, 0x4ef7e1aa, 0x0ef7e1b7, 0x4ef6e1cb
	.long	0x0ef6e1d6, 0x4e284b60, 0x4e286800, 0x4e284b67
	.long	0x4e2868e7, 0x6e301d8c, 0x4ece29ed, 0x4e284b63
	.long	0x4e286863, 0x4e284b61, 0x4e286821, 0x4e284b65
	.long	0x4e2868a5, 0x4e284b66, 0x4e2868c6, 0x4e284b62
	.long	0x4e286842, 0x4e284b64, 0x4e286884, 0x4ece69ee
	.long	0xad436d1a, 0x4e284b80, 0x4e286800, 0x4ef8e190
	.long	0x4e284b82, 0x4e286842, 0x6e2d1dce, 0x4e284b81
	.long	0x4e286821, 0x0ef8e198, 0x4e284b86, 0x4e2868c6
	.long	0x4e284b87, 0x4e2868e7, 0x4e284b83, 0x4e286863
	.long	0x4e284b85, 0x4e2868a5, 0x4e284b84, 0x4e286884
	.long	0x4ef4e1ec, 0xce184252, 0xce195e73, 0x4e284b43
	.long	0x4e286863, 0xce082a31, 0x4e284b47, 0x4e2868e7
	.long	0x4e284b41, 0x4e286821, 0x4ef5e1cd, 0x4e284b46
	.long	0x4e2868c6, 0x4e284b42, 0x4e286842, 0x4e284b45
	.long	0x4e2868a5, 0x0ef4e1f4, 0x0ef5e1d5, 0x4e284b40
	.long	0x4e286800, 0x4ebf87de, 0xce0b3231, 0x4e284b44
	.long	0x4e286884, 0xad44691c, 0xfd400150, 0xce165273
	.long	0x4e284b65, 0x4e2868a5, 0x6e200bd4, 0xce153652
	.long	0x4ebf87de, 0x4e284b66, 0x4e2868c6, 0x4e284b63
	.long	0x4e286863, 0x4e284b67, 0x4e2868e7, 0x4e284b62
	.long	0x4e286842, 0x4e284b61, 0x4e286821, 0x6e200bd6
	.long	0x4e284b64, 0x4e286884, 0x6e114235, 0x0ef0e23d
	.long	0xce114e52, 0x4e284b60, 0x4e286800, 0x4ebf87de
	.long	0x4e284b85, 0x4e2868a5, 0x4e284b81, 0x4e286821
	.long	0xacc12408, 0xacc12c0a, 0x4e284b80, 0x4e286800
	.long	0x6e200bd7, 0xacc1340c, 0x4e284b84, 0x4e286884
	.long	0xce1d5652, 0xacc13c0e, 0x4e284b83, 0x4e286863
	.long	0x4ebf87de, 0x4e284b87, 0x4e2868e7, 0x4e284b82
	.long	0x4e286842, 0x4e284b86, 0x4e2868c6, 0x4e284b40
	.long	0x4e284b41, 0x3dc0291b, 0x4e284b46, 0x0ef0e251
	.long	0x4e284b42, 0x4e284b47, 0x4e284b44, 0x6e124255
	.long	0x6e200bd9, 0x4ebf87de, 0x4e284b43, 0x4e284b45
	.long	0xce016d21, 0xce006d00, 0xce076de7, 0xce066dc6
	.long	0xce026d42, 0xac810440, 0x4eb61ec1, 0xce046d84
	.long	0xce115673, 0x4eb41e80, 0xce036d63, 0xeb05001f
	.long	0xac810c42, 0xce056da5, 0x4eb71ee2, 0xac811444
	.long	0x6e200bc4, 0x4ebf87de, 0xac811c46, 0x4eb91f23
	.long	0x54ffdceb, 0x4e20096b, 0x6e134273, 0x4e200908
	.long	0x4e20094a, 0x6e200bc5, 0xad406d1a, 0x3dc02c77
	.long	0x6e1742f7, 0x3dc03479, 0x6e194339, 0x6e331d08
	.long	0x4e200929, 0x4ebf87de, 0x3dc02074, 0x6e144294
	.long	0x3dc02876, 0x6e1642d6, 0x4e2009ad, 0x4e20098c
	.long	0x4e2009ce, 0x3dc02475, 0x3dc03078, 0x6e200bc6
	.long	0x4ebf87de, 0x4ef7e130, 0x0ef9e113, 0x4ef9e111
	.long	0x4ec82932, 0x4ec86928, 0x4ef6e15d, 0x0ef7e137
	.long	0x4ef4e169, 0x4e284b40, 0x4e286800, 0x6e301e31
	.long	0x4e284b44, 0x4e286884, 0x6e321d08, 0x0ef6e156
	.long	0x6e200bc7, 0x4e284b43, 0x4e286863, 0xce1d2631
	.long	0x4eca297d, 0x4eca696a, 0x4e284b42, 0x4e286842
	.long	0x4e284b41, 0x4e286821, 0x4e284b45, 0x4e2868a5
	.long	0x4ef8e112, 0x0ef8e118, 0x0ef4e174, 0x4e284b62
	.long	0x4e286842, 0x4e284b47, 0x4e2868e7, 0x4e284b46
	.long	0x4e2868c6, 0x6e371e73, 0x6e3d1d4a, 0x6e381e52
	.long	0x4e284b66, 0x4e2868c6, 0x4e284b64, 0x4e286884
	.long	0x4e284b65, 0x4e2868a5, 0xad41691c, 0xce165273
	.long	0x4ef5e15d, 0x3dc01477, 0x6e1742f7, 0x3dc01c79
	.long	0x6e194339, 0x4e284b61, 0x4e286821, 0x0ef5e155
	.long	0x4e284b63, 0x4e286863, 0x4e284b67, 0x4e2868e7
	.long	0x4e284b60, 0x4e286800, 0x3dc00874, 0x6e144294
	.long	0x3dc01076, 0x6e1642d6, 0xce157652, 0x4e284b80
	.long	0x4e286800, 0x4e284b86, 0x4e2868c6, 0x4e284b82
	.long	0x4e286842, 0x4e284b84, 0x4e286884, 0x4ecc29b0
	.long	0x4e284b87, 0x4e2868e7, 0x4e284b81, 0x4e286821
	.long	0x4e284b85, 0x4e2868a5, 0x4e284b83, 0x4e286863
	.long	0x4ef9e188, 0x0ef9e199, 0x4ecc69ac, 0xad42711b
	.long	0x4e2009ef, 0x4e284b46, 0x4e2868c6, 0x3dc00c75
	.long	0x3dc01878, 0x4ef7e1aa, 0x0ef7e1b7, 0x4e284b42
	.long	0x4e286842, 0x4e284b40, 0x4e286800, 0x4ece29ed
	.long	0x4ef6e1cb, 0x0ef6e1d6, 0x4ece69ee, 0x4e284b44
	.long	0x4e286884, 0x4e284b43, 0x4e286863, 0x4e284b47
	.long	0x4e2868e7, 0x4e284b41, 0x4e286821, 0x4e284b45
	.long	0x4e2868a5, 0x6e301d8c, 0xce082a31, 0x4e284b60
	.long	0x4e286800, 0x4e284b62, 0x4e286842, 0x6e2d1dce
	.long	0x4e284b65, 0x4e2868a5, 0x4ef8e190, 0x4e284b61
	.long	0x4e286821, 0x4e284b66, 0x4e2868c6, 0x4e284b64
	.long	0x4e286884, 0x4e284b67, 0x4e2868e7, 0x4e284b63
	.long	0x4e286863, 0x0ef8e198, 0x4ef4e1ec, 0x4ef5e1cd
	.long	0x0ef5e1d5, 0xad436d1a, 0xce184252, 0x4e284b86
	.long	0x4e2868c6, 0xfd400150, 0x0ef4e1f4, 0xce195e73
	.long	0x4e284b80, 0x4e286800, 0x4e284b82, 0x4e286842
	.long	0x4e284b84, 0x4e286884, 0x4e284b83, 0x4e286863
	.long	0x4e284b81, 0x4e286821, 0x4e284b85, 0x4e2868a5
	.long	0x4e284b87, 0x4e2868e7, 0xce153652, 0xce165273
	.long	0x4e284b44, 0x4e286884, 0x4e284b41, 0x4e286821
	.long	0x4e284b42, 0x4e286842, 0xce0b3231, 0x4e284b45
	.long	0x4e2868a5, 0x4e284b40, 0x4e286800, 0x4e284b43
	.long	0x4e286863, 0x4e284b46, 0x4e2868c6, 0x4e284b47
	.long	0x4e2868e7, 0x4e284b64, 0x4e286884, 0xce114e52
	.long	0xad44691c, 0x0ef0e23d, 0x4e284b63, 0x4e286863
	.long	0x6e114235, 0x4e284b65, 0x4e2868a5, 0x4e284b66
	.long	0x4e2868c6, 0x4e284b60, 0x4e286800, 0x4e284b67
	.long	0x4e2868e7, 0x4e284b61, 0x4e286821, 0x4e284b62
	.long	0x4e286842, 0xce1d5652, 0x3dc0291b, 0x4e284b83
	.long	0x4e286863, 0x4e284b80, 0x4e286800, 0x0ef0e251
	.long	0x4e284b86, 0x4e2868c6, 0x6e124255, 0x4e284b82
	.long	0x4e286842, 0x4e284b81, 0x4e286821, 0x4e284b87
	.long	0x4e2868e7, 0x4e284b46, 0x4e284b85, 0x4e2868a5
	.long	0x4e284b84, 0x4e286884, 0xce115673, 0x4ebf87de
	.long	0x4e284b42, 0x4e284b43, 0x4e284b45, 0x4e284b40
	.long	0x4e284b44, 0x4e284b41, 0x4e284b47, 0x4ebb1f7d
	.long	0xcb000085, 0xf101c0bf, 0xad466478, 0x6e194339
	.long	0x3cc10409, 0xad445474, 0x6e144294, 0x6e134270
	.long	0xad455c76, 0x6e1642d6, 0x6e1742f7, 0xce00752c
	.long	0x540005ec, 0xf10180bf, 0x4ea61cc7, 0x0f00e413
	.long	0x0f00e411, 0x4ea51ca6, 0x4ea41c85, 0x4ea31c64
	.long	0x4ea21c43, 0x4ea11c22, 0x0f00e412, 0x6ebf87de
	.long	0x540005ec, 0xf10140bf, 0x6ebf87de, 0x4ea61cc7
	.long	0x4ea51ca6, 0x4ea41c85, 0x4ea31c64, 0x4ea11c23
	.long	0x540006ac, 0xf10100bf, 0x4ea61cc7, 0x4ea51ca6
	.long	0x4ea41c85, 0x4ea11c24, 0x6ebf87de, 0x540007ac
	.long	0x6ebf87de, 0x4ea61cc7, 0x4ea51ca6, 0x4ea11c25
	.long	0xf100c0bf, 0x540008ac, 0x6ebf87de, 0x4ea61cc7
	.long	0xf10080bf, 0x3dc01878, 0x4ea11c26, 0x54000a2c
	.long	0xf10040bf, 0x4ea11c27, 0x6ebf87de, 0x54000bac
	.long	0x6ebf87de, 0x3dc00c75, 0x1400006c, 0x4e200928
	.long	0x6e301d08, 0x6e084712, 0x0ef9e113, 0x6e08451b
	.long	0x0f00e410, 0x3cc10409, 0x2e281f7b, 0x4ef9e111
	.long	0x4c9f704c, 0xce01752c, 0x0ef2e372, 0x4e200928
	.long	0x6e301d08, 0x6e08451b, 0x2e281f7b, 0x0ef7e11a
	.long	0x3cc10409, 0x0f00e410, 0x0ef8e37b, 0x4c9f704c
	.long	0x4ef7e11c, 0x6e3a1e73, 0x6e3c1e31, 0x6e3b1e52
	.long	0xce02752c, 0x4e200928, 0x3cc10409, 0x4c9f704c
	.long	0x6e301d08, 0x6e08451b, 0xce03752c, 0x2e281f7b
	.long	0x6e18077b, 0x0ef6e11a, 0x0f00e410, 0x4ef5e37b
	.long	0x4ef6e11c, 0x6e3a1e73, 0x6e3b1e52, 0x6e3c1e31
	.long	0x4e200928, 0x6e301d08, 0x3cc10409, 0x6e08451b
	.long	0x0f00e410, 0x4ef4e11c, 0x0ef4e11a, 0x6e3c1e31
	.long	0x4c9f704c, 0x2e281f7b, 0xce04752c, 0x6e3a1e73
	.long	0x0ef5e37b, 0x6e3b1e52, 0x4c9f704c, 0x4e200928
	.long	0x6e301d08, 0x6e08451b, 0x3dc01c79, 0x6e194339
	.long	0x3dc01878, 0x2e281f7b, 0x3cc10409, 0x6e18077b
	.long	0x0ef9e11a, 0x4ef9e11c, 0x0f00e410, 0xce05752c
	.long	0x6e3a1e73, 0x4ef8e37b, 0x6e3c1e31, 0x6e3b1e52
	.long	0x4e200928, 0x4c9f704c, 0x6e301d08, 0x3dc01477
	.long	0x6e1742f7, 0x0f00e410, 0x6e08451b, 0x2e281f7b
	.long	0x0ef7e11a, 0x4ef7e11c, 0x0ef8e37b, 0x3cc10409
	.long	0x6e3b1e52, 0x6e3a1e73, 0xce06752c, 0x6e3c1e31
	.long	0x4c9f704c, 0x4e200928, 0x3dc01076, 0x6e1642d6
	.long	0x6e301d08, 0x0f00e410, 0x6e08451b, 0x3cc10409
	.long	0x4ef6e11c, 0x2e281f7b, 0x6e3c1e31, 0x3dc00c75
	.long	0x6e18077b, 0xce07752c, 0x0ef6e11a, 0x4ef5e37b
	.long	0x6e3a1e73, 0x6e3b1e52, 0x92401821, 0xd1020021
	.long	0xcb0103e1, 0xaa3f03e6, 0x92401821, 0x9ac124c6
	.long	0xf101003f, 0xaa3f03e7, 0x9a86b0ed, 0x9a9fb0ce
	.long	0x4e181dc0, 0x4e081da0, 0x3dc00874, 0x6e144294
	.long	0x4c40705a, 0x4e201d29, 0x4e200928, 0x6e301d08
	.long	0x4ef4e11c, 0x6e084510, 0x6e3c1e31, 0x2e281e10
	.long	0x6ee01f4c, 0x0ef5e210, 0x4c00704c, 0x0ef4e11a
	.long	0x6e301e52, 0xfd400150, 0x6e3a1e73, 0x6e331e2e
	.long	0x0ef0e235, 0x6e114231, 0x6e2e1e52, 0xce115652
	.long	0x0ef0e251, 0x6e124252, 0xce124673, 0x6e134273
	.long	0x4e200a73, 0x4c007073, 0x6e200bde, 0x3d80021e
	.long	0xaa0903e0, 0x6d412fea, 0x6d4237ec, 0x6d433fee
	.long	0x6cc527e8, 0xd65f03c0, 0x52800000, 0xd65f03c0
SET_SIZE(aes_gcm_dec_128_eor3_zfs)


SECTION_STATIC
.byte	71,72,65,83,72,32,102,111,114,32,65,82,77,118,56,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
.align	2
#endif
