/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
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

/*
 * Based on BLAKE3 v1.3.1, https://github.com/BLAKE3-team/BLAKE3
 * Copyright (c) 2019-2022 Samuel Neves and Matthew Krupcale
 * Copyright (c) 2022-2023 Tino Reichardt <milky-zfs@mcmilk.de>
 *
 * This is converted assembly: SSE2 -> ARMv8-A
 * Used tools: SIMDe https://github.com/simd-everywhere/simde
 * C source files are here: https://github.com/mcmilk/BLAKE3-tests
 */

#if defined(__aarch64__)
	.text
	.globl	zfs_blake3_compress_in_place_sse2
	.p2align	2
	.type	zfs_blake3_compress_in_place_sse2,@function
zfs_blake3_compress_in_place_sse2:
	.cfi_startproc
	sub	sp, sp, #80
	stp	x30, x19, [sp, #64]
	.cfi_def_cfa_offset 80
	.cfi_offset w19, -8
	.cfi_offset w30, -16
	mov	x19, x0
	mov	w5, w4
	mov	x4, x3
	mov	w3, w2
	mov	x2, x1
	mov	x0, sp
	mov	x1, x19
	bl	compress_pre
	ldp	q0, q1, [sp]
	ldp	q2, q3, [sp, #32]
	eor	v0.16b, v2.16b, v0.16b
	eor	v1.16b, v3.16b, v1.16b
	stp	q0, q1, [x19]
	ldp	x30, x19, [sp, #64]
	add	sp, sp, #80
	ret
.Lfunc_end0:
	.size	zfs_blake3_compress_in_place_sse2, .Lfunc_end0-zfs_blake3_compress_in_place_sse2
	.cfi_endproc

	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI1_0:
	.xword	-4942790177982912921
	.xword	-6534734903820487822
.LCPI1_1:
	.xword	0
	.xword	-4294967296
.LCPI1_2:
	.xword	-1
	.xword	4294967295
	.text
	.p2align	2
	.type	compress_pre,@function
compress_pre:
	.cfi_startproc
	ldr	q2, [x1]
	adrp	x9, .LCPI1_0
	fmov	s1, w3
	ldr	q3, [x9, :lo12:.LCPI1_0]
	str	q2, [x0]
	ldr	q6, [x1, #16]
	lsr	x8, x4, #32
	fmov	s4, w4
	movi	d5, #0x0000ff000000ff
	mov	v1.s[1], w5
	mov	v4.s[1], w8
	and	v1.8b, v1.8b, v5.8b
	mov	v4.d[1], v1.d[0]
	stp	q3, q4, [x0, #32]
	str	q6, [x0, #16]
	add	x9, x2, #32
	ldp	q5, q7, [x2]
	adrp	x8, .LCPI1_2
	ld2	{ v17.4s, v18.4s }, [x9]
	ldr	q1, [x8, :lo12:.LCPI1_2]
	uzp1	v16.4s, v5.4s, v7.4s
	uzp2	v5.4s, v5.4s, v7.4s
	ext	v20.16b, v18.16b, v18.16b, #12
	add	v2.4s, v2.4s, v16.4s
	uzp1	v7.4s, v16.4s, v16.4s
	ext	v21.16b, v16.16b, v16.16b, #12
	ext	v19.16b, v17.16b, v17.16b, #12
	zip1	v22.2d, v20.2d, v5.2d
	zip2	v23.4s, v5.4s, v20.4s
	add	v2.4s, v2.4s, v6.4s
	ext	v7.16b, v7.16b, v16.16b, #8
	ext	v21.16b, v16.16b, v21.16b, #12
	mov	v16.16b, v1.16b
	bsl	v16.16b, v22.16b, v19.16b
	zip1	v22.4s, v23.4s, v19.4s
	zip1	v23.4s, v19.4s, v23.4s
	eor	v24.16b, v2.16b, v4.16b
	uzp2	v7.4s, v7.4s, v5.4s
	ext	v4.16b, v23.16b, v22.16b, #8
	rev32	v22.8h, v24.8h
	add	v2.4s, v2.4s, v5.4s
	ext	v5.16b, v16.16b, v16.16b, #12
	ext	v23.16b, v7.16b, v7.16b, #4
	add	v3.4s, v22.4s, v3.4s
	uzp1	v5.4s, v16.4s, v5.4s
	uzp1	v16.4s, v23.4s, v23.4s
	ext	v24.16b, v23.16b, v23.16b, #12
	eor	v6.16b, v3.16b, v6.16b
	ext	v25.16b, v16.16b, v23.16b, #8
	ext	v16.16b, v23.16b, v24.16b, #12
	ushr	v23.4s, v6.4s, #12
	shl	v6.4s, v6.4s, #20
	orr	v6.16b, v6.16b, v23.16b
	add	v2.4s, v2.4s, v6.4s
	eor	v22.16b, v2.16b, v22.16b
	add	v2.4s, v2.4s, v17.4s
	ushr	v17.4s, v22.4s, #8
	shl	v18.4s, v22.4s, #24
	orr	v17.16b, v18.16b, v17.16b
	add	v3.4s, v17.4s, v3.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v18.4s, v6.4s, #7
	shl	v6.4s, v6.4s, #25
	ext	v2.16b, v2.16b, v2.16b, #12
	orr	v6.16b, v6.16b, v18.16b
	ext	v17.16b, v17.16b, v17.16b, #8
	add	v2.4s, v2.4s, v6.4s
	eor	v17.16b, v17.16b, v2.16b
	ext	v3.16b, v3.16b, v3.16b, #4
	rev32	v22.8h, v17.8h
	add	v18.4s, v2.4s, v20.4s
	mov	v20.s[1], v19.s[2]
	add	v19.4s, v3.4s, v22.4s
	movi	v0.2d, #0xffffffff00000000
	eor	v3.16b, v19.16b, v6.16b
	bif	v20.16b, v21.16b, v0.16b
	ushr	v21.4s, v3.4s, #12
	shl	v3.4s, v3.4s, #20
	orr	v21.16b, v3.16b, v21.16b
	add	v18.4s, v18.4s, v21.4s
	eor	v22.16b, v18.16b, v22.16b
	add	v7.4s, v18.4s, v7.4s
	ushr	v18.4s, v22.4s, #8
	shl	v22.4s, v22.4s, #24
	orr	v18.16b, v22.16b, v18.16b
	add	v19.4s, v18.4s, v19.4s
	eor	v21.16b, v19.16b, v21.16b
	ushr	v22.4s, v21.4s, #7
	shl	v21.4s, v21.4s, #25
	ext	v7.16b, v7.16b, v7.16b, #4
	orr	v21.16b, v21.16b, v22.16b
	ext	v18.16b, v18.16b, v18.16b, #8
	add	v7.4s, v7.4s, v21.4s
	eor	v18.16b, v18.16b, v7.16b
	ext	v19.16b, v19.16b, v19.16b, #12
	rev32	v18.8h, v18.8h
	add	v19.4s, v19.4s, v18.4s
	uzp2	v2.4s, v25.4s, v20.4s
	zip1	v6.2d, v4.2d, v20.2d
	zip2	v17.4s, v20.4s, v4.4s
	add	v7.4s, v7.4s, v20.4s
	eor	v20.16b, v19.16b, v21.16b
	ushr	v21.4s, v20.4s, #12
	shl	v20.4s, v20.4s, #20
	orr	v20.16b, v20.16b, v21.16b
	add	v7.4s, v7.4s, v20.4s
	eor	v18.16b, v7.16b, v18.16b
	ushr	v21.4s, v18.4s, #8
	shl	v18.4s, v18.4s, #24
	orr	v18.16b, v18.16b, v21.16b
	add	v19.4s, v18.4s, v19.4s
	eor	v20.16b, v19.16b, v20.16b
	ext	v7.16b, v7.16b, v7.16b, #12
	ushr	v21.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	adrp	x10, .LCPI1_1
	add	v7.4s, v7.4s, v5.4s
	orr	v20.16b, v20.16b, v21.16b
	ldr	q23, [x10, :lo12:.LCPI1_1]
	ext	v18.16b, v18.16b, v18.16b, #8
	add	v7.4s, v7.4s, v20.4s
	eor	v18.16b, v18.16b, v7.16b
	ext	v19.16b, v19.16b, v19.16b, #4
	rev32	v18.8h, v18.8h
	add	v19.4s, v19.4s, v18.4s
	bit	v6.16b, v5.16b, v23.16b
	zip1	v23.4s, v17.4s, v5.4s
	zip1	v17.4s, v5.4s, v17.4s
	add	v21.4s, v7.4s, v4.4s
	mov	v4.s[1], v5.s[2]
	eor	v5.16b, v19.16b, v20.16b
	ushr	v20.4s, v5.4s, #12
	shl	v5.4s, v5.4s, #20
	orr	v20.16b, v5.16b, v20.16b
	add	v21.4s, v21.4s, v20.4s
	eor	v18.16b, v21.16b, v18.16b
	ext	v24.16b, v2.16b, v2.16b, #4
	add	v2.4s, v21.4s, v2.4s
	ushr	v21.4s, v18.4s, #8
	shl	v18.4s, v18.4s, #24
	orr	v18.16b, v18.16b, v21.16b
	add	v19.4s, v18.4s, v19.4s
	eor	v20.16b, v19.16b, v20.16b
	ushr	v21.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	ext	v2.16b, v2.16b, v2.16b, #4
	orr	v20.16b, v20.16b, v21.16b
	ext	v18.16b, v18.16b, v18.16b, #8
	add	v2.4s, v2.4s, v20.4s
	eor	v18.16b, v18.16b, v2.16b
	ext	v19.16b, v19.16b, v19.16b, #12
	rev32	v18.8h, v18.8h
	add	v19.4s, v19.4s, v18.4s
	mov	v22.16b, v0.16b
	eor	v20.16b, v19.16b, v20.16b
	bsl	v22.16b, v4.16b, v16.16b
	ushr	v21.4s, v20.4s, #12
	shl	v20.4s, v20.4s, #20
	add	v2.4s, v2.4s, v22.4s
	orr	v20.16b, v20.16b, v21.16b
	add	v2.4s, v2.4s, v20.4s
	eor	v18.16b, v2.16b, v18.16b
	ushr	v21.4s, v18.4s, #8
	shl	v18.4s, v18.4s, #24
	orr	v18.16b, v18.16b, v21.16b
	add	v19.4s, v18.4s, v19.4s
	ext	v25.16b, v6.16b, v6.16b, #12
	eor	v20.16b, v19.16b, v20.16b
	uzp1	v6.4s, v6.4s, v25.4s
	ext	v2.16b, v2.16b, v2.16b, #12
	ushr	v21.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	ext	v3.16b, v17.16b, v23.16b, #8
	uzp1	v17.4s, v24.4s, v24.4s
	add	v2.4s, v2.4s, v6.4s
	orr	v20.16b, v20.16b, v21.16b
	ext	v25.16b, v17.16b, v24.16b, #8
	ext	v18.16b, v18.16b, v18.16b, #8
	add	v2.4s, v2.4s, v20.4s
	ext	v23.16b, v24.16b, v24.16b, #12
	uzp2	v4.4s, v25.4s, v22.4s
	zip1	v7.2d, v3.2d, v22.2d
	zip2	v16.4s, v22.4s, v3.4s
	eor	v18.16b, v18.16b, v2.16b
	ext	v17.16b, v24.16b, v23.16b, #12
	ext	v23.16b, v4.16b, v4.16b, #4
	bif	v7.16b, v6.16b, v1.16b
	zip1	v24.4s, v16.4s, v6.4s
	zip1	v16.4s, v6.4s, v16.4s
	ext	v19.16b, v19.16b, v19.16b, #4
	add	v21.4s, v2.4s, v3.4s
	rev32	v18.8h, v18.8h
	mov	v3.s[1], v6.s[2]
	ext	v25.16b, v7.16b, v7.16b, #12
	ext	v5.16b, v16.16b, v24.16b, #8
	uzp1	v16.4s, v23.4s, v23.4s
	add	v19.4s, v19.4s, v18.4s
	bit	v17.16b, v3.16b, v0.16b
	uzp1	v7.4s, v7.4s, v25.4s
	ext	v25.16b, v16.16b, v23.16b, #8
	eor	v2.16b, v19.16b, v20.16b
	zip1	v3.2d, v5.2d, v17.2d
	ext	v24.16b, v23.16b, v23.16b, #12
	uzp2	v6.4s, v25.4s, v17.4s
	zip2	v20.4s, v17.4s, v5.4s
	ushr	v22.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	bif	v3.16b, v7.16b, v1.16b
	ext	v16.16b, v23.16b, v24.16b, #12
	ext	v23.16b, v6.16b, v6.16b, #4
	zip1	v24.4s, v20.4s, v7.4s
	zip1	v20.4s, v7.4s, v20.4s
	orr	v22.16b, v2.16b, v22.16b
	ext	v25.16b, v3.16b, v3.16b, #12
	ext	v2.16b, v20.16b, v24.16b, #8
	uzp1	v20.4s, v23.4s, v23.4s
	uzp1	v3.4s, v3.4s, v25.4s
	ext	v24.16b, v23.16b, v23.16b, #12
	add	v21.4s, v21.4s, v22.4s
	ext	v20.16b, v20.16b, v23.16b, #8
	ext	v23.16b, v23.16b, v24.16b, #12
	dup	v24.4s, v2.s[3]
	eor	v18.16b, v21.16b, v18.16b
	add	v4.4s, v21.4s, v4.4s
	trn1	v21.4s, v3.4s, v3.4s
	ext	v21.16b, v21.16b, v24.16b, #8
	ushr	v24.4s, v18.4s, #8
	shl	v18.4s, v18.4s, #24
	orr	v18.16b, v18.16b, v24.16b
	add	v19.4s, v18.4s, v19.4s
	ext	v25.16b, v4.16b, v4.16b, #4
	mov	v4.16b, v0.16b
	eor	v22.16b, v19.16b, v22.16b
	bsl	v4.16b, v21.16b, v23.16b
	ushr	v23.4s, v22.4s, #7
	shl	v22.4s, v22.4s, #25
	orr	v22.16b, v22.16b, v23.16b
	ext	v18.16b, v18.16b, v18.16b, #8
	add	v23.4s, v25.4s, v22.4s
	eor	v18.16b, v18.16b, v23.16b
	ext	v19.16b, v19.16b, v19.16b, #12
	rev32	v18.8h, v18.8h
	add	v19.4s, v19.4s, v18.4s
	eor	v22.16b, v19.16b, v22.16b
	add	v17.4s, v23.4s, v17.4s
	ushr	v23.4s, v22.4s, #12
	shl	v22.4s, v22.4s, #20
	orr	v22.16b, v22.16b, v23.16b
	add	v17.4s, v17.4s, v22.4s
	eor	v18.16b, v17.16b, v18.16b
	ushr	v23.4s, v18.4s, #8
	shl	v18.4s, v18.4s, #24
	orr	v18.16b, v18.16b, v23.16b
	add	v19.4s, v18.4s, v19.4s
	eor	v22.16b, v19.16b, v22.16b
	ext	v17.16b, v17.16b, v17.16b, #12
	ushr	v23.4s, v22.4s, #7
	shl	v22.4s, v22.4s, #25
	add	v17.4s, v17.4s, v7.4s
	orr	v22.16b, v22.16b, v23.16b
	ext	v18.16b, v18.16b, v18.16b, #8
	add	v17.4s, v17.4s, v22.4s
	eor	v18.16b, v18.16b, v17.16b
	ext	v19.16b, v19.16b, v19.16b, #4
	add	v23.4s, v17.4s, v5.4s
	rev32	v24.8h, v18.8h
	mov	v5.s[1], v7.s[2]
	mov	v17.16b, v0.16b
	add	v19.4s, v19.4s, v24.4s
	bsl	v17.16b, v5.16b, v16.16b
	eor	v5.16b, v19.16b, v22.16b
	uzp2	v16.4s, v20.4s, v17.4s
	zip1	v7.2d, v2.2d, v17.2d
	zip2	v18.4s, v17.4s, v2.4s
	ushr	v20.4s, v5.4s, #12
	shl	v5.4s, v5.4s, #20
	ext	v22.16b, v16.16b, v16.16b, #4
	mov	v25.16b, v1.16b
	bsl	v25.16b, v7.16b, v3.16b
	orr	v20.16b, v5.16b, v20.16b
	zip1	v5.4s, v18.4s, v3.4s
	zip1	v7.4s, v3.4s, v18.4s
	ext	v18.16b, v22.16b, v22.16b, #12
	ext	v18.16b, v22.16b, v18.16b, #12
	ext	v22.16b, v22.16b, v22.16b, #8
	ext	v7.16b, v7.16b, v5.16b, #8
	ext	v5.16b, v25.16b, v25.16b, #12
	add	v23.4s, v23.4s, v20.4s
	uzp2	v21.4s, v22.4s, v21.4s
	uzp1	v5.4s, v25.4s, v5.4s
	eor	v24.16b, v23.16b, v24.16b
	add	v23.4s, v23.4s, v6.4s
	ext	v6.16b, v21.16b, v22.16b, #4
	zip2	v21.4s, v4.4s, v7.4s
	mov	v22.16b, v1.16b
	zip1	v1.4s, v21.4s, v5.4s
	zip1	v21.4s, v5.4s, v21.4s
	ext	v1.16b, v21.16b, v1.16b, #8
	ushr	v21.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	zip1	v25.2d, v7.2d, v4.2d
	orr	v21.16b, v24.16b, v21.16b
	bsl	v22.16b, v25.16b, v5.16b
	add	v19.4s, v21.4s, v19.4s
	ext	v24.16b, v22.16b, v22.16b, #12
	eor	v20.16b, v19.16b, v20.16b
	uzp1	v22.4s, v22.4s, v24.4s
	ushr	v24.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	orr	v20.16b, v20.16b, v24.16b
	ext	v23.16b, v23.16b, v23.16b, #4
	ext	v21.16b, v21.16b, v21.16b, #8
	add	v23.4s, v23.4s, v20.4s
	eor	v21.16b, v21.16b, v23.16b
	ext	v19.16b, v19.16b, v19.16b, #12
	rev32	v21.8h, v21.8h
	add	v19.4s, v19.4s, v21.4s
	eor	v20.16b, v19.16b, v20.16b
	add	v17.4s, v23.4s, v17.4s
	ushr	v23.4s, v20.4s, #12
	shl	v20.4s, v20.4s, #20
	orr	v20.16b, v20.16b, v23.16b
	add	v17.4s, v17.4s, v20.4s
	eor	v21.16b, v17.16b, v21.16b
	ext	v17.16b, v17.16b, v17.16b, #12
	add	v3.4s, v17.4s, v3.4s
	ushr	v17.4s, v21.4s, #8
	shl	v21.4s, v21.4s, #24
	orr	v17.16b, v21.16b, v17.16b
	add	v19.4s, v17.4s, v19.4s
	eor	v20.16b, v19.16b, v20.16b
	ushr	v21.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	orr	v20.16b, v20.16b, v21.16b
	ext	v17.16b, v17.16b, v17.16b, #8
	add	v3.4s, v3.4s, v20.4s
	eor	v17.16b, v17.16b, v3.16b
	ext	v19.16b, v19.16b, v19.16b, #4
	add	v2.4s, v3.4s, v2.4s
	rev32	v3.8h, v17.8h
	add	v17.4s, v19.4s, v3.4s
	eor	v19.16b, v17.16b, v20.16b
	ushr	v20.4s, v19.4s, #12
	shl	v19.4s, v19.4s, #20
	orr	v19.16b, v19.16b, v20.16b
	add	v2.4s, v2.4s, v19.4s
	eor	v3.16b, v2.16b, v3.16b
	add	v2.4s, v2.4s, v16.4s
	ushr	v16.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	orr	v3.16b, v3.16b, v16.16b
	add	v16.4s, v3.4s, v17.4s
	eor	v17.16b, v16.16b, v19.16b
	ushr	v19.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	ext	v2.16b, v2.16b, v2.16b, #4
	orr	v17.16b, v17.16b, v19.16b
	ext	v3.16b, v3.16b, v3.16b, #8
	add	v2.4s, v2.4s, v17.4s
	eor	v3.16b, v3.16b, v2.16b
	ext	v16.16b, v16.16b, v16.16b, #12
	rev32	v3.8h, v3.8h
	add	v2.4s, v2.4s, v4.4s
	add	v4.4s, v16.4s, v3.4s
	eor	v16.16b, v4.16b, v17.16b
	ushr	v17.4s, v16.4s, #12
	shl	v16.4s, v16.4s, #20
	orr	v16.16b, v16.16b, v17.16b
	add	v2.4s, v2.4s, v16.4s
	eor	v3.16b, v2.16b, v3.16b
	ushr	v17.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	orr	v3.16b, v3.16b, v17.16b
	add	v4.4s, v3.4s, v4.4s
	eor	v16.16b, v4.16b, v16.16b
	ext	v2.16b, v2.16b, v2.16b, #12
	ushr	v17.4s, v16.4s, #7
	shl	v16.4s, v16.4s, #25
	add	v2.4s, v2.4s, v5.4s
	orr	v16.16b, v16.16b, v17.16b
	ext	v3.16b, v3.16b, v3.16b, #8
	add	v2.4s, v2.4s, v16.4s
	eor	v3.16b, v3.16b, v2.16b
	ext	v4.16b, v4.16b, v4.16b, #4
	rev32	v3.8h, v3.8h
	add	v4.4s, v4.4s, v3.4s
	add	v2.4s, v2.4s, v7.4s
	mov	v7.s[1], v5.s[2]
	eor	v5.16b, v4.16b, v16.16b
	bsl	v0.16b, v7.16b, v18.16b
	ushr	v7.4s, v5.4s, #12
	shl	v5.4s, v5.4s, #20
	orr	v5.16b, v5.16b, v7.16b
	add	v2.4s, v2.4s, v5.4s
	eor	v3.16b, v2.16b, v3.16b
	ushr	v7.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	orr	v3.16b, v3.16b, v7.16b
	add	v4.4s, v3.4s, v4.4s
	ext	v2.16b, v2.16b, v2.16b, #4
	eor	v5.16b, v4.16b, v5.16b
	add	v2.4s, v2.4s, v6.4s
	ushr	v6.4s, v5.4s, #7
	shl	v5.4s, v5.4s, #25
	orr	v5.16b, v5.16b, v6.16b
	ext	v3.16b, v3.16b, v3.16b, #8
	add	v2.4s, v5.4s, v2.4s
	eor	v3.16b, v3.16b, v2.16b
	ext	v4.16b, v4.16b, v4.16b, #12
	add	v0.4s, v2.4s, v0.4s
	rev32	v2.8h, v3.8h
	add	v3.4s, v4.4s, v2.4s
	eor	v4.16b, v3.16b, v5.16b
	ushr	v5.4s, v4.4s, #12
	shl	v4.4s, v4.4s, #20
	orr	v4.16b, v4.16b, v5.16b
	add	v0.4s, v0.4s, v4.4s
	eor	v2.16b, v0.16b, v2.16b
	ushr	v5.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v5.16b
	add	v3.4s, v2.4s, v3.4s
	eor	v4.16b, v3.16b, v4.16b
	ext	v0.16b, v0.16b, v0.16b, #12
	ushr	v5.4s, v4.4s, #7
	shl	v4.4s, v4.4s, #25
	add	v0.4s, v0.4s, v22.4s
	orr	v4.16b, v4.16b, v5.16b
	ext	v2.16b, v2.16b, v2.16b, #8
	add	v0.4s, v0.4s, v4.4s
	eor	v2.16b, v2.16b, v0.16b
	ext	v3.16b, v3.16b, v3.16b, #4
	add	v0.4s, v0.4s, v1.4s
	rev32	v1.8h, v2.8h
	add	v2.4s, v3.4s, v1.4s
	eor	v3.16b, v2.16b, v4.16b
	ushr	v4.4s, v3.4s, #12
	shl	v3.4s, v3.4s, #20
	orr	v3.16b, v3.16b, v4.16b
	add	v0.4s, v0.4s, v3.4s
	eor	v1.16b, v0.16b, v1.16b
	ushr	v4.4s, v1.4s, #8
	shl	v1.4s, v1.4s, #24
	orr	v1.16b, v1.16b, v4.16b
	add	v2.4s, v1.4s, v2.4s
	eor	v3.16b, v2.16b, v3.16b
	ushr	v4.4s, v3.4s, #7
	shl	v3.4s, v3.4s, #25
	ext	v0.16b, v0.16b, v0.16b, #4
	ext	v1.16b, v1.16b, v1.16b, #8
	ext	v2.16b, v2.16b, v2.16b, #12
	orr	v3.16b, v3.16b, v4.16b
	stp	q0, q3, [x0]
	stp	q2, q1, [x0, #32]
	ret
.Lfunc_end1:
	.size	compress_pre, .Lfunc_end1-compress_pre
	.cfi_endproc

	.globl	zfs_blake3_compress_xof_sse2
	.p2align	2
	.type	zfs_blake3_compress_xof_sse2,@function
zfs_blake3_compress_xof_sse2:
	.cfi_startproc
	sub	sp, sp, #96
	str	x30, [sp, #64]
	stp	x20, x19, [sp, #80]
	.cfi_def_cfa_offset 96
	.cfi_offset w19, -8
	.cfi_offset w20, -16
	.cfi_offset w30, -32
	mov	x20, x0
	mov	x19, x5
	mov	w5, w4
	mov	x4, x3
	mov	w3, w2
	mov	x2, x1
	mov	x0, sp
	mov	x1, x20
	bl	compress_pre
	ldp	q0, q1, [sp]
	ldp	q2, q3, [sp, #32]
	ldr	x30, [sp, #64]
	eor	v0.16b, v2.16b, v0.16b
	eor	v1.16b, v3.16b, v1.16b
	stp	q0, q1, [x19]
	ldr	q0, [x20]
	eor	v0.16b, v0.16b, v2.16b
	str	q0, [x19, #32]
	ldr	q0, [x20, #16]
	eor	v0.16b, v0.16b, v3.16b
	str	q0, [x19, #48]
	ldp	x20, x19, [sp, #80]
	add	sp, sp, #96
	ret
.Lfunc_end2:
	.size	zfs_blake3_compress_xof_sse2, .Lfunc_end2-zfs_blake3_compress_xof_sse2
	.cfi_endproc

	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI3_0:
	.word	0
	.word	1
	.word	2
	.word	3
	.text
	.globl	zfs_blake3_hash_many_sse2
	.p2align	2
	.type	zfs_blake3_hash_many_sse2,@function
zfs_blake3_hash_many_sse2:
	.cfi_startproc
	stp	d15, d14, [sp, #-160]!
	stp	d13, d12, [sp, #16]
	stp	d11, d10, [sp, #32]
	stp	d9, d8, [sp, #48]
	stp	x29, x30, [sp, #64]
	stp	x28, x27, [sp, #80]
	stp	x26, x25, [sp, #96]
	stp	x24, x23, [sp, #112]
	stp	x22, x21, [sp, #128]
	stp	x20, x19, [sp, #144]
	sub	sp, sp, #528
	.cfi_def_cfa_offset 688
	.cfi_offset w19, -8
	.cfi_offset w20, -16
	.cfi_offset w21, -24
	.cfi_offset w22, -32
	.cfi_offset w23, -40
	.cfi_offset w24, -48
	.cfi_offset w25, -56
	.cfi_offset w26, -64
	.cfi_offset w27, -72
	.cfi_offset w28, -80
	.cfi_offset w30, -88
	.cfi_offset w29, -96
	.cfi_offset b8, -104
	.cfi_offset b9, -112
	.cfi_offset b10, -120
	.cfi_offset b11, -128
	.cfi_offset b12, -136
	.cfi_offset b13, -144
	.cfi_offset b14, -152
	.cfi_offset b15, -160
	ldr	x26, [sp, #696]
	ldrb	w27, [sp, #688]
	mov	w19, w6
	mov	x20, x4
	mov	x21, x3
	mov	x22, x2
	mov	x23, x1
	mov	x24, x0
	cmp	x1, #4
	orr	w8, w7, w6
	str	w8, [sp, #60]
	b.lo	.LBB3_6
	sbfx	w8, w5, #0, #1
	dup	v0.4s, w8
	adrp	x8, .LCPI3_0
	ldr	q1, [x8, :lo12:.LCPI3_0]
	mov	w8, #58983
	movk	w8, #27145, lsl #16
	dup	v2.4s, w8
	mov	w8, #44677
	movk	w8, #47975, lsl #16
	dup	v3.4s, w8
	mov	w8, #62322
	movk	w8, #15470, lsl #16
	and	v0.16b, v0.16b, v1.16b
	dup	v1.4s, w8
	mov	w8, #62778
	str	q0, [sp, #32]
	orr	v0.4s, #128, lsl #24
	movk	w8, #42319, lsl #16
	str	q0, [sp, #16]
	stp	q2, q1, [sp, #80]
	str	q3, [sp, #64]
	b	.LBB3_3
.LBB3_2:
	zip1	v1.4s, v0.4s, v4.4s
	zip2	v0.4s, v0.4s, v4.4s
	zip1	v2.4s, v18.4s, v17.4s
	zip2	v3.4s, v18.4s, v17.4s
	zip1	v4.4s, v11.4s, v12.4s
	zip2	v5.4s, v11.4s, v12.4s
	zip1	v6.4s, v15.4s, v7.4s
	zip2	v7.4s, v15.4s, v7.4s
	add	x9, x20, #4
	tst	w5, #0x1
	sub	x23, x23, #4
	zip1	v16.2d, v1.2d, v2.2d
	zip2	v1.2d, v1.2d, v2.2d
	zip1	v2.2d, v0.2d, v3.2d
	zip2	v0.2d, v0.2d, v3.2d
	zip1	v3.2d, v4.2d, v6.2d
	zip2	v4.2d, v4.2d, v6.2d
	zip1	v6.2d, v5.2d, v7.2d
	zip2	v5.2d, v5.2d, v7.2d
	add	x24, x24, #32
	csel	x20, x9, x20, ne
	cmp	x23, #3
	stp	q16, q3, [x26]
	stp	q1, q4, [x26, #32]
	stp	q2, q6, [x26, #64]
	stp	q0, q5, [x26, #96]
	add	x26, x26, #128
	b.ls	.LBB3_6
.LBB3_3:
	mov	x9, x21
	ld1r	{ v0.4s }, [x9], #4
	add	x10, x21, #8
	add	x11, x21, #12
	add	x12, x21, #16
	add	x13, x21, #20
	add	x14, x21, #24
	add	x15, x21, #28
	ld1r	{ v18.4s }, [x10]
	ld1r	{ v17.4s }, [x11]
	ld1r	{ v11.4s }, [x12]
	ld1r	{ v12.4s }, [x13]
	ld1r	{ v15.4s }, [x14]
	ld1r	{ v4.4s }, [x9]
	ld1r	{ v7.4s }, [x15]
	cbz	x22, .LBB3_2
	ldr	q5, [sp, #32]
	dup	v1.4s, w20
	ldp	x10, x11, [x24]
	ldp	x12, x13, [x24, #16]
	add	v5.4s, v1.4s, v5.4s
	movi	v1.4s, #128, lsl #24
	str	q5, [sp, #128]
	eor	v1.16b, v5.16b, v1.16b
	ldr	q5, [sp, #16]
	ldr	w17, [sp, #60]
	lsr	x14, x20, #32
	dup	v2.4s, w14
	cmgt	v1.4s, v5.4s, v1.4s
	mov	x9, xzr
	sub	v1.4s, v2.4s, v1.4s
	mov	x14, x22
	str	q1, [sp, #112]
.LBB3_5:
	subs	x14, x14, #1
	csel	w0, w27, wzr, eq
	orr	w0, w0, w17
	and	w0, w0, #0xff
	add	v0.4s, v11.4s, v0.4s
	add	x15, x10, x9
	add	x16, x11, x9
	add	x17, x12, x9
	dup	v1.4s, w0
	add	x0, x13, x9
	str	q0, [sp, #192]
	add	v0.4s, v7.4s, v17.4s
	str	q1, [sp, #304]
	stp	q0, q7, [sp, #208]
	ldp	q1, q2, [x15]
	ldp	q3, q5, [x16]
	ldp	q6, q7, [x17]
	ldp	q16, q19, [x0]
	ldp	q20, q21, [x15, #32]
	ldp	q22, q24, [x16, #32]
	ldp	q27, q28, [x17, #32]
	ldp	q29, q31, [x0, #32]
	add	v13.4s, v12.4s, v4.4s
	add	v4.4s, v15.4s, v18.4s
	zip1	v25.4s, v1.4s, v3.4s
	zip1	v18.4s, v6.4s, v16.4s
	zip2	v23.4s, v1.4s, v3.4s
	zip1	v17.4s, v2.4s, v5.4s
	zip2	v10.4s, v2.4s, v5.4s
	zip1	v1.4s, v7.4s, v19.4s
	zip2	v2.4s, v7.4s, v19.4s
	zip1	v30.4s, v20.4s, v22.4s
	zip2	v14.4s, v20.4s, v22.4s
	zip1	v3.4s, v27.4s, v29.4s
	zip2	v5.4s, v27.4s, v29.4s
	zip1	v22.4s, v21.4s, v24.4s
	zip2	v27.4s, v21.4s, v24.4s
	zip2	v7.4s, v28.4s, v31.4s
	ext	v21.16b, v18.16b, v25.16b, #8
	ext	v0.16b, v5.16b, v14.16b, #8
	ext	v20.16b, v25.16b, v21.16b, #8
	mov	v25.d[1], v18.d[0]
	ext	v18.16b, v7.16b, v27.16b, #8
	zip2	v6.4s, v6.4s, v16.4s
	zip1	v16.4s, v28.4s, v31.4s
	ext	v29.16b, v14.16b, v0.16b, #8
	ext	v0.16b, v27.16b, v18.16b, #8
	ext	v9.16b, v16.16b, v22.16b, #8
	str	q0, [sp, #144]
	mov	v0.16b, v27.16b
	ext	v31.16b, v22.16b, v9.16b, #8
	mov	v22.d[1], v16.d[0]
	mov	v0.d[1], v7.d[0]
	mov	v9.16b, v22.16b
	mov	v22.16b, v0.16b
	ldr	q0, [sp, #192]
	ext	v24.16b, v1.16b, v17.16b, #8
	ext	v26.16b, v17.16b, v24.16b, #8
	mov	v17.d[1], v1.d[0]
	add	v1.4s, v0.4s, v25.4s
	ldr	q0, [sp, #128]
	ext	v28.16b, v2.16b, v10.16b, #8
	ext	v8.16b, v3.16b, v30.16b, #8
	ext	v24.16b, v10.16b, v28.16b, #8
	ext	v28.16b, v30.16b, v8.16b, #8
	mov	v30.d[1], v3.d[0]
	eor	v3.16b, v1.16b, v0.16b
	ldr	q0, [sp, #112]
	ext	v19.16b, v6.16b, v23.16b, #8
	ext	v19.16b, v23.16b, v19.16b, #8
	mov	v23.d[1], v6.d[0]
	mov	v10.d[1], v2.d[0]
	add	v2.4s, v13.4s, v23.4s
	add	v6.4s, v4.4s, v17.4s
	eor	v4.16b, v2.16b, v0.16b
	movi	v0.4s, #64
	mov	v14.d[1], v5.d[0]
	eor	v5.16b, v6.16b, v0.16b
	ldr	q0, [sp, #80]
	rev32	v3.8h, v3.8h
	rev32	v4.8h, v4.8h
	rev32	v5.8h, v5.8h
	add	v7.4s, v3.4s, v0.4s
	ldr	q0, [sp, #64]
	stp	q25, q17, [sp, #384]
	mov	v21.16b, v10.16b
	eor	v18.16b, v7.16b, v11.16b
	add	v16.4s, v4.4s, v0.4s
	ldr	q0, [sp, #96]
	eor	v11.16b, v16.16b, v12.16b
	ushr	v12.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	add	v17.4s, v5.4s, v0.4s
	ldr	q0, [sp, #208]
	str	q10, [sp, #416]
	eor	v10.16b, v17.16b, v15.16b
	orr	v18.16b, v18.16b, v12.16b
	add	v13.4s, v0.4s, v21.4s
	ldr	q0, [sp, #304]
	ushr	v12.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	orr	v11.16b, v11.16b, v12.16b
	eor	v15.16b, v13.16b, v0.16b
	ldr	q0, [sp, #224]
	ushr	v12.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v12.16b
	dup	v12.4s, w8
	rev32	v15.8h, v15.8h
	add	v12.4s, v15.4s, v12.4s
	add	v1.4s, v1.4s, v20.4s
	mov	v27.16b, v14.16b
	eor	v14.16b, v12.16b, v0.16b
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v19.4s
	ushr	v0.4s, v14.4s, #12
	shl	v14.4s, v14.4s, #20
	eor	v3.16b, v1.16b, v3.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v26.4s
	orr	v0.16b, v14.16b, v0.16b
	ushr	v14.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v2.16b, v4.16b
	add	v6.4s, v6.4s, v10.4s
	orr	v3.16b, v3.16b, v14.16b
	ushr	v14.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v24.4s
	orr	v4.16b, v4.16b, v14.16b
	ushr	v14.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	add	v13.4s, v13.4s, v0.4s
	orr	v5.16b, v5.16b, v14.16b
	eor	v14.16b, v13.16b, v15.16b
	add	v7.4s, v3.4s, v7.4s
	ushr	v15.4s, v14.4s, #8
	shl	v14.4s, v14.4s, #24
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v4.4s, v16.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v5.4s, v17.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v14.4s, v12.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v0.16b, v12.16b, v0.16b
	add	v1.4s, v1.4s, v30.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v27.4s
	orr	v0.16b, v0.16b, v15.16b
	eor	v14.16b, v1.16b, v14.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v9.4s
	rev32	v14.8h, v14.8h
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v0.4s
	add	v13.4s, v13.4s, v22.4s
	add	v17.4s, v17.4s, v14.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v12.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v13.16b, v5.16b
	mov	v21.16b, v19.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v7.4s, v4.4s
	rev32	v5.8h, v5.8h
	mov	v19.16b, v31.16b
	add	v6.4s, v6.4s, v31.4s
	ldr	q31, [sp, #144]
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v0.16b, v7.16b, v0.16b
	add	v16.4s, v16.4s, v5.4s
	add	v1.4s, v1.4s, v28.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	eor	v18.16b, v16.16b, v18.16b
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v29.4s
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v14.16b, v1.16b, v14.16b
	add	v2.4s, v2.4s, v10.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v14.4s, #8
	shl	v14.4s, v14.4s, #24
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v0.4s
	add	v13.4s, v13.4s, v31.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v13.16b, v5.16b
	add	v17.4s, v14.4s, v17.4s
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v3.4s, v12.4s
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v4.4s, v7.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v0.16b, v7.16b, v0.16b
	add	v16.4s, v5.4s, v16.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	eor	v18.16b, v16.16b, v18.16b
	str	q26, [sp, #176]
	str	q30, [sp, #352]
	mov	v26.16b, v9.16b
	mov	v30.16b, v22.16b
	mov	v9.16b, v28.16b
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	mov	v22.16b, v21.16b
	add	v2.4s, v2.4s, v21.4s
	ldp	q21, q28, [sp, #400]
	orr	v18.16b, v18.16b, v15.16b
	add	v1.4s, v1.4s, v23.4s
	add	v1.4s, v1.4s, v18.4s
	eor	v3.16b, v3.16b, v1.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v24.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v4.16b, v2.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v21.4s
	add	v7.4s, v7.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v0.4s
	mov	v8.16b, v20.16b
	str	q20, [sp, #368]
	mov	v20.16b, v27.16b
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v16.4s, v4.4s
	mov	v27.16b, v24.16b
	rev32	v5.8h, v5.8h
	eor	v14.16b, v13.16b, v14.16b
	ldr	q24, [sp, #384]
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v17.4s, v5.4s
	rev32	v14.8h, v14.8h
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v12.4s, v14.4s
	add	v1.4s, v1.4s, v28.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v0.16b, v12.16b, v0.16b
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v20.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	eor	v3.16b, v1.16b, v3.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v24.4s
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v2.16b, v4.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v19.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v0.4s
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v14.16b, v13.16b, v14.16b
	add	v7.4s, v3.4s, v7.4s
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v14.4s, #8
	shl	v14.4s, v14.4s, #24
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v4.4s, v16.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v5.4s, v17.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v14.4s, v12.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v0.16b, v12.16b, v0.16b
	add	v1.4s, v1.4s, v8.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v26.4s
	orr	v0.16b, v0.16b, v15.16b
	eor	v14.16b, v1.16b, v14.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v9.4s
	rev32	v14.8h, v14.8h
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v0.4s
	add	v13.4s, v13.4s, v31.4s
	add	v17.4s, v17.4s, v14.4s
	mov	v24.16b, v26.16b
	rev32	v3.8h, v3.8h
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	ldr	q26, [sp, #176]
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v12.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v13.16b, v5.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v7.4s, v4.4s
	rev32	v5.8h, v5.8h
	add	v1.4s, v1.4s, v29.4s
	mov	v25.16b, v29.16b
	str	q29, [sp, #160]
	ldr	q29, [sp, #352]
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v0.16b, v7.16b, v0.16b
	add	v16.4s, v16.4s, v5.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	eor	v18.16b, v16.16b, v18.16b
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v26.4s
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v14.16b, v1.16b, v14.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v30.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v14.4s, #8
	shl	v14.4s, v14.4s, #24
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v0.4s
	add	v13.4s, v13.4s, v29.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v13.16b, v5.16b
	add	v17.4s, v14.4s, v17.4s
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v3.4s, v12.4s
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v4.4s, v7.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v0.16b, v7.16b, v0.16b
	add	v16.4s, v5.4s, v16.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	eor	v18.16b, v16.16b, v18.16b
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	orr	v18.16b, v18.16b, v15.16b
	add	v1.4s, v1.4s, v22.4s
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v20.4s
	eor	v3.16b, v3.16b, v1.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v19.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v4.16b, v2.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v27.4s
	add	v7.4s, v7.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v0.4s
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v16.4s, v4.4s
	rev32	v5.8h, v5.8h
	eor	v14.16b, v13.16b, v14.16b
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v17.4s, v5.4s
	rev32	v14.8h, v14.8h
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v12.4s, v14.4s
	add	v1.4s, v1.4s, v21.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v0.16b, v12.16b, v0.16b
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v24.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	eor	v3.16b, v1.16b, v3.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v23.4s
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v2.16b, v4.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v30.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v0.4s
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v14.16b, v13.16b, v14.16b
	add	v7.4s, v3.4s, v7.4s
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v14.4s, #8
	shl	v14.4s, v14.4s, #24
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v4.4s, v16.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v5.4s, v17.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v14.4s, v12.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v0.16b, v12.16b, v0.16b
	add	v1.4s, v1.4s, v28.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v9.4s
	orr	v0.16b, v0.16b, v15.16b
	eor	v14.16b, v1.16b, v14.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v25.4s
	rev32	v14.8h, v14.8h
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v0.4s
	add	v17.4s, v17.4s, v14.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v6.16b, v4.16b
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v12.4s, v3.4s
	rev32	v4.8h, v4.8h
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v7.4s, v4.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v0.16b, v7.16b, v0.16b
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v15.16b, v0.16b, v15.16b
	add	v0.4s, v13.4s, v29.4s
	add	v13.4s, v0.4s, v18.4s
	eor	v0.16b, v13.16b, v5.16b
	rev32	v5.8h, v0.8h
	mov	v8.16b, v31.16b
	mov	v31.16b, v22.16b
	str	q22, [sp, #288]
	mov	v22.16b, v20.16b
	mov	v20.16b, v27.16b
	add	v16.4s, v16.4s, v5.4s
	ldp	q27, q25, [sp, #368]
	eor	v0.16b, v16.16b, v18.16b
	ushr	v18.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v18.16b, v0.16b, v18.16b
	add	v0.4s, v1.4s, v26.4s
	add	v1.4s, v0.4s, v11.4s
	add	v2.4s, v2.4s, v25.4s
	eor	v0.16b, v1.16b, v14.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v8.4s
	ushr	v14.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v15.4s
	add	v13.4s, v13.4s, v27.4s
	orr	v0.16b, v0.16b, v14.16b
	ushr	v14.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	orr	v3.16b, v3.16b, v14.16b
	ushr	v14.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v13.16b, v5.16b
	add	v17.4s, v0.4s, v17.4s
	orr	v4.16b, v4.16b, v14.16b
	ushr	v14.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v3.4s, v12.4s
	orr	v5.16b, v5.16b, v14.16b
	ushr	v14.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v12.16b, v10.16b
	orr	v11.16b, v11.16b, v14.16b
	ushr	v14.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	add	v7.4s, v4.4s, v7.4s
	orr	v10.16b, v10.16b, v14.16b
	eor	v14.16b, v7.16b, v15.16b
	add	v16.4s, v5.4s, v16.4s
	ushr	v15.4s, v14.4s, #7
	shl	v14.4s, v14.4s, #25
	eor	v18.16b, v16.16b, v18.16b
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	orr	v18.16b, v18.16b, v15.16b
	add	v1.4s, v1.4s, v22.4s
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v24.4s
	eor	v3.16b, v3.16b, v1.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v30.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v4.16b, v2.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v19.4s
	add	v7.4s, v7.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v14.4s
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v16.4s, v4.4s
	rev32	v5.8h, v5.8h
	eor	v0.16b, v13.16b, v0.16b
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v17.4s, v5.4s
	rev32	v0.8h, v0.8h
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v12.4s, v0.4s
	add	v1.4s, v1.4s, v20.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v14.16b, v12.16b, v14.16b
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v9.4s
	mov	v29.16b, v8.16b
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	shl	v14.4s, v14.4s, #20
	eor	v3.16b, v1.16b, v3.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v31.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v2.16b, v4.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v29.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v14.4s
	str	q23, [sp, #272]
	mov	v23.16b, v22.16b
	str	q22, [sp, #336]
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v0.16b, v13.16b, v0.16b
	add	v7.4s, v3.4s, v7.4s
	ldr	q22, [sp, #400]
	mov	v28.16b, v26.16b
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v4.4s, v16.4s
	ldr	q26, [sp, #160]
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v5.4s, v17.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v0.4s, v12.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v14.16b, v12.16b, v14.16b
	add	v1.4s, v1.4s, v22.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #7
	shl	v14.4s, v14.4s, #25
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v26.4s
	orr	v14.16b, v14.16b, v15.16b
	eor	v0.16b, v1.16b, v0.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v28.4s
	rev32	v0.8h, v0.8h
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v14.4s
	add	v13.4s, v13.4s, v27.4s
	add	v17.4s, v17.4s, v0.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	ldr	q21, [sp, #272]
	mov	v8.16b, v24.16b
	mov	v24.16b, v29.16b
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v12.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v13.16b, v5.16b
	ldr	q29, [sp, #352]
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v7.4s, v4.4s
	rev32	v5.8h, v5.8h
	ldr	q27, [sp, #416]
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v14.16b, v7.16b, v14.16b
	add	v16.4s, v16.4s, v5.4s
	add	v1.4s, v1.4s, v25.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	shl	v14.4s, v14.4s, #20
	eor	v18.16b, v16.16b, v18.16b
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v21.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v0.16b, v1.16b, v0.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v29.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v14.4s
	add	v13.4s, v13.4s, v27.4s
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v13.16b, v5.16b
	add	v17.4s, v0.4s, v17.4s
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v3.4s, v12.4s
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v4.4s, v7.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v14.16b, v7.16b, v14.16b
	add	v16.4s, v5.4s, v16.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #7
	shl	v14.4s, v14.4s, #25
	eor	v18.16b, v16.16b, v18.16b
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	orr	v18.16b, v18.16b, v15.16b
	add	v1.4s, v1.4s, v8.4s
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v9.4s
	eor	v3.16b, v3.16b, v1.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v24.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v4.16b, v2.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v30.4s
	add	v7.4s, v7.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v14.4s
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v16.4s, v4.4s
	rev32	v5.8h, v5.8h
	eor	v0.16b, v13.16b, v0.16b
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v17.4s, v5.4s
	rev32	v0.8h, v0.8h
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v12.4s, v0.4s
	add	v1.4s, v1.4s, v19.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v14.16b, v12.16b, v14.16b
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v26.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	shl	v14.4s, v14.4s, #20
	eor	v3.16b, v1.16b, v3.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v23.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v2.16b, v4.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v29.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v14.4s
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v0.16b, v13.16b, v0.16b
	add	v7.4s, v3.4s, v7.4s
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v4.4s, v16.4s
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v5.4s, v17.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v0.4s, v12.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v14.16b, v12.16b, v14.16b
	add	v1.4s, v1.4s, v20.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #7
	shl	v14.4s, v14.4s, #25
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v28.4s
	orr	v14.16b, v14.16b, v15.16b
	eor	v0.16b, v1.16b, v0.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v25.4s
	rev32	v0.8h, v0.8h
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v14.4s
	add	v13.4s, v13.4s, v27.4s
	mov	v23.16b, v29.16b
	add	v17.4s, v17.4s, v0.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	ldr	q29, [sp, #288]
	mov	v31.16b, v19.16b
	eor	v11.16b, v17.16b, v11.16b
	mov	v19.16b, v28.16b
	add	v12.4s, v12.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v13.16b, v5.16b
	ldr	q28, [sp, #368]
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v7.4s, v4.4s
	rev32	v5.8h, v5.8h
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v14.16b, v7.16b, v14.16b
	add	v16.4s, v16.4s, v5.4s
	add	v1.4s, v1.4s, v21.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	shl	v14.4s, v14.4s, #20
	eor	v18.16b, v16.16b, v18.16b
	add	v1.4s, v1.4s, v11.4s
	add	v2.4s, v2.4s, v29.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v0.16b, v1.16b, v0.16b
	add	v2.4s, v2.4s, v10.4s
	add	v6.4s, v6.4s, v28.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	eor	v3.16b, v2.16b, v3.16b
	add	v6.4s, v6.4s, v14.4s
	add	v13.4s, v13.4s, v22.4s
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v6.16b, v4.16b
	add	v13.4s, v13.4s, v18.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v13.16b, v5.16b
	add	v17.4s, v0.4s, v17.4s
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v11.16b, v17.16b, v11.16b
	add	v12.4s, v3.4s, v12.4s
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v12.16b, v10.16b
	add	v7.4s, v4.4s, v7.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v14.16b, v7.16b, v14.16b
	add	v16.4s, v5.4s, v16.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #7
	shl	v14.4s, v14.4s, #25
	eor	v18.16b, v16.16b, v18.16b
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	orr	v18.16b, v18.16b, v15.16b
	add	v1.4s, v1.4s, v9.4s
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v26.4s
	eor	v3.16b, v3.16b, v1.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v23.4s
	rev32	v3.8h, v3.8h
	eor	v4.16b, v4.16b, v2.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v24.4s
	add	v7.4s, v7.4s, v3.4s
	rev32	v4.8h, v4.8h
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v14.4s
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v16.4s, v4.4s
	rev32	v5.8h, v5.8h
	eor	v0.16b, v13.16b, v0.16b
	ushr	v15.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v17.4s, v5.4s
	rev32	v0.8h, v0.8h
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v12.4s, v0.4s
	add	v1.4s, v1.4s, v30.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v14.16b, v12.16b, v14.16b
	add	v1.4s, v1.4s, v18.4s
	add	v2.4s, v2.4s, v19.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	shl	v14.4s, v14.4s, #20
	eor	v3.16b, v1.16b, v3.16b
	add	v2.4s, v2.4s, v11.4s
	add	v6.4s, v6.4s, v8.4s
	orr	v14.16b, v14.16b, v15.16b
	ushr	v15.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	eor	v4.16b, v2.16b, v4.16b
	add	v6.4s, v6.4s, v10.4s
	add	v13.4s, v13.4s, v28.4s
	orr	v3.16b, v3.16b, v15.16b
	ushr	v15.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v6.16b, v5.16b
	add	v13.4s, v13.4s, v14.4s
	orr	v4.16b, v4.16b, v15.16b
	ushr	v15.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	eor	v0.16b, v13.16b, v0.16b
	add	v7.4s, v3.4s, v7.4s
	orr	v5.16b, v5.16b, v15.16b
	ushr	v15.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	eor	v18.16b, v7.16b, v18.16b
	add	v16.4s, v4.4s, v16.4s
	orr	v0.16b, v0.16b, v15.16b
	ushr	v15.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	eor	v11.16b, v16.16b, v11.16b
	add	v17.4s, v5.4s, v17.4s
	orr	v18.16b, v18.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v17.16b, v10.16b
	add	v12.4s, v0.4s, v12.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v14.16b, v12.16b, v14.16b
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #7
	shl	v14.4s, v14.4s, #25
	add	v1.4s, v1.4s, v31.4s
	orr	v14.16b, v14.16b, v15.16b
	add	v15.4s, v1.4s, v11.4s
	eor	v0.16b, v15.16b, v0.16b
	rev32	v0.8h, v0.8h
	str	q30, [sp, #240]
	mov	v30.16b, v19.16b
	add	v19.4s, v17.4s, v0.4s
	eor	v1.16b, v19.16b, v11.16b
	ushr	v11.4s, v1.4s, #12
	shl	v1.4s, v1.4s, #20
	add	v2.4s, v2.4s, v25.4s
	orr	v17.16b, v1.16b, v11.16b
	add	v11.4s, v2.4s, v10.4s
	eor	v2.16b, v11.16b, v3.16b
	add	v6.4s, v6.4s, v21.4s
	rev32	v1.8h, v2.8h
	add	v6.4s, v6.4s, v14.4s
	add	v2.4s, v12.4s, v1.4s
	eor	v4.16b, v6.16b, v4.16b
	eor	v3.16b, v2.16b, v10.16b
	rev32	v4.8h, v4.8h
	ushr	v10.4s, v3.4s, #12
	shl	v3.4s, v3.4s, #20
	add	v7.4s, v7.4s, v4.4s
	orr	v3.16b, v3.16b, v10.16b
	eor	v10.16b, v7.16b, v14.16b
	ushr	v12.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v12.16b
	add	v12.4s, v13.4s, v22.4s
	add	v12.4s, v12.4s, v18.4s
	eor	v5.16b, v12.16b, v5.16b
	rev32	v5.8h, v5.8h
	add	v16.4s, v16.4s, v5.4s
	eor	v18.16b, v16.16b, v18.16b
	ushr	v13.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	orr	v18.16b, v18.16b, v13.16b
	add	v13.4s, v15.4s, v29.4s
	add	v13.4s, v13.4s, v17.4s
	str	q8, [sp, #256]
	eor	v0.16b, v13.16b, v0.16b
	add	v8.4s, v13.4s, v26.4s
	ldr	q13, [sp, #336]
	str	q20, [sp, #320]
	mov	v20.16b, v9.16b
	mov	v9.16b, v31.16b
	add	v11.4s, v11.4s, v13.4s
	add	v11.4s, v11.4s, v3.4s
	eor	v1.16b, v11.16b, v1.16b
	add	v31.4s, v11.4s, v30.4s
	ldr	q11, [sp, #320]
	add	v6.4s, v6.4s, v27.4s
	add	v6.4s, v6.4s, v10.4s
	ushr	v30.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	mov	v14.16b, v29.16b
	eor	v4.16b, v6.16b, v4.16b
	add	v29.4s, v12.4s, v11.4s
	orr	v0.16b, v0.16b, v30.16b
	ushr	v30.4s, v1.4s, #8
	shl	v1.4s, v1.4s, #24
	add	v29.4s, v29.4s, v18.4s
	orr	v1.16b, v1.16b, v30.16b
	ushr	v30.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v5.16b, v29.16b, v5.16b
	orr	v4.16b, v4.16b, v30.16b
	add	v19.4s, v0.4s, v19.4s
	ushr	v30.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	add	v2.4s, v1.4s, v2.4s
	add	v7.4s, v4.4s, v7.4s
	eor	v17.16b, v19.16b, v17.16b
	orr	v5.16b, v5.16b, v30.16b
	eor	v3.16b, v2.16b, v3.16b
	eor	v30.16b, v7.16b, v10.16b
	ushr	v10.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	add	v16.4s, v5.4s, v16.4s
	orr	v17.16b, v17.16b, v10.16b
	ushr	v10.4s, v3.4s, #7
	shl	v3.4s, v3.4s, #25
	eor	v18.16b, v16.16b, v18.16b
	orr	v3.16b, v3.16b, v10.16b
	ushr	v10.4s, v30.4s, #7
	shl	v30.4s, v30.4s, #25
	orr	v30.16b, v30.16b, v10.16b
	ushr	v10.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	orr	v18.16b, v18.16b, v10.16b
	add	v8.4s, v8.4s, v18.4s
	add	v6.4s, v6.4s, v28.4s
	eor	v1.16b, v1.16b, v8.16b
	add	v31.4s, v31.4s, v17.4s
	add	v29.4s, v29.4s, v23.4s
	eor	v4.16b, v4.16b, v31.16b
	add	v6.4s, v6.4s, v3.4s
	rev32	v1.8h, v1.8h
	mov	v26.16b, v27.16b
	eor	v5.16b, v6.16b, v5.16b
	add	v27.4s, v29.4s, v30.4s
	rev32	v4.8h, v4.8h
	add	v7.4s, v7.4s, v1.4s
	eor	v0.16b, v27.16b, v0.16b
	rev32	v5.8h, v5.8h
	add	v16.4s, v16.4s, v4.4s
	eor	v18.16b, v7.16b, v18.16b
	rev32	v0.8h, v0.8h
	add	v19.4s, v19.4s, v5.4s
	eor	v17.16b, v16.16b, v17.16b
	ushr	v29.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	add	v2.4s, v2.4s, v0.4s
	eor	v3.16b, v19.16b, v3.16b
	orr	v18.16b, v18.16b, v29.16b
	ushr	v29.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	add	v28.4s, v8.4s, v24.4s
	add	v26.4s, v27.4s, v26.4s
	eor	v27.16b, v2.16b, v30.16b
	orr	v17.16b, v17.16b, v29.16b
	ushr	v29.4s, v3.4s, #12
	shl	v3.4s, v3.4s, #20
	add	v25.4s, v31.4s, v25.4s
	orr	v3.16b, v3.16b, v29.16b
	ushr	v29.4s, v27.4s, #12
	shl	v27.4s, v27.4s, #20
	add	v28.4s, v28.4s, v18.4s
	add	v6.4s, v6.4s, v20.4s
	orr	v27.16b, v27.16b, v29.16b
	eor	v1.16b, v28.16b, v1.16b
	add	v25.4s, v25.4s, v17.4s
	eor	v4.16b, v25.16b, v4.16b
	add	v23.4s, v25.4s, v21.4s
	add	v6.4s, v6.4s, v3.4s
	add	v25.4s, v26.4s, v27.4s
	ushr	v26.4s, v1.4s, #8
	shl	v1.4s, v1.4s, #24
	eor	v5.16b, v6.16b, v5.16b
	orr	v1.16b, v1.16b, v26.16b
	ushr	v26.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	eor	v0.16b, v25.16b, v0.16b
	orr	v4.16b, v4.16b, v26.16b
	ushr	v26.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	orr	v5.16b, v5.16b, v26.16b
	ushr	v26.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	ldr	q20, [sp, #240]
	orr	v0.16b, v0.16b, v26.16b
	add	v7.4s, v1.4s, v7.4s
	add	v16.4s, v4.4s, v16.4s
	add	v2.4s, v0.4s, v2.4s
	eor	v18.16b, v7.16b, v18.16b
	add	v19.4s, v5.4s, v19.4s
	eor	v17.16b, v16.16b, v17.16b
	eor	v26.16b, v2.16b, v27.16b
	ushr	v27.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	eor	v3.16b, v19.16b, v3.16b
	orr	v18.16b, v18.16b, v27.16b
	ushr	v27.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	add	v24.4s, v28.4s, v20.4s
	orr	v17.16b, v17.16b, v27.16b
	ushr	v27.4s, v3.4s, #7
	shl	v3.4s, v3.4s, #25
	orr	v3.16b, v3.16b, v27.16b
	ushr	v27.4s, v26.4s, #7
	shl	v26.4s, v26.4s, #25
	add	v24.4s, v24.4s, v17.4s
	add	v6.4s, v6.4s, v14.4s
	orr	v26.16b, v26.16b, v27.16b
	eor	v0.16b, v24.16b, v0.16b
	add	v23.4s, v23.4s, v3.4s
	add	v25.4s, v25.4s, v11.4s
	eor	v1.16b, v23.16b, v1.16b
	ldr	q20, [sp, #256]
	add	v6.4s, v6.4s, v26.4s
	rev32	v0.8h, v0.8h
	eor	v4.16b, v6.16b, v4.16b
	add	v6.4s, v6.4s, v22.4s
	add	v22.4s, v25.4s, v18.4s
	rev32	v1.8h, v1.8h
	add	v19.4s, v19.4s, v0.4s
	eor	v5.16b, v22.16b, v5.16b
	rev32	v4.8h, v4.8h
	add	v2.4s, v2.4s, v1.4s
	eor	v17.16b, v19.16b, v17.16b
	add	v21.4s, v24.4s, v13.4s
	rev32	v5.8h, v5.8h
	add	v7.4s, v7.4s, v4.4s
	eor	v3.16b, v2.16b, v3.16b
	ushr	v24.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	add	v20.4s, v23.4s, v20.4s
	add	v16.4s, v16.4s, v5.4s
	eor	v23.16b, v7.16b, v26.16b
	orr	v17.16b, v17.16b, v24.16b
	ushr	v24.4s, v3.4s, #12
	shl	v3.4s, v3.4s, #20
	eor	v18.16b, v16.16b, v18.16b
	orr	v3.16b, v3.16b, v24.16b
	ushr	v24.4s, v23.4s, #12
	shl	v23.4s, v23.4s, #20
	add	v21.4s, v21.4s, v17.4s
	orr	v23.16b, v23.16b, v24.16b
	ushr	v24.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	add	v20.4s, v20.4s, v3.4s
	eor	v0.16b, v21.16b, v0.16b
	add	v22.4s, v22.4s, v9.4s
	orr	v18.16b, v18.16b, v24.16b
	add	v6.4s, v6.4s, v23.4s
	eor	v1.16b, v20.16b, v1.16b
	ushr	v24.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	add	v22.4s, v22.4s, v18.4s
	eor	v4.16b, v6.16b, v4.16b
	orr	v24.16b, v0.16b, v24.16b
	ushr	v0.4s, v1.4s, #8
	shl	v1.4s, v1.4s, #24
	eor	v5.16b, v22.16b, v5.16b
	orr	v1.16b, v1.16b, v0.16b
	ushr	v0.4s, v4.4s, #8
	shl	v4.4s, v4.4s, #24
	orr	v25.16b, v4.16b, v0.16b
	ushr	v0.4s, v5.4s, #8
	shl	v4.4s, v5.4s, #24
	orr	v5.16b, v4.16b, v0.16b
	add	v4.4s, v5.4s, v16.4s
	eor	v16.16b, v4.16b, v18.16b
	add	v18.4s, v24.4s, v19.4s
	eor	v19.16b, v18.16b, v17.16b
	add	v2.4s, v1.4s, v2.4s
	add	v0.4s, v25.4s, v7.4s
	eor	v18.16b, v6.16b, v18.16b
	eor	v3.16b, v2.16b, v3.16b
	eor	v17.16b, v2.16b, v22.16b
	ushr	v2.4s, v19.4s, #7
	shl	v6.4s, v19.4s, #25
	eor	v7.16b, v0.16b, v23.16b
	orr	v2.16b, v6.16b, v2.16b
	ushr	v6.4s, v3.4s, #7
	shl	v3.4s, v3.4s, #25
	orr	v3.16b, v3.16b, v6.16b
	ushr	v6.4s, v7.4s, #7
	shl	v7.4s, v7.4s, #25
	orr	v6.16b, v7.16b, v6.16b
	ushr	v7.4s, v16.4s, #7
	shl	v16.4s, v16.4s, #25
	orr	v7.16b, v16.16b, v7.16b
	eor	v0.16b, v0.16b, v21.16b
	eor	v4.16b, v20.16b, v4.16b
	eor	v11.16b, v1.16b, v7.16b
	eor	v12.16b, v25.16b, v2.16b
	eor	v15.16b, v3.16b, v5.16b
	eor	v7.16b, v6.16b, v24.16b
	prfm	pldl1keep, [x15, #256]
	prfm	pldl1keep, [x16, #256]
	prfm	pldl1keep, [x17, #256]
	add	x9, x9, #64
	mov	w17, w19
	prfm	pldl1keep, [x0, #256]
	cbnz	x14, .LBB3_5
	b	.LBB3_2
.LBB3_6:
	cbz	x23, .LBB3_14
	and	x29, x5, #0x1
.LBB3_8:
	ldp	q0, q1, [x21]
	ldr	x25, [x24]
	ldr	w5, [sp, #60]
	mov	x8, x22
	stp	q0, q1, [sp, #432]
	b	.LBB3_11
.LBB3_9:
	orr	w5, w5, w27
.LBB3_10:
	add	x0, sp, #464
	add	x1, sp, #432
	mov	w3, #64
	mov	x2, x25
	mov	x4, x20
	bl	compress_pre
	ldp	q0, q1, [sp, #464]
	ldp	q2, q3, [sp, #496]
	add	x25, x25, #64
	mov	x8, x28
	mov	w5, w19
	eor	v0.16b, v2.16b, v0.16b
	eor	v1.16b, v3.16b, v1.16b
	stp	q0, q1, [sp, #432]
.LBB3_11:
	subs	x28, x8, #1
	b.eq	.LBB3_9
	cbnz	x8, .LBB3_10
	ldp	q0, q1, [sp, #432]
	add	x20, x20, x29
	add	x24, x24, #8
	subs	x23, x23, #1
	stp	q0, q1, [x26], #32
	b.ne	.LBB3_8
.LBB3_14:
	add	sp, sp, #528
	ldp	x20, x19, [sp, #144]
	ldp	x22, x21, [sp, #128]
	ldp	x24, x23, [sp, #112]
	ldp	x26, x25, [sp, #96]
	ldp	x28, x27, [sp, #80]
	ldp	x29, x30, [sp, #64]
	ldp	d9, d8, [sp, #48]
	ldp	d11, d10, [sp, #32]
	ldp	d13, d12, [sp, #16]
	ldp	d15, d14, [sp], #160
	ret
.Lfunc_end3:
	.size	zfs_blake3_hash_many_sse2, .Lfunc_end3-zfs_blake3_hash_many_sse2
	.cfi_endproc
	.section	".note.GNU-stack","",@progbits
#endif
