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
 * Copyright (c) 2019-2022 Samuel Neves
 * Copyright (c) 2022-2023 Tino Reichardt <milky-zfs@mcmilk.de>
 *
 * This is converted assembly: SSE4.1 -> ARMv8-A
 * Used tools: SIMDe https://github.com/simd-everywhere/simde
 * C source files are here: https://github.com/mcmilk/BLAKE3-tests
 */

#if defined(__aarch64__)
	.text
	.globl	zfs_blake3_compress_in_place_sse41
	.p2align	2
	.type	zfs_blake3_compress_in_place_sse41,@function
zfs_blake3_compress_in_place_sse41:
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
	.size	zfs_blake3_compress_in_place_sse41, .Lfunc_end0-zfs_blake3_compress_in_place_sse41
	.cfi_endproc

	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI1_0:
	.xword	-4942790177982912921
	.xword	-6534734903820487822
.LCPI1_1:
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	6
	.byte	7
	.byte	4
	.byte	5
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	14
	.byte	15
	.byte	12
	.byte	13
.LCPI1_2:
	.byte	1
	.byte	2
	.byte	3
	.byte	0
	.byte	5
	.byte	6
	.byte	7
	.byte	4
	.byte	9
	.byte	10
	.byte	11
	.byte	8
	.byte	13
	.byte	14
	.byte	15
	.byte	12
.LCPI1_3:
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	20
	.byte	21
	.byte	22
	.byte	23
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	28
	.byte	29
	.byte	30
	.byte	31
.LCPI1_4:
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	28
	.byte	29
	.byte	30
	.byte	31
	.text
	.p2align	2
	.type	compress_pre,@function
compress_pre:
	.cfi_startproc
	ldr	q4, [x1]
	adrp	x8, .LCPI1_0
	fmov	s2, w3
	ldr	q5, [x8, :lo12:.LCPI1_0]
	str	q4, [x0]
	ldr	q19, [x1, #16]
	lsr	x9, x4, #32
	fmov	s6, w4
	movi	d3, #0x0000ff000000ff
	mov	v2.s[1], w5
	mov	v6.s[1], w9
	and	v2.8b, v2.8b, v3.8b
	mov	v6.d[1], v2.d[0]
	add	x8, x2, #32
	stp	q5, q6, [x0, #32]
	str	q19, [x0, #16]
	ldp	q7, q16, [x2]
	ld2	{ v21.4s, v22.4s }, [x8]
	adrp	x9, .LCPI1_2
	ldr	q1, [x9, :lo12:.LCPI1_2]
	adrp	x9, .LCPI1_4
	adrp	x10, .LCPI1_1
	ldr	q2, [x9, :lo12:.LCPI1_4]
	ldr	q0, [x10, :lo12:.LCPI1_1]
	adrp	x10, .LCPI1_3
	uzp1	v17.4s, v7.4s, v16.4s
	uzp2	v16.4s, v7.4s, v16.4s
	ext	v7.16b, v22.16b, v22.16b, #12
	ldr	q3, [x10, :lo12:.LCPI1_3]
	ext	v24.16b, v21.16b, v21.16b, #12
	add	v4.4s, v4.4s, v17.4s
	uzp1	v18.4s, v17.4s, v17.4s
	mov	v26.16b, v7.16b
	ext	v27.16b, v17.16b, v17.16b, #12
	zip2	v28.4s, v16.4s, v7.4s
	add	v4.4s, v4.4s, v19.4s
	ext	v18.16b, v18.16b, v17.16b, #8
	mov	v26.s[1], v24.s[2]
	zip1	v23.2d, v7.2d, v16.2d
	eor	v6.16b, v4.16b, v6.16b
	add	v29.4s, v4.4s, v16.4s
	uzp2	v20.4s, v18.4s, v16.4s
	ext	v25.16b, v17.16b, v27.16b, #12
	tbl	v17.16b, { v23.16b, v24.16b }, v2.16b
	zip1	v4.4s, v28.4s, v24.4s
	zip1	v18.4s, v24.4s, v28.4s
	ext	v24.16b, v17.16b, v17.16b, #12
	ext	v4.16b, v18.16b, v4.16b, #8
	tbl	v23.16b, { v6.16b }, v0.16b
	ext	v6.16b, v20.16b, v20.16b, #4
	tbl	v16.16b, { v25.16b, v26.16b }, v3.16b
	uzp1	v18.4s, v17.4s, v24.4s
	mov	v25.16b, v4.16b
	add	v5.4s, v23.4s, v5.4s
	ext	v26.16b, v6.16b, v6.16b, #12
	mov	v25.s[1], v18.s[2]
	ext	v24.16b, v6.16b, v26.16b, #12
	uzp1	v26.4s, v6.4s, v6.4s
	eor	v19.16b, v5.16b, v19.16b
	ext	v6.16b, v26.16b, v6.16b, #8
	ushr	v26.4s, v19.4s, #12
	shl	v19.4s, v19.4s, #20
	orr	v26.16b, v19.16b, v26.16b
	uzp2	v19.4s, v6.4s, v16.4s
	tbl	v6.16b, { v24.16b, v25.16b }, v3.16b
	add	v25.4s, v29.4s, v26.4s
	eor	v23.16b, v23.16b, v25.16b
	tbl	v23.16b, { v23.16b }, v1.16b
	add	v21.4s, v25.4s, v21.4s
	add	v25.4s, v5.4s, v23.4s
	eor	v5.16b, v25.16b, v26.16b
	ext	v24.16b, v19.16b, v19.16b, #4
	ushr	v26.4s, v5.4s, #7
	shl	v5.4s, v5.4s, #25
	uzp1	v22.4s, v24.4s, v24.4s
	orr	v26.16b, v5.16b, v26.16b
	ext	v21.16b, v21.16b, v21.16b, #12
	ext	v5.16b, v22.16b, v24.16b, #8
	ext	v22.16b, v23.16b, v23.16b, #8
	add	v21.4s, v21.4s, v26.4s
	eor	v22.16b, v22.16b, v21.16b
	ext	v23.16b, v25.16b, v25.16b, #4
	add	v7.4s, v21.4s, v7.4s
	tbl	v21.16b, { v22.16b }, v0.16b
	add	v22.4s, v23.4s, v21.4s
	eor	v23.16b, v22.16b, v26.16b
	ushr	v25.4s, v23.4s, #12
	shl	v23.4s, v23.4s, #20
	orr	v23.16b, v23.16b, v25.16b
	add	v7.4s, v7.4s, v23.4s
	eor	v21.16b, v21.16b, v7.16b
	add	v7.4s, v7.4s, v20.4s
	tbl	v20.16b, { v21.16b }, v1.16b
	add	v21.4s, v22.4s, v20.4s
	eor	v22.16b, v21.16b, v23.16b
	ushr	v23.4s, v22.4s, #7
	shl	v22.4s, v22.4s, #25
	ext	v7.16b, v7.16b, v7.16b, #4
	orr	v22.16b, v22.16b, v23.16b
	ext	v20.16b, v20.16b, v20.16b, #8
	add	v7.4s, v7.4s, v22.4s
	eor	v20.16b, v20.16b, v7.16b
	ext	v21.16b, v21.16b, v21.16b, #12
	tbl	v20.16b, { v20.16b }, v0.16b
	add	v21.4s, v21.4s, v20.4s
	eor	v22.16b, v21.16b, v22.16b
	ushr	v23.4s, v22.4s, #12
	shl	v22.4s, v22.4s, #20
	add	v7.4s, v7.4s, v16.4s
	orr	v22.16b, v22.16b, v23.16b
	add	v7.4s, v7.4s, v22.4s
	ext	v23.16b, v7.16b, v7.16b, #12
	eor	v7.16b, v20.16b, v7.16b
	tbl	v7.16b, { v7.16b }, v1.16b
	add	v20.4s, v21.4s, v7.4s
	zip2	v27.4s, v16.4s, v4.4s
	add	v23.4s, v23.4s, v18.4s
	zip1	v17.2d, v4.2d, v16.2d
	eor	v21.16b, v20.16b, v22.16b
	tbl	v25.16b, { v17.16b, v18.16b }, v2.16b
	zip1	v16.4s, v27.4s, v18.4s
	zip1	v17.4s, v18.4s, v27.4s
	ushr	v22.4s, v21.4s, #7
	shl	v21.4s, v21.4s, #25
	ext	v18.16b, v25.16b, v25.16b, #12
	ext	v16.16b, v17.16b, v16.16b, #8
	orr	v21.16b, v21.16b, v22.16b
	uzp1	v26.4s, v25.4s, v18.4s
	mov	v18.16b, v16.16b
	ext	v7.16b, v7.16b, v7.16b, #8
	add	v23.4s, v23.4s, v21.4s
	ext	v28.16b, v24.16b, v24.16b, #12
	mov	v18.s[1], v26.s[2]
	eor	v7.16b, v7.16b, v23.16b
	ext	v17.16b, v24.16b, v28.16b, #12
	ext	v20.16b, v20.16b, v20.16b, #4
	tbl	v7.16b, { v7.16b }, v0.16b
	tbl	v17.16b, { v17.16b, v18.16b }, v3.16b
	add	v18.4s, v20.4s, v7.4s
	eor	v20.16b, v18.16b, v21.16b
	ushr	v21.4s, v20.4s, #12
	shl	v20.4s, v20.4s, #20
	add	v23.4s, v23.4s, v4.4s
	orr	v20.16b, v20.16b, v21.16b
	add	v21.4s, v23.4s, v20.4s
	eor	v7.16b, v7.16b, v21.16b
	tbl	v7.16b, { v7.16b }, v1.16b
	add	v18.4s, v18.4s, v7.4s
	eor	v20.16b, v18.16b, v20.16b
	add	v19.4s, v21.4s, v19.4s
	ushr	v21.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	ext	v19.16b, v19.16b, v19.16b, #4
	orr	v20.16b, v20.16b, v21.16b
	ext	v7.16b, v7.16b, v7.16b, #8
	add	v19.4s, v19.4s, v20.4s
	eor	v7.16b, v7.16b, v19.16b
	ext	v18.16b, v18.16b, v18.16b, #12
	tbl	v21.16b, { v7.16b }, v0.16b
	add	v18.4s, v18.4s, v21.4s
	eor	v7.16b, v18.16b, v20.16b
	ushr	v20.4s, v7.4s, #12
	shl	v7.4s, v7.4s, #20
	add	v19.4s, v19.4s, v6.4s
	orr	v20.16b, v7.16b, v20.16b
	add	v19.4s, v19.4s, v20.4s
	uzp2	v5.4s, v5.4s, v6.4s
	ext	v7.16b, v19.16b, v19.16b, #12
	eor	v19.16b, v21.16b, v19.16b
	ext	v24.16b, v5.16b, v5.16b, #4
	zip2	v28.4s, v6.4s, v16.4s
	add	v23.4s, v7.4s, v26.4s
	zip1	v25.2d, v16.2d, v6.2d
	tbl	v19.16b, { v19.16b }, v1.16b
	uzp1	v27.4s, v24.4s, v24.4s
	tbl	v6.16b, { v25.16b, v26.16b }, v2.16b
	zip1	v7.4s, v28.4s, v26.4s
	zip1	v25.4s, v26.4s, v28.4s
	add	v18.4s, v18.4s, v19.4s
	ext	v27.16b, v27.16b, v24.16b, #8
	ext	v26.16b, v6.16b, v6.16b, #12
	ext	v7.16b, v25.16b, v7.16b, #8
	eor	v20.16b, v18.16b, v20.16b
	uzp2	v4.4s, v27.4s, v17.4s
	uzp1	v26.4s, v6.4s, v26.4s
	mov	v28.16b, v7.16b
	ushr	v21.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	ext	v22.16b, v24.16b, v24.16b, #12
	mov	v28.s[1], v26.s[2]
	orr	v20.16b, v20.16b, v21.16b
	ext	v27.16b, v24.16b, v22.16b, #12
	ext	v19.16b, v19.16b, v19.16b, #8
	ext	v24.16b, v18.16b, v18.16b, #4
	add	v18.4s, v23.4s, v20.4s
	eor	v19.16b, v19.16b, v18.16b
	tbl	v19.16b, { v19.16b }, v0.16b
	add	v24.4s, v24.4s, v19.4s
	eor	v20.16b, v24.16b, v20.16b
	add	v16.4s, v18.4s, v16.4s
	tbl	v18.16b, { v27.16b, v28.16b }, v3.16b
	ushr	v27.4s, v20.4s, #12
	shl	v20.4s, v20.4s, #20
	orr	v20.16b, v20.16b, v27.16b
	add	v16.4s, v16.4s, v20.4s
	eor	v19.16b, v19.16b, v16.16b
	add	v5.4s, v16.4s, v5.4s
	tbl	v16.16b, { v19.16b }, v1.16b
	add	v19.4s, v24.4s, v16.4s
	eor	v20.16b, v19.16b, v20.16b
	ushr	v24.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	ext	v5.16b, v5.16b, v5.16b, #4
	orr	v20.16b, v20.16b, v24.16b
	ext	v16.16b, v16.16b, v16.16b, #8
	add	v5.4s, v5.4s, v20.4s
	eor	v16.16b, v16.16b, v5.16b
	ext	v19.16b, v19.16b, v19.16b, #12
	tbl	v24.16b, { v16.16b }, v0.16b
	add	v19.4s, v19.4s, v24.4s
	eor	v16.16b, v19.16b, v20.16b
	ushr	v20.4s, v16.4s, #12
	shl	v16.4s, v16.4s, #20
	add	v5.4s, v5.4s, v17.4s
	orr	v20.16b, v16.16b, v20.16b
	add	v27.4s, v5.4s, v20.4s
	ext	v5.16b, v27.16b, v27.16b, #12
	add	v28.4s, v5.4s, v26.4s
	zip1	v25.2d, v7.2d, v17.2d
	zip2	v23.4s, v17.4s, v7.4s
	tbl	v16.16b, { v25.16b, v26.16b }, v2.16b
	zip1	v5.4s, v23.4s, v26.4s
	zip1	v17.4s, v26.4s, v23.4s
	ext	v23.16b, v16.16b, v16.16b, #12
	uzp1	v26.4s, v16.4s, v23.4s
	eor	v23.16b, v24.16b, v27.16b
	tbl	v23.16b, { v23.16b }, v1.16b
	add	v19.4s, v19.4s, v23.4s
	eor	v20.16b, v19.16b, v20.16b
	ushr	v24.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	orr	v20.16b, v20.16b, v24.16b
	ext	v23.16b, v23.16b, v23.16b, #8
	add	v27.4s, v28.4s, v20.4s
	eor	v23.16b, v23.16b, v27.16b
	ext	v19.16b, v19.16b, v19.16b, #4
	tbl	v23.16b, { v23.16b }, v0.16b
	add	v19.4s, v19.4s, v23.4s
	eor	v20.16b, v19.16b, v20.16b
	add	v7.4s, v27.4s, v7.4s
	ushr	v27.4s, v20.4s, #12
	shl	v20.4s, v20.4s, #20
	orr	v20.16b, v20.16b, v27.16b
	add	v7.4s, v7.4s, v20.4s
	eor	v23.16b, v23.16b, v7.16b
	ext	v22.16b, v4.16b, v4.16b, #4
	add	v4.4s, v7.4s, v4.4s
	tbl	v7.16b, { v23.16b }, v1.16b
	add	v19.4s, v19.4s, v7.4s
	eor	v20.16b, v19.16b, v20.16b
	ushr	v23.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	ext	v4.16b, v4.16b, v4.16b, #4
	orr	v20.16b, v20.16b, v23.16b
	ext	v7.16b, v7.16b, v7.16b, #8
	add	v4.4s, v4.4s, v20.4s
	eor	v7.16b, v7.16b, v4.16b
	ext	v19.16b, v19.16b, v19.16b, #12
	tbl	v7.16b, { v7.16b }, v0.16b
	add	v19.4s, v19.4s, v7.4s
	eor	v20.16b, v19.16b, v20.16b
	ushr	v23.4s, v20.4s, #12
	shl	v20.4s, v20.4s, #20
	add	v4.4s, v4.4s, v18.4s
	orr	v20.16b, v20.16b, v23.16b
	ext	v5.16b, v17.16b, v5.16b, #8
	add	v4.4s, v4.4s, v20.4s
	uzp1	v6.4s, v22.4s, v22.4s
	mov	v17.16b, v5.16b
	ext	v23.16b, v4.16b, v4.16b, #12
	ext	v6.16b, v6.16b, v22.16b, #8
	mov	v17.s[1], v26.s[2]
	zip2	v24.4s, v18.4s, v5.4s
	add	v23.4s, v23.4s, v26.4s
	zip1	v25.2d, v5.2d, v18.2d
	uzp2	v6.4s, v6.4s, v18.4s
	tbl	v18.16b, { v25.16b, v26.16b }, v2.16b
	zip1	v27.4s, v24.4s, v26.4s
	zip1	v24.4s, v26.4s, v24.4s
	eor	v4.16b, v7.16b, v4.16b
	ext	v21.16b, v22.16b, v22.16b, #12
	ext	v25.16b, v18.16b, v18.16b, #12
	ext	v24.16b, v24.16b, v27.16b, #8
	tbl	v4.16b, { v4.16b }, v1.16b
	ext	v16.16b, v22.16b, v21.16b, #12
	ext	v21.16b, v6.16b, v6.16b, #4
	uzp1	v26.4s, v18.4s, v25.4s
	mov	v28.16b, v24.16b
	add	v19.4s, v19.4s, v4.4s
	ext	v22.16b, v21.16b, v21.16b, #12
	mov	v28.s[1], v26.s[2]
	ext	v18.16b, v21.16b, v21.16b, #8
	eor	v20.16b, v19.16b, v20.16b
	ext	v27.16b, v21.16b, v22.16b, #12
	uzp2	v21.4s, v18.4s, v17.4s
	tbl	v7.16b, { v16.16b, v17.16b }, v3.16b
	zip2	v16.4s, v16.4s, v24.4s
	ushr	v17.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	orr	v17.16b, v20.16b, v17.16b
	ext	v4.16b, v4.16b, v4.16b, #8
	add	v20.4s, v23.4s, v17.4s
	eor	v4.16b, v4.16b, v20.16b
	ext	v19.16b, v19.16b, v19.16b, #4
	tbl	v4.16b, { v4.16b }, v0.16b
	add	v19.4s, v19.4s, v4.4s
	eor	v17.16b, v19.16b, v17.16b
	add	v5.4s, v20.4s, v5.4s
	ushr	v20.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	orr	v17.16b, v17.16b, v20.16b
	add	v5.4s, v5.4s, v17.4s
	eor	v4.16b, v4.16b, v5.16b
	tbl	v4.16b, { v4.16b }, v1.16b
	add	v5.4s, v5.4s, v6.4s
	add	v6.4s, v19.4s, v4.4s
	eor	v17.16b, v6.16b, v17.16b
	ushr	v19.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	ext	v5.16b, v5.16b, v5.16b, #4
	orr	v17.16b, v17.16b, v19.16b
	ext	v4.16b, v4.16b, v4.16b, #8
	add	v5.4s, v5.4s, v17.4s
	eor	v4.16b, v4.16b, v5.16b
	ext	v6.16b, v6.16b, v6.16b, #12
	tbl	v4.16b, { v4.16b }, v0.16b
	add	v6.4s, v6.4s, v4.4s
	eor	v17.16b, v6.16b, v17.16b
	ushr	v19.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	add	v5.4s, v5.4s, v7.4s
	orr	v17.16b, v17.16b, v19.16b
	add	v5.4s, v5.4s, v17.4s
	eor	v4.16b, v4.16b, v5.16b
	tbl	v4.16b, { v4.16b }, v1.16b
	ext	v5.16b, v5.16b, v5.16b, #12
	add	v6.4s, v6.4s, v4.4s
	add	v5.4s, v5.4s, v26.4s
	zip1	v25.2d, v24.2d, v7.2d
	zip1	v7.4s, v16.4s, v26.4s
	zip1	v16.4s, v26.4s, v16.4s
	eor	v17.16b, v6.16b, v17.16b
	ext	v7.16b, v16.16b, v7.16b, #8
	ushr	v16.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	orr	v16.16b, v17.16b, v16.16b
	ext	v4.16b, v4.16b, v4.16b, #8
	add	v5.4s, v5.4s, v16.4s
	eor	v4.16b, v4.16b, v5.16b
	ext	v6.16b, v6.16b, v6.16b, #4
	tbl	v4.16b, { v4.16b }, v0.16b
	add	v6.4s, v6.4s, v4.4s
	eor	v16.16b, v6.16b, v16.16b
	ushr	v17.4s, v16.4s, #12
	shl	v16.4s, v16.4s, #20
	add	v5.4s, v5.4s, v24.4s
	orr	v16.16b, v16.16b, v17.16b
	add	v5.4s, v5.4s, v16.4s
	eor	v4.16b, v4.16b, v5.16b
	tbl	v4.16b, { v4.16b }, v1.16b
	add	v6.4s, v6.4s, v4.4s
	eor	v16.16b, v6.16b, v16.16b
	ext	v18.16b, v21.16b, v18.16b, #4
	ext	v5.16b, v5.16b, v5.16b, #4
	ushr	v17.4s, v16.4s, #7
	shl	v16.4s, v16.4s, #25
	add	v5.4s, v5.4s, v18.4s
	orr	v16.16b, v16.16b, v17.16b
	ext	v4.16b, v4.16b, v4.16b, #8
	add	v5.4s, v16.4s, v5.4s
	eor	v4.16b, v4.16b, v5.16b
	tbl	v3.16b, { v27.16b, v28.16b }, v3.16b
	ext	v6.16b, v6.16b, v6.16b, #12
	tbl	v4.16b, { v4.16b }, v0.16b
	add	v3.4s, v5.4s, v3.4s
	add	v5.4s, v6.4s, v4.4s
	eor	v6.16b, v5.16b, v16.16b
	ushr	v16.4s, v6.4s, #12
	shl	v6.4s, v6.4s, #20
	orr	v6.16b, v6.16b, v16.16b
	tbl	v2.16b, { v25.16b, v26.16b }, v2.16b
	add	v3.4s, v3.4s, v6.4s
	ext	v19.16b, v2.16b, v2.16b, #12
	eor	v4.16b, v4.16b, v3.16b
	uzp1	v2.4s, v2.4s, v19.4s
	ext	v3.16b, v3.16b, v3.16b, #12
	tbl	v4.16b, { v4.16b }, v1.16b
	add	v2.4s, v3.4s, v2.4s
	add	v3.4s, v5.4s, v4.4s
	eor	v5.16b, v3.16b, v6.16b
	ushr	v6.4s, v5.4s, #7
	shl	v5.4s, v5.4s, #25
	orr	v5.16b, v5.16b, v6.16b
	ext	v4.16b, v4.16b, v4.16b, #8
	add	v2.4s, v2.4s, v5.4s
	eor	v4.16b, v4.16b, v2.16b
	ext	v3.16b, v3.16b, v3.16b, #4
	tbl	v0.16b, { v4.16b }, v0.16b
	add	v3.4s, v3.4s, v0.4s
	eor	v4.16b, v3.16b, v5.16b
	ushr	v5.4s, v4.4s, #12
	shl	v4.4s, v4.4s, #20
	add	v2.4s, v2.4s, v7.4s
	orr	v4.16b, v4.16b, v5.16b
	add	v2.4s, v2.4s, v4.4s
	eor	v0.16b, v0.16b, v2.16b
	tbl	v0.16b, { v0.16b }, v1.16b
	add	v1.4s, v3.4s, v0.4s
	eor	v3.16b, v1.16b, v4.16b
	ushr	v4.4s, v3.4s, #7
	shl	v3.4s, v3.4s, #25
	ext	v2.16b, v2.16b, v2.16b, #4
	ext	v0.16b, v0.16b, v0.16b, #8
	ext	v1.16b, v1.16b, v1.16b, #12
	orr	v3.16b, v3.16b, v4.16b
	stp	q2, q3, [x0]
	stp	q1, q0, [x0, #32]
	ret
.Lfunc_end1:
	.size	compress_pre, .Lfunc_end1-compress_pre
	.cfi_endproc

	.globl	zfs_blake3_compress_xof_sse41
	.p2align	2
	.type	zfs_blake3_compress_xof_sse41,@function
zfs_blake3_compress_xof_sse41:
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
	.size	zfs_blake3_compress_xof_sse41, .Lfunc_end2-zfs_blake3_compress_xof_sse41
	.cfi_endproc

	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI3_0:
	.word	0
	.word	1
	.word	2
	.word	3
.LCPI3_1:
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	6
	.byte	7
	.byte	4
	.byte	5
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	14
	.byte	15
	.byte	12
	.byte	13
.LCPI3_2:
	.byte	1
	.byte	2
	.byte	3
	.byte	0
	.byte	5
	.byte	6
	.byte	7
	.byte	4
	.byte	9
	.byte	10
	.byte	11
	.byte	8
	.byte	13
	.byte	14
	.byte	15
	.byte	12
.LCPI3_3:
	.word	1779033703
	.word	3144134277
	.word	1013904242
	.word	2773480762
.LCPI3_4:
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	20
	.byte	21
	.byte	22
	.byte	23
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	28
	.byte	29
	.byte	30
	.byte	31
.LCPI3_5:
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	28
	.byte	29
	.byte	30
	.byte	31
	.text
	.globl	zfs_blake3_hash_many_sse41
	.p2align	2
	.type	zfs_blake3_hash_many_sse41,@function
zfs_blake3_hash_many_sse41:
	.cfi_startproc
	stp	d15, d14, [sp, #-112]!
	stp	d13, d12, [sp, #16]
	stp	d11, d10, [sp, #32]
	stp	d9, d8, [sp, #48]
	stp	x29, x23, [sp, #64]
	stp	x22, x21, [sp, #80]
	stp	x20, x19, [sp, #96]
	sub	sp, sp, #448
	.cfi_def_cfa_offset 560
	.cfi_offset w19, -8
	.cfi_offset w20, -16
	.cfi_offset w21, -24
	.cfi_offset w22, -32
	.cfi_offset w23, -40
	.cfi_offset w29, -48
	.cfi_offset b8, -56
	.cfi_offset b9, -64
	.cfi_offset b10, -72
	.cfi_offset b11, -80
	.cfi_offset b12, -88
	.cfi_offset b13, -96
	.cfi_offset b14, -104
	.cfi_offset b15, -112
	ldr	x8, [sp, #568]
	ldrb	w9, [sp, #560]
	cmp	x1, #4
	orr	w10, w7, w6
	b.lo	.LBB3_6
	adrp	x12, .LCPI3_0
	adrp	x13, .LCPI3_1
	ldr	q1, [x12, :lo12:.LCPI3_0]
	ldr	q3, [x13, :lo12:.LCPI3_1]
	sbfx	w11, w5, #0, #1
	dup	v0.4s, w11
	mov	w14, #58983
	mov	w15, #44677
	movk	w14, #27145, lsl #16
	movk	w15, #47975, lsl #16
	mov	w11, #62322
	mov	w12, #62778
	and	v0.16b, v0.16b, v1.16b
	movk	w11, #15470, lsl #16
	dup	v2.4s, w14
	movk	w12, #42319, lsl #16
	dup	v1.4s, w15
	stp	q0, q3, [sp, #16]
	orr	v0.4s, #128, lsl #24
	adrp	x13, .LCPI3_2
	str	q0, [sp]
	stp	q1, q2, [sp, #48]
	b	.LBB3_3
.LBB3_2:
	zip1	v0.4s, v20.4s, v21.4s
	zip2	v1.4s, v20.4s, v21.4s
	zip1	v3.4s, v2.4s, v17.4s
	zip2	v2.4s, v2.4s, v17.4s
	zip1	v4.4s, v11.4s, v12.4s
	zip2	v5.4s, v11.4s, v12.4s
	zip1	v6.4s, v16.4s, v7.4s
	zip2	v7.4s, v16.4s, v7.4s
	add	x14, x4, #4
	tst	w5, #0x1
	sub	x1, x1, #4
	zip1	v16.2d, v0.2d, v3.2d
	zip2	v0.2d, v0.2d, v3.2d
	zip1	v3.2d, v1.2d, v2.2d
	zip2	v1.2d, v1.2d, v2.2d
	zip1	v2.2d, v4.2d, v6.2d
	zip2	v4.2d, v4.2d, v6.2d
	zip1	v6.2d, v5.2d, v7.2d
	zip2	v5.2d, v5.2d, v7.2d
	add	x0, x0, #32
	csel	x4, x14, x4, ne
	cmp	x1, #3
	stp	q16, q2, [x8]
	stp	q0, q4, [x8, #32]
	stp	q3, q6, [x8, #64]
	stp	q1, q5, [x8, #96]
	add	x8, x8, #128
	b.ls	.LBB3_6
.LBB3_3:
	mov	x14, x3
	ld1r	{ v20.4s }, [x14], #4
	add	x15, x3, #8
	add	x16, x3, #12
	add	x17, x3, #16
	add	x7, x3, #20
	add	x19, x3, #24
	add	x20, x3, #28
	ld1r	{ v2.4s }, [x15]
	ld1r	{ v17.4s }, [x16]
	ld1r	{ v11.4s }, [x17]
	ld1r	{ v12.4s }, [x7]
	ld1r	{ v16.4s }, [x19]
	ld1r	{ v21.4s }, [x14]
	ld1r	{ v7.4s }, [x20]
	cbz	x2, .LBB3_2
	ldr	q1, [sp, #16]
	dup	v0.4s, w4
	ldp	x15, x16, [x0]
	ldp	x17, x7, [x0, #16]
	add	v1.4s, v0.4s, v1.4s
	movi	v0.4s, #128, lsl #24
	str	q1, [sp, #96]
	eor	v0.16b, v1.16b, v0.16b
	ldr	q1, [sp]
	lsr	x19, x4, #32
	mov	x14, xzr
	mov	w22, w10
	cmgt	v0.4s, v1.4s, v0.4s
	dup	v1.4s, w19
	sub	v0.4s, v1.4s, v0.4s
	mov	x19, x2
	str	q0, [sp, #80]
.LBB3_5:
	subs	x19, x19, #1
	csel	w23, w9, wzr, eq
	orr	w23, w23, w22
	and	w23, w23, #0xff
	dup	v0.4s, w23
	str	q0, [sp, #272]
	add	v0.4s, v21.4s, v12.4s
	add	x20, x15, x14
	add	x21, x16, x14
	add	x22, x17, x14
	add	x23, x7, x14
	stp	q7, q0, [sp, #176]
	add	v0.4s, v17.4s, v7.4s
	str	q16, [sp, #144]
	add	v22.4s, v20.4s, v11.4s
	add	v4.4s, v2.4s, v16.4s
	str	q0, [sp, #208]
	ldp	q0, q1, [x20]
	ldp	q3, q5, [x21]
	ldp	q7, q16, [x22]
	ldp	q17, q20, [x23]
	ldp	q21, q25, [x20, #32]
	ldp	q28, q29, [x21, #32]
	ldp	q30, q8, [x22, #32]
	ldp	q9, q13, [x23, #32]
	zip1	v26.4s, v0.4s, v3.4s
	zip1	v19.4s, v7.4s, v17.4s
	zip2	v23.4s, v0.4s, v3.4s
	zip2	v2.4s, v7.4s, v17.4s
	zip1	v18.4s, v1.4s, v5.4s
	zip2	v10.4s, v1.4s, v5.4s
	zip1	v1.4s, v16.4s, v20.4s
	zip2	v3.4s, v16.4s, v20.4s
	zip1	v31.4s, v21.4s, v28.4s
	zip2	v20.4s, v21.4s, v28.4s
	zip1	v5.4s, v30.4s, v9.4s
	zip2	v16.4s, v30.4s, v9.4s
	zip1	v21.4s, v25.4s, v29.4s
	zip1	v7.4s, v8.4s, v13.4s
	ext	v30.16b, v19.16b, v26.16b, #8
	zip2	v15.4s, v25.4s, v29.4s
	zip2	v0.4s, v8.4s, v13.4s
	ext	v8.16b, v2.16b, v23.16b, #8
	ext	v28.16b, v1.16b, v18.16b, #8
	ext	v24.16b, v26.16b, v30.16b, #8
	mov	v26.d[1], v19.d[0]
	ext	v19.16b, v7.16b, v21.16b, #8
	ext	v13.16b, v16.16b, v20.16b, #8
	ext	v17.16b, v23.16b, v8.16b, #8
	mov	v23.d[1], v2.d[0]
	ext	v14.16b, v0.16b, v15.16b, #8
	ext	v25.16b, v18.16b, v28.16b, #8
	ext	v19.16b, v21.16b, v19.16b, #8
	ldr	q2, [sp, #96]
	ext	v28.16b, v20.16b, v13.16b, #8
	stp	q25, q19, [sp, #288]
	ext	v19.16b, v15.16b, v14.16b, #8
	ext	v29.16b, v3.16b, v10.16b, #8
	mov	v30.16b, v18.16b
	stp	q28, q19, [sp, #112]
	mov	v28.16b, v15.16b
	ext	v27.16b, v10.16b, v29.16b, #8
	mov	v29.16b, v10.16b
	mov	v30.d[1], v1.d[0]
	mov	v28.d[1], v0.d[0]
	add	v0.4s, v22.4s, v26.4s
	ldr	q1, [sp, #192]
	mov	v29.d[1], v3.d[0]
	add	v3.4s, v4.4s, v30.4s
	eor	v4.16b, v0.16b, v2.16b
	ldr	q2, [sp, #80]
	ext	v9.16b, v5.16b, v31.16b, #8
	add	v1.4s, v1.4s, v23.4s
	ext	v8.16b, v31.16b, v9.16b, #8
	mov	v31.d[1], v5.d[0]
	eor	v5.16b, v1.16b, v2.16b
	movi	v2.4s, #64
	ldr	q18, [sp, #32]
	mov	v21.d[1], v7.d[0]
	eor	v7.16b, v3.16b, v2.16b
	ldr	q2, [sp, #64]
	tbl	v4.16b, { v4.16b }, v18.16b
	mov	v20.d[1], v16.d[0]
	tbl	v5.16b, { v5.16b }, v18.16b
	add	v16.4s, v4.4s, v2.4s
	ldr	q2, [sp, #48]
	dup	v6.4s, w11
	tbl	v7.16b, { v7.16b }, v18.16b
	add	v6.4s, v7.4s, v6.4s
	add	v22.4s, v5.4s, v2.4s
	ldr	q2, [sp, #144]
	eor	v19.16b, v16.16b, v11.16b
	eor	v11.16b, v22.16b, v12.16b
	ushr	v12.4s, v19.4s, #12
	eor	v10.16b, v6.16b, v2.16b
	ldr	q2, [sp, #208]
	shl	v19.4s, v19.4s, #20
	orr	v12.16b, v19.16b, v12.16b
	ushr	v19.4s, v11.4s, #12
	add	v14.4s, v2.4s, v29.4s
	ldr	q2, [sp, #272]
	shl	v11.4s, v11.4s, #20
	orr	v11.16b, v11.16b, v19.16b
	ushr	v19.4s, v10.4s, #12
	eor	v13.16b, v14.16b, v2.16b
	ldr	q2, [sp, #176]
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v19.16b
	dup	v19.4s, w12
	tbl	v13.16b, { v13.16b }, v18.16b
	add	v15.4s, v13.4s, v19.4s
	eor	v19.16b, v15.16b, v2.16b
	ushr	v2.4s, v19.4s, #12
	shl	v19.4s, v19.4s, #20
	orr	v2.16b, v19.16b, v2.16b
	ldr	q19, [x13, :lo12:.LCPI3_2]
	add	v0.4s, v0.4s, v24.4s
	add	v0.4s, v0.4s, v12.4s
	add	v1.4s, v1.4s, v17.4s
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v25.4s
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v3.16b
	eor	v12.16b, v16.16b, v12.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	mov	v9.16b, v24.16b
	str	q24, [sp, #240]
	ushr	v24.4s, v12.4s, #7
	shl	v12.4s, v12.4s, #25
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	orr	v24.16b, v12.16b, v24.16b
	ushr	v12.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v6.16b, v10.16b
	orr	v11.16b, v11.16b, v12.16b
	ushr	v12.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v12.16b
	add	v12.4s, v14.4s, v27.4s
	add	v12.4s, v12.4s, v2.4s
	eor	v13.16b, v13.16b, v12.16b
	tbl	v13.16b, { v13.16b }, v19.16b
	add	v14.4s, v15.4s, v13.4s
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v31.4s
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v20.4s
	orr	v2.16b, v2.16b, v15.16b
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v21.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v28.4s
	stp	q26, q17, [sp, #400]
	str	q31, [sp, #160]
	mov	v26.16b, v23.16b
	str	q23, [sp, #384]
	mov	v23.16b, v27.16b
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	mov	v31.16b, v8.16b
	add	v0.4s, v0.4s, v8.4s
	ldp	q27, q8, [sp, #112]
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v12.16b
	ldr	q17, [sp, #304]
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v24.16b, v22.16b, v24.16b
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v27.4s
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v17.4s
	orr	v24.16b, v24.16b, v15.16b
	tbl	v13.16b, { v13.16b }, v19.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v8.4s
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v12.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	ldr	q25, [sp, #416]
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	eor	v24.16b, v22.16b, v24.16b
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v15.16b
	add	v0.4s, v0.4s, v26.4s
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v25.4s
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v23.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v30.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	str	q21, [sp, #432]
	eor	v24.16b, v24.16b, v16.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	eor	v13.16b, v13.16b, v12.16b
	ldr	q21, [sp, #400]
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	add	v0.4s, v0.4s, v29.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v20.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v21.4s
	orr	v2.16b, v2.16b, v15.16b
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v17.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	eor	v24.16b, v16.16b, v24.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	eor	v13.16b, v13.16b, v12.16b
	ldr	q21, [sp, #432]
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v19.16b
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v9.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v21.4s
	orr	v2.16b, v2.16b, v15.16b
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v31.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v8.4s
	stp	q28, q29, [sp, #320]
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	ldr	q29, [sp, #288]
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	mov	v28.16b, v31.16b
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v12.16b
	add	v0.4s, v0.4s, v27.4s
	mov	v31.16b, v27.16b
	ldr	q27, [sp, #320]
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	ldr	q9, [sp, #160]
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v24.16b, v22.16b, v24.16b
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v29.4s
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v27.4s
	orr	v24.16b, v24.16b, v15.16b
	tbl	v13.16b, { v13.16b }, v19.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v9.4s
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v12.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	eor	v24.16b, v22.16b, v24.16b
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v15.16b
	add	v0.4s, v0.4s, v25.4s
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v20.4s
	mov	v26.16b, v23.16b
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v17.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v26.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	mov	v23.16b, v17.16b
	eor	v24.16b, v24.16b, v16.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	mov	v17.16b, v26.16b
	eor	v13.16b, v13.16b, v12.16b
	add	v1.4s, v1.4s, v21.4s
	mov	v26.16b, v21.16b
	ldr	q21, [sp, #384]
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	add	v0.4s, v0.4s, v30.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v24.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v21.4s
	orr	v2.16b, v2.16b, v15.16b
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v27.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	ldr	q21, [sp, #336]
	eor	v24.16b, v16.16b, v24.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	eor	v13.16b, v13.16b, v12.16b
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v19.16b
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v21.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v28.4s
	orr	v2.16b, v2.16b, v15.16b
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v31.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v9.4s
	mov	v25.16b, v20.16b
	stp	q30, q20, [sp, #352]
	mov	v20.16b, v30.16b
	add	v6.4s, v6.4s, v13.4s
	mov	v30.16b, v28.16b
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	ldr	q28, [sp, #400]
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v12.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	add	v0.4s, v0.4s, v29.4s
	mov	v21.16b, v29.16b
	ldr	q29, [sp, #240]
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v24.16b, v22.16b, v24.16b
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v28.4s
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v8.4s
	orr	v24.16b, v24.16b, v15.16b
	tbl	v13.16b, { v13.16b }, v19.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v29.4s
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v12.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	eor	v24.16b, v22.16b, v24.16b
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v15.16b
	add	v0.4s, v0.4s, v25.4s
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v26.4s
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v27.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v23.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	eor	v24.16b, v24.16b, v16.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	eor	v13.16b, v13.16b, v12.16b
	add	v0.4s, v0.4s, v17.4s
	mov	v25.16b, v17.16b
	str	q17, [sp, #256]
	ldr	q17, [sp, #416]
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v30.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v17.4s
	orr	v2.16b, v2.16b, v15.16b
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v8.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	eor	v24.16b, v16.16b, v24.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	eor	v13.16b, v13.16b, v12.16b
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v19.16b
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v20.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v31.4s
	orr	v2.16b, v2.16b, v15.16b
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v21.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v29.4s
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	ldr	q20, [sp, #384]
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v12.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	mov	v17.16b, v31.16b
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	ldr	q31, [sp, #336]
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	add	v0.4s, v0.4s, v28.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v24.16b, v22.16b, v24.16b
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v20.4s
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v9.4s
	orr	v24.16b, v24.16b, v15.16b
	tbl	v13.16b, { v13.16b }, v19.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v31.4s
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v12.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	eor	v24.16b, v22.16b, v24.16b
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v15.16b
	add	v0.4s, v0.4s, v26.4s
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v30.4s
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v8.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v27.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	eor	v24.16b, v24.16b, v16.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	eor	v13.16b, v13.16b, v12.16b
	ldr	q21, [sp, #368]
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	add	v0.4s, v0.4s, v23.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v17.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	add	v3.4s, v3.4s, v21.4s
	orr	v2.16b, v2.16b, v15.16b
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v9.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	mov	v26.16b, v30.16b
	str	q30, [sp, #224]
	eor	v24.16b, v16.16b, v24.16b
	add	v22.4s, v22.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	eor	v13.16b, v13.16b, v12.16b
	ldr	q30, [sp, #288]
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	eor	v11.16b, v22.16b, v11.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v19.16b
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v25.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v30.4s
	orr	v2.16b, v2.16b, v15.16b
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v28.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v31.4s
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	ldr	q21, [sp, #416]
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v12.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	ldr	q25, [sp, #352]
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	add	v0.4s, v0.4s, v20.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v24.16b, v22.16b, v24.16b
	add	v0.4s, v0.4s, v11.4s
	add	v1.4s, v1.4s, v21.4s
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v29.4s
	orr	v24.16b, v24.16b, v15.16b
	tbl	v13.16b, { v13.16b }, v19.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v25.4s
	add	v6.4s, v6.4s, v13.4s
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	eor	v11.16b, v6.16b, v11.16b
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	eor	v7.16b, v7.16b, v12.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v19.16b
	orr	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	eor	v24.16b, v22.16b, v24.16b
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v15.16b
	add	v0.4s, v0.4s, v26.4s
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v17.4s
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v9.4s
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v8.4s
	eor	v24.16b, v24.16b, v16.16b
	add	v22.4s, v22.4s, v5.4s
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	mov	v28.16b, v20.16b
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	eor	v11.16b, v22.16b, v11.16b
	tbl	v7.16b, { v7.16b }, v18.16b
	eor	v13.16b, v13.16b, v12.16b
	ldr	q20, [sp, #432]
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v18.16b
	add	v0.4s, v0.4s, v27.4s
	orr	v11.16b, v11.16b, v15.16b
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	add	v0.4s, v0.4s, v24.4s
	add	v1.4s, v1.4s, v30.4s
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v14.16b, v2.16b
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v11.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v5.16b, v5.16b, v1.16b
	add	v3.4s, v3.4s, v20.4s
	orr	v2.16b, v2.16b, v15.16b
	add	v16.4s, v16.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	add	v3.4s, v3.4s, v10.4s
	add	v12.4s, v12.4s, v29.4s
	eor	v24.16b, v16.16b, v24.16b
	add	v22.4s, v22.4s, v5.4s
	eor	v7.16b, v7.16b, v3.16b
	add	v12.4s, v12.4s, v2.4s
	ushr	v15.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	eor	v11.16b, v22.16b, v11.16b
	tbl	v7.16b, { v7.16b }, v19.16b
	eor	v13.16b, v13.16b, v12.16b
	add	v0.4s, v0.4s, v23.4s
	ldr	q23, [sp, #400]
	orr	v24.16b, v24.16b, v15.16b
	ushr	v15.4s, v11.4s, #7
	shl	v11.4s, v11.4s, #25
	add	v6.4s, v6.4s, v7.4s
	tbl	v13.16b, { v13.16b }, v19.16b
	orr	v11.16b, v11.16b, v15.16b
	eor	v10.16b, v6.16b, v10.16b
	add	v14.4s, v14.4s, v13.4s
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v2.16b, v14.16b, v2.16b
	add	v0.4s, v0.4s, v11.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	eor	v13.16b, v13.16b, v0.16b
	add	v1.4s, v1.4s, v23.4s
	orr	v2.16b, v2.16b, v15.16b
	tbl	v13.16b, { v13.16b }, v18.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v28.4s
	add	v6.4s, v6.4s, v13.4s
	eor	v4.16b, v4.16b, v1.16b
	add	v3.4s, v3.4s, v2.4s
	add	v12.4s, v12.4s, v25.4s
	eor	v11.16b, v6.16b, v11.16b
	tbl	v4.16b, { v4.16b }, v18.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v12.4s, v12.4s, v24.4s
	ushr	v15.4s, v11.4s, #12
	shl	v11.4s, v11.4s, #20
	add	v14.4s, v14.4s, v4.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	eor	v7.16b, v7.16b, v12.16b
	orr	v11.16b, v11.16b, v15.16b
	eor	v10.16b, v14.16b, v10.16b
	add	v16.4s, v16.4s, v5.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	add	v0.4s, v0.4s, v21.4s
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	eor	v2.16b, v16.16b, v2.16b
	add	v22.4s, v22.4s, v7.4s
	add	v0.4s, v0.4s, v11.4s
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v24.16b, v22.16b, v24.16b
	eor	v13.16b, v13.16b, v0.16b
	add	v0.4s, v0.4s, v17.4s
	ldr	q17, [sp, #368]
	orr	v2.16b, v2.16b, v15.16b
	ushr	v15.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v15.16b
	ldr	q15, [sp, #256]
	add	v1.4s, v1.4s, v17.4s
	add	v3.4s, v3.4s, v31.4s
	mov	v26.16b, v8.16b
	mov	v8.16b, v30.16b
	mov	v30.16b, v29.16b
	add	v1.4s, v1.4s, v10.4s
	add	v3.4s, v3.4s, v2.4s
	eor	v4.16b, v4.16b, v1.16b
	mov	v29.16b, v31.16b
	eor	v5.16b, v5.16b, v3.16b
	add	v3.4s, v3.4s, v30.4s
	add	v30.4s, v12.4s, v15.4s
	tbl	v31.16b, { v13.16b }, v19.16b
	add	v30.4s, v30.4s, v24.4s
	tbl	v4.16b, { v4.16b }, v19.16b
	add	v6.4s, v6.4s, v31.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v7.16b, v7.16b, v30.16b
	add	v30.4s, v30.4s, v9.4s
	tbl	v5.16b, { v5.16b }, v19.16b
	add	v8.4s, v14.4s, v4.4s
	eor	v9.16b, v6.16b, v11.16b
	tbl	v7.16b, { v7.16b }, v19.16b
	add	v16.4s, v16.4s, v5.4s
	eor	v10.16b, v8.16b, v10.16b
	ushr	v11.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	add	v22.4s, v22.4s, v7.4s
	eor	v2.16b, v16.16b, v2.16b
	orr	v9.16b, v9.16b, v11.16b
	ushr	v11.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	eor	v24.16b, v22.16b, v24.16b
	orr	v10.16b, v10.16b, v11.16b
	ushr	v11.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	orr	v2.16b, v2.16b, v11.16b
	ushr	v11.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v11.16b
	add	v0.4s, v0.4s, v24.4s
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v9.4s
	eor	v5.16b, v5.16b, v1.16b
	tbl	v4.16b, { v4.16b }, v18.16b
	add	v1.4s, v1.4s, v23.4s
	add	v3.4s, v3.4s, v10.4s
	ldr	q23, [sp, #224]
	tbl	v5.16b, { v5.16b }, v18.16b
	add	v16.4s, v16.4s, v4.4s
	add	v0.4s, v0.4s, v26.4s
	eor	v7.16b, v7.16b, v3.16b
	add	v26.4s, v30.4s, v2.4s
	add	v22.4s, v22.4s, v5.4s
	eor	v24.16b, v24.16b, v16.16b
	mov	v20.16b, v28.16b
	eor	v28.16b, v31.16b, v26.16b
	add	v26.4s, v26.4s, v29.4s
	tbl	v7.16b, { v7.16b }, v18.16b
	eor	v29.16b, v22.16b, v9.16b
	ushr	v31.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	tbl	v27.16b, { v28.16b }, v18.16b
	add	v6.4s, v6.4s, v7.4s
	orr	v24.16b, v24.16b, v31.16b
	ushr	v31.4s, v29.4s, #12
	shl	v29.4s, v29.4s, #20
	add	v3.4s, v3.4s, v23.4s
	add	v28.4s, v8.4s, v27.4s
	eor	v30.16b, v6.16b, v10.16b
	orr	v29.16b, v29.16b, v31.16b
	add	v0.4s, v0.4s, v24.4s
	ldr	q23, [sp, #320]
	eor	v2.16b, v28.16b, v2.16b
	ushr	v31.4s, v30.4s, #12
	shl	v30.4s, v30.4s, #20
	eor	v4.16b, v4.16b, v0.16b
	add	v1.4s, v1.4s, v29.4s
	orr	v30.16b, v30.16b, v31.16b
	ushr	v31.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v5.16b, v5.16b, v1.16b
	tbl	v4.16b, { v4.16b }, v19.16b
	orr	v2.16b, v2.16b, v31.16b
	tbl	v5.16b, { v5.16b }, v19.16b
	add	v16.4s, v16.4s, v4.4s
	add	v0.4s, v0.4s, v23.4s
	add	v23.4s, v26.4s, v2.4s
	add	v22.4s, v22.4s, v5.4s
	eor	v24.16b, v16.16b, v24.16b
	add	v3.4s, v3.4s, v30.4s
	eor	v25.16b, v27.16b, v23.16b
	eor	v27.16b, v22.16b, v29.16b
	ushr	v29.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	eor	v7.16b, v7.16b, v3.16b
	orr	v24.16b, v24.16b, v29.16b
	ushr	v29.4s, v27.4s, #7
	shl	v27.4s, v27.4s, #25
	tbl	v7.16b, { v7.16b }, v19.16b
	orr	v27.16b, v27.16b, v29.16b
	tbl	v25.16b, { v25.16b }, v19.16b
	add	v6.4s, v6.4s, v7.4s
	add	v0.4s, v0.4s, v27.4s
	add	v26.4s, v28.4s, v25.4s
	eor	v28.16b, v6.16b, v30.16b
	eor	v25.16b, v25.16b, v0.16b
	add	v0.4s, v0.4s, v17.4s
	ldr	q17, [sp, #432]
	ushr	v29.4s, v28.4s, #7
	shl	v28.4s, v28.4s, #25
	add	v1.4s, v1.4s, v20.4s
	orr	v28.16b, v28.16b, v29.16b
	add	v1.4s, v1.4s, v28.4s
	eor	v2.16b, v26.16b, v2.16b
	eor	v4.16b, v4.16b, v1.16b
	add	v1.4s, v1.4s, v17.4s
	ldr	q17, [sp, #352]
	ushr	v29.4s, v2.4s, #7
	shl	v2.4s, v2.4s, #25
	ldr	q20, [sp, #304]
	add	v3.4s, v3.4s, v21.4s
	orr	v2.16b, v2.16b, v29.16b
	add	v23.4s, v23.4s, v15.4s
	add	v3.4s, v3.4s, v2.4s
	eor	v5.16b, v5.16b, v3.16b
	add	v3.4s, v3.4s, v17.4s
	add	v17.4s, v23.4s, v24.4s
	eor	v7.16b, v7.16b, v17.16b
	add	v17.4s, v17.4s, v20.4s
	tbl	v20.16b, { v25.16b }, v18.16b
	tbl	v4.16b, { v4.16b }, v18.16b
	tbl	v7.16b, { v7.16b }, v18.16b
	add	v6.4s, v6.4s, v20.4s
	tbl	v5.16b, { v5.16b }, v18.16b
	add	v23.4s, v26.4s, v4.4s
	add	v21.4s, v22.4s, v7.4s
	eor	v22.16b, v6.16b, v27.16b
	add	v16.4s, v16.4s, v5.4s
	eor	v25.16b, v23.16b, v28.16b
	ushr	v26.4s, v22.4s, #12
	shl	v22.4s, v22.4s, #20
	eor	v2.16b, v16.16b, v2.16b
	orr	v22.16b, v22.16b, v26.16b
	ushr	v26.4s, v25.4s, #12
	shl	v25.4s, v25.4s, #20
	eor	v24.16b, v21.16b, v24.16b
	orr	v25.16b, v25.16b, v26.16b
	ushr	v26.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	orr	v2.16b, v2.16b, v26.16b
	ushr	v26.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v26.16b
	add	v3.4s, v3.4s, v2.4s
	add	v17.4s, v17.4s, v24.4s
	eor	v5.16b, v5.16b, v3.16b
	add	v0.4s, v0.4s, v22.4s
	eor	v7.16b, v7.16b, v17.16b
	tbl	v5.16b, { v5.16b }, v19.16b
	add	v1.4s, v1.4s, v25.4s
	eor	v20.16b, v20.16b, v0.16b
	tbl	v7.16b, { v7.16b }, v19.16b
	add	v16.4s, v16.4s, v5.4s
	eor	v4.16b, v4.16b, v1.16b
	tbl	v26.16b, { v20.16b }, v19.16b
	eor	v20.16b, v16.16b, v0.16b
	add	v0.4s, v21.4s, v7.4s
	tbl	v4.16b, { v4.16b }, v19.16b
	eor	v19.16b, v16.16b, v2.16b
	eor	v16.16b, v0.16b, v24.16b
	eor	v21.16b, v0.16b, v1.16b
	add	v0.4s, v6.4s, v26.4s
	eor	v1.16b, v0.16b, v22.16b
	eor	v2.16b, v3.16b, v0.16b
	add	v0.4s, v23.4s, v4.4s
	eor	v3.16b, v0.16b, v25.16b
	eor	v17.16b, v17.16b, v0.16b
	ushr	v0.4s, v1.4s, #7
	shl	v1.4s, v1.4s, #25
	orr	v0.16b, v1.16b, v0.16b
	ushr	v1.4s, v3.4s, #7
	shl	v3.4s, v3.4s, #25
	orr	v1.16b, v3.16b, v1.16b
	ushr	v3.4s, v19.4s, #7
	shl	v6.4s, v19.4s, #25
	orr	v3.16b, v6.16b, v3.16b
	ushr	v6.4s, v16.4s, #7
	shl	v16.4s, v16.4s, #25
	orr	v6.16b, v16.16b, v6.16b
	eor	v11.16b, v6.16b, v4.16b
	eor	v12.16b, v0.16b, v5.16b
	eor	v16.16b, v1.16b, v7.16b
	eor	v7.16b, v3.16b, v26.16b
	prfm	pldl1keep, [x20, #256]
	prfm	pldl1keep, [x21, #256]
	prfm	pldl1keep, [x22, #256]
	add	x14, x14, #64
	mov	w22, w6
	prfm	pldl1keep, [x23, #256]
	cbnz	x19, .LBB3_5
	b	.LBB3_2
.LBB3_6:
	cbz	x1, .LBB3_14
	adrp	x11, .LCPI3_1
	adrp	x12, .LCPI3_3
	adrp	x13, .LCPI3_2
	adrp	x14, .LCPI3_4
	adrp	x15, .LCPI3_5
	ldr	q0, [x11, :lo12:.LCPI3_1]
	ldr	q1, [x12, :lo12:.LCPI3_3]
	ldr	q2, [x13, :lo12:.LCPI3_2]
	ldr	q3, [x14, :lo12:.LCPI3_4]
	ldr	q4, [x15, :lo12:.LCPI3_5]
	and	x11, x5, #0x1
.LBB3_8:
	ldr	x12, [x0]
	ldp	q6, q7, [x3]
	movi	v5.4s, #64
	lsr	x13, x4, #32
	mov	v5.s[0], w4
	mov	v5.s[1], w13
	mov	x15, x2
	mov	w14, w10
	b	.LBB3_11
.LBB3_9:
	orr	w14, w14, w9
.LBB3_10:
	and	w14, w14, #0xff
	mov	v20.16b, v5.16b
	ldp	q19, q21, [x12]
	mov	v20.s[3], w14
	add	x14, x12, #32
	ld2	{ v16.4s, v17.4s }, [x14]
	add	v6.4s, v6.4s, v7.4s
	uzp1	v18.4s, v19.4s, v21.4s
	uzp2	v19.4s, v19.4s, v21.4s
	add	v21.4s, v6.4s, v18.4s
	ext	v6.16b, v17.16b, v17.16b, #12
	ext	v23.16b, v16.16b, v16.16b, #12
	uzp1	v24.4s, v18.4s, v18.4s
	eor	v20.16b, v21.16b, v20.16b
	mov	v27.16b, v6.16b
	ext	v25.16b, v18.16b, v18.16b, #12
	ext	v24.16b, v24.16b, v18.16b, #8
	zip2	v28.4s, v19.4s, v6.4s
	tbl	v29.16b, { v20.16b }, v0.16b
	mov	v27.s[1], v23.s[2]
	zip1	v22.2d, v6.2d, v19.2d
	uzp2	v20.4s, v24.4s, v19.4s
	add	v24.4s, v29.4s, v1.4s
	ext	v26.16b, v18.16b, v25.16b, #12
	tbl	v25.16b, { v22.16b, v23.16b }, v4.16b
	zip1	v30.4s, v28.4s, v23.4s
	zip1	v22.4s, v23.4s, v28.4s
	eor	v28.16b, v24.16b, v7.16b
	ext	v23.16b, v25.16b, v25.16b, #12
	ext	v7.16b, v22.16b, v30.16b, #8
	add	v21.4s, v21.4s, v19.4s
	ext	v19.16b, v20.16b, v20.16b, #4
	uzp1	v23.4s, v25.4s, v23.4s
	mov	v31.16b, v7.16b
	tbl	v18.16b, { v26.16b, v27.16b }, v3.16b
	ext	v26.16b, v19.16b, v19.16b, #12
	mov	v31.s[1], v23.s[2]
	uzp1	v25.4s, v19.4s, v19.4s
	ext	v30.16b, v19.16b, v26.16b, #12
	ext	v19.16b, v25.16b, v19.16b, #8
	ushr	v25.4s, v28.4s, #12
	shl	v26.4s, v28.4s, #20
	orr	v25.16b, v26.16b, v25.16b
	add	v21.4s, v21.4s, v25.4s
	add	v16.4s, v21.4s, v16.4s
	eor	v21.16b, v29.16b, v21.16b
	tbl	v21.16b, { v21.16b }, v2.16b
	add	v24.4s, v24.4s, v21.4s
	uzp2	v19.4s, v19.4s, v18.4s
	eor	v25.16b, v25.16b, v24.16b
	ext	v27.16b, v19.16b, v19.16b, #4
	ushr	v29.4s, v25.4s, #7
	shl	v25.4s, v25.4s, #25
	tbl	v17.16b, { v30.16b, v31.16b }, v3.16b
	uzp1	v28.4s, v27.4s, v27.4s
	orr	v25.16b, v25.16b, v29.16b
	ext	v30.16b, v16.16b, v16.16b, #12
	ext	v16.16b, v28.16b, v27.16b, #8
	ext	v21.16b, v21.16b, v21.16b, #8
	add	v28.4s, v30.4s, v25.4s
	eor	v21.16b, v28.16b, v21.16b
	ext	v24.16b, v24.16b, v24.16b, #4
	tbl	v21.16b, { v21.16b }, v0.16b
	add	v24.4s, v24.4s, v21.4s
	eor	v25.16b, v25.16b, v24.16b
	add	v6.4s, v28.4s, v6.4s
	ushr	v28.4s, v25.4s, #12
	shl	v25.4s, v25.4s, #20
	orr	v25.16b, v25.16b, v28.16b
	add	v6.4s, v6.4s, v25.4s
	eor	v21.16b, v21.16b, v6.16b
	add	v6.4s, v6.4s, v20.4s
	tbl	v20.16b, { v21.16b }, v2.16b
	add	v21.4s, v24.4s, v20.4s
	eor	v24.16b, v25.16b, v21.16b
	ushr	v25.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	ext	v6.16b, v6.16b, v6.16b, #4
	orr	v24.16b, v24.16b, v25.16b
	ext	v20.16b, v20.16b, v20.16b, #8
	add	v6.4s, v6.4s, v24.4s
	eor	v20.16b, v6.16b, v20.16b
	ext	v21.16b, v21.16b, v21.16b, #12
	tbl	v20.16b, { v20.16b }, v0.16b
	add	v21.4s, v21.4s, v20.4s
	eor	v24.16b, v24.16b, v21.16b
	ushr	v25.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v25.16b
	add	v25.4s, v24.4s, v18.4s
	add	v6.4s, v25.4s, v6.4s
	eor	v20.16b, v20.16b, v6.16b
	tbl	v20.16b, { v20.16b }, v2.16b
	add	v21.4s, v21.4s, v20.4s
	eor	v24.16b, v24.16b, v21.16b
	ushr	v25.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v25.16b
	zip2	v26.4s, v18.4s, v7.4s
	add	v25.4s, v24.4s, v23.4s
	zip1	v22.2d, v7.2d, v18.2d
	tbl	v28.16b, { v22.16b, v23.16b }, v4.16b
	zip1	v18.4s, v26.4s, v23.4s
	zip1	v22.4s, v23.4s, v26.4s
	ext	v23.16b, v28.16b, v28.16b, #12
	ext	v18.16b, v22.16b, v18.16b, #8
	uzp2	v16.4s, v16.4s, v17.4s
	uzp1	v23.4s, v28.4s, v23.4s
	mov	v31.16b, v18.16b
	ext	v6.16b, v6.16b, v6.16b, #12
	ext	v29.16b, v27.16b, v27.16b, #12
	mov	v31.s[1], v23.s[2]
	ext	v26.16b, v16.16b, v16.16b, #4
	add	v25.4s, v25.4s, v6.4s
	ext	v20.16b, v20.16b, v20.16b, #8
	ext	v30.16b, v27.16b, v29.16b, #12
	uzp1	v27.4s, v26.4s, v26.4s
	eor	v20.16b, v25.16b, v20.16b
	ext	v6.16b, v27.16b, v26.16b, #8
	ext	v21.16b, v21.16b, v21.16b, #4
	tbl	v27.16b, { v20.16b }, v0.16b
	add	v21.4s, v21.4s, v27.4s
	eor	v24.16b, v24.16b, v21.16b
	ushr	v29.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v29.16b
	add	v7.4s, v24.4s, v7.4s
	add	v7.4s, v7.4s, v25.4s
	eor	v25.16b, v27.16b, v7.16b
	add	v7.4s, v7.4s, v19.4s
	tbl	v19.16b, { v25.16b }, v2.16b
	add	v21.4s, v21.4s, v19.4s
	eor	v24.16b, v24.16b, v21.16b
	ushr	v25.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	ext	v7.16b, v7.16b, v7.16b, #4
	orr	v24.16b, v24.16b, v25.16b
	ext	v19.16b, v19.16b, v19.16b, #8
	add	v7.4s, v7.4s, v24.4s
	eor	v19.16b, v7.16b, v19.16b
	ext	v21.16b, v21.16b, v21.16b, #12
	tbl	v19.16b, { v19.16b }, v0.16b
	add	v21.4s, v21.4s, v19.4s
	eor	v24.16b, v24.16b, v21.16b
	ushr	v25.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v25.16b
	add	v25.4s, v24.4s, v17.4s
	add	v7.4s, v25.4s, v7.4s
	eor	v19.16b, v19.16b, v7.16b
	tbl	v19.16b, { v19.16b }, v2.16b
	add	v21.4s, v21.4s, v19.4s
	eor	v24.16b, v24.16b, v21.16b
	ushr	v25.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v25.16b
	zip2	v29.4s, v17.4s, v18.4s
	add	v25.4s, v24.4s, v23.4s
	zip1	v22.2d, v18.2d, v17.2d
	tbl	v27.16b, { v22.16b, v23.16b }, v4.16b
	zip1	v17.4s, v29.4s, v23.4s
	zip1	v22.4s, v23.4s, v29.4s
	ext	v23.16b, v27.16b, v27.16b, #12
	ext	v17.16b, v22.16b, v17.16b, #8
	tbl	v20.16b, { v30.16b, v31.16b }, v3.16b
	uzp1	v23.4s, v27.4s, v23.4s
	mov	v30.16b, v17.16b
	ext	v7.16b, v7.16b, v7.16b, #12
	ext	v28.16b, v26.16b, v26.16b, #12
	uzp2	v6.4s, v6.4s, v20.4s
	mov	v30.s[1], v23.s[2]
	add	v25.4s, v25.4s, v7.4s
	ext	v19.16b, v19.16b, v19.16b, #8
	ext	v29.16b, v26.16b, v28.16b, #12
	ext	v26.16b, v6.16b, v6.16b, #4
	eor	v19.16b, v25.16b, v19.16b
	uzp1	v27.4s, v26.4s, v26.4s
	ext	v21.16b, v21.16b, v21.16b, #4
	tbl	v19.16b, { v19.16b }, v0.16b
	ext	v7.16b, v27.16b, v26.16b, #8
	add	v27.4s, v21.4s, v19.4s
	eor	v24.16b, v24.16b, v27.16b
	tbl	v21.16b, { v29.16b, v30.16b }, v3.16b
	ushr	v29.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v29.16b
	add	v18.4s, v24.4s, v18.4s
	add	v18.4s, v18.4s, v25.4s
	eor	v19.16b, v19.16b, v18.16b
	add	v16.4s, v18.4s, v16.4s
	tbl	v18.16b, { v19.16b }, v2.16b
	add	v19.4s, v27.4s, v18.4s
	eor	v24.16b, v24.16b, v19.16b
	ushr	v25.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	ext	v16.16b, v16.16b, v16.16b, #4
	orr	v24.16b, v24.16b, v25.16b
	ext	v18.16b, v18.16b, v18.16b, #8
	add	v16.4s, v16.4s, v24.4s
	eor	v18.16b, v16.16b, v18.16b
	ext	v19.16b, v19.16b, v19.16b, #12
	tbl	v18.16b, { v18.16b }, v0.16b
	add	v19.4s, v19.4s, v18.4s
	eor	v24.16b, v24.16b, v19.16b
	ushr	v25.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v25.16b
	add	v25.4s, v24.4s, v20.4s
	add	v25.4s, v25.4s, v16.4s
	eor	v16.16b, v18.16b, v25.16b
	tbl	v27.16b, { v16.16b }, v2.16b
	add	v30.4s, v19.4s, v27.4s
	eor	v16.16b, v24.16b, v30.16b
	ushr	v18.4s, v16.4s, #7
	shl	v16.4s, v16.4s, #25
	orr	v24.16b, v16.16b, v18.16b
	zip2	v29.4s, v20.4s, v17.4s
	add	v31.4s, v24.4s, v23.4s
	zip1	v22.2d, v17.2d, v20.2d
	tbl	v18.16b, { v22.16b, v23.16b }, v4.16b
	zip1	v16.4s, v29.4s, v23.4s
	zip1	v19.4s, v23.4s, v29.4s
	ext	v20.16b, v18.16b, v18.16b, #12
	ext	v16.16b, v19.16b, v16.16b, #8
	ext	v25.16b, v25.16b, v25.16b, #12
	uzp1	v23.4s, v18.4s, v20.4s
	mov	v19.16b, v16.16b
	ext	v27.16b, v27.16b, v27.16b, #8
	add	v25.4s, v31.4s, v25.4s
	ext	v28.16b, v26.16b, v26.16b, #12
	mov	v19.s[1], v23.s[2]
	eor	v27.16b, v25.16b, v27.16b
	ext	v18.16b, v26.16b, v28.16b, #12
	ext	v28.16b, v30.16b, v30.16b, #4
	tbl	v27.16b, { v27.16b }, v0.16b
	add	v28.4s, v28.4s, v27.4s
	eor	v24.16b, v24.16b, v28.16b
	ushr	v29.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v29.16b
	add	v17.4s, v24.4s, v17.4s
	add	v17.4s, v17.4s, v25.4s
	eor	v25.16b, v27.16b, v17.16b
	add	v6.4s, v17.4s, v6.4s
	tbl	v17.16b, { v25.16b }, v2.16b
	add	v25.4s, v28.4s, v17.4s
	eor	v24.16b, v24.16b, v25.16b
	ushr	v27.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	ext	v6.16b, v6.16b, v6.16b, #4
	orr	v24.16b, v24.16b, v27.16b
	ext	v17.16b, v17.16b, v17.16b, #8
	add	v6.4s, v6.4s, v24.4s
	eor	v17.16b, v6.16b, v17.16b
	ext	v25.16b, v25.16b, v25.16b, #12
	tbl	v17.16b, { v17.16b }, v0.16b
	add	v25.4s, v25.4s, v17.4s
	eor	v24.16b, v24.16b, v25.16b
	ushr	v27.4s, v24.4s, #12
	shl	v24.4s, v24.4s, #20
	orr	v24.16b, v24.16b, v27.16b
	add	v27.4s, v24.4s, v21.4s
	add	v6.4s, v27.4s, v6.4s
	eor	v17.16b, v17.16b, v6.16b
	tbl	v17.16b, { v17.16b }, v2.16b
	add	v25.4s, v25.4s, v17.4s
	eor	v24.16b, v24.16b, v25.16b
	ushr	v27.4s, v24.4s, #7
	shl	v24.4s, v24.4s, #25
	orr	v24.16b, v24.16b, v27.16b
	zip2	v29.4s, v21.4s, v16.4s
	add	v27.4s, v24.4s, v23.4s
	zip1	v22.2d, v16.2d, v21.2d
	uzp2	v7.4s, v7.4s, v21.4s
	tbl	v21.16b, { v22.16b, v23.16b }, v4.16b
	zip1	v28.4s, v29.4s, v23.4s
	zip1	v22.4s, v23.4s, v29.4s
	ext	v23.16b, v21.16b, v21.16b, #12
	ext	v22.16b, v22.16b, v28.16b, #8
	ext	v20.16b, v7.16b, v7.16b, #4
	uzp1	v29.4s, v21.4s, v23.4s
	mov	v31.16b, v22.16b
	ext	v6.16b, v6.16b, v6.16b, #12
	ext	v26.16b, v20.16b, v20.16b, #12
	mov	v31.s[1], v29.s[2]
	add	v6.4s, v27.4s, v6.4s
	ext	v17.16b, v17.16b, v17.16b, #8
	ext	v30.16b, v20.16b, v26.16b, #12
	ext	v20.16b, v20.16b, v20.16b, #8
	eor	v17.16b, v6.16b, v17.16b
	uzp2	v21.4s, v20.4s, v19.4s
	ext	v23.16b, v25.16b, v25.16b, #4
	tbl	v17.16b, { v17.16b }, v0.16b
	ext	v20.16b, v21.16b, v20.16b, #4
	tbl	v21.16b, { v18.16b, v19.16b }, v3.16b
	zip2	v18.4s, v18.4s, v22.4s
	add	v19.4s, v23.4s, v17.4s
	eor	v23.16b, v24.16b, v19.16b
	ushr	v24.4s, v23.4s, #12
	shl	v23.4s, v23.4s, #20
	orr	v23.16b, v23.16b, v24.16b
	add	v16.4s, v23.4s, v16.4s
	add	v6.4s, v16.4s, v6.4s
	eor	v16.16b, v17.16b, v6.16b
	add	v6.4s, v6.4s, v7.4s
	tbl	v7.16b, { v16.16b }, v2.16b
	add	v16.4s, v19.4s, v7.4s
	eor	v17.16b, v23.16b, v16.16b
	ushr	v19.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	ext	v6.16b, v6.16b, v6.16b, #4
	orr	v17.16b, v17.16b, v19.16b
	ext	v7.16b, v7.16b, v7.16b, #8
	add	v6.4s, v6.4s, v17.4s
	eor	v7.16b, v6.16b, v7.16b
	ext	v16.16b, v16.16b, v16.16b, #12
	tbl	v7.16b, { v7.16b }, v0.16b
	add	v16.4s, v16.4s, v7.4s
	eor	v17.16b, v17.16b, v16.16b
	ushr	v19.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	orr	v17.16b, v17.16b, v19.16b
	add	v19.4s, v17.4s, v21.4s
	add	v6.4s, v19.4s, v6.4s
	eor	v7.16b, v7.16b, v6.16b
	tbl	v7.16b, { v7.16b }, v2.16b
	add	v16.4s, v16.4s, v7.4s
	eor	v17.16b, v17.16b, v16.16b
	ushr	v19.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	orr	v17.16b, v17.16b, v19.16b
	ext	v6.16b, v6.16b, v6.16b, #12
	add	v19.4s, v17.4s, v29.4s
	ext	v7.16b, v7.16b, v7.16b, #8
	add	v6.4s, v19.4s, v6.4s
	eor	v7.16b, v6.16b, v7.16b
	ext	v16.16b, v16.16b, v16.16b, #4
	tbl	v7.16b, { v7.16b }, v0.16b
	add	v16.4s, v16.4s, v7.4s
	zip1	v28.2d, v22.2d, v21.2d
	zip1	v21.4s, v18.4s, v29.4s
	zip1	v18.4s, v29.4s, v18.4s
	eor	v17.16b, v17.16b, v16.16b
	ext	v18.16b, v18.16b, v21.16b, #8
	ushr	v21.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	orr	v17.16b, v17.16b, v21.16b
	add	v21.4s, v17.4s, v22.4s
	add	v6.4s, v21.4s, v6.4s
	eor	v7.16b, v7.16b, v6.16b
	tbl	v7.16b, { v7.16b }, v2.16b
	add	v16.4s, v16.4s, v7.4s
	ext	v6.16b, v6.16b, v6.16b, #4
	eor	v17.16b, v17.16b, v16.16b
	add	v6.4s, v6.4s, v20.4s
	ushr	v20.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	orr	v17.16b, v17.16b, v20.16b
	ext	v7.16b, v7.16b, v7.16b, #8
	add	v6.4s, v6.4s, v17.4s
	eor	v7.16b, v6.16b, v7.16b
	ext	v16.16b, v16.16b, v16.16b, #12
	tbl	v7.16b, { v7.16b }, v0.16b
	add	v16.4s, v16.4s, v7.4s
	eor	v17.16b, v17.16b, v16.16b
	ushr	v20.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	tbl	v25.16b, { v30.16b, v31.16b }, v3.16b
	orr	v17.16b, v17.16b, v20.16b
	add	v20.4s, v17.4s, v25.4s
	add	v6.4s, v20.4s, v6.4s
	eor	v7.16b, v7.16b, v6.16b
	tbl	v7.16b, { v7.16b }, v2.16b
	add	v16.4s, v16.4s, v7.4s
	tbl	v19.16b, { v28.16b, v29.16b }, v4.16b
	eor	v17.16b, v17.16b, v16.16b
	ext	v23.16b, v19.16b, v19.16b, #12
	ushr	v20.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	uzp1	v19.4s, v19.4s, v23.4s
	orr	v17.16b, v17.16b, v20.16b
	ext	v6.16b, v6.16b, v6.16b, #12
	add	v19.4s, v17.4s, v19.4s
	ext	v7.16b, v7.16b, v7.16b, #8
	add	v6.4s, v19.4s, v6.4s
	eor	v7.16b, v6.16b, v7.16b
	ext	v16.16b, v16.16b, v16.16b, #4
	tbl	v7.16b, { v7.16b }, v0.16b
	add	v16.4s, v16.4s, v7.4s
	eor	v17.16b, v17.16b, v16.16b
	ushr	v19.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	orr	v17.16b, v17.16b, v19.16b
	add	v18.4s, v17.4s, v18.4s
	add	v6.4s, v18.4s, v6.4s
	eor	v7.16b, v7.16b, v6.16b
	tbl	v7.16b, { v7.16b }, v2.16b
	add	v16.4s, v16.4s, v7.4s
	eor	v17.16b, v17.16b, v16.16b
	ext	v6.16b, v6.16b, v6.16b, #4
	ext	v16.16b, v16.16b, v16.16b, #12
	ushr	v18.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	ext	v7.16b, v7.16b, v7.16b, #8
	eor	v6.16b, v6.16b, v16.16b
	orr	v16.16b, v17.16b, v18.16b
	eor	v7.16b, v16.16b, v7.16b
	add	x12, x12, #64
	mov	x15, x13
	mov	w14, w6
.LBB3_11:
	subs	x13, x15, #1
	b.eq	.LBB3_9
	cbnz	x15, .LBB3_10
	stp	q6, q7, [x8], #32
	add	x4, x4, x11
	add	x0, x0, #8
	subs	x1, x1, #1
	b.ne	.LBB3_8
.LBB3_14:
	add	sp, sp, #448
	ldp	x20, x19, [sp, #96]
	ldp	x22, x21, [sp, #80]
	ldp	x29, x23, [sp, #64]
	ldp	d9, d8, [sp, #48]
	ldp	d11, d10, [sp, #32]
	ldp	d13, d12, [sp, #16]
	ldp	d15, d14, [sp], #112
	ret
.Lfunc_end3:
	.size	zfs_blake3_hash_many_sse41, .Lfunc_end3-zfs_blake3_hash_many_sse41
	.cfi_endproc
	.section	".note.GNU-stack","",@progbits
#endif
