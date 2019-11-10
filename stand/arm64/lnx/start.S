/*-
 * Copyright (c) 2014 Andrew Turner
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * We need to be the correct format for HBOOT.
 */

#define	INIT_STACK_SIZE		(4096 * 8)

.global hboot_start
hboot_start:
	/* The Linux boot header */
	b	_start
	.word	0	/* Reserved */
	.quad	0x0	/* Load offset from start of ram */
	.quad	0x0	/* Effective size of kernel */
	.quad	0x0	/* Informative flags */
	.quad	0	/* Reserved */
	.quad	0	/* Reserved */
	.quad	0	/* Reserved */
	.byte	0x41	/* string "ARM\x64" */
	.byte	0x52
	.byte	0x4d
	.byte	0x64
	.word	0	/* Reserved */

	.globl	_start
_start:
	/* Backup the data passed to us */
	mov	x20, x0
	mov	x21, x1
	mov	x22, x2
	mov	x23, x3

	adr	x0, __bss_start
	adr	x1, __bss_end

	b 2f

1:
	stp	xzr, xzr, [x0], #16
2:
	cmp	x0, x1
	b.lo	1b

	adr	x0, end_stack
	mov	sp, x0

	adr	x0, hboot_start
	adr	x1, _DYNAMIC

	bl	self_reloc

	mov	x0, x20
	mov	x1, x21
	mov	x2, x22
	mov	x3, x23

	bl	arm64_main

1:	wfi
	b	1b

	.data
init_stack:
	.space	INIT_STACK_SIZE
	.align	4
end_stack:
