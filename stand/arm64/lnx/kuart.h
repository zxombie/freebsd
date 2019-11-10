/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Andrew Turner
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
 * $FreeBSD$
 */

#ifndef _LNX_KUART_H_
#define	_LNX_KUART_H_

#include <sys/linker_set.h>

struct mtx;

struct uart_bas {
	void *bst;
	void *bsh;
	int regshft;
	int rclk;
};

#define	uart_regofs(bas, reg)	((reg) << (bas)->regshft)

static inline uint32_t
bus_space_read_4(void *bst __unused, void *bsh, size_t reg)
{

	return (*(volatile uint32_t *)((char *)bsh + reg));
}

static inline void
bus_space_write_4(void *bst __unused, void *bsh, size_t reg, uint32_t val)
{

	 *(volatile uint32_t *)((char *)bsh + reg) = val;
}

struct uart_ops {
	int (*probe)(struct uart_bas *);
	void (*init)(struct uart_bas *, int, int, int, int);
	void (*term)(struct uart_bas *);
	void (*putc)(struct uart_bas *, int);
	int (*rxready)(struct uart_bas *);
	int (*getc)(struct uart_bas *, struct mtx *);
};

struct uart_class {
	struct uart_ops *uc_ops;
	u_int uc_range;
	u_int uc_rclk;
	u_int uc_rshift;
};

struct ofw_compat_data {
	const char *ocd_str;
	uintptr_t ocd_data;
};

SET_DECLARE(uart_fdt_class_set, struct ofw_compat_data );
#define	UART_FDT_CLASS_AND_DEVICE(compat)				\
    DATA_SET(uart_fdt_class_set, compat)

#endif
