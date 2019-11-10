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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>

#include <stdbool.h>

#include <stand.h>
#include <bootstrap.h>

#include <libfdt.h>
#include <fdt.h>
#include <fdt_platform.h>

#include <kuart.h>

static struct uart_bas fdt_uart_bas;

static struct fdt_header *fdtp;
struct uart_class *fdt_class;

static struct uart_class *
fdt_find_uart_class(struct fdt_header *fdtp, int offset)
{
	struct ofw_compat_data **cd;

	SET_FOREACH(cd, uart_fdt_class_set) {
		if (fdt_node_check_compatible(fdtp, offset,(*cd)->ocd_str) == 0)
			return ((struct uart_class *)(*cd)->ocd_data);
	}

	return (NULL);
}

static uintmax_t
fdt_read_prop(struct fdt_header *fdtp, int offset, const char *prop)
{
	const void *data;
	uintmax_t val;
	int i, len;

	data = fdt_getprop(fdtp, offset, prop, &len);
	if (data == NULL)
		return (0);

	val = 0;
	for (i = 0; len > 3; len -= 4, i++) {
		val <<= 32;
		val |= fdt32_to_cpu(*((const uint32_t *)data + i));
	}
	return (val);
}

static void
fdt_addr_props(int offset, u_int *addrp, u_int *sizep)
{

	*addrp = fdt_read_prop(fdtp, offset, "#address-cells");
	if (*addrp == 0)
		*addrp = 2;

	*sizep = fdt_read_prop(fdtp, offset, "#size-cells");
	if (*sizep == 0)
		*sizep = 1;
}

static bool
fdt_reg_to_paddr(int offset, vm_paddr_t *addrp, vm_size_t *sizep)
{
	const void *data;
	vm_paddr_t addr;
	vm_size_t size;
	u_int naddr, nsize;
	int i, len, parent;

	fdt_addr_props(offset, &naddr, &nsize);
	data = fdt_getprop(fdtp, offset, "reg", &len);
	if (data == NULL)
		return (false);

	addr = 0;
	size = 0;

	for (i = 0; i < naddr; i++)
		addr = (addr << 32) |
		    fdt32_to_cpu(*((const uint32_t *)data + i));
	for (i = 0; i < nsize; i++)
		size = (size << 32) |
		    fdt32_to_cpu(*((const uint32_t *)data + i + naddr));

	parent = fdt_parent_offset(fdtp, offset);
	while (parent > 0) {
		data = fdt_getprop(fdtp, parent, "ranges", &len);
		if (data == NULL)
			goto next;

		/* TODO: Adjust addr as needed based on the ranged property */

next:
		parent = fdt_parent_offset(fdtp, parent);
	}

	if (addrp != NULL)
		*addrp = addr;
	if (sizep != NULL)
		*sizep = size;

	return (true);
}

static void
fdt_cons_probe(struct console *cp)
{
	const void *data;
	struct uart_class *class;
	vm_offset_t addr;
	int offset, len;

	fdtp = fdt_get();
	if (fdtp == NULL)
		return;

	offset = fdt_path_offset(fdtp, "/chosen");
	if (offset < 0)
		return;

	data = fdt_getprop(fdtp, offset, "stdout-path", &len);
	if (data == NULL)
		return;

	offset = fdt_path_offset(fdtp, data);
	if (offset < 0)
		return;

	class = fdt_find_uart_class(fdtp, offset);
	if (class == NULL)
		return;

	if (!fdt_reg_to_paddr(offset, &addr, NULL))
		return;

	fdt_uart_bas.bsh = (void *)addr;

	data = fdt_getprop(fdtp, offset, "reg-shift", NULL);
	if (data != NULL)
		fdt_uart_bas.regshft = fdt32_to_cpu(*(const uint32_t *)data);
	else
		fdt_uart_bas.regshft = class->uc_rshift;

	if (class->uc_ops->probe(&fdt_uart_bas) != 0)
		return;

	fdt_class = class;
	cp->c_flags |= C_PRESENTIN | C_PRESENTOUT;
}

static int
fdt_cons_init(int arg)
{

	/* Assume 115200 8-n-1 for now */
	fdt_class->uc_ops->init(&fdt_uart_bas, 115200, 8, 1, 0);
	return (0);
}

static void
fdt_cons_putchar(int c)
{

	fdt_class->uc_ops->putc(&fdt_uart_bas, c);
}

static int
fdt_cons_getchar(void)
{

	if (!fdt_class->uc_ops->rxready(&fdt_uart_bas))
		return (-1);

	return (fdt_class->uc_ops->getc(&fdt_uart_bas, NULL));
}

static int
fdt_cons_poll(void)
{

	return (fdt_class->uc_ops->rxready(&fdt_uart_bas) ? 1 : 0);
}

struct console fdt_console = {
	"fdt",
	"fdt console",
	0,
	fdt_cons_probe,
	fdt_cons_init,
	fdt_cons_putchar,
	fdt_cons_getchar,
	fdt_cons_poll
};
