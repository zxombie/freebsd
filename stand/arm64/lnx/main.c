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
#include <machine/elf.h>

#include <stand.h>
#include <bootstrap.h>
#include <disk.h>

#include <libfdt.h>
#include <fdt.h>
#include <fdt_platform.h>

#include <arm/include/physmem.h>

struct arch_switch archsw;

extern char hboot_start[];
extern char _edata[];

static vm_paddr_t kernpa = -1;
int stage_offset_set = 0;
ssize_t stage_offset;

static int elf64_exec(struct preloaded_file *amp);

int lnx_getdev(void **, const char *, const char **);
int lnx_setcurrdev(struct env_var *, int, const void *);

void
exit(int code)
{

	while (1)
		asm ("wfe");
}

static time_t t;

time_t
time(time_t *tloc)
{
	uint64_t freq, count;

	asm (
	    "mrs %0, CNTFRQ_EL0 \n"
	    "mrs %1, CNTVCT_EL0" :
	    "=&r" (freq), "=&r" (count));

	return (count / freq);
}

void
delay(int usecs)
{
	uint64_t freq, start, end;

	asm("mrs %0, CNTFRQ_EL0 \n"
	    "mrs %1, CNTVCT_EL0" :
	    "=&r" (freq), "=&r" (start));

	end = (freq * usecs) / 1000000 + start;

	while (start < end)
		asm("mrs %0, CNTVCT_EL0" : "=&r" (start));
}

int
fdt_platform_load_dtb(void)
{

	return (1);
}

void
fdt_platform_load_overlays(void)
{
}

void
fdt_platform_fixups(void)
{
}

int
lnx_autoload(void)
{

	/* We don't need to load the DTB as it's already loaded */
	return (0);
}

static void
set_currdev(const char *devname)
{

	env_setenv("currdev", EV_VOLATILE, devname, lnx_setcurrdev,
	    env_nounset);
	env_setenv("loaddev", EV_VOLATILE, devname, env_noset, env_nounset);
}

static ssize_t
lnx_copyin(const void *src, vm_offset_t dest, const size_t len)
{

	if (kernpa == -1) {
		errno = ENOMEM;
		return (-1);
	}
	if (!stage_offset_set) {
		stage_offset = (vm_offset_t)kernpa - dest;
		stage_offset_set = 1;
	}

	bcopy(src, (void *)(dest + stage_offset), len);
	return (len);
}

ssize_t
lnx_copyout(const vm_offset_t src, void *dest, const size_t len)
{

	if (kernpa == -1) {
		errno = ENOMEM;
		return (-1);
	}

	bcopy((void *)(src + stage_offset), dest, len);
	return (len);
}

ssize_t
lnx_readin(const int fd, vm_offset_t dest, const size_t len)
{

	if (kernpa == -1) {
		errno = ENOMEM;
		return (-1);
	}
	if (!stage_offset_set) {
		stage_offset = (vm_offset_t)kernpa - dest;
		stage_offset_set = 1;
	}

	return (read(fd, (void *)(dest + stage_offset), len));
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
mem_probe(void)
{
	struct fdt_header *fdtp;
	const void *data;
	uint64_t base, length, end;
	vm_paddr_t memory[16];
	int offset, len, i;

	fdtp = fdt_get();
	if (fdtp == NULL)
		return;

	/* Include memory reported to us */
	offset = fdt_path_offset(fdtp, "/memory");
	if (offset < 0)
		return;

	data = fdt_getprop(fdtp, offset, "reg", &len);
	if (data == NULL)
		return;

	for (i = 0; i < (len / 16); i++) {
		base = fdt32_to_cpu(((uint32_t *)data)[i]);
		base <<= 32;
		base |= fdt32_to_cpu(((uint32_t *)data)[i + 1]);

		length = fdt32_to_cpu(((uint32_t *)data)[i + 2]);
		length <<= 32;
		length |= fdt32_to_cpu(((uint32_t *)data)[i + 3]);

		arm_physmem_hardware_region(base, length);
	}

	/* Exclude memory in the initrd image */
	offset = fdt_path_offset(fdtp, "/chosen");
	if (offset > 0) {
		base = fdt_read_prop(fdtp, offset,
		    "linux,initrd-start");
		end = fdt_read_prop(fdtp, offset,
		    "linux,initrd-end");

		arm_physmem_exclude_region(base, end - base, EXFLAG_NOALLOC);
	}

	/* Find memory to copy the kernel to */
	arm_physmem_avail(memory, nitems(memory));
	for (i = 0; i < (nitems(memory) / 2); i++) {
		if (memory[2 * i] == 0)
			break;
		base = roundup2(memory[2 * i], 2 * 1024 * 1024);
		if ((memory[2 * i + 1] - base) > 64 * 1024 * 1024) {
			kernpa = base;
			break;
		}
	}
}

int
arm64_main(struct fdt_header *fdtp)
{
	uintptr_t loader_end;
	int i;

	archsw.arch_autoload = lnx_autoload;
	archsw.arch_getdev = lnx_getdev;
	archsw.arch_copyin = lnx_copyin;
	archsw.arch_copyout = lnx_copyout;
	archsw.arch_readin = lnx_readin;

	/* Exclude loader code */
	arm_physmem_exclude_region((vm_paddr_t)&hboot_start,
	    loader_end - (vm_paddr_t)&hboot_start, EXFLAG_NOALLOC);

	/* Use a 2MiB heap */
	loader_end = roundup2((uintptr_t)&_edata, PAGE_SIZE);
	setheap((void *)loader_end, (void *)(loader_end + 2 * 1024 * 1024));
	arm_physmem_exclude_region(loader_end, 2 * 1024 * 1024, EXFLAG_NOALLOC);

	/* Exclude the DTB and apss it to the fdt code */
	arm_physmem_exclude_region((uintptr_t)fdtp, fdt_totalsize(fdtp),
	    EXFLAG_NOALLOC);
	fdt_load_dtb_addr(fdtp);

	/* Find the console */
	cons_probe();

	mem_probe();
	/* Find the board memory */
	if (kernpa == -1)
		panic("Unable to find memory to copy the kernel to");
	printf("Loading kernel to %lx\n", kernpa);

	/* Print the memory maps */
	arm_physmem_print_tables();

	/* Init devices */	
	for (i = 0; devsw[i] != NULL; i++) {
		if (devsw[i]->dv_init != NULL)
			(devsw[i]->dv_init)();
	}

	/* Load from md0, the initrd image */
	set_currdev("md0");

	interact();			/* doesn't return */

	while (1)
		asm("wfi");
}

extern int command_fdt_internal(int argc, char *argv[]);

/*
 * Since proper fdt command handling function is defined in fdt_loader_cmd.c,
 * and declaring it as extern is in contradiction with COMMAND_SET() macro
 * (which uses static pointer), we're defining wrapper function, which
 * calls the proper fdt handling routine.
 */
static int
command_fdt(int argc, char *argv[])
{

	return (command_fdt_internal(argc, argv));
}

COMMAND_SET(fdt, "fdt", "flattened device tree handling", command_fdt);
