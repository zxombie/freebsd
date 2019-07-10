/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018, 2019 Andrew Turner
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include "opt_sanitizer.h"
#include "opt_stack.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kasan.h>
#include <sys/ktr.h>
#include <sys/malloc.h>
#include <sys/stack.h>

#include <machine/kasan.h>
#include <machine/vmparam.h>

uintptr_t kasan_limit;
static int kasan_ready;
static bool kasan_reporting;

void __asan_handle_no_return(void);
void __asan_alloca_poison(uintptr_t, size_t);
void __asan_allocas_unpoison(uintptr_t, uintptr_t);
void __asan_loadN_noabort(uintptr_t, size_t);
void __asan_storeN_noabort(uintptr_t, size_t);

vm_offset_t
kasan_kmem_to_shadow(vm_offset_t addr)
{

	KASSERT(addr >= VM_MIN_KERNEL_ADDRESS && addr < VM_MAX_KERNEL_ADDRESS,
	    ("kasan_kmem_to_shadow: Invalid kernel address %#jx", (uintmax_t)addr));
#ifdef __aarch64__
	return ((addr >> 3) + (vm_offset_t)0xe0001fe000000000ul);
#else
	return (((addr - VM_MIN_KERNEL_ADDRESS) >> 3) + KASAN_MIN_ADDRESS);
#endif
}

vm_offset_t
kasan_shadow_to_kmem(vm_offset_t addr)
{

	KASSERT(addr >= KASAN_MIN_ADDRESS && addr < KASAN_MAX_ADDRESS,
	    ("kasan_shadow_to_kmem: Invalid shadow address %#jx",
	    (uintmax_t)addr));
	return (((addr - KASAN_MIN_ADDRESS) << 3) + VM_MIN_KERNEL_ADDRESS);
}

vm_paddr_t pmap_kextract(vm_offset_t);

static bool
kasan_check_address(uintptr_t addr, size_t size)
{

	if (kasan_reporting)
		return (false);

	/* Don't check while handling a panic */
	if (panicstr != NULL)
		return (false);

	/* Ignore writes to the shadow memory */
	if (addr > KASAN_MIN_ADDRESS && addr + size < KASAN_MAX_ADDRESS)
		return (false);

	if (kasan_ignore_addr(addr, size))
		return (false);

	if (addr < VM_MIN_KERNEL_ADDRESS)
		panic("Invalid userspace load for address %#jx",
		    (uintmax_t)addr);

	if (addr + size > VM_MAX_KERNEL_ADDRESS)
		panic("Invalid kernel load for address %#jx",
		    (uintmax_t)addr);

	/* There is no support for early KASAN support yet */
	if (kasan_ready == 0)
		return (false);

	if (kasan_limit == 0)
		return (false);

#if 0
	/* Hack to get past the early boot */
	if (kasan_kmem_to_shadow(addr) > kasan_limit)
		return (false);
#endif

	return (true);
}

static void
kasan_report(uintptr_t addr, size_t size, bool is_store, void *retaddr)
{
#ifdef STACK
	struct stack *st;
#endif

	kasan_reporting = true;
	printf("KASAN: Attempted %s of address %#jx size %zu from %p\n",
	    is_store ? "store" : "load", (uintmax_t)addr, size, retaddr);
#ifdef STACK
	st = stack_create(M_NOWAIT);
	if (st == NULL) {
		printf("KASAN: Unable to allocate the stack\n");
	} else {
		printf("Stack:\n");
		stack_save(st);
		stack_print(st);
		stack_destroy(st);
	}
#endif
	kasan_reporting = false;
}

/*
 * Check a single byte access is valid. As a side affect of how KASAN works
 * it will also check all the bytes within the same shadow region, but
 * before the checked address. We use this when checking if later regions are
 * poisoned.
 */
static bool
kasan_memory_is_poisioned_1(uintptr_t addr)
{
	int8_t shadow_val;

	shadow_val = *(int8_t *)kasan_kmem_to_shadow(addr);

	/* A shadow value of 0 means all bytes are valid */
	if (shadow_val == 0)
		return (false);

	/*
	 * If any bytes are valid shadow_val will contain how many.
	 * If none are it will hold a negative number.
	 */
	return ((addr & KASAN_SHADOW_MASK) >= shadow_val);
}

/*
 * Check if a 2, 4, or 8 byte access is valid. It may need to split the check
 * into 2 smaller accesses if the access crosses a KASAN boundary.
 */
static bool
kasan_memory_is_poisioned_2_4_8(uintptr_t addr, size_t size)
{
	int8_t shadow_val;

	/*
	 * The access crosses a KASAN boundary. The first shadow value must
	 * be 0 for all memory to be valid. We can fall out to the call to
	 * kasan_memory_is_poisioned_1 to check the second.
	 */
	if (((addr + size - 1) & KASAN_SHADOW_MASK) < size - 1) {
		shadow_val = *(int8_t *)kasan_kmem_to_shadow(addr);

		if (shadow_val != 0)
			return (true);
	}

	return (kasan_memory_is_poisioned_1(addr + size - 1));
}

/*
 * Check if a 16 byte access is valid. It will split the check into 2 smaller
 * accesses, and my need to split it into 3 if the access crosses 2 KASAN
 * boundaries.
 */
static bool
kasan_memory_is_poisioned_16(uintptr_t addr, size_t size)
{
	int8_t *shadow_addr;

	shadow_addr = (int8_t *)kasan_kmem_to_shadow(addr);

	/*
	 * Check the lead in bytes. These will be at the end of the first
	 * KASAN region so the entire region needs to be valid.
	 */
	if (*shadow_addr != 0)
		return (true);

	/* Align to the next KASAN region */
	size -= KASAN_SHADOW_SCALE_SIZE + addr & KASAN_SHADOW_MASK;
	addr += KASAN_SHADOW_SCALE_SIZE - addr & KASAN_SHADOW_MASK;
	shadow_addr++;

	/* Check the second region */
	if (*shadow_addr != 0)
		return (true);

	/* We are crossing 3 regions, check the end bytes */
	if (size > KASAN_SHADOW_SCALE_SIZE)
		return (kasan_memory_is_poisioned_1(addr + size - 1));

	return (false);
}

static bool
kasan_memory_is_poisioned_range(uintptr_t addr, size_t size)
{
	int8_t shadow_val;

	/* Align addr to the start of a KASAN region */
	size += addr & KASAN_SHADOW_MASK;
	addr -= addr & KASAN_SHADOW_MASK;

	while (size >= KASAN_SHADOW_SCALE_SIZE) {
		shadow_val = *(int8_t *)kasan_kmem_to_shadow(addr);

		if (shadow_val != 0)
			return (true);

		addr += KASAN_SHADOW_SCALE_SIZE;
		size -= KASAN_SHADOW_SCALE_SIZE;
	}

	return (kasan_memory_is_poisioned_1(addr + size - 1));
}

static bool
kasan_memory_is_poisioned(uintptr_t addr, size_t size)
{

	if (kasan_kmem_to_shadow(addr) > kasan_limit)
		return (true);

	switch(size) {
	case 1:
		return (kasan_memory_is_poisioned_1(addr));
	case 2:
	case 4:
	case 8:
		return (kasan_memory_is_poisioned_2_4_8(addr, size));
	case 16:
		return (kasan_memory_is_poisioned_16(addr, size));
	default:
		if (__builtin_constant_p(size))
			panic("KASAN: Invalid constant size %zu", size);
	}

	return (kasan_memory_is_poisioned_range(addr, size));
}

static void
kasan_check_region(uintptr_t addr, size_t size, bool is_store, void *retaddr)
{

	if (!kasan_check_address(addr, size))
		return;

	if (kasan_memory_is_poisioned(addr, size))
		kasan_report(addr, size, is_store, retaddr);
}

#define	ASAN_LOAD_STORE(size)						\
void __asan_load##size##_noabort(uintptr_t);				\
void									\
__asan_load##size##_noabort(uintptr_t addr)				\
{									\
									\
	kasan_check_region(addr, size, false,				\
	    __builtin_return_address(0));				\
}									\
									\
void __asan_store##size##_noabort(uintptr_t);				\
void									\
__asan_store##size##_noabort(uintptr_t addr)				\
{									\
									\
	kasan_check_region(addr, size, true,				\
	    __builtin_return_address(0));				\
}

ASAN_LOAD_STORE(1)
ASAN_LOAD_STORE(2)
ASAN_LOAD_STORE(4)
ASAN_LOAD_STORE(8)
ASAN_LOAD_STORE(16)

void
__asan_handle_no_return(void)
{
}

void
__asan_loadN_noabort(uintptr_t addr, size_t size)
{

	kasan_check_region(addr, size, false, __builtin_return_address(0));
}

void
__asan_storeN_noabort(uintptr_t addr, size_t size)
{

	kasan_check_region(addr, size, true,  __builtin_return_address(0));
}

#if 0
void
__asan_alloca_poison(uintptr_t addr, size_t size)
{
}

void
__asan_allocas_unpoison(uintptr_t addr1, uintptr_t addr2)
{
}
#endif

void
kasan_init(void)
{

	kasan_reporting = false;
	kasan_ready = 1;
	printf("KASAN ready\n");
}

void
kasan_poison(vm_offset_t addr, vm_size_t size)
{
	uint8_t *shadow;
	int i;

	KASSERT((addr & KASAN_SHADOW_MASK) == 0,
	    ("kasan_poison: Incorrectly aligned address %lx", addr));

	if (kasan_ignore_addr(addr, size))
		return;

	shadow = (uint8_t *)kasan_kmem_to_shadow(addr);

	/* Hack to get past the early boot */
	//if ((uintptr_t)shadow > kasan_limit)
	if (kasan_limit == 0)
		return;

	CTR3(KTR_KASAN, "poison %#jx %#jx %p", addr, size,
	    __builtin_return_address(0));

	/* TODO: Set the correct value */
	for (i = 0; i < size; i += 8) {
		*shadow = 0xff;
		shadow++;
	}
}

void
kasan_unpoison(vm_offset_t addr, vm_size_t size)
{
	int8_t *shadow;
	int i;

	size += addr & KASAN_SHADOW_MASK;
	addr = addr & ~KASAN_SHADOW_MASK;

	KASSERT((addr & KASAN_SHADOW_MASK) == 0,
	    ("kasan_unpoison: Incorrectly aligned address %lx", addr));

	if (kasan_ignore_addr(addr, size))
		return;

	shadow = (int8_t *)kasan_kmem_to_shadow(addr);

	/* Hack to get past the early boot */
	//if ((uintptr_t)shadow > kasan_limit)
	if (kasan_limit == 0)
		return;

	CTR3(KTR_KASAN, "unpoison %#jx %#jx %p", addr, size,
	    __builtin_return_address(0));

	/* TODO: Set the correct value */
	for (i = 0; i < size; i += 8) {
		KASSERT(*shadow < 0,
		    ("kasan_unpoison: Already unpoisioned: %lx (%x)",
		    addr + i, *shadow));
		*shadow = 0;
		shadow++;
	}
}

void
kasan_unpoison_buf(vm_offset_t addr, vm_size_t size)
{
	uint8_t *shadow;
	int i;

	KASSERT((addr & KASAN_SHADOW_MASK) == 0,
	    ("kasan_unpoison_buf: Incorrectly aligned address %lx", addr));

	if (kasan_ignore_addr(addr, size))
		return;

	shadow = (uint8_t *)kasan_kmem_to_shadow(addr);

	/* Hack to get past the early boot */
	//if ((uintptr_t)shadow > kasan_limit)
	if (kasan_limit == 0)
		return;

	CTR3(KTR_KASAN, "unpoison buf %#jx %#jx %p", addr, size,
	    __builtin_return_address(0));

	/* TODO: Set the correct value */
	for (i = 0; i < size; i += KASAN_SHADOW_SCALE_SIZE) {
		if (i >= KASAN_SHADOW_SCALE_SIZE)
			*shadow = 0;
		else
			*shadow = size & KASAN_SHADOW_MASK;
		shadow++;
	}
}

/*
 * This might be useful for testing.
 */
#if 0
bool
kasan_addr_valid(vm_offset_t addr)
{

	if (!kasan_check_address(addr, size))
		return (false);

	return (kasan_memory_is_poisioned(addr, 1));
}
#endif
