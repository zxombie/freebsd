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

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/kasan.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>

void
kasan_shadow_map(vm_offset_t addr, vm_size_t size)
{
	vm_offset_t start, end;
	pd_entry_t *pde = NULL, newpdir;
	pdp_entry_t *pdpe;
	vm_paddr_t paddr;
	vm_page_t nkpg;
	pmap_t kpm = kernel_pmap;

	KASSERT(addr >= VM_MIN_KERNEL_ADDRESS,
	    ("kasan_grow_shadow_map: Invalid userspace address %lx", addr));
	KASSERT(addr < VM_MAX_KERNEL_ADDRESS,
	    ("kasan_grow_shadow_map: Invalid address %lx", addr));

	start = kasan_kmem_to_shadow(addr);
	KASSERT(start < KASAN_MAX_ADDRESS,
	    ("kasan_grow_shadow_map: Bad start address found: %lx", start));
	end = kasan_kmem_to_shadow(addr + size);
	if (end > KASAN_MAX_ADDRESS)
		end = KASAN_MAX_ADDRESS;
	while (start < end) {
		pdpe = pmap_pdpe(kpm, start);
		if ((*pdpe & X86_PG_V) == 0) {
			/* We need a new PDP entry */
			nkpg = vm_page_alloc(NULL, 0,
			    VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ |
			    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
			if (nkpg == NULL)
				panic("kasan_grow_shadow_map: "
				    "no memory to grow PDPE shadow map");
			if ((nkpg->flags & PG_ZERO) == 0)
				pmap_zero_page(nkpg);
			paddr = VM_PAGE_TO_PHYS(nkpg);
			*pdpe = (pdp_entry_t)(paddr | X86_PG_V | X86_PG_RW |
			    X86_PG_A | X86_PG_M);
			continue; /* try again */
		}

		nkpg = vm_page_alloc(NULL, 0,
		    VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED |
		    VM_ALLOC_ZERO);
		if (nkpg == NULL)
			panic("kasan_grow_shadow_map: "
			    "no memory to grow PDE shadow map");
		if ((nkpg->flags & PG_ZERO) == 0)
			pmap_zero_page(nkpg);
		paddr = VM_PAGE_TO_PHYS(nkpg);
		newpdir = paddr | X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;
		pde_store(pde, newpdir);
	}
}
