/*-
 * Copyright (c) 2015 The FreeBSD Foundation
 *
 * This software was developed by Andrew Turner under
 * sponsorship from the FreeBSD Foundation.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysproto.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <machine/sysarch.h>
#include <machine/vmparam.h>

int
sysarch(struct thread *td, struct sysarch_args *uap)
{
	struct arm64_guard_page_args gp_args;
	int error;

	switch(uap->op) {
	case ARM64_GUARD_PAGE:
		error = copyin(uap->parms, &gp_args, sizeof(gp_args));
		if (error != 0)
			break;

		/* Only accept canonical addresses, no PAC or TBI */
		if (!ADDR_IS_CANONICAL(gp_args.addr))
			return (EINVAL);

		/* Align the start to a page alignment */
		gp_args.len += gp_args.addr & PAGE_MASK;
		gp_args.addr = trunc_page(gp_args.addr);
		/* Align the length */
		gp_args.len = round_page(gp_args.len);

		/* Check the address points to user memory */
		if (gp_args.addr >= VM_MAX_USER_ADDRESS)
			return (EINVAL);

		/*
		 * Check the length is not too long. As the length may wrap
		 * we need to make sure it is no longer than the remaining
		 * user memory.
		 */
		 if ((VM_MAX_USER_ADDRESS - gp_args.addr) < gp_args.len)
			return (EINVAL);

		error = pmap_bti_set(PCPU_GET(curpmap), gp_args.addr,
		    gp_args.addr + gp_args.len);
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}
