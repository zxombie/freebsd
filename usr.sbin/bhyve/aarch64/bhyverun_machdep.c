/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2021-2022 The FreeBSD Foundation
 * Copyright (c) 2022-2023 Arm Ltd
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdlib.h>

#include <vmmapi.h>

#include "bhyverun.h"
#include "bootcode.h"
#include "config.h"

/* TODO: Move to a header */
int fdt_build(struct vmctx *ctx, struct vcpu *bsp, int ncpu);
void init_uart(struct vmctx *);

void
bhyve_init_config(void)
{
	init_config();

#if 0
	/* Set default values prior to option parsing. */
	set_config_bool("acpi_tables", true);
	set_config_bool("acpi_tables_in_memory", true);
	set_config_value("memory.size", "256M");
	set_config_bool("x86.strictmsr", true);
	set_config_value("lpc.fwcfg", "bhyve");
#endif
}

void
bhyve_init_vcpu(struct vcpu *vcpu __unused)
{
#if 0
	int err, tmp;

	if (get_config_bool_default("x86.vmexit_on_hlt", false)) {
		err = vm_get_capability(vcpu, VM_CAP_HALT_EXIT, &tmp);
		if (err < 0) {
			fprintf(stderr, "VM exit on HLT not supported\n");
			exit(4);
		}
		vm_set_capability(vcpu, VM_CAP_HALT_EXIT, 1);
	}

	if (get_config_bool_default("x86.vmexit_on_pause", false)) {
		/*
		 * pause exit support required for this mode
		 */
		err = vm_get_capability(vcpu, VM_CAP_PAUSE_EXIT, &tmp);
		if (err < 0) {
			fprintf(stderr,
			    "SMP mux requested, no pause support\n");
			exit(4);
		}
		vm_set_capability(vcpu, VM_CAP_PAUSE_EXIT, 1);
	}

	if (get_config_bool_default("x86.x2apic", false))
		err = vm_set_x2apic_state(vcpu, X2APIC_ENABLED);
	else
		err = vm_set_x2apic_state(vcpu, X2APIC_DISABLED);

	if (err) {
		fprintf(stderr, "Unable to set x2apic state (%d)\n", err);
		exit(4);
	}

	vm_set_capability(vcpu, VM_CAP_ENABLE_INVPCID, 1);

	err = vm_set_capability(vcpu, VM_CAP_IPI_EXIT, 1);
	assert(err == 0);
#endif
}

void
bhyve_start_vcpu(struct vcpu *vcpu __unused, bool bsp __unused)
{
#if 0
	int error;

	if (bsp) {
		if (lpc_bootrom()) {
			error = vm_set_capability(vcpu,
			    VM_CAP_UNRESTRICTED_GUEST, 1);
			if (error != 0) {
				err(4, "ROM boot failed: unrestricted guest "
				    "capability not available");
			}
			error = vcpu_reset(vcpu);
			assert(error == 0);
		}
	} else {
		bhyve_init_vcpu(vcpu);

		/*
		 * Enable the 'unrestricted guest' mode for APs.
		 *
		 * APs startup in power-on 16-bit mode.
		 */
		error = vm_set_capability(vcpu, VM_CAP_UNRESTRICTED_GUEST, 1);
		assert(error == 0);
	}
#endif

	fbsdrun_addcpu(vcpu_id(vcpu));
}

int
bhyve_init_platform(struct vmctx *ctx, struct vcpu *bsp __unused)
{
	const char *bootrom = NULL;
	vm_paddr_t pc;
	int error;

	init_uart(ctx);

	bootrom = get_config_value("bootrom");
	if (bootrom == NULL)
		bootrom = "/root/u-boot.bin";

	error = bootcode_load(ctx, bootrom, &pc);
	assert(error == 0);
	error = vm_set_register(bsp, VM_REG_GUEST_PC, pc);
	assert(error == 0);
	error = vm_attach_vgic(ctx, 0x2f000000UL, 0x10000UL, 0x2f100000UL,
	    (2UL * PAGE_SIZE_64K) * guest_ncpus);
	assert(error == 0);

	return (0);
}

int
bhyve_init_platform_late(struct vmctx *ctx, struct vcpu *bsp __unused)
{
	int error;

	error = fdt_build(ctx, bsp, guest_ncpus);
	assert(error == 0);


	return (0);
}
