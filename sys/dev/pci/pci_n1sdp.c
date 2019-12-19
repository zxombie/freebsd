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
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>
#include <dev/acpica/acpi_pcibvar.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcib_private.h>
#include <dev/pci/pci_host_generic.h>
#include <dev/pci/pci_host_generic_acpi.h>

#include "pcib_if.h"

/* Assembling ECAM Configuration Address */
#define	PCIE_BUS_SHIFT		20
#define	PCIE_SLOT_SHIFT		15
#define	PCIE_FUNC_SHIFT		12
#define	PCIE_BUS_MASK		0xFF
#define	PCIE_SLOT_MASK		0x1F
#define	PCIE_FUNC_MASK		0x07
#define	PCIE_REG_MASK		0xFFF

#define	PCIE_ADDR_OFFSET(bus, slot, func, reg)			\
	((((bus) & PCIE_BUS_MASK) << PCIE_BUS_SHIFT)	|	\
	(((slot) & PCIE_SLOT_MASK) << PCIE_SLOT_SHIFT)	|	\
	(((func) & PCIE_FUNC_MASK) << PCIE_FUNC_SHIFT)	|	\
	((reg) & PCIE_REG_MASK))

static int
n1sdp_pcie_acpi_probe(device_t dev)
{
	ACPI_DEVICE_INFO *devinfo;
	ACPI_TABLE_HEADER *hdr;
	ACPI_STATUS status;
	ACPI_HANDLE h;
	int root;

	if (acpi_disabled("pcib") || (h = acpi_get_handle(dev)) == NULL ||
	    ACPI_FAILURE(AcpiGetObjectInfo(h, &devinfo)))
		return (ENXIO);
	root = (devinfo->Flags & ACPI_PCI_ROOT_BRIDGE) != 0;
	AcpiOsFree(devinfo);
	if (!root)
		return (ENXIO);

	/* TODO: Move this to an ACPI quirk? */
	status = AcpiGetTable(ACPI_SIG_MCFG, 1, &hdr);
	if (ACPI_FAILURE(status))
		return (ENXIO);

	if (memcmp(hdr->OemId, "ARMLTD", ACPI_OEM_ID_SIZE) != 0 ||
	    memcmp(hdr->OemTableId, "ARMN1SDP", ACPI_OEM_TABLE_ID_SIZE) != 0 ||
	    hdr->OemRevision != 0x20181101)
		return (ENXIO);

	device_set_desc(dev, "ARM N1SDP PCI host controller");
	return (BUS_PROBE_DEFAULT);
}

static uint32_t
n1sdp_pcie_read_config(device_t dev, u_int bus, u_int slot,
    u_int func, u_int reg, int bytes)
{
	struct generic_pcie_core_softc *sc;
	bus_space_handle_t h;
	bus_space_tag_t	t;
	uint64_t offset;
	uint32_t data;

	sc = device_get_softc(dev);
	if ((bus < sc->bus_start) || (bus > sc->bus_end))
		return (~0U);
	if ((slot > PCI_SLOTMAX) || (func > PCI_FUNCMAX) ||
	    (reg > PCIE_REGMAX))
		return (~0U);

	offset = PCIE_ADDR_OFFSET(bus - sc->bus_start, slot, func, reg);
	t = sc->bst;
	h = sc->bsh;

	data = bus_space_read_4(t, h, offset & ~3);
	switch (bytes) {
	case 1:
		data >>= offset & 3;
		break;
	case 2:
		data >>= (offset & 3) >> 1;
		data = le16toh(data);
		break;
	case 4:
		data = le32toh(data);
		break;
	default:
		return (~0U);
	}

	return (data);
}

static void
n1sdp_pcie_write_config(device_t dev, u_int bus, u_int slot,
    u_int func, u_int reg, uint32_t val, int bytes)
{
	struct generic_pcie_core_softc *sc;
	bus_space_handle_t h;
	bus_space_tag_t t;
	uint64_t offset;
	uint32_t data;

	sc = device_get_softc(dev);
	if ((bus < sc->bus_start) || (bus > sc->bus_end))
		return;
	if ((slot > PCI_SLOTMAX) || (func > PCI_FUNCMAX) ||
	    (reg > PCIE_REGMAX))
		return;

	offset = PCIE_ADDR_OFFSET(bus - sc->bus_start, slot, func, reg);

	t = sc->bst;
	h = sc->bsh;

	/*
	 * TODO: This is probably wrong on big-endian, however as arm64 is
	 * little endian it should be fine.
	 */
	switch (bytes) {
	case 1:
		data = bus_space_read_4(t, h, offset & ~3);
		data &= ~(0xff << (offset & 3));
		data |= (val & 0xff) << (offset & 3);
		bus_space_write_4(t, h, offset, htole32(data));
		break;
	case 2:
		data = bus_space_read_4(t, h, offset & ~3);
		data &= ~(0xffff << ((offset & 3) >> 1));
		data |= (val & 0xffff) << ((offset & 3) >> 1);
		bus_space_write_4(t, h, offset, htole32(data));
		break;
	case 4:
		bus_space_write_4(t, h, offset, htole32(val));
		break;
	default:
		return;
	}
}

static device_method_t n1sdp_pcie_acpi_methods[] = {
	DEVMETHOD(device_probe,		n1sdp_pcie_acpi_probe),

	/* pcib interface */
	DEVMETHOD(pcib_read_config,	n1sdp_pcie_read_config),
	DEVMETHOD(pcib_write_config,	n1sdp_pcie_write_config),

	DEVMETHOD_END
};

DEFINE_CLASS_1(pcib, n1sdp_pcie_acpi_driver, n1sdp_pcie_acpi_methods,
    sizeof(struct generic_pcie_acpi_softc), generic_pcie_acpi_driver);

static devclass_t n1sdp_pcie_acpi_devclass;

DRIVER_MODULE(n1sdp_pcib, acpi, n1sdp_pcie_acpi_driver,
    n1sdp_pcie_acpi_devclass, 0, 0);
