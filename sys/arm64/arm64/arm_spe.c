/*-
 * Copyright (c) 2022 The FreeBSD Foundation
 *
 * This software was developed by Andrew Turner under sponsorship from
 * the FreeBSD Foundation.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rman.h>
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include "arm_spe.h"

/*
  PSB CSYNC is a Profiling Synchronization Barrier encoded in the hint space
 * so it is a NOP on earlier architecture.
 */
#define	psb_csync()	__asm __volatile("hint #17" ::: "memory");

static device_attach_t arm_spe_attach;
static int arm_spe_intr(void *);

static void arm_spe_stop(void);

static struct cdevsw arm_spe_cdevsw;

static device_method_t arm_spe_methods[] = {
	/* Device interface */
	DEVMETHOD(device_attach,	arm_spe_attach),

	DEVMETHOD_END,
};

DEFINE_CLASS_0(spe, arm_spe_driver, arm_spe_methods,
    sizeof(struct arm_spe_softc));

static int
arm_spe_attach(device_t dev)
{
	struct make_dev_args args;
	struct arm_spe_softc *sc;
	int error, rid;

	sc = device_get_softc(dev);

	rid = 0;
	sc->sc_irq_res = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
	    RF_ACTIVE);
	if (sc->sc_irq_res == NULL) {
		device_printf(dev, "Unable to allocate interrupt\n");
		return (ENXIO);
	}
	error = bus_setup_intr(dev, sc->sc_irq_res,
	    INTR_TYPE_MISC | INTR_MPSAFE, arm_spe_intr, NULL, sc,
	    &sc->sc_irq_cookie);
	if (error != 0) {
		device_printf(dev, "Inable to set up interrupt\n");
		return (error);
	}

	device_printf(dev, "PMBIDR_EL1: %lx\n", READ_SPECIALREG_M(PMBIDR_EL1));
	device_printf(dev, "PMSIDR_EL1: %lx\n", READ_SPECIALREG_M(PMSIDR_EL1));

	mtx_init(&sc->sc_lock, "Arm SPE lock", NULL, MTX_SPIN);

	make_dev_args_init(&args);
	args.mda_devsw = &arm_spe_cdevsw;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0600;
	args.mda_si_drv1 = sc;
	error = make_dev_s(&args, &sc->sc_cdev, "spe%d",
	    device_get_unit(dev));
	if (error != 0) {
		device_printf(dev, "Failed to create spe device");
		return (error);
	}

	sc->sc_pmsidr = READ_SPECIALREG_M(PMSIDR_EL1);

	return (0);
}

static uint64_t
arm_spe_min_interval(struct arm_spe_softc *sc)
{
	/*
	 *  TODO: This is the worst case, add more based on PMSIDR_EL1.Interval
	 */
	return (4096);
}

static int
arm_spe_intr(void *arg)
{
	/* Make sure the profiling data is visible to the CPU */
	psb_csync();
	dsb(nsh);

	/* Make sure any HW update of PMBPTR_EL1 is visible to the CPU */
	isb();

	arm_spe_stop();

	return (FILTER_HANDLED);
}

/*
 * SPE device file
 */

MALLOC_DEFINE(M_ARM_SPE, "armspe", "Arm SPE tracing");

struct arm_spe_info {
	struct arm_spe_softc	*softc;
	struct thread		*thread;
	vm_object_t		 bufobj;
	vm_offset_t		 kvaddr;
	size_t			 bufsize;

	uint64_t		 pmsfcr;
	uint64_t		 pmsevfr;
	uint64_t		 pmslatefr;
	uint64_t		 pmsirr;
	uint64_t		 pmsicr;
	uint64_t		 pmscr;
};

static d_open_t		arm_spe_open;
static d_close_t	arm_spe_close;
static d_mmap_single_t	arm_spe_mmap_single;
static d_priv_dtor_t	arm_spe_mmap_cleanup;
static d_ioctl_t	arm_spe_ioctl;

static struct cdevsw arm_spe_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	arm_spe_open,
	.d_close =	arm_spe_close,
	.d_mmap_single = arm_spe_mmap_single,
	.d_ioctl =	arm_spe_ioctl,
	.d_name =	"spe",
};

static int
arm_spe_alloc(struct arm_spe_info *info, size_t npages)
{
	size_t n;
	vm_page_t m;

	info->bufsize = npages * PAGE_SIZE;

	if ((info->kvaddr = kva_alloc(info->bufsize)) == 0)
		return (ENOMEM);

	info->bufobj = vm_pager_allocate(OBJT_PHYS, 0, info->bufsize,
	    PROT_READ | PROT_WRITE, 0, curthread->td_ucred);

	VM_OBJECT_WLOCK(info->bufobj);
	for (n = 0; n < npages; n++) {
		m = vm_page_grab(info->bufobj, n,
		    VM_ALLOC_ZERO | VM_ALLOC_WIRED);
		vm_page_valid(m);
		vm_page_xunbusy(m);
		pmap_qenter(info->kvaddr + n * PAGE_SIZE, &m, 1);
	}
	VM_OBJECT_WUNLOCK(info->bufobj);

	/* Set defaults */
	info->pmsfcr = 0;
	info->pmsevfr = 0xfffffffffffffffful;
	info->pmslatefr = 0;
	info->pmsirr =
	    (arm_spe_min_interval(info->softc) << PMSIRR_INTERVAL_SHIFT) |
	    PMSIRR_RND;
	info->pmsicr = 0;
	info->pmscr = PMSCR_TS | PMSCR_PA | PMSCR_CX | PMSCR_E1SPE |
	    PMSCR_E0SPE;

	return (0);
}

static void
arm_spe_free(struct arm_spe_info *info)
{
	vm_page_t m;
	size_t i;

	if (info->kvaddr != 0) {
		pmap_qremove(info->kvaddr, info->bufsize / PAGE_SIZE);
		kva_free(info->kvaddr, info->bufsize);
	}
	if (info->bufobj != NULL) {
		VM_OBJECT_WLOCK(info->bufobj);
		m = vm_page_lookup(info->bufobj, 0);
		for (i = 0; i < info->bufsize / PAGE_SIZE; i++) {
			vm_page_unwire_noq(m);
			m = vm_page_next(m);
		}
		VM_OBJECT_WUNLOCK(info->bufobj);
		vm_object_deallocate(info->bufobj);
	}
	free(info, M_ARM_SPE);
}

static void
arm_spe_start(struct arm_spe_info *info)
{
	uint64_t base, limit;

	WRITE_SPECIALREG_M(PMSFCR_EL1, info->pmsfcr);
	WRITE_SPECIALREG_M(PMSEVFR_EL1, info->pmsevfr);
	WRITE_SPECIALREG_M(PMSLATFR_EL1, info->pmslatefr);

	WRITE_SPECIALREG_M(PMSIRR_EL1, info->pmsirr);
	isb();

	/* Set the sampling interval */
	WRITE_SPECIALREG_M(PMSICR_EL1, info->pmsicr);
	isb();

	WRITE_SPECIALREG_M(PMSCR_EL1, info->pmscr);
	isb();

	base = info->kvaddr;
	limit = base + info->bufsize;
	limit |= PMBLIMITR_E;
	/* Set the base and limit */
	WRITE_SPECIALREG_M(PMBPTR_EL1, base);
	WRITE_SPECIALREG_M(PMBLIMITR_EL1, limit);
}

static void
arm_spe_stop(void)
{
	/* Disable profiling in userspace and the kernel */
	WRITE_SPECIALREG_M(PMSCR_EL1, 0x0);
	isb();

	/* Drain any remaining tracing data */
	psb_csync();
	dsb(nsh);

	/* Disable the profiling buffer */
	WRITE_SPECIALREG_M(PMBLIMITR_EL1, 0);
	isb();

	WRITE_SPECIALREG_M(PMBSR_EL1, 0x0);
}

static int
arm_spe_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct arm_spe_softc *sc;
	struct arm_spe_info *info;
	int error;

	sc = dev->si_drv1;
	info = malloc(sizeof(struct arm_spe_info), M_ARM_SPE,
	    M_ZERO | M_WAITOK);
	info->thread = td;
	info->softc = sc;

	if ((error = devfs_set_cdevpriv(info, arm_spe_mmap_cleanup)) != 0)
		arm_spe_mmap_cleanup(info);

	return (error);
}

static int
arm_spe_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct arm_spe_info *info;
	int error;

	if ((error = devfs_get_cdevpriv((void **)&info)) != 0)
		return (error);

	KASSERT(info != NULL,
	    ("arm_spe_close with no arm_spe_info structure"));

	return (0);
}

#define	SPE_ENABLE		_IO('S', 1)
#define	SPE_DISABLE		_IO('S', 2)
#define	SPE_SETBUFSIZ		_IOWINT('S', 3)

#define	SPE_GET_PMSFCR		_IOR('S', 4, uint64_t)
#define	SPE_SET_PMSFCR		_IOW('S', 5, uint64_t)

#define	SPE_GET_PMSEVFR		_IOR('S', 6, uint64_t)
#define	SPE_SET_PMSEVFR		_IOW('S', 7, uint64_t)

#define	SPE_GET_PMSLATEFR	_IOR('S', 8, uint64_t)
#define	SPE_SET_PMSLATEFR	_IOW('S', 9, uint64_t)

#define	SPE_GET_PMSIRR		_IOR('S', 10, uint64_t)
#define	SPE_SET_PMSIRR		_IOW('S', 11, uint64_t)

#define	SPE_GET_PMSICR		_IOR('S', 12, uint64_t)
#define	SPE_SET_PMSICR		_IOW('S', 13, uint64_t)

#define	SPE_GET_PMSCR		_IOR('S', 14, uint64_t)
#define	SPE_SET_PMSCR		_IOW('S', 15, uint64_t)

static int
arm_spe_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag __unused,
    struct thread *td)
{
	struct arm_spe_info *info;
	int error;

	if ((error = devfs_get_cdevpriv((void **)&info)) != 0)
		return (error);

	switch(cmd) {
	case SPE_SETBUFSIZ:
		error = arm_spe_alloc(info, *(u_int *)data);
		return (error);
	case SPE_ENABLE:
		arm_spe_start(info);
		return (0);
	case SPE_DISABLE:
		arm_spe_stop();
		return (0);

	case SPE_GET_PMSFCR:
		*(uint64_t *)data = info->pmsfcr;
		return (0);
	case SPE_SET_PMSFCR:
		info->pmsfcr = *(uint64_t *)data;
		return (0);

	case SPE_GET_PMSEVFR:
		*(uint64_t *)data = info->pmsevfr;
		return (0);
	case SPE_SET_PMSEVFR:
		info->pmsevfr = *(uint64_t *)data;
		return (0);

	case SPE_GET_PMSLATEFR:
		*(uint64_t *)data = info->pmslatefr;
		return (0);
	case SPE_SET_PMSLATEFR:
		info->pmslatefr = *(uint64_t *)data;
		return (0);

	case SPE_GET_PMSIRR:
		*(uint64_t *)data = info->pmsirr;
		return (0);
	case SPE_SET_PMSIRR:
		info->pmsirr = *(uint64_t *)data;
		return (0);

	case SPE_GET_PMSICR:
		*(uint64_t *)data = info->pmsicr;
		return (0);
	case SPE_SET_PMSICR:
		info->pmsicr = *(uint64_t *)data;
		return (0);

	case SPE_GET_PMSCR:
		*(uint64_t *)data = info->pmscr;
		return (0);
	case SPE_SET_PMSCR:
		info->pmscr = *(uint64_t *)data;
		return (0);

	default:
		return (EINVAL);
	}
}

static int
arm_spe_mmap_single(struct cdev *dev, vm_ooffset_t *offset, vm_size_t size,
    struct vm_object **object, int nprot)
{
	struct arm_spe_info *info;
	int error;

	if ((nprot & (PROT_EXEC | PROT_READ | PROT_WRITE)) !=
	    (PROT_READ | PROT_WRITE))
		return (EINVAL);

	if ((error = devfs_get_cdevpriv((void **)&info)) != 0)
		return (error);

	if (info->kvaddr == 0 || size != info->bufsize)
		return (EINVAL);

	vm_object_reference(info->bufobj);
	*offset = 0;
	*object = info->bufobj;
	return (0);
}

static void
arm_spe_mmap_cleanup(void *arg)
{
	struct arm_spe_info *info = arg;

	arm_spe_free(info);
}
