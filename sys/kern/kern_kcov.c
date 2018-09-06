/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2018 The FreeBSD Foundation. All rights reserved.
 *
 * This software was developed by Mitchell Horne under sponsorship of
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/kcov.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <machine/cpufunc.h>

#include <vm/pmap.h>

#define BUF_SIZE_BYTES(info)						\
    (info != NULL ? (size_t)info->size * sizeof(uintptr_t) : 0)

MALLOC_DEFINE(M_KCOV_INFO, "kcovinfo", "KCOV info type");
MALLOC_DEFINE(M_KCOV_BUF, "kcovbuffer", "KCOV buffer type");

struct kcov_info {
	struct sx	lock;
	struct thread	*td;
	uintptr_t	*buf;
	u_int		size;
	int		mode;
};

/* Prototypes */
static d_open_t		kcov_open;
static d_close_t	kcov_close;
static d_mmap_t		kcov_mmap;
static d_ioctl_t	kcov_ioctl;

static void kcov_info_reset(struct kcov_info *info);
static int  kcov_alloc(struct kcov_info *info, u_int entries);
static void kcov_init(const void *unused);

static bool kcov_initialized = false;

static struct cdevsw kcov_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	kcov_open,
	.d_close =	kcov_close,
	.d_mmap =	kcov_mmap,
	.d_ioctl =	kcov_ioctl,
	.d_name =	"kcov",
};

static u_int kcov_max_entries = KCOV_MAXENTRIES;
SYSCTL_UINT(_kern, OID_AUTO, kcov_max_entries, CTLFLAG_RW,
    &kcov_max_entries, 0,
    "Maximum number of entries that can be stored in a kcov buffer");

/*
 * Main entry point. A call to this function will be inserted
 * at every edge, and if coverage is enabled for the thread
 * this function will add the PC to the buffer.
 */
void
__sanitizer_cov_trace_pc(void)
{
	struct thread *td;
	struct kcov_info *info;
	u_int index;

	/*
	 * To guarantee curthread is properly set, we exit early
	 * until the driver has been initialized
	 */
	if (!kcov_initialized)
		return;

	td = curthread;
	info = td->td_kcov_info;

	/*
	 * Check first that KCOV is enabled for the current thread.
	 * Additionally, we want to exclude (for now) all code that
	 * is not explicitly part of syscall call chain, such as
	 * interrupt handlers, since we are mainly interested in
	 * finding non-trivial paths through the syscall.
	 */
	if (info == NULL || info->buf == NULL ||
	    info->mode != KCOV_MODE_TRACE_PC ||
	    td->td_intr_nesting_level > 0 || !interrupts_enabled())
		return;

	/* The first entry of the buffer holds the index */
	index = info->buf[0];
	if (index < info->size) {
		info->buf[index + 1] =
		    (uintptr_t)__builtin_return_address(0);
		info->buf[0] = index + 1;
	}
}

static int
kcov_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct kcov_info *info;

	info = malloc(sizeof(struct kcov_info), M_KCOV_INFO,
	    M_ZERO | M_WAITOK);
	kcov_info_reset(info);
	sx_init(&info->lock, "kcov_lock");
	dev->si_drv1 = info;

	return (0);
}

static int
kcov_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct kcov_info *info;

	info = dev->si_drv1;
	if (info == NULL)
		return (EINVAL);

	if (info->td != NULL)
		info->td->td_kcov_info = NULL;
	dev->si_drv1 = NULL;
	sx_destroy(&info->lock);
	free(info->buf, M_KCOV_BUF);
	free(info, M_KCOV_INFO);

	return (0);
}

static int
kcov_mmap(struct cdev *dev, vm_ooffset_t offset, vm_paddr_t *paddr,
    int prot, vm_memattr_t *memattr __unused)
{
	struct kcov_info *info;

	if (prot & PROT_EXEC)
		return (EINVAL);

	info = dev->si_drv1;
	if (info->buf == NULL || offset < 0 || offset >= BUF_SIZE_BYTES(info))
		return (EINVAL);

	*paddr = vtophys(info->buf) + offset;
	return (0);
}

static void
kcov_info_reset(struct kcov_info *info)
{

	if (info == NULL)
		return;

	free(info->buf, M_KCOV_BUF);
	info->buf = NULL;
	info->mode = KCOV_MODE_NONE;
	info->size = 0;
}

static int
kcov_alloc(struct kcov_info *info, u_int entries)
{
	size_t buf_size;

	if (entries > kcov_max_entries)
		return (EINVAL);

	/* Align to page size so mmap can't access other kernel memory */
	buf_size = roundup2((entries + 1) * sizeof(uintptr_t), PAGE_SIZE);

	kcov_info_reset(info);
	info->buf = malloc(buf_size, M_KCOV_BUF, M_ZERO | M_WAITOK);
	info->size = entries;

	return (0);
}

static int
kcov_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag __unused,
    struct thread *td)
{
	struct kcov_info *info;
	int error;

	error = 0;
	info = dev->si_drv1;

	sx_xlock(&info->lock);
	switch (cmd) {
	case KIOSETBUFSIZE:
		/*
		 * Set the size of the coverage buffer. Should be called
		 * before enabling coverage collection for that thread.
		 */
		if (info->td != NULL) {
			error = EBUSY;
			break;
		}
		error = kcov_alloc(info, *(u_int *)data);
		break;
	case KIOENABLE:
		/* Only enable if not currently owned */
		if (info->td != NULL) {
			error = EBUSY;
			break;
		}
		info->mode = *(int *)data;
		td->td_kcov_info = info;
		info->td = td;
		break;
	case KIODISABLE:
		/* Only the currently enabled thread may disable itself */
		if (info->td != td) {
			error = EINVAL;
			break;
		}
		info->mode = KCOV_MODE_NONE;
		td->td_kcov_info = NULL;
		info->td = NULL;
		break;
	default:
		error = EINVAL;
		break;
	}
	sx_xunlock(&info->lock);

	return (error);
}

static void
kcov_init(const void *unused)
{
	struct make_dev_args args;
	struct cdev *dev;

	make_dev_args_init(&args);
	args.mda_devsw = &kcov_cdevsw;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0660;
	if (make_dev_s(&args, &dev, "kcov") != 0) {
		printf("%s", "Failed to create kcov device");
		return;
	}

	kcov_initialized = true;
}

/*
 * thread_exit() hook
 */
void
kcov_thread_exit(struct thread *td)
{

	if (td->td_kcov_info != NULL) {
		td->td_kcov_info->td = NULL;
		td->td_kcov_info = NULL;
	}
}

SYSINIT(kcovdev, SI_SUB_DEVFS, SI_ORDER_ANY, kcov_init, NULL);
