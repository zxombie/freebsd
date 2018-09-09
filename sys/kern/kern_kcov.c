/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2018 The FreeBSD Foundation. All rights reserved.
 * Copyright (C) 2018 Andrew Turner
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

MALLOC_DEFINE(M_KCOV_INFO, "kcovinfo", "KCOV info type");
MALLOC_DEFINE(M_KCOV_BUF, "kcovbuffer", "KCOV buffer type");

/*
 * - Only move away from the running state in the current thread. This is to
 *   ensure we are not currently recording a trace while this happens.
 * - There need to be barriers before moving to the running state and after
 *   leaving it. This ensures a consistent state if an interrupt happens
 *   when enabling or disabling.
 */

typedef enum {
	KCOV_STATE_INVALID,
	KCOV_STATE_OPEN,	/* The device is open, but with no buffer */
	KCOV_STATE_READY,	/* The buffer has been allocated */
	KCOV_STATE_RUNNING,	/* Recording trace data */
} kcov_state_t;

struct kcov_info {
	uintptr_t	*buf;
	size_t		entries;
	kcov_state_t	state;
	int		mode;
};

/* Prototypes */
static d_open_t		kcov_open;
static d_close_t	kcov_close;
static d_mmap_t		kcov_mmap;
static d_ioctl_t	kcov_ioctl;

static int  kcov_alloc(struct kcov_info *info, u_int entries);
static void kcov_init(const void *unused);

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
	if (cold)
		return;

	td = curthread;

	/* We might have a NULL thread when releasing the secondary CPUs */
	if (td == NULL)
		return;

	/*
	 * We are in an interrupt, stop tracing as it is not explicitly
	 * part of a syscall.
	 */
	if (td->td_intr_nesting_level > 0 || td->td_intr_frame != NULL)
		return;

	/*
	 * If info is NULL or the state is not running we are not tracing.
	 */
	info = td->td_kcov_info;
	if (info == NULL || info->state != KCOV_STATE_RUNNING)
		return;

	/*
	 * Check we are in the PC-trace mode.
	 */
	if (info->mode != KCOV_MODE_TRACE_PC)
		return;

	KASSERT(info->buf != NULL,
	    ("__sanitizer_cov_trace_pc: NULL buf while running"));

	/* The first entry of the buffer holds the index */
	index = info->buf[0];
	if (index < info->entries) {
		info->buf[index + 1] =
		    (uintptr_t)__builtin_return_address(0);
		info->buf[0] = index + 1;
	}
}

static void
kcov_dtor(void *data __unused)
{
}

static int
kcov_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct kcov_info *info;
	int error;

	info = malloc(sizeof(struct kcov_info), M_KCOV_INFO, M_ZERO | M_WAITOK);

	error = devfs_set_cdevpriv(info, kcov_dtor);
	if (error == 0) {
		info->state = KCOV_STATE_OPEN;
		info->mode = -1;
	} else {
		free(info, M_KCOV_INFO);
	}

	return (error);
}

static int
kcov_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct kcov_info *info;
	int error;

	error = devfs_get_cdevpriv((void **)&info);
	if (error)
		return (error);

	KASSERT(info != NULL, ("kcov_close with no kcov_info structure"));

	/* Trying to close, but haven't disabled */
	if (info->state == KCOV_STATE_RUNNING)
		return (EBUSY);

	free(info->buf, M_KCOV_BUF);
	free(info, M_KCOV_INFO);

	return (0);
}

static int
kcov_mmap(struct cdev *dev, vm_ooffset_t offset, vm_paddr_t *paddr,
    int prot, vm_memattr_t *memattr __unused)
{
	struct kcov_info *info;
	int error;

	if (prot & PROT_EXEC)
		return (EINVAL);

	error = devfs_get_cdevpriv((void **)&info);
	if (error)
		return (error);

	if (info->buf == NULL || offset < 0 ||
	    offset >= info->entries * sizeof(uintptr_t))
		return (EINVAL);

	*paddr = vtophys(info->buf) + offset;
	return (0);
}

static int
kcov_alloc(struct kcov_info *info, u_int entries)
{
	size_t buf_size;

	KASSERT(info->buf == NULL, ("kcov_alloc: Already have a buffer"));
	KASSERT(info->state == KCOV_STATE_OPEN,
	    ("kcov_alloc: Not in open state (%x)", info->state));

	if (entries < 2 || entries > kcov_max_entries)
		return (EINVAL);

	/* Align to page size so mmap can't access other kernel memory */
	buf_size = roundup2(entries * sizeof(uintptr_t), PAGE_SIZE);

	info->buf = malloc(buf_size, M_KCOV_BUF, M_ZERO | M_WAITOK);
	info->entries = entries;

	return (0);
}

static int
kcov_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag __unused,
    struct thread *td)
{
	struct kcov_info *info;
	int mode, error;

	error = devfs_get_cdevpriv((void **)&info);
	if (error)
		return (error);

	error = 0;

	switch (cmd) {
	case KIOSETBUFSIZE:
		/*
		 * Set the size of the coverage buffer. Should be called
		 * before enabling coverage collection for that thread.
		 */
		if (info->state != KCOV_STATE_OPEN) {
			error = EBUSY;
			break;
		}
		error = kcov_alloc(info, *(u_int *)data);
		info->state = KCOV_STATE_READY;
		break;
	case KIOENABLE:
		if (info->state != KCOV_STATE_READY) {
			error = EBUSY;
			break;
		}
		if (td->td_kcov_info != NULL) {
			error = EINVAL;
			break;
		}
		mode = *(int *)data;
		if (mode != KCOV_MODE_TRACE_PC) {
			error = EINVAL;
			break;
		}
		td->td_kcov_info = info;
		info->mode = mode;
		/*
		 * Atomically store the pointer to the info struct to protect
		 * against an interrupt happening at the wrong time.
		 */
		atomic_thread_fence_seq_cst();
		info->state = KCOV_STATE_RUNNING;
		break;
	case KIODISABLE:
		/* Only the currently enabled thread may disable itself */
		if (info->state != KCOV_STATE_RUNNING ||
		    info != td->td_kcov_info) {
			error = EINVAL;
			break;
		}
		info->state = KCOV_STATE_READY;
		atomic_thread_fence_seq_cst();
		td->td_kcov_info = NULL;
		break;
	default:
		error = EINVAL;
		break;
	}

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
}

/*
 * thread_exit() hook
 */
void
kcov_thread_exit(struct thread *td)
{
#if 0
	struct kcov_info *info;

	if (td->td_kcov_info != NULL) {
		info = td->td_kcov_info;
		/* TODO */
	}
#endif
}

SYSINIT(kcovdev, SI_SUB_DEVFS, SI_ORDER_ANY, kcov_init, NULL);
