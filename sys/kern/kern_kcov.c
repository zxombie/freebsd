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
	uint64_t	*buf;
	size_t		size;
	kcov_state_t	state;
	int		mode;
};

/* Prototypes */
static d_open_t		kcov_open;
static d_close_t	kcov_close;
static d_mmap_t		kcov_mmap;
static d_ioctl_t	kcov_ioctl;

void __sanitizer_cov_trace_pc(void);
void __sanitizer_cov_trace_cmp1(uint8_t, uint8_t);
void __sanitizer_cov_trace_cmp2(uint16_t, uint16_t);
void __sanitizer_cov_trace_cmp4(uint32_t, uint32_t);
void __sanitizer_cov_trace_cmp8(uint64_t, uint64_t);
void __sanitizer_cov_trace_const_cmp1(uint8_t, uint8_t);
void __sanitizer_cov_trace_const_cmp2(uint16_t, uint16_t);
void __sanitizer_cov_trace_const_cmp4(uint32_t, uint32_t);
void __sanitizer_cov_trace_const_cmp8(uint64_t, uint64_t);
void __sanitizer_cov_trace_switch(uint64_t, uint64_t *);

static int  kcov_alloc(struct kcov_info *info, size_t size);
static void kcov_init(const void *unused);

static struct cdevsw kcov_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	kcov_open,
	.d_close =	kcov_close,
	.d_mmap =	kcov_mmap,
	.d_ioctl =	kcov_ioctl,
	.d_name =	"kcov",
};

SYSCTL_NODE(_kern, OID_AUTO, kcov, CTLFLAG_RW, 0, "Kernel coverage");

static u_int kcov_max_size = KCOV_MAXENTRIES;
SYSCTL_UINT(_kern_kcov, OID_AUTO, max_size, CTLFLAG_RW,
    &kcov_max_size, 0,
    "Maximum size of the kcov buffer");

static struct mtx kcov_mtx;

static struct kcov_info *
get_kinfo(struct thread *td)
{
	struct kcov_info *info;

	/* We might have a NULL thread when releasing the secondary CPUs */
	if (td == NULL)
		return (NULL);

	/*
	 * We are in an interrupt, stop tracing as it is not explicitly
	 * part of a syscall.
	 */
	if (td->td_intr_nesting_level > 0 || td->td_intr_frame != NULL)
		return (NULL);

	/*
	 * If info is NULL or the state is not running we are not tracing.
	 */
	info = td->td_kcov_info;
	if (info == NULL || info->state != KCOV_STATE_RUNNING)
		return (NULL);

	return (info);
}

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
	uint64_t index;

	/*
	 * To guarantee curthread is properly set, we exit early
	 * until the driver has been initialized
	 */
	if (cold)
		return;

	td = curthread;
	info = get_kinfo(td);
	if (info == NULL)
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
	if (index + 2 >= info->size / sizeof(info->buf[0]))
		return;

	info->buf[index + 1] = (uint64_t)__builtin_return_address(0);
	info->buf[0] = index + 1;
}

static bool
trace_cmp(uint64_t type, uint64_t arg1, uint64_t arg2, uint64_t ret)
{
	struct thread *td;
	struct kcov_info *info;
	uint64_t index;

	/*
	 * To guarantee curthread is properly set, we exit early
	 * until the driver has been initialized
	 */
	if (cold)
		return (false);

	td = curthread;
	info = get_kinfo(td);
	if (info == NULL)
		return (false);

	/*
	 * Check we are in the comparison-trace mode.
	 */
	if (info->mode != KCOV_MODE_TRACE_CMP)
		return (false);

	KASSERT(info->buf != NULL,
	    ("__sanitizer_cov_trace_pc: NULL buf while running"));

	/* The first entry of the buffer holds the index */
	index = info->buf[0];

	/* Check we have space to store all elements */
	if (index * 4 + 5 >= info->size / sizeof(info->buf[0]))
		return (false);

	info->buf[index * 4 + 1] = type;
	info->buf[index * 4 + 2] = arg1;
	info->buf[index * 4 + 3] = arg2;
	info->buf[index * 4 + 4] = ret;
	info->buf[0] = index + 1;

	return (true);
}

void
__sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(0), arg1, arg2,
	    (uint64_t)__builtin_return_address(0));
}

void
__sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(1), arg1, arg2,
	    (uint64_t)__builtin_return_address(0));
}

void
__sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(2), arg1, arg2,
	    (uint64_t)__builtin_return_address(0));
}

void
__sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(3), arg1, arg2,
	    (uint64_t)__builtin_return_address(0));
}

void
__sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(0) | KCOV_CMP_CONST, arg1, arg2,
	    (uint64_t)__builtin_return_address(0));
}

void
__sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(1) | KCOV_CMP_CONST, arg1, arg2,
	    (uint64_t)__builtin_return_address(0));
}

void
__sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(2) | KCOV_CMP_CONST, arg1, arg2,
	    (uint64_t)__builtin_return_address(0));
}

void
__sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2)
{

	trace_cmp(KCOV_CMP_SIZE(3) | KCOV_CMP_CONST, arg1, arg2,
	    (uint64_t)__builtin_return_address(0));
}

/*
 * val is the switch operand
 * cases[0] is the number of case constants
 * cases[1] is the size of val in bits
 * cases[2..n] are the case constants
 */
void
__sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases)
{
	uint64_t i, count, ret, type;

	count = cases[0];
	ret = (uint64_t)__builtin_return_address(0);

	switch (cases[1]) {
	case 8:
		type = KCOV_CMP_SIZE(3);
		break;
	case 16:
		type = KCOV_CMP_SIZE(3);
		break;
	case 32:
		type = KCOV_CMP_SIZE(3);
		break;
	case 64:
		type = KCOV_CMP_SIZE(3);
		break;
	default:
		return;
	}

	val |= KCOV_CMP_CONST;

	for (i = 0; i < count; i++)
		if (!trace_cmp(type, val, cases[i + 2], ret))
			return;
}

static int
kcov_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct kcov_info *info;

	/*
	 * TODO: We could use devfs_set_cdevpriv, but it needs care around
	 * mmap. For now only allow a single user to open the device at a
	 * time.
	 */
	info = malloc(sizeof(struct kcov_info), M_KCOV_INFO, M_ZERO | M_WAITOK);
	info->state = KCOV_STATE_OPEN;
	info->mode = -1;

	mtx_lock(&kcov_mtx);
	if (dev->si_drv1 != NULL) {
		mtx_unlock(&kcov_mtx);
		free(info, M_KCOV_INFO);
		return (EBUSY);
	}

	dev->si_drv1 = info;
	mtx_unlock(&kcov_mtx);

	return (0);
}

static int
kcov_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	struct kcov_info *info;

	info = dev->si_drv1;

	KASSERT(info != NULL, ("kcov_close with no kcov_info structure"));

	/* Trying to close, but haven't disabled */
	if (info->state == KCOV_STATE_RUNNING)
		return (EBUSY);

	dev->si_drv1 = NULL;
	atomic_thread_fence_seq_cst();

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

	if (info->buf == NULL || offset < 0 || offset >= info->size)
		return (EINVAL);

	*paddr = vtophys(info->buf) + offset;
	return (0);
}

static int
kcov_alloc(struct kcov_info *info, size_t size)
{
	size_t buf_size;

	KASSERT(info->buf == NULL, ("kcov_alloc: Already have a buffer"));
	KASSERT(info->state == KCOV_STATE_OPEN,
	    ("kcov_alloc: Not in open state (%x)", info->state));

	if (size < 2 * sizeof(info->buf[0]) || size > kcov_max_size)
		return (EINVAL);

	/* Align to page size so mmap can't access other kernel memory */
	buf_size = roundup2(size, PAGE_SIZE);

	info->buf = malloc(buf_size, M_KCOV_BUF, M_ZERO | M_WAITOK);
	info->size = size;

	return (0);
}

static int
kcov_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag __unused,
    struct thread *td)
{
	struct kcov_info *info;
	int mode, error;

	info = dev->si_drv1;

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
		if (mode != KCOV_MODE_TRACE_PC && mode != KCOV_MODE_TRACE_CMP) {
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

	mtx_init(&kcov_mtx, "kcov", NULL, MTX_DEF);

	make_dev_args_init(&args);
	args.mda_devsw = &kcov_cdevsw;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0600;
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
