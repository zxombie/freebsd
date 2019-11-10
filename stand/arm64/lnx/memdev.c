/*-
 * Copyright (c) 2009 Marcel Moolenaar
 * All rights reserved.
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

#include <stand.h>
#include <sys/param.h>
#include <sys/disk.h>
#include <sys/endian.h>
#include <sys/queue.h>
#include <machine/stdarg.h>

#include "bootstrap.h"

#include <libfdt.h>
#include <fdt.h>
#include <fdt_platform.h>

#define	MD_BLOCK_SIZE	512

static struct fdt_header *fdtp;

/*
 * Preloaded image gets put here.
 * Applications that patch the object with the image can determine
 * the size looking at the start and end markers (strings),
 * so we want them contiguous.
 */
static struct {
	void *start;
	void *end;
} md_image;

/* devsw I/F */
static int md_init(void);
static int md_strategy(void *, int, daddr_t, size_t, char *, size_t *);
static int md_open(struct open_file *, ...);
static int md_close(struct open_file *);
static int md_ioctl(struct open_file *, u_long, void *);
static int md_print(int);

struct devsw memdisk_dev = {
	.dv_name = "md",
	.dv_type = DEVT_DISK,
	.dv_init = md_init,
	.dv_strategy = md_strategy,
	.dv_open = md_open,
	.dv_close = md_close,
	.dv_ioctl = md_ioctl,
	.dv_print = md_print,
	.dv_cleanup = NULL
};

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

static int
md_init(void)
{
	int offset;

	fdtp = fdt_get();
	if (fdtp == NULL)
		return (EINVAL);

	offset = fdt_path_offset(fdtp, "/chosen");
	if (offset < 0)
		return (EINVAL);

	md_image.start = (void *)fdt_read_prop(fdtp, offset,
	    "linux,initrd-start");
	md_image.end = (void *)fdt_read_prop(fdtp, offset,
	    "linux,initrd-end");

	return (0);
}

static int
md_strategy(void *devdata, int rw, daddr_t blk, size_t size,
    char *buf, size_t *rsize)
{
	struct devdesc *dev = (struct devdesc *)devdata;
	size_t ofs, memsz;

	if (dev->d_unit != 0)
		return (ENXIO);

	memsz = md_image.end - md_image.start;
	if (blk < 0 || blk >= howmany(memsz, MD_BLOCK_SIZE))
		return (EIO);

	if (size % MD_BLOCK_SIZE)
		return (EIO);

	ofs = blk * MD_BLOCK_SIZE;
	if ((ofs + size) > roundup2(memsz, MD_BLOCK_SIZE))
		size = roundup2(memsz, MD_BLOCK_SIZE) - ofs;

	if (rsize != NULL)
		*rsize = size;

	switch (rw & F_MASK) {
	case F_READ:
		if ((ofs + size) <= memsz) {
			bcopy(md_image.start + ofs, buf, size);
		} else {
			memset(buf, 0, size);
			bcopy(md_image.start + ofs, buf, memsz - ofs);
		}
		return (0);
	case F_WRITE:
		if ((ofs + size) <= memsz)
			bcopy(buf, md_image.start + ofs, size);
		else
			bcopy(buf, md_image.start + ofs, memsz - ofs);
		return (0);
	}

	return (ENODEV);
}

static int
md_open(struct open_file *f, ...)
{
	va_list ap;
	struct devdesc *dev;

	va_start(ap, f);
	dev = va_arg(ap, struct devdesc *);
	va_end(ap);

	if (dev->d_unit != 0)
		return (ENXIO);

	return (0);
}

static int
md_close(struct open_file *f)
{
	struct devdesc *dev;

	dev = (struct devdesc *)(f->f_devdata);
	return ((dev->d_unit != 0) ? ENXIO : 0);
}

static int
md_ioctl(struct open_file *f, u_long cmd, void *data)
{

	switch (cmd) {
	default:
		return (EINVAL);
	case DIOCGSECTORSIZE:
		*(u_int *)data = MD_BLOCK_SIZE;
		return (0);
	case DIOCGMEDIASIZE:
		*(uint64_t *)data = roundup2(md_image.end - md_image.start,
		    MD_BLOCK_SIZE);
		return (0);
	}
}

static int
md_print(int verbose)
{

	printf("%s devices:", memdisk_dev.dv_name);
	if (pager_output("\n") != 0)
		return (1);

	printf("MD (%lu bytes)", md_image.end - md_image.start);
	return (pager_output("\n"));
}
