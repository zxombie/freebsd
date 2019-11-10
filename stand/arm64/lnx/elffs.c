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

#include <sys/disk.h>
#include <sys/elf.h>
#include "stand.h"

struct elf_file {
	uint64_t mediasize;
	uint64_t offset;
};

static int	elf_open(const char *path, struct open_file *fd);
static int	elf_close(struct open_file *fd);
static int	elf_read(struct open_file *fd, void *buf, size_t size, size_t *resid);
static off_t	elf_seek(struct open_file *fd, off_t offset, int whence);
static int	elf_stat(struct open_file *fd, struct stat *sb);
static int	elf_readdir(struct open_file *fd, struct dirent *d);

struct fs_ops elffs_fsops = {

	"elffs",
	elf_open,
	elf_close,
	elf_read,
	null_write,
	elf_seek,
	elf_stat,
	elf_readdir
};

static int
elf_open(const char *path, struct open_file *fd)
{
	char buf[512];
	Elf64_Ehdr *hdr;
	struct elf_file *f;
	size_t rsize;
	int err;

	if (strcmp(path, "/boot/kernel/kernel") != 0)
		return (ENOENT);

	f = malloc(sizeof(*f));

	err = fd->f_dev->dv_strategy(fd->f_devdata, F_READ, 0, sizeof(buf), buf,
	    &rsize);
	if (err == 0 && rsize != sizeof(buf))
		err = EIO;
	if (err != 0) {
		free(f);
		return (err);
	}

	hdr = (Elf64_Ehdr *)&buf[0];
	if (!IS_ELF(*hdr)) {
		free(f);
		return (EINVAL);
	}

	fd->f_dev->dv_ioctl(fd, DIOCGMEDIASIZE, &f->mediasize);
	f->offset = 0;
	fd->f_fsdata = (void *)f;

	return (0);
}

static int
elf_close(struct open_file *fd)
{

	free(fd->f_fsdata);
	return (0);
}

static int
elf_read(struct open_file *fd, void *buf, size_t nbyte, size_t *resid)
{
	char *b, *tmp;
	struct elf_file *f;
	size_t onbyte, rsize, rlen;
	int err;

	f = fd->f_fsdata;

	b = buf;
	onbyte = nbyte;
	err = 0;
	rlen = 0;
	while (nbyte >= 512) {
		err = fd->f_dev->dv_strategy(fd->f_devdata, F_READ,
		    f->offset / 512, 512, b, &rsize);
		if (err != 0)
			goto out;
		f->offset += rsize;
		rlen += rsize;
		nbyte -= 512;
		b += 512;
	}
	if (nbyte > 0) {
		tmp = malloc(512);
		if (tmp == NULL) {
			errno = ENOMEM;
			goto out;
		}
		err = fd->f_dev->dv_strategy(fd->f_devdata, F_READ,
		    f->offset / 512, 512, tmp, &rsize);
		if (err != 0)
			goto out;
		f->offset += rsize;
		rlen += nbyte;
		memcpy(b, tmp, nbyte);
		free(tmp);
	}

out:
	if (resid != NULL)
		*resid = onbyte - rlen;

	return (err);
}

static off_t
elf_seek(struct open_file *fd, off_t offset, int whence)
{
	struct elf_file *f;

	f = fd->f_fsdata;

	switch (whence) {
	case SEEK_SET:
		f->offset = offset;
		break;
	case SEEK_CUR:
		f->offset += offset;
		break;
	case SEEK_END:
	default:
		errno = EINVAL;
		return (-1);
	}

	return (f->offset);
}

static int
elf_stat(struct open_file *fd, struct stat *sb)
{

	sb->st_mode = S_IFREG | 0444;
	sb->st_nlink = 1;
	sb->st_uid = 0;
	sb->st_gid = 0;
	sb->st_size = 1;
	return (0);
}

static int
elf_readdir(struct open_file *fd, struct dirent *d)
{

	return (EINVAL);
}
