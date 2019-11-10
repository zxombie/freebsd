# $FreeBSD$

.include <bsd.init.mk>

HAVE_FDT=yes

LOADER?=	loader_${LOADER_INTERP}
PROG=		${LOADER}.sym
INTERNALPROG=

FILES=		${LOADER}.lnx
FILESMODE_${LOADER}.lnx=${BINMODE}

SRCS=		start.S \
		main.c \
		bootinfo.c \
		conf.c \
		devicename.c \
		elffs.c \
		exec.c \
		fdt_console.c \
		memdev.c

# Always add MI sources
.include	"${BOOTSRC}/loader.mk"
.include	"${BOOTSRC}/fdt.mk"

SRCS+=		self_reloc.c

.PATH:		${FDTSRC}
OPT_SRCS=	opt_acpi.h opt_ddb.h opt_platform.h opt_uart.h
SRCS+=		${OPT_SRCS}
SRCS+=		fdt_loader_cmd.c

.PATH:		${SYSDIR}/dev/uart
SRCS+=		uart_dev_pl011.c
CFLAGS+=	-DFDT -I${.CURDIR}

.PATH:		${SYSDIR}/arm/arm
SRCS+=		physmem.c

.PATH:		${.CURDIR}/../libarm64
CFLAGS+=	-I${.CURDIR}/../libarm64
SRCS+=		cache.c

LDFLAGS+=	-nostdlib

LDSCRIPT=	${.CURDIR}/ldscript.${MACHINE}
LDFLAGS+=	-Wl,-T${LDSCRIPT},-Bsymbolic,-znotext -shared

.if ${MACHINE_CPUARCH} == "aarch64"
CFLAGS+=	-mgeneral-regs-only
.endif

DPADD=		${LDR_INTERP} ${LIBFDT} ${LIBSA}
LDADD=		${LDR_INTERP} ${LIBFDT} ${LIBSA}

${OPT_SRCS}:
	touch ${.OBJDIR}/${.TARGET}

${LOADER}.lnx: ${PROG}
	if ${NM} ${.ALLSRC} | grep ' U '; then \
		echo "Undefined symbols in ${.ALLSRC}"; \
		exit 1; \
	fi
	SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
	${OBJCOPY} -j .peheader -j .text -j .sdata -j .data \
		-j set_Xcommand_set -j set_uart_fdt_class_and_device_set \
		-j set_uart_fdt_class_set \
		-j .dynamic -j .dynsym -j .rel.dyn \
		-j .rela.dyn -j .reloc -j .eh_frame \
		--output-target=binary ${.ALLSRC} ${.TARGET}

.include <bsd.prog.mk>
