PACKAGE=lib${LIB}
LIB=	vmmapi
SHLIB_MAJOR=	6
SRCS=	vmmapi.c
INCS=	vmmapi.h

CFLAGS+= -I${.CURDIR}
CFLAGS+=-DPAGE_SIZE_HACK

.PATH:	${.CURDIR}/${MACHINE_CPUARCH}

.include "${MACHINE_CPUARCH}/Makefile.inc"

LIBADD=	util

.include <bsd.lib.mk>
