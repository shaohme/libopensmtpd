LIB=		opensmtpd

LOCALBASE?=	/usr

SRCS=		opensmtpd.c iobuf.c ioev.c
HDRS=		opensmtpd.h
MAN=		osmtpd_run.3
LIBDIR?=	${LOCALBASE}/lib/
MANDIR?=	${LOCALBASE}/share/man/man3
LDLIBS+=	-levent

mkfile_path := ${abspath ${lastword ${MAKEFILE_LIST}}}
CURDIR := ${dir ${mkfile_path}}

CFLAGS+=	-I${CURDIR} -I${CURDIR}/openbsd-compat/
CFLAGS+=	-Wall
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare

CLEANFILES= ${VERSION_SCRIPT}

VERSION_SCRIPT=	Symbols.map
SYMBOL_LIST=	${CURDIR}/Symbols.list

includes:
	@cd ${CURDIR}; for i in ${HDRS}; do \
	    j="cmp -s $$i ${DESTDIR}${LOCALBASE}/include/$$i || \
	    ${INSTALL} -D -o ${BINOWN} -g ${BINGRP} -m 444 $$i\
		${DESTDIR}${LOCALBASE}/include/$$i"; \
	    echo $$j; \
	    eval "$$j"; \
	done;

${VERSION_SCRIPT}: ${SYMBOL_LIST}
	{ printf '{\n\tglobal:\n'; \
	  sed '/^[._a-zA-Z]/s/$$/;/; s/^/		/' ${SYMBOL_LIST}; \
	  printf '\n\tlocal:\n\t\t*;\n};\n'; } >$@.tmp && mv $@.tmp $@

# Defines for OpenBSD-specific interfaces
# Add a OS-specific defines here.
NEED_EXPLICIT_BZERO?=	0
NEED_RECALLOCARRAY?=	1
NEED_REALLOCARRAY?=	0
NEED_STRLCAT?=		1
NEED_STRLCPY?=		1
NEED_STRTONUM?=		1

MANFORMAT?=		mangz

INSTALL?=	install
LINK?=		ln

BINOWN?=	root
BINGRP?=	root
LIBPERM?=	755
MANOWN?=	root
MANGRP?=	root
MANPERM?=	644

include ${CURDIR}/shlib_version
BASE_LIB=lib${LIB}.so
TARGET_LIB=lib${LIB}.so.${major}.${minor}.0
SONAME_LIB=lib${LIB}.so.${major}

CFLAGS+=	-fPIC
LDFLAGS+=	-shared -Wl,-soname=${SONAME_LIB}

ifeq (${MANFORMAT}, mangz)
TARGET_MAN=		${MAN}.gz
CLEANFILES+=		${TARGET_MAN}
${TARGET_MAN}: ${MAN}
	mandoc -Tman ${MAN} | gzip > $@
else
TARGET_MAN=		${MAN}
endif

${SRCS:.c=.d}:%.d:%.c
	 ${CC} ${CFLAGS} -MM $< >$@

ifeq (${NEED_EXPLICIT_BZERO}, 1)
SRCS+=		${CURDIR}/openbsd-compat/explicit_bzero.c
CFLAGS+=	-DNEED_EXPLICIT_BZERO=1

explicit_bzero.o: ${CURDIR}/openbsd-compat/explicit_bzero.c
	${CC} ${CFLAGS} -c -o explicit_bzero.o ${CURDIR}/openbsd-compat/explicit_bzero.c
endif
ifeq (${NEED_RECALLOCARRAY}, 1)
SRCS+=		${CURDIR}/openbsd-compat/recallocarray.c
CFLAGS+=	-DNEED_RECALLOCARRAY=1

recallocarray.o: ${CURDIR}/openbsd-compat/recallocarray.c
	${CC} ${CFLAGS} -c -o recallocarray.o ${CURDIR}/openbsd-compat/recallocarray.c
endif
ifeq (${NEED_REALLOCARRAY}, 1)
SRCS+=		${CURDIR}/openbsd-compat/reallocarray.c
CFLAGS+=	-DNEED_REALLOCARRAY=1

reallocarray.o: ${CURDIR}/openbsd-compat/reallocarray.c
	${CC} ${CFLAGS} -c -o reallocarray.o ${CURDIR}/openbsd-compat/reallocarray.c
endif
ifeq (${NEED_STRLCAT}, 1)
SRCS+=		${CURDIR}/openbsd-compat/strlcat.c
CFLAGS+=	-DNEED_STRLCAT=1

strlcat.o: ${CURDIR}/openbsd-compat/strlcat.c
	${CC} ${CFLAGS} -c -o strlcat.o ${CURDIR}/openbsd-compat/strlcat.c
endif
ifeq (${NEED_STRLCPY}, 1)
SRCS+=		${CURDIR}/openbsd-compat/strlcpy.c
CFLAGS+=	-DNEED_STRLCPY=1

strlcpy.o: ${CURDIR}/openbsd-compat/strlcpy.c
	${CC} ${CFLAGS} -c -o strlcpy.o ${CURDIR}/openbsd-compat/strlcpy.c
endif
ifeq (${NEED_STRTONUM}, 1)
SRCS+=		${CURDIR}/openbsd-compat/strtonum.c
CFLAGS+=	-DNEED_STRTONUM=1

strtonum.o: ${CURDIR}/openbsd-compat/strtonum.c
	${CC} ${CFLAGS} -c -o strtonum.o ${CURDIR}/openbsd-compat/strtonum.c
endif

OBJS=		${notdir ${SRCS:.c=.o}}

ifdef VERSION_SCRIPT
${TARGET_LIB}: ${VERSION_SCRIPT}
LDFLAGS+=	-Wl,--version-script=${VERSION_SCRIPT}
endif

${TARGET_LIB}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDLIBS}

.DEFAULT_GOAL=		all
.PHONY: all
all: ${TARGET_LIB} ${TARGET_MAN}

.PHONY: install
install: includes ${TARGET_LIB} ${TARGET_MAN}
	${INSTALL} -D -o ${BINOWN} -g ${BINGRP} -m ${LIBPERM} ${TARGET_LIB} ${DESTDIR}${LIBDIR}/${TARGET_LIB}
	${LINK} -s ${TARGET_LIB} ${DESTDIR}${LIBDIR}/${SONAME_LIB}
	${LINK} -s ${TARGET_LIB} ${DESTDIR}${LIBDIR}/${BASE_LIB}
	${INSTALL} -D -o ${MANOWN} -g ${MANGRP} -m ${MANPERM} ${TARGET_MAN} ${DESTDIR}${MANDIR}/${TARGET_MAN}

CLEANFILES+=	*.o ${TARGET_LIB}

.PHONY: clean
clean:
	rm -f ${CLEANFILES}
