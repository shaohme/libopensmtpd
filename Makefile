LIB=		opensmtpd

LOCALBASE?=	/usr/local/

SRCS=		opensmtpd.c iobuf.c ioev.c
HDRS=		opensmtpd.h
MAN=		osmtpd_run.3
LIBDIR=		${LOCALBASE}/lib/
MANDIR=		${LOCALBASE}/man/man
LDADD=		-levent
DPADD=		${EVENT}

CFLAGS+=	-Wall -I${.CURDIR} -I${.CURDIR}/openbsd-compat
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare

CLEANFILES= ${VERSION_SCRIPT}

VERSION_SCRIPT=	Symbols.map
SYMBOL_LIST=	${.CURDIR}/Symbols.list

includes:
	@cd ${.CURDIR}; for i in $(HDRS); do \
	    j="cmp -s $$i ${DESTDIR}${LOCALBASE}/include/$$i || \
	    ${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m 444 $$i\
		${DESTDIR}${LOCALBASE}/include/"; \
	    echo $$j; \
	    eval "$$j"; \
	done;

${VERSION_SCRIPT}: ${SYMBOL_LIST}
	{ printf '{\n\tglobal:\n'; \
	  sed '/^[._a-zA-Z]/s/$$/;/; s/^/		/' ${SYMBOL_LIST}; \
	  printf '\n\tlocal:\n\t\t*;\n};\n'; } >$@.tmp && mv $@.tmp $@

.include <bsd.lib.mk>
