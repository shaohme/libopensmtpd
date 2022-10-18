/*
 * Copyright (c) 2019 Martijn van Duren <martijn@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#define _GNU_SOURCE 1

#include <sys/time.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "openbsd-compat.h"
#include "opensmtpd.h"
#include "ioev.h"

#define NITEMS(x) (sizeof(x) / sizeof(*x))

struct osmtpd_callback {
	enum osmtpd_type type;
	enum osmtpd_phase phase;
	int incoming;
	void (*osmtpd_cb)(struct osmtpd_callback *, struct osmtpd_ctx *, char *,
	    char *);
	void *cb;
	int doregister;
	int storereport;
};

struct osmtpd_session {
	struct osmtpd_ctx ctx;
	RB_ENTRY(osmtpd_session) entry;
};

static void osmtpd_register(enum osmtpd_type, enum osmtpd_phase, int, int,
    void *);
static const char *osmtpd_typetostr(enum osmtpd_type);
static const char *osmtpd_phasetostr(enum osmtpd_phase);
static enum osmtpd_phase osmtpd_strtophase(const char *, const char *);
static void osmtpd_newline(struct io *, int, void *);
static void osmtpd_outevt(struct io *, int, void *);
static void osmtpd_noargs(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_onearg(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_connect(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_identify(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_link_auth(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_link_connect(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_link_disconnect(struct osmtpd_callback *,
    struct osmtpd_ctx *, char *, char *);
static void osmtpd_link_greeting(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_link_identify(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_link_tls(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_tx_begin(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_tx_mail(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_tx_rcpt(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_tx_envelope(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_tx_data(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_tx_commit(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_tx_rollback(struct osmtpd_callback *, struct osmtpd_ctx *,
    char *, char *);
static void osmtpd_addrtoss(char *, struct sockaddr_storage *, int, char *);
static enum osmtpd_status osmtpd_strtostatus(const char *, char *);
static int osmtpd_session_cmp(struct osmtpd_session *, struct osmtpd_session *);
static void *(*oncreatecb_session)(struct osmtpd_ctx *) = NULL;
static void (*ondeletecb_session)(struct osmtpd_ctx *, void *) = NULL;
static void *(*oncreatecb_message)(struct osmtpd_ctx *) = NULL;
static void (*ondeletecb_message)(struct osmtpd_ctx *, void *) = NULL;
static void (*conf_cb)(const char *, const char *);

static struct osmtpd_callback osmtpd_callbacks[] = {
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_CONNECT,
	    1,
	    osmtpd_connect,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_HELO,
	    1,
	    osmtpd_identify,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_EHLO,
	    1,
	    osmtpd_identify,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_STARTTLS,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_AUTH,
	    1,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_MAIL_FROM,
	    1,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_RCPT_TO,
	    1,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_DATA,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_DATA_LINE,
	    1,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_RSET,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_QUIT,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_NOOP,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_HELP,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_WIZ,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_FILTER,
	    OSMTPD_PHASE_COMMIT,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
  	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_AUTH,
	    1,
	    osmtpd_link_auth,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_CONNECT,
	    1,
	    osmtpd_link_connect,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_DISCONNECT,
	    1,
	    osmtpd_link_disconnect,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_GREETING,
	    1,
	    osmtpd_link_greeting,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_IDENTIFY,
	    1,
	    osmtpd_link_identify,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_TLS,
	    1,
	    osmtpd_link_tls,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_BEGIN,
	    1,
	    osmtpd_tx_begin,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_MAIL,
	    1,
	    osmtpd_tx_mail,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_RCPT,
	    1,
	    osmtpd_tx_rcpt,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_ENVELOPE,
	    1,
	    osmtpd_tx_envelope,
	    NULL,
	    0,
	   0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_DATA,
	    1,
	    osmtpd_tx_data,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_COMMIT,
	    1,
	    osmtpd_tx_commit,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_ROLLBACK,
	    1,
	    osmtpd_tx_rollback,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_PROTOCOL_CLIENT,
	    1,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_PROTOCOL_SERVER,
	    1,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_FILTER_RESPONSE,
	    1,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TIMEOUT,
	    1,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_CONNECT,
	    0,
	    osmtpd_link_connect,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_DISCONNECT,
	    0,
	    osmtpd_link_disconnect,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_GREETING,
	    0,
	    osmtpd_link_greeting,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_IDENTIFY,
	    0,
	    osmtpd_link_identify,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_LINK_TLS,
	    0,
	    osmtpd_link_tls,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_BEGIN,
	    0,
	    osmtpd_tx_begin,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_MAIL,
	    0,
	    osmtpd_tx_mail,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_RCPT,
	    0,
	    osmtpd_tx_rcpt,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_ENVELOPE,
	    0,
	    osmtpd_tx_envelope,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_DATA,
	    0,
	    osmtpd_tx_data,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_COMMIT,
	    0,
	    osmtpd_tx_commit,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TX_ROLLBACK,
	    0,
	    osmtpd_tx_rollback,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_PROTOCOL_CLIENT,
	    0,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_PROTOCOL_SERVER,
	    0,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_FILTER_RESPONSE,
	    0,
	    osmtpd_onearg,
	    NULL,
	    0,
	    0
	},
	{
	    OSMTPD_TYPE_REPORT,
	    OSMTPD_PHASE_TIMEOUT,
	    0,
	    osmtpd_noargs,
	    NULL,
	    0,
	    0
	}
};

static struct io *io_stdout;
static int needs;
static int ready = 0;
/* Default from smtpd */
static int session_timeout = 300;

RB_HEAD(osmtpd_sessions, osmtpd_session) osmtpd_sessions = RB_INITIALIZER(NULL);
RB_PROTOTYPE_STATIC(osmtpd_sessions, osmtpd_session, entry, osmtpd_session_cmp);

void
osmtpd_register_conf(void (*cb)(const char *, const char *))
{
	conf_cb = cb;
}

void
osmtpd_register_filter_connect(void (*cb)(struct osmtpd_ctx *, const char *,
    struct sockaddr_storage *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_CONNECT, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_helo(void (*cb)(struct osmtpd_ctx *, const char *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_HELO, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_ehlo(void (*cb)(struct osmtpd_ctx *, const char *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_EHLO, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_starttls(void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_STARTTLS, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_auth(void (*cb)(struct osmtpd_ctx *, const char *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_AUTH, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_mailfrom(void (*cb)(struct osmtpd_ctx *, const char *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_MAIL_FROM, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_rcptto(void (*cb)(struct osmtpd_ctx *, const char *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_RCPT_TO, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_data(void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_DATA, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_dataline(void (*cb)(struct osmtpd_ctx *, const char *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_DATA_LINE, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_rset(void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_RSET, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_quit(void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_QUIT, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_noop(void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_NOOP, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_help(void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_HELP, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_wiz(void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_WIZ, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_filter_commit(void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_FILTER, OSMTPD_PHASE_COMMIT, 1, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT, 1, 0,
	    NULL);
}

void
osmtpd_register_report_connect(int incoming, void (*cb)(struct osmtpd_ctx *,
    const char *, enum osmtpd_status, struct sockaddr_storage *,
    struct sockaddr_storage *))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_CONNECT, incoming,
	    0, (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_disconnect(int incoming, void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, (void *)cb);
}

void
osmtpd_register_report_identify(int incoming, void (*cb)(struct osmtpd_ctx *,
    const char *))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_IDENTIFY,
	    incoming, 0, (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_tls(int incoming, void (*cb)(struct osmtpd_ctx *,
    const char *))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_TLS, incoming, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_begin(int incoming, void (*cb)(struct osmtpd_ctx *,
    uint32_t))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_BEGIN, incoming, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_mail(int incoming, void (*cb)(struct osmtpd_ctx *,
    uint32_t, const char *, enum osmtpd_status))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_MAIL, incoming, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_rcpt(int incoming, void (*cb)(struct osmtpd_ctx *,
    uint32_t, const char *, enum osmtpd_status))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_RCPT, incoming, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_envelope(int incoming, void (*cb)(struct osmtpd_ctx *,
    uint32_t, uint64_t))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_ENVELOPE, incoming,
	    0, (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_data(int incoming, void (*cb)(struct osmtpd_ctx *,
    uint32_t, enum osmtpd_status))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_DATA, incoming, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_commit(int incoming, void (*cb)(struct osmtpd_ctx *,
    uint32_t, size_t))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_COMMIT, incoming, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_rollback(int incoming, void (*cb)(struct osmtpd_ctx *,
    uint32_t))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_ROLLBACK, incoming,
	    0, (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_client(int incoming, void (*cb)(struct osmtpd_ctx *,
    const char *))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_PROTOCOL_CLIENT,
	    incoming, 0, (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_server(int incoming, void (*cb)(struct osmtpd_ctx *,
    const char *))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_PROTOCOL_SERVER,
	    incoming, 0, (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_response(int incoming, void (*cb)(struct osmtpd_ctx *,
    const char *))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_FILTER_RESPONSE,
	    incoming, 0, (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_timeout(int incoming, void (*cb)(struct osmtpd_ctx *))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TIMEOUT, incoming, 0,
	    (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_register_report_auth(int incoming, void (*cb)(struct osmtpd_ctx *,
    const char * username, enum osmtpd_auth_result))
{
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_AUTH,
	    incoming, 0, (void *)cb);
	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_local_session(void *(*oncreate)(struct osmtpd_ctx *),
    void (*ondelete)(struct osmtpd_ctx *, void *))
{
	oncreatecb_session = oncreate;
	ondeletecb_session = ondelete;
}

void
osmtpd_local_message(void *(*oncreate)(struct osmtpd_ctx *),
    void (*ondelete)(struct osmtpd_ctx *, void *))
{
	oncreatecb_message = oncreate;
	ondeletecb_message = ondelete;
}

void
osmtpd_need(int lneeds)
{
	needs |= lneeds;
}

static void
osmtpd_register_need(int incoming)
{
	if (needs & (OSMTPD_NEED_SRC | OSMTPD_NEED_DST | OSMTPD_NEED_RDNS |
	    OSMTPD_NEED_FCRDNS))
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_CONNECT,
		    incoming, 1, NULL);
	if (needs & OSMTPD_NEED_GREETING)
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_GREETING,
		    incoming, 1, NULL);
	if (needs & OSMTPD_NEED_IDENTITY)
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_IDENTIFY,
		    incoming, 1, NULL);
	if (needs & OSMTPD_NEED_CIPHERS)
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_TLS,
		    incoming, 1, NULL);
	if (needs & OSMTPD_NEED_MSGID) {
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_BEGIN,
		    incoming, 1, NULL);
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_ROLLBACK,
		    incoming, 0, NULL);
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_COMMIT,
		    incoming, 0, NULL);
	}
	if (needs & OSMTPD_NEED_MAILFROM) {
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_MAIL,
		    incoming, 1, NULL);
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_ROLLBACK,
		    incoming, 0, NULL);
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_COMMIT,
		    incoming, 0, NULL);
	}
	if (needs & OSMTPD_NEED_RCPTTO) {
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_RCPT,
		    incoming, 1, NULL);
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_ROLLBACK,
		    incoming, 0, NULL);
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_COMMIT,
		    incoming, 0, NULL);
	}
	if (needs & OSMTPD_NEED_EVPID) {
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_ENVELOPE,
		    incoming, 1, NULL);
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_ROLLBACK,
		    incoming, 0, NULL);
		osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_TX_COMMIT,
		    incoming, 0, NULL);
	}

	osmtpd_register(OSMTPD_TYPE_REPORT, OSMTPD_PHASE_LINK_DISCONNECT,
	    incoming, 0, NULL);
}

void
osmtpd_run(void)
{
	size_t i = 0;
	int registered = 0;
	struct event_base *evbase;
	struct io *io_stdin;
	struct osmtpd_callback *hidenity = NULL, *eidentity = NULL;
	struct osmtpd_callback *ridentity = NULL;

	evbase = event_init();

	if ((io_stdin = io_new()) == NULL ||
	    (io_stdout = io_new()) == NULL)
		osmtpd_err(1, "io_new");
	io_set_nonblocking(STDIN_FILENO);
	io_set_fd(io_stdin, STDIN_FILENO);
	io_set_callback(io_stdin, osmtpd_newline, NULL);
	io_set_read(io_stdin);
	io_set_nonblocking(STDOUT_FILENO);
	io_set_fd(io_stdout, STDOUT_FILENO);
	io_set_callback(io_stdout, osmtpd_outevt, NULL);
	io_set_write(io_stdout);

	for (i = 0; i < NITEMS(osmtpd_callbacks); i++) {
		if (osmtpd_callbacks[i].doregister) {
			osmtpd_register_need(osmtpd_callbacks[i].incoming);
			if (oncreatecb_message != NULL) {
				osmtpd_register(OSMTPD_TYPE_REPORT,
				    OSMTPD_PHASE_TX_BEGIN,
				    osmtpd_callbacks[i].incoming, 0, NULL);
				osmtpd_register(OSMTPD_TYPE_REPORT,
				    OSMTPD_PHASE_TX_ROLLBACK,
				    osmtpd_callbacks[i].incoming, 0, NULL);
				osmtpd_register(OSMTPD_TYPE_REPORT,
				    OSMTPD_PHASE_TX_COMMIT,
				    osmtpd_callbacks[i].incoming, 0, NULL);
			}
			if (osmtpd_callbacks[i].type == OSMTPD_TYPE_FILTER &&
			    osmtpd_callbacks[i].phase == OSMTPD_PHASE_HELO)
				hidenity = &(osmtpd_callbacks[i]);
			if (osmtpd_callbacks[i].type == OSMTPD_TYPE_FILTER &&
			    osmtpd_callbacks[i].phase == OSMTPD_PHASE_EHLO)
				eidentity = &(osmtpd_callbacks[i]);
			if (osmtpd_callbacks[i].type == OSMTPD_TYPE_REPORT &&
			    osmtpd_callbacks[i].phase ==
			    OSMTPD_PHASE_LINK_IDENTIFY &&
			    osmtpd_callbacks[i].incoming == 1)
				ridentity = &(osmtpd_callbacks[i]);
		}
	}
	if (ridentity != NULL && ridentity->storereport) {
		if (hidenity != NULL && hidenity->doregister)
			hidenity->storereport = 1;
		if (eidentity != NULL && eidentity->doregister)
			eidentity->storereport = 1;
	}
	for (i = 0; i < NITEMS(osmtpd_callbacks); i++) {
		if (osmtpd_callbacks[i].doregister) {
			if (osmtpd_callbacks[i].cb != NULL)
				registered = 1;
			io_printf(io_stdout, "register|%s|smtp-%s|%s\n",
			    osmtpd_typetostr(osmtpd_callbacks[i].type),
			    osmtpd_callbacks[i].incoming ? "in" : "out",
			    osmtpd_phasetostr(osmtpd_callbacks[i].phase));
		}
	}

	if (!registered)
		osmtpd_errx(1, "No events registered");
	io_printf(io_stdout, "register|ready\n");
	ready = 1;

	event_dispatch();
	io_free(io_stdin);
	io_free(io_stdout);
	event_base_free(evbase);
}

__dead void
osmtpd_err(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(errno));
	exit(eval);
}

__dead void
osmtpd_errx(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(eval);
}

static void
osmtpd_newline(struct io *io, int ev, __unused void *arg)
{
	static char *linedup = NULL;
	static size_t dupsize = 0;
	struct osmtpd_session *ctx, search;
	enum osmtpd_type type;
	enum osmtpd_phase phase;
	int version_major, version_minor, incoming;
	struct timespec tm;
	char *line = NULL;
	const char *errstr = NULL;
	size_t linelen;
	char *end;
	size_t i;

	if (ev == IO_DISCONNECTED) {
		event_loopexit(0);
		return;
	}
	if (ev != IO_DATAIN)
		return;
	/*
	 * Multiple calls to io_printf (through osmtpd_filter_dataline) can
	 * cause a build-up of kevents, because of event_add/event_del loop.
	 */
	io_pause(io_stdout, IO_OUT);
	while ((line = io_getline(io, &linelen)) != NULL) {
		if (dupsize < linelen) {
			if ((linedup = realloc(linedup, linelen + 1)) == NULL)
				osmtpd_err(1, NULL);
			dupsize = linelen + 1;
		}
		strlcpy(linedup, line, dupsize);
		if ((end = strchr(line, '|')) == NULL)
			osmtpd_errx(1, "Invalid line received: missing "
			    "version: %s", linedup);
		end++[0] = '\0';
		if (strcmp(line, "filter") == 0)
			type = OSMTPD_TYPE_FILTER;
		else if (strcmp(line, "report") == 0)
			type = OSMTPD_TYPE_REPORT;
		else if (strcmp(line, "config") == 0) {
			line = end;
			if (strcmp(line, "ready") == 0) {
				if (conf_cb != NULL)
					conf_cb(NULL, NULL);
				continue;
			}
			if ((end = strchr(line, '|')) == NULL)
				osmtpd_errx(1, "Invalid line received: missing "
				    "key: %s", linedup);
			end++[0] = '\0';
			if (conf_cb != NULL)
				conf_cb(line, end);
			if (strcmp(line, "smtp-session-timeout") == 0) {
				session_timeout = strtonum(end, 0, INT_MAX,
				    &errstr);
				if (errstr != NULL)
					osmtpd_errx(1, "Invalid line received: "
					    "invalid smtp-sesion-timeout: %s",
					    linedup);
			}
			continue;
		}
		else
			osmtpd_errx(1, "Invalid line received: unknown message "
			    "type: %s", linedup);
		line = end;
		version_major = strtoul(line, &end, 10);
		if (line == end || end[0] != '.')
			osmtpd_errx(1, "Invalid protocol received: %s",
			    linedup);
		line = end + 1;
		version_minor = strtoul(line, &end, 10);
		if (end[0] == '\0')
			osmtpd_errx(1, "Invalid line received: missing time: "
			    "%s", linedup);
		if (line == end || end[0] != '|')
			osmtpd_errx(1, "Invalid protocol received: %s",
			    linedup);
		if (version_major != 0)
			osmtpd_errx(1, "Unsupported protocol received: %s",
			    linedup);
		line = end + 1;
		if ((end = strchr(line, '.')) == NULL)
			osmtpd_errx(1, "Invalid line received: invalid "
			    "timestamp: %s", linedup);
		end++[0] = '\0';
		tm.tv_sec = (time_t) strtonum(line, 0, INT64_MAX, &errstr);
		if (errstr != NULL)
			osmtpd_errx(1, "Invalid line received: invalid "
			    "timestamp: %s", linedup);
		line = end;
		if ((end = strchr(line, '|')) == NULL)
			osmtpd_errx(1, "Invalid line received: missing "
			    "direction: %s", linedup);
		end++[0] = '\0';
		tm.tv_nsec = (long) strtonum(line, 0, LONG_MAX, &errstr);
		if (errstr != NULL)
			osmtpd_errx(1, "Invalid line received: invalid "
			    "timestamp: %s", linedup);
		tm.tv_nsec *= 10 * (9 - (end - line));
		line = end;
		if ((end = strchr(line, '|')) == NULL)
			osmtpd_errx(1, "Invalid line received: missing "
			    "phase: %s", linedup);
		end++[0] = '\0';
		if (strcmp(line, "smtp-in") == 0)
			incoming = 1;
		else if (strcmp(line, "smtp-out") == 0)
			incoming = 0;
		else
			osmtpd_errx(1, "Invalid line: invalid direction: %s",
			    linedup);
		line = end;
		if ((end = strchr(line, '|')) == NULL)
			osmtpd_errx(1, "Invalid line received: missing reqid: "
			    "%s", linedup);
		end++[0] = '\0';
		phase = osmtpd_strtophase(line, linedup);
		line = end;
		errno = 0;
		search.ctx.reqid = strtoull(line, &end, 16);
		if ((search.ctx.reqid == ULLONG_MAX && errno != 0) ||
		    (end[0] != '|' && end[0] != '\0'))
			osmtpd_errx(1, "Invalid line received: invalid reqid: "
			    "%s", linedup);
		line = end + 1;
		ctx = RB_FIND(osmtpd_sessions, &osmtpd_sessions, &search);
		if (ctx == NULL) {
			if ((ctx = malloc(sizeof(*ctx))) == NULL)
				osmtpd_err(1, NULL);
			ctx->ctx.reqid = search.ctx.reqid;
			ctx->ctx.rdns = NULL;
			ctx->ctx.fcrdns = OSMTPD_STATUS_TEMPFAIL;
			ctx->ctx.identity = NULL;
			ctx->ctx.greeting.identity = NULL;
			ctx->ctx.ciphers = NULL;
			ctx->ctx.msgid = 0;
			ctx->ctx.mailfrom = NULL;
			ctx->ctx.rcptto = malloc(sizeof(*(ctx->ctx.rcptto)));
			if (ctx->ctx.rcptto == NULL)
				osmtpd_err(1, "malloc");
			ctx->ctx.rcptto[0] = NULL;
			memset(&(ctx->ctx.src), 0, sizeof(ctx->ctx.src));
			ctx->ctx.src.ss_family = AF_UNSPEC;
			memset(&(ctx->ctx.dst), 0, sizeof(ctx->ctx.dst));
			ctx->ctx.dst.ss_family = AF_UNSPEC;
			RB_INSERT(osmtpd_sessions, &osmtpd_sessions, ctx);
			ctx->ctx.evpid = 0;
			ctx->ctx.local_session = NULL;
			ctx->ctx.local_message = NULL;
			if (oncreatecb_session != NULL)
				ctx->ctx.local_session =
				    oncreatecb_session(&ctx->ctx);
		}
		ctx->ctx.type = type;
		ctx->ctx.phase = phase;
		ctx->ctx.version_major = version_major;
		ctx->ctx.version_minor = version_minor;
		ctx->ctx.incoming = incoming;
		ctx->ctx.tm.tv_sec = tm.tv_sec;
		ctx->ctx.tm.tv_nsec = tm.tv_nsec;
		ctx->ctx.token = 0;

		for (i = 0; i < NITEMS(osmtpd_callbacks); i++) {
			if (ctx->ctx.type == osmtpd_callbacks[i].type &&
			    ctx->ctx.phase == osmtpd_callbacks[i].phase &&
			    ctx->ctx.incoming == osmtpd_callbacks[i].incoming)
				break;
		}
		if (i == NITEMS(osmtpd_callbacks)) {
			osmtpd_errx(1, "Invalid line received: received "
			    "unregistered line: %s", linedup);
		}
		if (ctx->ctx.type == OSMTPD_TYPE_FILTER) {
			ctx->ctx.token = strtoull(line, &end, 16);
			if ((ctx->ctx.token == ULLONG_MAX && errno != 0) ||
			    end[0] != '|')
				osmtpd_errx(1, "Invalid line received: invalid "
				    "token: %s", linedup);
			line = end + 1;
		}
		osmtpd_callbacks[i].osmtpd_cb(&(osmtpd_callbacks[i]),
		    &(ctx->ctx), line, linedup);
	}
	io_resume(io_stdout, IO_OUT);
}

static void
osmtpd_outevt(__unused struct io *io, int evt, __unused void *arg)
{
	switch (evt) {
	case IO_LOWAT:
		return;
	case IO_DISCONNECTED:
		exit(0);
	default:
		osmtpd_errx(1, "Unexpectd event");
	}
}

static void
osmtpd_noargs(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    __unused char *params, __unused char *linedup)
{
	void (*f)(struct osmtpd_ctx *);

	f = cb->cb;
	f(ctx);
}

static void
osmtpd_onearg(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx, char *line,
    __unused char *linedup)
{
	void (*f)(struct osmtpd_ctx *, const char *);

	f = cb->cb;
	f(ctx, line);
}

static void
osmtpd_connect(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx, char *params,
    char *linedup)
{
	struct sockaddr_storage ss;
	char *hostname;
	char *address;
	void (*f)(struct osmtpd_ctx *, const char *, struct sockaddr_storage *);

	hostname = params;
	if ((address = strchr(params, '|')) == NULL)
		osmtpd_errx(1, "Invalid line received: missing address: %s",
		    linedup);
	address++[0] = '\0';

	osmtpd_addrtoss(address, &ss, 0, linedup);

	f = cb->cb;
	f(ctx, hostname, &ss);
}

static void
osmtpd_identify(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *identity, __unused char *linedup)
{
	void (*f)(struct osmtpd_ctx *, const char *);

	if (cb->storereport) {
		free(ctx->identity);
		if ((ctx->identity = strdup(identity)) == NULL)
			osmtpd_err(1, "strdup");
	}

	f = cb->cb;
	f(ctx, identity);
}

static void
osmtpd_link_auth(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *params, char *linedup)
{
	enum osmtpd_auth_result auth_res;
	char * username, *end;
	void (*f)(struct osmtpd_ctx *, const char *, enum osmtpd_auth_result);

	if ((end = strchr(params, '|')) == NULL)
		osmtpd_errx(1, "Invalid line received: missing username: %s",
		    linedup);
	end++[0] = '\0';
	username = params;
	params = end;
	if (strcmp(params, "pass") == 0)
		auth_res = OSMTPD_AUTH_PASS;
	else if (strcmp(params, "fail") == 0)
		auth_res = OSMTPD_AUTH_FAIL;
	else if (strcmp(params, "error") == 0)
		auth_res = OSMTPD_AUTH_ERROR;
	else
		osmtpd_errx(1, "Invalid line received: invalid result: %s",
		    linedup);

	if ((f = cb->cb) != NULL)
		f(ctx, username, auth_res);
}

static void
osmtpd_link_connect(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *params, char *linedup)
{
	char *end, *rdns;
	enum osmtpd_status fcrdns;
	struct sockaddr_storage src, dst;
	void (*f)(struct osmtpd_ctx *, const char *, enum osmtpd_status,
	    struct sockaddr_storage *, struct sockaddr_storage *);

	if ((end = strchr(params, '|')) == NULL)
		osmtpd_errx(1, "Invalid line received: missing fcrdns: %s",
		    linedup);
	end++[0] = '\0';
	rdns = params;
	params = end;
	if ((end = strchr(params, '|')) == NULL)
		osmtpd_errx(1, "Invalid line received: missing src: %s",
		    linedup);
	end++[0] = '\0';
	if (strcmp(params, "pass") == 0)
		fcrdns = OSMTPD_STATUS_OK;
	else if (strcmp(params, "fail") == 0)
		fcrdns = OSMTPD_STATUS_PERMFAIL;
	else if (strcmp(params, "error") == 0)
		fcrdns = OSMTPD_STATUS_TEMPFAIL;
	else
		osmtpd_errx(1, "Invalid line received: invalid fcrdns: %s",
		    linedup);
	params = end;
	if ((end = strchr(params, '|')) == NULL)
		osmtpd_errx(1, "Invalid line received: missing dst: %s",
		    linedup);
	end++[0] = '\0';
	osmtpd_addrtoss(params, &src, 1, linedup);
	params = end;
	osmtpd_addrtoss(params, &dst, 1, linedup);
	if (cb->storereport) {
		if ((ctx->rdns = strdup(rdns)) == NULL)
			osmtpd_err(1, "strdup");
		ctx->fcrdns = fcrdns;
		memcpy(&(ctx->src), &src, sizeof(ctx->src));
		memcpy(&(ctx->dst), &dst, sizeof(ctx->dst));
	}
	if ((f = cb->cb) != NULL)
		f(ctx, rdns, fcrdns, &src, &dst);
}

static void
osmtpd_link_disconnect(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    __unused char *param, __unused char *linedup)
{
	void (*f)(struct osmtpd_ctx *);
	size_t i;
	struct osmtpd_session *session, search;

	if ((f = cb->cb) != NULL)
		f(ctx);

	search.ctx.reqid = ctx->reqid;
	session = RB_FIND(osmtpd_sessions, &osmtpd_sessions, &search);
	if (session != NULL) {
		RB_REMOVE(osmtpd_sessions, &osmtpd_sessions, session);
		if (ondeletecb_session != NULL)
			ondeletecb_session(ctx, session->ctx.local_session);
		free(session->ctx.rdns);
		free(session->ctx.identity);
		free(session->ctx.greeting.identity);
		free(session->ctx.ciphers);
		free(session->ctx.mailfrom);
		for (i = 0; session->ctx.rcptto[i] != NULL; i++)
			free(session->ctx.rcptto[i]);
		free(session->ctx.rcptto);
		free(session);
	}
}

static void
osmtpd_link_greeting(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *identity, __unused char *linedup)
{
	void (*f)(struct osmtpd_ctx *, const char *);

	if (cb->storereport) {
		free(ctx->greeting.identity);
		if ((ctx->greeting.identity = strdup(identity)) == NULL)
			osmtpd_err(1, NULL);
	}

	if ((f = cb->cb) != NULL)
		f(ctx, identity);
}

static void
osmtpd_link_identify(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *identity, __unused char *linedup)
{
	void (*f)(struct osmtpd_ctx *, const char *);

	if (cb->storereport) {
		free(ctx->identity);
		if ((ctx->identity = strdup(identity)) == NULL)
			osmtpd_err(1, NULL);
	}

	if ((f = cb->cb) != NULL)
		f(ctx, identity);
}

static void
osmtpd_link_tls(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *ciphers, __unused char *linedup)
{
	void (*f)(struct osmtpd_ctx *, const char *);

	if (cb->storereport) {
		if ((ctx->ciphers = strdup(ciphers)) == NULL)
			osmtpd_err(1, NULL);
	}

	if ((f = cb->cb) != NULL)
		f(ctx, ciphers);
}

static void
osmtpd_tx_begin(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *msgid, char *linedup)
{
	unsigned long imsgid;
	char *endptr;
	void (*f)(struct osmtpd_ctx *, uint32_t);

	errno = 0;
	imsgid = strtoul(msgid, &endptr, 16);
	if ((imsgid == ULONG_MAX && errno != 0) || endptr[0] != '\0')
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	ctx->msgid = imsgid;
	/* Check if we're in range */
	if ((unsigned long) ctx->msgid != imsgid)
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);

	if (!cb->storereport)
		ctx->msgid = 0;

	if (oncreatecb_message != NULL)
		ctx->local_message = oncreatecb_message(ctx);

	if ((f = cb->cb) != NULL)
		f(ctx, imsgid);
}

static void
osmtpd_tx_mail(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *params, char *linedup)
{
	char *end, *mailfrom;
	enum osmtpd_status status;
	unsigned long imsgid;
	uint32_t msgid;
	void (*f)(struct osmtpd_ctx *, uint32_t, const char *,
	    enum osmtpd_status);

	errno = 0;
	imsgid = strtoul(params, &end, 16);
	if ((imsgid == ULONG_MAX && errno != 0))
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	if (end[0] != '|')
		osmtpd_errx(1, "Invalid line received: missing address: %s",
		    linedup);
	msgid = imsgid;
	if ((unsigned long) msgid != imsgid)
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	params = end + 1;

	if ((end = strchr(params, '|')) == NULL)
		osmtpd_errx(1, "Invalid line received: missing status: %s",
		    linedup);
	end++[0] = '\0';
	if (ctx->version_major == 0 && ctx->version_minor < 6) {
		mailfrom = params;
		status = osmtpd_strtostatus(end, linedup);
	} else {
		mailfrom = end;
		status = osmtpd_strtostatus(params, linedup);
	}
	if (cb->storereport) {
		if ((ctx->mailfrom = strdup(mailfrom)) == NULL)
			osmtpd_err(1, NULL);
	}

	if ((f = cb->cb) != NULL)
		f(ctx, msgid, mailfrom, status);
}

static void
osmtpd_tx_rcpt(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *params, char *linedup)
{
	char *end, *rcptto;
	enum osmtpd_status status;
	unsigned long imsgid;
	uint32_t msgid;
	size_t i;
	void (*f)(struct osmtpd_ctx *, uint32_t, const char *,
	    enum osmtpd_status);

	errno = 0;
	imsgid = strtoul(params, &end, 16);
	if ((imsgid == ULONG_MAX && errno != 0))
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	if (end[0] != '|')
		osmtpd_errx(1, "Invalid line received: missing address: %s",
		    linedup);
	msgid = imsgid;
	if ((unsigned long) msgid != imsgid)
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	params = end + 1;

	if ((end = strchr(params, '|')) == NULL)
		osmtpd_errx(1, "Invalid line received: missing status: %s",
		    linedup);
	end++[0] = '\0';

	if (ctx->version_major == 0 && ctx->version_minor < 6) {
		rcptto = params;
		status = osmtpd_strtostatus(end, linedup);
	} else {
		rcptto = end;
		status = osmtpd_strtostatus(params, linedup);
	}

	if (cb->storereport) {
		for (i = 0; ctx->rcptto[i] != NULL; i++)
			;
		ctx->rcptto = reallocarray(ctx->rcptto, i + 2,
		    sizeof(*(ctx->rcptto)));
		if (ctx->rcptto == NULL)
			osmtpd_err(1, NULL);

		if ((ctx->rcptto[i] = strdup(rcptto)) == NULL)
			osmtpd_err(1, NULL);
		ctx->rcptto[i + 1] = NULL;
	}

	if ((f = cb->cb) != NULL)
		f(ctx, msgid, rcptto, status);
}

static void
osmtpd_tx_envelope(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *params, char *linedup)
{
	unsigned long imsgid;
	uint32_t msgid;
	uint64_t evpid;
	char *end;
	void (*f)(struct osmtpd_ctx *, uint32_t, uint64_t);

	errno = 0;
	imsgid = strtoul(params, &end, 16);
	if ((imsgid == ULONG_MAX && errno != 0))
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	if (end[0] != '|')
		osmtpd_errx(1, "Invalid line received: missing address: %s",
		    linedup);
	msgid = imsgid;
	if ((unsigned long) msgid != imsgid)
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	params = end + 1;

	evpid = strtoull(params, &end, 16);
	if ((ctx->evpid == ULLONG_MAX && errno != 0) ||
	    end[0] != '\0')
		osmtpd_errx(1, "Invalid line received: invalid evpid: %s",
		    linedup);
	if (cb->storereport)
		ctx->evpid = evpid;

	if ((f = cb->cb) != NULL)
		f(ctx, msgid, evpid);
}

static void
osmtpd_tx_data(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *params, char *linedup)
{
	char *end;
	unsigned long imsgid;
	uint32_t msgid;
	void (*f)(struct osmtpd_ctx *, uint32_t, enum osmtpd_status);

	errno = 0;
	imsgid = strtoul(params, &end, 16);
	if ((imsgid == ULONG_MAX && errno != 0))
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	if (end[0] != '|')
		osmtpd_errx(1, "Invalid line received: missing address: %s",
		    linedup);
	msgid = imsgid;
	if ((unsigned long) msgid != imsgid)
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	params = end + 1;

	if ((f = cb->cb) != NULL)
		f(ctx, msgid, osmtpd_strtostatus(params, linedup));
}

static void
osmtpd_tx_commit(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *params, char *linedup)
{
	char *end;
	const char *errstr = NULL;
	unsigned long imsgid;
	uint32_t msgid;
	size_t i, msgsz;
	void (*f)(struct osmtpd_ctx *, uint32_t, size_t);

	errno = 0;
	imsgid = strtoul(params, &end, 16);
	if ((imsgid == ULONG_MAX && errno != 0))
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	if (end[0] != '|')
		osmtpd_errx(1, "Invalid line received: missing address: %s",
		    linedup);
	msgid = imsgid;
	if ((unsigned long) msgid != imsgid)
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	params = end + 1;

	msgsz = strtonum(params, 0, UINT32_MAX, &errstr);
	if (errstr != NULL)
		osmtpd_errx(1, "Invalid line received: invalid msg size: %s",
		    linedup);

	if ((f = cb->cb) != NULL)
		f(ctx, msgid, msgsz);

	if (ondeletecb_message != NULL) {
		ondeletecb_message(ctx, ctx->local_message);
		ctx->local_message = NULL;
	}

	free(ctx->mailfrom);
	ctx->mailfrom = NULL;

	for (i = 0; ctx->rcptto[i] != NULL; i++)
		free(ctx->rcptto[i]);
	ctx->rcptto[0] = NULL;
	ctx->evpid = 0;
	ctx->msgid = 0;
}

static void
osmtpd_tx_rollback(struct osmtpd_callback *cb, struct osmtpd_ctx *ctx,
    char *params, char *linedup)
{
	char *end;
	unsigned long imsgid;
	uint32_t msgid;
	size_t i;
	void (*f)(struct osmtpd_ctx *, uint32_t);

	errno = 0;
	imsgid = strtoul(params, &end, 16);
	if ((imsgid == ULONG_MAX && errno != 0))
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);
	if (end[0] != '\0')
		osmtpd_errx(1, "Invalid line received: missing address: %s",
		    linedup);
	msgid = imsgid;
	if ((unsigned long) msgid != imsgid)
		osmtpd_errx(1, "Invalid line received: invalid msgid: %s",
		    linedup);

	if ((f = cb->cb) != NULL)
		f(ctx, msgid);

	if (ondeletecb_message != NULL) {
		ondeletecb_message(ctx, ctx->local_message);
		ctx->local_message = NULL;
	}

	free(ctx->mailfrom);
	ctx->mailfrom = NULL;

	for (i = 0; ctx->rcptto[i] != NULL; i++)
		free(ctx->rcptto[i]);
	ctx->rcptto[0] = NULL;
	ctx->evpid = 0;
	ctx->msgid = 0;
}

void
osmtpd_filter_proceed(struct osmtpd_ctx *ctx)
{
	if (ctx->version_major == 0 && ctx->version_minor < 5)
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "proceed\n", ctx->token, ctx->reqid);
	else
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "proceed\n", ctx->reqid, ctx->token);
}

void
osmtpd_filter_reject(struct osmtpd_ctx *ctx, int code, const char *reason, ...)
{
	va_list ap;

	if (code < 200 || code > 599)
		osmtpd_errx(1, "Invalid reject code");

	if (ctx->version_major == 0 && ctx->version_minor < 5)
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "reject|%d ", ctx->token, ctx->reqid, code);
	else
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "reject|%d ", ctx->reqid, ctx->token, code);
	va_start(ap, reason);
	io_vprintf(io_stdout, reason, ap);
	va_end(ap);
	io_printf(io_stdout, "\n");
}

void
osmtpd_filter_reject_enh(struct osmtpd_ctx *ctx, int code, int class,
    int subject, int detail, const char *reason, ...)
{
	va_list ap;

	if (code < 200 || code > 599)
		osmtpd_errx(1, "Invalid reject code");
	if (class < 2 || class > 5)
		osmtpd_errx(1, "Invalid enhanced status class");
	if (subject < 0 || subject > 999)
		osmtpd_errx(1, "Invalid enhanced status subject");
	if (detail < 0 || detail > 999)
		osmtpd_errx(1, "Invalid enhanced status detail");

	if (ctx->version_major == 0 && ctx->version_minor < 5)
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "reject|%d %d.%d.%d ", ctx->token, ctx->reqid, code, class,
		    subject, detail);
	else
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "reject|%d %d.%d.%d ", ctx->reqid, ctx->token, code, class,
		    subject, detail);
	va_start(ap, reason);
	io_vprintf(io_stdout, reason, ap);
	va_end(ap);
	io_printf(io_stdout, "\n");
}

void
osmtpd_filter_disconnect(struct osmtpd_ctx *ctx, const char *reason, ...)
{
	va_list ap;

	if (ctx->version_major == 0 && ctx->version_minor < 5)
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "disconnect|421 ", ctx->token, ctx->reqid);
	else
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "disconnect|421 ", ctx->reqid, ctx->token);
	va_start(ap, reason);
	io_vprintf(io_stdout, reason, ap);
	va_end(ap);
	io_printf(io_stdout, "\n");
}

void
osmtpd_filter_disconnect_enh(struct osmtpd_ctx *ctx, int class, int subject,
    int detail, const char *reason, ...)
{
	va_list ap;

	if (class <= 2 || class >= 5)
		osmtpd_errx(1, "Invalid enhanced status class");
	if (subject < 0 || subject > 999)
		osmtpd_errx(1, "Invalid enhanced status subject");
	if (detail < 0 || detail > 999)
		osmtpd_errx(1, "Invalid enhanced status detail");
	if (ctx->version_major == 0 && ctx->version_minor < 5)
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "disconnect|421 %d.%d.%d ", ctx->token, ctx->reqid, class,
		    subject, detail);
	else
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "disconnect|421 %d.%d.%d ", ctx->reqid, ctx->token, class,
		    subject, detail);
	va_start(ap, reason);
	io_vprintf(io_stdout, reason, ap);
	va_end(ap);
	io_printf(io_stdout, "\n");
}

void
osmtpd_filter_rewrite(struct osmtpd_ctx *ctx, const char *value, ...)
{
	va_list ap;

	if (ctx->version_major == 0 && ctx->version_minor < 5)
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "rewrite|", ctx->token, ctx->reqid);
	else
		io_printf(io_stdout, "filter-result|%016"PRIx64"|%016"PRIx64"|"
		    "rewrite|", ctx->reqid, ctx->token);
	va_start(ap, value);
	io_vprintf(io_stdout, value, ap);
	va_end(ap);
	io_printf(io_stdout, "\n");
}

void
osmtpd_filter_dataline(struct osmtpd_ctx *ctx, const char *line, ...)
{
	va_list ap;

	if (ctx->version_major == 0 && ctx->version_minor < 5)
		io_printf(io_stdout, "filter-dataline|%016"PRIx64"|%016"PRIx64"|",
		    ctx->token, ctx->reqid);
	else
		io_printf(io_stdout, "filter-dataline|%016"PRIx64"|%016"PRIx64"|",
		    ctx->reqid, ctx->token);
	va_start(ap, line);
	io_vprintf(io_stdout, line, ap);
	va_end(ap);
	io_printf(io_stdout, "\n");
}

static void
osmtpd_register(enum osmtpd_type type, enum osmtpd_phase phase, int incoming,
    int storereport, void *cb)
{
	size_t i;

	if (ready)
		osmtpd_errx(1, "Can't register when proc is running");

	for (i = 0; i < NITEMS(osmtpd_callbacks); i++) {
		if (type ==  osmtpd_callbacks[i].type &&
		    phase == osmtpd_callbacks[i].phase &&
		    incoming == osmtpd_callbacks[i].incoming) {
			if (osmtpd_callbacks[i].cb != NULL && cb != NULL)
				osmtpd_errx(1, "Event already registered");
			if (cb != NULL)
				osmtpd_callbacks[i].cb = cb;
			osmtpd_callbacks[i].doregister = 1;
			if (storereport)
				osmtpd_callbacks[i].storereport = 1;
			return;
		}
	}
	/* NOT REACHED */
	osmtpd_errx(1, "Trying to register unknown event");
}

static enum osmtpd_phase
osmtpd_strtophase(const char *phase, const char *linedup)
{
	if (strcmp(phase, "connect") == 0)
		return OSMTPD_PHASE_CONNECT;
	if (strcmp(phase, "helo") == 0)
		return OSMTPD_PHASE_HELO;
	if (strcmp(phase, "ehlo") == 0)
		return OSMTPD_PHASE_EHLO;
	if (strcmp(phase, "starttls") == 0)
		return OSMTPD_PHASE_STARTTLS;
	if (strcmp(phase, "auth") == 0)
		return OSMTPD_PHASE_AUTH;
	if (strcmp(phase, "mail-from") == 0)
		return OSMTPD_PHASE_MAIL_FROM;
	if (strcmp(phase, "rcpt-to") == 0)
		return OSMTPD_PHASE_RCPT_TO;
	if (strcmp(phase, "data") == 0)
		return OSMTPD_PHASE_DATA;
	if (strcmp(phase, "data-line") == 0)
		return OSMTPD_PHASE_DATA_LINE;
	if (strcmp(phase, "rset") == 0)
		return OSMTPD_PHASE_RSET;
	if (strcmp(phase, "quit") == 0)
		return OSMTPD_PHASE_QUIT;
	if (strcmp(phase, "noop") == 0)
		return OSMTPD_PHASE_NOOP;
	if (strcmp(phase, "help") == 0)
		return OSMTPD_PHASE_HELP;
	if (strcmp(phase, "wiz") == 0)
		return OSMTPD_PHASE_WIZ;
	if (strcmp(phase, "commit") == 0)
		return OSMTPD_PHASE_COMMIT;
	if (strcmp(phase, "link-auth") == 0)
		return OSMTPD_PHASE_LINK_AUTH;
	if (strcmp(phase, "link-connect") == 0)
		return OSMTPD_PHASE_LINK_CONNECT;
	if (strcmp(phase, "link-disconnect") == 0)
		return OSMTPD_PHASE_LINK_DISCONNECT;
	if (strcmp(phase, "link-greeting") == 0)
		return OSMTPD_PHASE_LINK_GREETING;
	if (strcmp(phase, "link-identify") == 0)
		return OSMTPD_PHASE_LINK_IDENTIFY;
	if (strcmp(phase, "link-tls") == 0)
		return OSMTPD_PHASE_LINK_TLS;
	if (strcmp(phase, "tx-begin") == 0)
		return OSMTPD_PHASE_TX_BEGIN;
	if (strcmp(phase, "tx-mail") == 0)
		return OSMTPD_PHASE_TX_MAIL;
	if (strcmp(phase, "tx-rcpt") == 0)
		return OSMTPD_PHASE_TX_RCPT;
	if (strcmp(phase, "tx-envelope") == 0)
		return OSMTPD_PHASE_TX_ENVELOPE;
	if (strcmp(phase, "tx-data") == 0)
		return OSMTPD_PHASE_TX_DATA;
	if (strcmp(phase, "tx-commit") == 0)
		return OSMTPD_PHASE_TX_COMMIT;
	if (strcmp(phase, "tx-rollback") == 0)
		return OSMTPD_PHASE_TX_ROLLBACK;
	if (strcmp(phase, "protocol-client") == 0)
		return OSMTPD_PHASE_PROTOCOL_CLIENT;
	if (strcmp(phase, "protocol-server") == 0)
		return OSMTPD_PHASE_PROTOCOL_SERVER;
	if (strcmp(phase, "filter-response") == 0)
		return OSMTPD_PHASE_FILTER_RESPONSE;
	if (strcmp(phase, "timeout") == 0)
		return OSMTPD_PHASE_TIMEOUT;
	osmtpd_errx(1, "Invalid line received: invalid phase: %s", linedup);
}

static const char *
osmtpd_typetostr(enum osmtpd_type type)
{
	switch (type) {
	case OSMTPD_TYPE_FILTER:
		return "filter";
	case OSMTPD_TYPE_REPORT:
		return "report";
	}
	osmtpd_errx(1, "In valid type: %d\n", type);
}

static const char *
osmtpd_phasetostr(enum osmtpd_phase phase)
{
	switch (phase) {
	case OSMTPD_PHASE_CONNECT:
		return "connect";
	case OSMTPD_PHASE_HELO:
		return "helo";
	case OSMTPD_PHASE_EHLO:
		return "ehlo";
	case OSMTPD_PHASE_STARTTLS:
		return "starttls";
	case OSMTPD_PHASE_AUTH:
		return "auth";
	case OSMTPD_PHASE_MAIL_FROM:
		return "mail-from";
	case OSMTPD_PHASE_RCPT_TO:
		return "rcpt-to";
	case OSMTPD_PHASE_DATA:
		return "data";
	case OSMTPD_PHASE_DATA_LINE:
		return "data-line";
	case OSMTPD_PHASE_RSET:
		return "rset";
	case OSMTPD_PHASE_QUIT:
		return "quit";
	case OSMTPD_PHASE_NOOP:
		return "noop";
	case OSMTPD_PHASE_HELP:
		return "help";
	case OSMTPD_PHASE_WIZ:
		return "wiz";
	case OSMTPD_PHASE_COMMIT:
		return "commit";
	case OSMTPD_PHASE_LINK_AUTH:
		return "link-auth";
	case OSMTPD_PHASE_LINK_CONNECT:
		return "link-connect";
	case OSMTPD_PHASE_LINK_DISCONNECT:
		return "link-disconnect";
	case OSMTPD_PHASE_LINK_GREETING:
		return "link-greeting";
	case OSMTPD_PHASE_LINK_IDENTIFY:
		return "link-identify";
	case OSMTPD_PHASE_LINK_TLS:
		return "link-tls";
	case OSMTPD_PHASE_TX_BEGIN:
		return "tx-begin";
	case OSMTPD_PHASE_TX_MAIL:
		return "tx-mail";
	case OSMTPD_PHASE_TX_RCPT:
		return "tx-rcpt";
	case OSMTPD_PHASE_TX_ENVELOPE:
		return "tx-envelope";
	case OSMTPD_PHASE_TX_DATA:
		return "tx-data";
	case OSMTPD_PHASE_TX_COMMIT:
		return "tx-commit";
	case OSMTPD_PHASE_TX_ROLLBACK:
		return "tx-rollback";
	case OSMTPD_PHASE_PROTOCOL_CLIENT:
		return "protocol-client";
	case OSMTPD_PHASE_PROTOCOL_SERVER:
		return "protocol-server";
	case OSMTPD_PHASE_FILTER_RESPONSE:
		return "filter-response";
	case OSMTPD_PHASE_TIMEOUT:
		return "timeout";
	}
	osmtpd_errx(1, "In valid phase: %d\n", phase);
}

static enum osmtpd_status
osmtpd_strtostatus(const char *status, char *linedup)
{
	if (strcmp(status, "ok") == 0)
		return OSMTPD_STATUS_OK;
	else if (strcmp(status, "tempfail") == 0)
		return OSMTPD_STATUS_TEMPFAIL;
	else if (strcmp(status, "permfail") == 0)
		return OSMTPD_STATUS_PERMFAIL;
	osmtpd_errx(1, "Invalid line received: invalid status: %s\n", linedup);
}

static void
osmtpd_addrtoss(char *addr, struct sockaddr_storage *ss, int hasport,
    char *linedup)
{
	char *port = NULL;
	const char *errstr = NULL;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_un *sun;
	size_t n;

	if (addr[0] == '[') {
		sin6 = (struct sockaddr_in6 *)ss;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = 0;
		if (hasport) {
			if ((port = strrchr(addr, ':')) == NULL)
				osmtpd_errx(1, "Invalid line received: invalid "
				    "address (%s): %s", addr, linedup);
			if (port[-1] != ']')
				osmtpd_errx(1, "Invalid line received: invalid "
				    "address (%s): %s", addr, linedup);
			port++;
			sin6->sin6_port = htons(strtonum(port, 0, UINT16_MAX,
			    &errstr));
			if (errstr != NULL)
				osmtpd_errx(1, "Invalid line received: invalid "
				    "address (%s): %s", addr, linedup);
			port[-2] = '\0';
		} else {
			n = strlen(addr);
			if (addr[n - 1] != ']')
				osmtpd_errx(1, "Invalid line received: invalid "
				    "address (%s): %s", addr, linedup);
			addr[n - 1] = '\0';
		}
		switch (inet_pton(AF_INET6, addr + 1, &(sin6->sin6_addr))) {
		case 1:
			break;
		case 0:
			if (hasport)
				port[-2] = ']';
			else
				addr[n - 1] = ']';
			osmtpd_errx(1, "Invalid line received: invalid address "
			    "(%s): %s", addr, linedup);
		default:
			if (hasport)
				port[-2] = ']';
			else
				addr[n - 1] = ']';
			osmtpd_err(1, "Can't parse address (%s): %s", addr,
			    linedup);
		}
	} else if (strncasecmp(addr, "unix:", 5) == 0) {
		sun = (struct sockaddr_un *)ss;
		sun->sun_family = AF_UNIX;
		if (strlcpy(sun->sun_path, addr,
		    sizeof(sun->sun_path)) >= sizeof(sun->sun_path)) {
			osmtpd_errx(1, "Invalid line received: address too "
			    "long (%s): %s", addr, linedup);
		}
	} else {
		sin = (struct sockaddr_in *)ss;
		sin->sin_family = AF_INET;
		sin->sin_port = 0;
		if (hasport) {
			if ((port = strrchr(addr, ':')) == NULL)
				osmtpd_errx(1, "Invalid line received: invalid "
				    "address (%s): %s", addr, linedup);
			port++;
			sin->sin_port = htons(strtonum(port, 0, UINT16_MAX,
			    &errstr));
			if (errstr != NULL)
				osmtpd_errx(1, "Invalid line received: invalid "
				    "address (%s): %s", addr, linedup);
			port[-1] = '\0';
		}
		switch (inet_pton(AF_INET, addr, &(sin->sin_addr))) {
		case 1:
			break;
		case 0:
			if (hasport)
				port[-1] = ':';
			osmtpd_errx(1, "Invalid line received: invalid address "
			    "(%s): %s", addr, linedup);
		default:
			if (hasport)
				port[-1] = ':';
			osmtpd_err(1, "Can't parse address (%s): %s", addr,
			    linedup);
		}
	}
}

static int
osmtpd_session_cmp(struct osmtpd_session *a, struct osmtpd_session *b)
{
	return a->ctx.reqid < b->ctx.reqid ? -1 : a->ctx.reqid > b->ctx.reqid;
}

RB_GENERATE_STATIC(osmtpd_sessions, osmtpd_session, entry, osmtpd_session_cmp);
