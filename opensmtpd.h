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
#include <sys/socket.h>

#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif
#ifndef __unused
#define __unused __attribute__((unused))
#endif

enum osmtpd_status {
	OSMTPD_STATUS_OK,
	OSMTPD_STATUS_TEMPFAIL,
	OSMTPD_STATUS_PERMFAIL
};

enum osmtpd_type {
	OSMTPD_TYPE_FILTER,
	OSMTPD_TYPE_REPORT
};

enum osmtpd_phase {
	OSMTPD_PHASE_CONNECT,
	OSMTPD_PHASE_HELO,
	OSMTPD_PHASE_EHLO,
	OSMTPD_PHASE_STARTTLS,
	OSMTPD_PHASE_AUTH,
	OSMTPD_PHASE_MAIL_FROM,
	OSMTPD_PHASE_RCPT_TO,
	OSMTPD_PHASE_DATA,
	OSMTPD_PHASE_DATA_LINE,
	OSMTPD_PHASE_RSET,
	OSMTPD_PHASE_QUIT,
	OSMTPD_PHASE_NOOP,
	OSMTPD_PHASE_HELP,
	OSMTPD_PHASE_WIZ,
	OSMTPD_PHASE_COMMIT,
	OSMTPD_PHASE_LINK_CONNECT,
	OSMTPD_PHASE_LINK_DISCONNECT,
	OSMTPD_PHASE_LINK_GREETING,
	OSMTPD_PHASE_LINK_IDENTIFY,
	OSMTPD_PHASE_LINK_TLS,
	OSMTPD_PHASE_TX_BEGIN,
	OSMTPD_PHASE_TX_MAIL,
	OSMTPD_PHASE_TX_RCPT,
	OSMTPD_PHASE_TX_ENVELOPE,
	OSMTPD_PHASE_TX_DATA,
	OSMTPD_PHASE_TX_COMMIT,
	OSMTPD_PHASE_TX_ROLLBACK,
	OSMTPD_PHASE_PROTOCOL_CLIENT,
	OSMTPD_PHASE_PROTOCOL_SERVER,
	OSMTPD_PHASE_FILTER_RESPONSE,
	OSMTPD_PHASE_TIMEOUT
};

#define OSMTPD_NEED_SRC 1 << 0
#define OSMTPD_NEED_DST 1 << 1
#define OSMTPD_NEED_RDNS 1 << 2
#define OSMTPD_NEED_FCRDNS 1 << 3
#define OSMTPD_NEED_IDENTITY 1 << 4
#define OSMTPD_NEED_GREETING 1 << 5
#define OSMTPD_NEED_CIPHERS 1 << 6
#define OSMTPD_NEED_MSGID 1 << 7
#define OSMTPD_NEED_MAILFROM 1 << 8
#define OSMTPD_NEED_RCPTTO 1 << 9
#define OSMTPD_NEED_EVPID 1 << 10

struct osmtpd_ctx {
	enum osmtpd_type	 type;
	enum osmtpd_phase	 phase;
	int			 version_major;
	int			 version_minor;
	struct timespec		 tm;
	int			 incoming;
	uint64_t		 reqid;
	uint64_t		 token;
	struct sockaddr_storage	 src;
	struct sockaddr_storage	 dst;
	char			*rdns;
	enum osmtpd_status	 fcrdns;
	/* HELO/EHLO identity */
	char			*identity;
	struct greeting {
		char			*identity;
		/* textstring not supplied by smtpd */
	}			 greeting;
	char			*ciphers;
	uint32_t		 msgid;
	char			*mailfrom;
	char			**rcptto;
	uint64_t		 evpid;
	void			*local_session;
	void			*local_message;
};

void osmtpd_register_conf(void (*)(const char *, const char *));
void osmtpd_register_filter_connect(void (*)(struct osmtpd_ctx *, const char *,
    struct sockaddr_storage *));
void osmtpd_register_filter_helo(void (*)(struct osmtpd_ctx *, const char *));
void osmtpd_register_filter_ehlo(void (*)(struct osmtpd_ctx *, const char *));
void osmtpd_register_filter_starttls(void (*)(struct osmtpd_ctx *));
void osmtpd_register_filter_auth(void (*)(struct osmtpd_ctx *, const char *));
void osmtpd_register_filter_mailfrom(void (*)(struct osmtpd_ctx *,
    const char *));
void osmtpd_register_filter_rcptto(void (*)(struct osmtpd_ctx *, const char *));
void osmtpd_register_filter_data(void (*)(struct osmtpd_ctx *));
void osmtpd_register_filter_dataline(void (*)(struct osmtpd_ctx *,
    const char *));
void osmtpd_register_filter_rset(void (*)(struct osmtpd_ctx *));
void osmtpd_register_filter_quit(void (*)(struct osmtpd_ctx *));
void osmtpd_register_filter_noop(void (*)(struct osmtpd_ctx *));
void osmtpd_register_filter_help(void (*)(struct osmtpd_ctx *));
void osmtpd_register_filter_wiz(void (*)(struct osmtpd_ctx *));
void osmtpd_register_filter_commit(void (*)(struct osmtpd_ctx *));
void osmtpd_register_report_connect(int, void (*)(struct osmtpd_ctx *,
    const char *, enum osmtpd_status, struct sockaddr_storage *,
    struct sockaddr_storage *));
void osmtpd_register_report_disconnect(int, void (*)(struct osmtpd_ctx *));
void osmtpd_register_report_greeting(int, void (*)(struct osmtpd_ctx *,
    const char *));
void osmtpd_register_report_identify(int, void (*)(struct osmtpd_ctx *,
    const char *));
void osmtpd_register_report_tls(int, void (*)(struct osmtpd_ctx *,
    const char *));
void osmtpd_register_report_begin(int, void (*)(struct osmtpd_ctx *, uint32_t));
void osmtpd_register_report_mail(int, void (*)(struct osmtpd_ctx *, uint32_t,
    const char *, enum osmtpd_status));
void osmtpd_register_report_rcpt(int, void (*)(struct osmtpd_ctx *, uint32_t,
    const char *, enum osmtpd_status));
void osmtpd_register_report_envelope(int, void (*)(struct osmtpd_ctx *, uint32_t,
    uint64_t));
void osmtpd_register_report_data(int, void (*)(struct osmtpd_ctx *, uint32_t,
    enum osmtpd_status));
void osmtpd_register_report_commit(int, void (*)(struct osmtpd_ctx *, uint32_t,
    size_t));
void osmtpd_register_report_rollback(int, void (*)(struct osmtpd_ctx *,
    uint32_t));
void osmtpd_register_report_client(int, void (*)(struct osmtpd_ctx *,
    const char *));
void osmtpd_register_report_server(int, void (*)(struct osmtpd_ctx *,
    const char *));
void osmtpd_register_report_response(int, void (*)(struct osmtpd_ctx *,
    const char *));
void osmtpd_register_report_timeout(int, void (*)(struct osmtpd_ctx *));
void osmtpd_local_session(void *(*)(struct osmtpd_ctx *),
    void (*)(struct osmtpd_ctx *, void *));
void osmtpd_local_message(void *(*)(struct osmtpd_ctx *),
    void (*)(struct osmtpd_ctx *, void *));
void osmtpd_need(int);

void osmtpd_filter_proceed(struct osmtpd_ctx *);
void osmtpd_filter_reject(struct osmtpd_ctx *, int, const char *, ...)
	__attribute__((__format__ (printf, 3, 4)));
void osmtpd_filter_reject_enh(struct osmtpd_ctx *, int, int, int, int,
    const char *, ...)
	__attribute__((__format__ (printf, 6, 7)));
void osmtpd_filter_disconnect(struct osmtpd_ctx *, const char *, ...)
	__attribute__((__format__ (printf, 2, 3)));
void osmtpd_filter_disconnect_enh(struct osmtpd_ctx *, int, int, int,
    const char *, ...)
	__attribute__((__format__ (printf, 5, 6)));
void osmtpd_filter_rewrite(struct osmtpd_ctx *, const char *, ...)
	__attribute__((__format__ (printf, 2, 3)));
void osmtpd_filter_dataline(struct osmtpd_ctx *, const char *, ...)
	__attribute__((__format__ (printf, 2, 3)));
void osmtpd_run(void);
__dead void osmtpd_err(int eval, const char *fmt, ...);
__dead void osmtpd_errx(int eval, const char *fmt, ...);
