/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2009, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Wireless AT signaling module
 *
 * \author David Yat Sin <dyatsin@sangoma.com>
 */

#include "asterisk.h"

#ifdef HAVE_WAT

#include <errno.h>
#include <ctype.h>
#include <signal.h>

#include "asterisk/cli.h"
#include "asterisk/stringfields.h"
#include "asterisk/callerid.h"
#include "asterisk/manager.h"
#include "asterisk/version.h"

#include "sig_wat.h"

#define SIGCHAN_NOTINALARM  (1 << 0)
#define SIGCHAN_UP          (1 << 1)

#define WAT_DEADLOCK_AVOIDANCE(p) \
	do { \
		sig_wat_unlock_private(p); \
		usleep(1); \
		sig_wat_lock_private(p); \
} while (0)


#if defined(ASTERISK_COMPILING_TRUNK)
#undef ASTERISK_VERSION_NUM
#define ASTERISK_VERSION_NUM 20000
#endif

void *sig_wat_malloc(size_t size);
void *sig_wat_calloc(size_t nmemb, size_t size);
void sig_wat_free(void *ptr);
void sig_wat_log(unsigned char loglevel, char *fmt, ...);
void sig_wat_log_span(unsigned char span_id, unsigned char loglevel, char *fmt, ...);
void sig_wat_assert(char *message);
int sig_wat_span_write(unsigned char span_id, void *buffer, unsigned len);
void sig_wat_span_sts(unsigned char span_id, wat_span_status_t *status);

void sig_wat_con_ind(unsigned char span_id, uint8_t call_id, wat_con_event_t *con_event);
void sig_wat_con_sts(unsigned char span_id, uint8_t call_id, wat_con_status_t *con_status);
void sig_wat_rel_ind(unsigned char span_id, uint8_t call_id, wat_rel_event_t *rel_event);
void sig_wat_rel_cfm(unsigned char span_id, uint8_t call_id);
void sig_wat_sms_ind(unsigned char span_id, wat_sms_event_t *sms_event);
void sig_wat_sms_sts(unsigned char span_id, uint8_t sms_id, wat_sms_status_t *sms_status);

static void sig_wat_handle_sigchan_exception(struct sig_wat_span *wat);
static void sig_wat_handle_sigchan_data(struct sig_wat_span *wat);
static void sig_wat_lock_private(struct sig_wat_chan *p);
static void sig_wat_unlock_private(struct sig_wat_chan *p);
static void wat_queue_control(struct sig_wat_span *wat, int subclass);
static void sig_wat_set_dialing(struct sig_wat_chan *p, int is_dialing);
static void sig_wat_lock_owner(struct sig_wat_span *wat);

static int sig_wat_set_echocanceller(struct sig_wat_chan *p, int enable);
static void sig_wat_open_media(struct sig_wat_chan *p);
static struct ast_channel *sig_wat_new_ast_channel(struct sig_wat_chan *p, int state, int startpbx, int sub, const struct ast_channel *requestor);

struct sig_wat_span **wat_spans = NULL;

extern struct dahdi_wat wats[WAT_NUM_SPANS];

void *sig_wat_malloc(size_t size)
{
	return ast_malloc(size);
}

void *sig_wat_calloc(size_t nmemb, size_t size)
{
	return ast_calloc(nmemb, size);
}

void sig_wat_free(void *ptr)
{
	return ast_free(ptr);
}

void sig_wat_log_span(unsigned char span_id, unsigned char loglevel, char *fmt, ...)
	__attribute__((format (printf, 3, 0)));
void sig_wat_log_span(unsigned char span_id, unsigned char loglevel, char *fmt, ...)
{
	char *data;
	va_list ap;

	va_start(ap, fmt);
	if (vasprintf(&data, fmt, ap) == -1) {
		ast_log(LOG_ERROR, "Failed to get arguments to log error\n");
		return;
	}
	sig_wat_log(loglevel, "Span %d:%s", span_id, data);
	free(data);
	return;
}

void sig_wat_log(unsigned char loglevel, char *fmt, ...)
	__attribute__((format (printf, 2, 0)));
void sig_wat_log(unsigned char loglevel, char *fmt, ...)
{
	char *data;
	va_list ap;

	va_start(ap, fmt);
	if (vasprintf(&data, fmt, ap) == -1) {
		ast_log(LOG_ERROR, "Failed to get arguments to log error\n");
		return;
	}

	switch(loglevel) {
		case WAT_LOG_DEBUG:
			ast_debug(1, "%s", data);
			break;
		case WAT_LOG_NOTICE:
			ast_verb(3, "%s", data);
			break;
		case WAT_LOG_WARNING:
			ast_log(LOG_WARNING, "%s", data);
			break;
		case WAT_LOG_INFO:
			ast_verb(1, "%s", data);
			break;		
		case WAT_LOG_CRIT:
		case WAT_LOG_ERROR:
		default:
			ast_log(LOG_ERROR, "%s", data);
			break;
	}
	free(data);
	return;
}

void sig_wat_assert(char *message)
{
	ast_log(LOG_ERROR, "%s\n", message);
	ast_assert(0);
	ast_backtrace();
}

int sig_wat_span_write(unsigned char span_id, void *buffer, unsigned len)
{
	int res;
	struct sig_wat_span *wat = wat_spans[span_id];
	char at_buf[len+2];
	
	ast_assert(wat != NULL);

	memcpy(at_buf, buffer, len);
	memset(&at_buf[len], 0, 2); /* set CRC to 0 to keep valgrind happy */
	len += 2;
	res = write(wat->fd, at_buf, len);
	if (res < 0) {
		if (errno != EAGAIN) {
			ast_log(LOG_ERROR, "Span %d:Write failed: %s\n", wat->span, strerror(errno));
		}
	}
	if (res != len) {
		ast_log(LOG_ERROR, "Span %d:Short write %d (len:%d)\n", wat->span + 1, res, len);
	}
	return res;
}

void sig_wat_span_sts(unsigned char span_id, wat_span_status_t *status)
{
	struct sig_wat_span *wat = wat_spans[span_id];
	
	ast_assert(wat != NULL);

	switch(status->type) {
		case WAT_SPAN_STS_READY:			
			/* Initialization is complete */
			/* Do nothing for now */
			ast_verb(2, "Span %d:Initialization complete\n", wat->span + 1);
			break;		
		case WAT_SPAN_STS_SIGSTATUS:
			if (status->sts.sigstatus == WAT_SIGSTATUS_UP) {
				ast_verb(2, "Span %d:Signalling up\n", wat->span + 1);
				wat->sigchanavail |= SIGCHAN_UP;
			} else {
				ast_verb(2, "Span %d:Signalling down\n", wat->span + 1);
				wat->sigchanavail &= ~SIGCHAN_UP;
			}

			if (wat->pvt->calls->set_alarm) {
				wat->pvt->calls->set_alarm(wat->pvt->chan_pvt, (status->sts.sigstatus == WAT_SIGSTATUS_UP) ? 0 : 1);
			}
			break;
		case WAT_SPAN_STS_ALARM:
			if (status->sts.alarm == WAT_ALARM_NONE) {
				ast_log(LOG_NOTICE, "Span %d:Alarms cleared\n", span_id);
			} else {
				ast_log(LOG_WARNING, "Span %d:Alarm (%s)\n", span_id, wat_decode_alarm(status->sts.alarm));
			}
			break;
		case WAT_SPAN_STS_SIM_INFO_READY:
			{
				ast_debug(1, "Span %d: Subscriber: %14s\n", span_id, status->sts.sim_info.subscriber.digits);
			}
			break;
		default:
			ast_log(LOG_ERROR, "Unhandled span status %d\n", status->type);
			break;
			
	}
	return;
}

static void sig_wat_set_caller_id(struct sig_wat_chan *p)
{
#if ASTERISK_VERSION_NUM >= 10800
	if (p->calls->set_callerid) {
		struct ast_party_caller caller;
		ast_party_caller_init(&caller);
		caller.id.name.str = p->cid_name;
		caller.id.name.valid = 1;

		caller.id.number.str = p->cid_num;
		caller.id.number.valid = 1;

		caller.ani.number.str = p->cid_num;
		caller.ani.number.valid = 1;

		p->calls->set_callerid(p->chan_pvt, &caller);
	}
#else
	/* nothing to do */
#endif
}

void sig_wat_con_ind(unsigned char span_id, uint8_t call_id, wat_con_event_t *con_event)
{
	struct sig_wat_span *wat;
	struct ast_channel *chan;

	char *cid_num = NULL;
	char *cid_name = NULL;
	char *context = NULL;

	wat = wat_spans[span_id];
	ast_assert(wat != NULL);
	ast_assert(con_event->sub < WAT_CALL_SUB_INVALID);


#if ASTERISK_VERSION_NUM >= 10800
	cid_num = wat->pvt->cid_num;
	cid_name = wat->pvt->cid_name;
	context = wat->pvt->context;
#else
	cid_num = wat->pvt->calls->get_cid_num(wat->pvt->chan_pvt);
	cid_name = wat->pvt->calls->get_cid_name(wat->pvt->chan_pvt);
	context = wat->pvt->calls->get_context(wat->pvt->chan_pvt);
#endif /* ASTERISK_VERSION_NUM >= 10800 */

	ast_verb(3, "Span %d: Incoming Call, Type = %s, CallingNum = '%s', CallingName = '%s'\n",
			wat->span + 1,
			(con_event->sub == WAT_CALL_SUB_REAL) ? "Real" :
			(con_event->sub == WAT_CALL_SUB_CALLWAIT) ? "Call Waiting" :
			(con_event->sub == WAT_CALL_SUB_THREEWAY) ? "3-way" : "Invalid",
			con_event->calling_num.digits,
			con_event->calling_name);

	sig_wat_lock_private(wat->pvt);

	if (wat->pvt->subs[con_event->sub].allocd) {
		ast_log(LOG_ERROR, "Span %d: Got CRING/RING but we already had a call. Dropping Call.\n", wat->span + 1);
		sig_wat_unlock_private(wat->pvt);
		return;
	}

	/* TODO
	apply_plan_to_existing_number(plancallingnum, sizeof(plancallingnum), pri,
	*/

	wat->pvt->subs[con_event->sub].allocd = 1;
	wat->pvt->subs[con_event->sub].wat_call_id = call_id;

	wat->pvt->remotehangup = 0;

#if ASTERISK_VERSION_NUM >= 10800
	if (wat->pvt->use_callerid) {
#else
	if (wat->pvt->calls->get_use_callerid(wat->pvt->chan_pvt)) {
#endif
		/* TODO: Set plan etc.. properly */
		char *calling_num = NULL;
		char *calling_name = NULL;
		char *num = ast_strdup(con_event->calling_num.digits);
		char *name = ast_strdup(con_event->calling_name);

		calling_num = ast_strip_quoted(num, "\"", "\"");
		calling_name = ast_strip_quoted(name, "\"", "\"");
		if (calling_num[0] == '+') {
			calling_num++;
		}
		if (calling_name[0] == '+') {
			calling_name++;
		}

		ast_copy_string(cid_num, calling_num, AST_MAX_EXTENSION);
		ast_shrink_phone_number(cid_num);

		ast_copy_string(cid_name, calling_name, AST_MAX_EXTENSION);
		if (ast_strlen_zero(cid_name)) {
			ast_copy_string(cid_name, cid_num, AST_MAX_EXTENSION);
		}

		sig_wat_set_caller_id(wat->pvt);

		ast_free(num);
		ast_free(name);
	}

	if (ast_exists_extension(NULL, context, "s", 1, cid_num)) {
		sig_wat_unlock_private(wat->pvt);
		chan = sig_wat_new_ast_channel(wat->pvt, AST_STATE_RING, 0, con_event->sub, NULL);
		sig_wat_lock_private(wat->pvt);
		if (chan && !ast_pbx_start(chan)) {
			ast_verb(3, "Accepting call from '%s', span %d\n", cid_num, wat->span);
			sig_wat_set_echocanceller(wat->pvt, 1);
			sig_wat_unlock_private(wat->pvt);
		} else {
			ast_log(LOG_WARNING, "Unable to start PBX, span %d\n", wat->span);
			if (chan) {
				sig_wat_unlock_private(wat->pvt);
				ast_hangup(chan);
			} else {
				wat_rel_req(span_id, call_id);
				/* Do not clear the call yet, as we will get a wat_rel_cfm as a response */
				sig_wat_unlock_private(wat->pvt);
			}
		}
	} else {
		ast_verb(3, "No \'s' extension in context '%s'\n", context);
		/* Do not clear the call yet, as we will get a wat_rel_cfm as a response */
		wat_rel_req(span_id, call_id);
		
		sig_wat_unlock_private(wat->pvt);
	}	
	return;
}

void sig_wat_con_sts(unsigned char span_id, uint8_t call_id, wat_con_status_t *con_status)
{
	struct sig_wat_span *wat = wat_spans[span_id];
	
	ast_assert(wat != NULL);

	ast_verb(3, "Span %d: Remote side %s\n",
								wat->span + 1,
								(con_status->type == WAT_CON_STATUS_TYPE_RINGING) ? "ringing":
								(con_status->type == WAT_CON_STATUS_TYPE_ANSWER) ? "answered":
								"Invalid");

	switch(con_status->type) {
		case WAT_CON_STATUS_TYPE_RINGING:
			sig_wat_lock_private(wat->pvt);
			sig_wat_set_echocanceller(wat->pvt, 1);
			sig_wat_lock_owner(wat);
			if (wat->pvt->owner) {
				ast_setstate(wat->pvt->owner, AST_STATE_RINGING);
				ast_channel_unlock(wat->pvt->owner);
			}
			wat_queue_control(wat, AST_CONTROL_RINGING);
			sig_wat_unlock_private(wat->pvt);
			break;
		case WAT_CON_STATUS_TYPE_ANSWER:
			sig_wat_lock_private(wat->pvt);
			sig_wat_open_media(wat->pvt);
			wat_queue_control(wat, AST_CONTROL_ANSWER);
			sig_wat_set_dialing(wat->pvt, 0);
			sig_wat_set_echocanceller(wat->pvt, 1);
			sig_wat_unlock_private(wat->pvt);
			break;
	
	}
	return;
}

void sig_wat_rel_ind(unsigned char span_id, uint8_t call_id, wat_rel_event_t *rel_event)
{
	struct sig_wat_span *wat = wat_spans[span_id];
	
	ast_assert(wat != NULL);	

	ast_verb(3, "Span %d: Call hangup requested\n", wat->span + 1);	

	sig_wat_lock_private(wat->pvt);
	if (!wat->pvt->subs[WAT_CALL_SUB_REAL].allocd) {
		ast_log(LOG_ERROR, "Span %d: Got hangup, but there was not call.\n", wat->span + 1);
		sig_wat_unlock_private(wat->pvt);
		return;
	}

	if (wat->pvt->owner) {
		wat->pvt->remotehangup = 1;
		wat->pvt->owner->hangupcause = rel_event->cause;
		wat->pvt->owner->_softhangup |= AST_SOFTHANGUP_DEV;
	} else {
		/* Proceed with the hangup even though we do not have an owner */
		wat_rel_cfm(span_id, call_id);
		memset(&wat->pvt->subs[WAT_CALL_SUB_REAL], 0, sizeof(wat->pvt->subs[0]));
	}
	
	sig_wat_unlock_private(wat->pvt);
	return;
}

void sig_wat_rel_cfm(unsigned char span_id, uint8_t call_id)
{
	struct sig_wat_span *wat = wat_spans[span_id];
	
	ast_assert(wat != NULL);

	ast_verb(3, "Span %d: Call Release\n", wat->span + 1);
	sig_wat_lock_private(wat->pvt);

	wat->pvt->owner = NULL;

	if (!wat->pvt->subs[WAT_CALL_SUB_REAL].allocd) {
		ast_log(LOG_ERROR, "Span %d: Got Release, but there was no call.\n", wat->span + 1);
		sig_wat_unlock_private(wat->pvt);
		return;
	}

	memset(&wat->pvt->subs[WAT_CALL_SUB_REAL], 0, sizeof(wat->pvt->subs[0]));
	
	sig_wat_unlock_private(wat->pvt);
	return;
}

void sig_wat_sms_ind(unsigned char span_id, wat_sms_event_t *sms_event)
{
	struct sig_wat_span *wat = wat_spans[span_id];
	char dest [30];
	char event [800];
	unsigned event_len = 0;
	int i = 0;

	ast_assert(wat != NULL);
	ast_verb(3, "Span %d: SMS received from %s\n", wat->span + 1, sms_event->from.digits);

	memset(event, 0, sizeof(event));
	
	event_len += sprintf(&event[event_len],
									"Span: %d\r\n"
									"From-Number: %s\r\n"
									"From-Plan: %s\r\n"
									"From-Type: %s\r\n"
									"Timestamp: %02d/%02d/%02d %02d:%02d:%02d %s\r\n"
									"Type: %s\r\n",
									(wat->span + 1),
									sms_event->from.digits,
		 							wat_number_plan2str(sms_event->from.plan), wat_number_type2str(sms_event->from.type),
									sms_event->scts.year, sms_event->scts.month, sms_event->scts.day,
									sms_event->scts.hour, sms_event->scts.minute, sms_event->scts.second,
									wat_decode_timezone(dest, sms_event->scts.timezone),
									(sms_event->type == WAT_SMS_TXT) ? "Text": "PDU");


	if (sms_event->type == WAT_SMS_PDU) {
		event_len += sprintf(&event[event_len],
									"X-SMS-Message-Type: %s\r\n"
									"X-SMS-SMSC-Plan: %s\r\n"
									"X-SMS-SMSC-Type: %s\r\n"
									"X-SMS-SMSC-Number: %s\r\n"
									"X-SMS-More-Messages-To-Send: %s\r\n"
									"X-SMS-Reply-Path: %s\r\n"
									"X-SMS-User-Data-Header-Indicator: %s\r\n"
									"X-SMS-Status-Report-Indication: %s\r\n"
									"X-SMS-Class: %s\r\n",
									wat_decode_pdu_mti(sms_event->pdu.sms.deliver.tp_mti),
									wat_number_plan2str(sms_event->pdu.smsc.plan),
									wat_number_type2str(sms_event->pdu.smsc.type),
									sms_event->pdu.smsc.digits,
									(sms_event->pdu.sms.deliver.tp_mms) ? "No" : "Yes",
									(sms_event->pdu.sms.deliver.tp_rp) ? "Yes" : "No",
									(sms_event->pdu.sms.deliver.tp_udhi) ? "Yes" : "No",
									(sms_event->pdu.sms.deliver.tp_sri) ? "Yes" : "No",
									wat_sms_pdu_dcs_msg_cls2str(sms_event->pdu.dcs.msg_class));

		if (sms_event->pdu.sms.deliver.tp_udhi) {
			event_len += sprintf(&event[event_len],
									"X-SMS-IE-Identifier: %d\r\n"
									"X-SMS-Reference-Number: %04x\r\n"
									"X-SMS-Concat-Sequence-Number: %02d\r\n"
									"X-SMS-Concat-Total-Messages: %02d\r\n",
									sms_event->pdu.udh.iei,
									sms_event->pdu.udh.refnr,
									sms_event->pdu.udh.seq,
									sms_event->pdu.udh.total);
		}
	}

	event_len += sprintf(&event[event_len],
									"Content-Type: %s; charset=%s\r\n"
									"Content-Transfer-Encoding: %s\r\n"
									"Content: ",
									(sms_event->pdu.dcs.compressed) ? "Compressed" : "text/plain",
									wat_sms_content_charset2str(sms_event->content.charset),
									wat_decode_sms_content_encoding(sms_event->content.encoding));

	for (i = 0; i < strlen(sms_event->content.data); i++) {
		if (sms_event->content.data[i] == '\n') {
			event_len += sprintf(&event[event_len], "\r");
		}
		event_len += sprintf(&event[event_len], "%c", sms_event->content.data[i]);
	}
	event_len += sprintf(&event[event_len], "\r\n\r\n");

	manager_event(EVENT_FLAG_CALL, "WATIncomingSms", "%s", event);
}

void sig_wat_sms_sts(unsigned char span_id, uint8_t sms_id, wat_sms_status_t *sms_status)
{
	char event [800];
	unsigned event_len = 0;
	struct sig_wat_sms *wat_sms = NULL;
	struct sig_wat_span *wat = wat_spans[span_id];	

	memset(event, 0, sizeof(event));

	ast_assert(wat != NULL);
	
	if (sms_status->success) {
		ast_verb(3, "Span %d: SMS sent OK (id:%d)\n", wat->span + 1, sms_id);
	} else {
		if (sms_status->error) {
			ast_verb(3, "Span %d: Failed to send SMS cause:%s error:%s (id:%d)\n",
													wat->span + 1,
													wat_decode_sms_cause(sms_status->cause),
													sms_status->error,
													sms_id);
		} else {
			ast_verb(3, "Span %d: Failed to send SMS cause:%s (id:%d)\n",
													wat->span + 1,
													wat_decode_sms_cause(sms_status->cause),
													sms_id);
		}

	}

	sig_wat_lock_private(wat->pvt);
	if (!wat->smss[sms_id]) {
		ast_log(LOG_ERROR, "Span %d: Could not find record for transmitted SMS (id:%d)\n", wat->span + 1, sms_id);
		sig_wat_unlock_private(wat->pvt);
		return;
	}

	wat_sms = wat->smss[sms_id];

	wat->smss[sms_id] = NULL;
	sig_wat_unlock_private(wat->pvt);

	event_len += sprintf(&event[event_len],
									"Span: %d\r\n"
									"To-Number: %s\r\n",
									wat->span + 1,
									wat_sms->sms_event.to.digits);
									

	if (!ast_strlen_zero(wat_sms->action_id)) {
		event_len += sprintf(&event[event_len], "ActionID: %s \r\n", wat_sms->action_id);
		ast_free(wat_sms->action_id);
	}

	event_len += sprintf(&event[event_len], "Status: %s\n", sms_status->success ? "Success": "Failed");

	if (!sms_status->success) {
		event_len += sprintf(&event[event_len], "Cause: %s\r\n", wat_decode_sms_cause(sms_status->cause));
		if (sms_status->error) {
			event_len += sprintf(&event[event_len], "Error: %s\r\n", sms_status->error);
		}
	}

	manager_event(EVENT_FLAG_CALL, "WATSendSmsComplete", "%s", event);

	ast_free(wat_sms);

	return;
}

/*!
 * \brief Determine if the specified channel is available for an outgoing call.
 *
 * \param p Signaling private structure pointer.
 *
 * \retval TRUE if the channel is available.
 */
int sig_wat_available(struct sig_wat_chan *p)
{
	struct sig_wat_span *wat;
	int available = 0;

	if (!p->wat) {
		/* Something is wrong here.  A WAT channel without the wat pointer? */
		return 0;
	}

	wat = p->wat;

	sig_wat_lock_private(wat->pvt);
	if (wat->pvt->owner) {
		available = 0;
	} else {
		available = 1;
	}
	
	sig_wat_unlock_private(wat->pvt);
	return available;
}


int sig_wat_call(struct sig_wat_chan *p, struct ast_channel *ast, char *rdest)
{
	int i,j;
	char *c;
	
	struct sig_wat_span *wat;
	wat_con_event_t con_event;

	wat = p->wat;

	sig_wat_lock_private(wat->pvt);
	
	/* Find a free call ID */
	i = 8;
	for (j = 0; j < ARRAY_LEN(wat->pvt->subs); j++) {
		if (wat->pvt->subs[j].allocd) {
			if (wat->pvt->subs[j].wat_call_id == i) {
				i++;
				continue;
			}
		}
	}

	if (i >= WAT_MAX_CALLS_PER_SPAN) {
		ast_log(LOG_ERROR, "Span :%d Failed to find a free call ID\n", p->wat->span + 1);
		sig_wat_unlock_private(wat->pvt);
		return -1;
	}

	if (wat->pvt->subs[WAT_CALL_SUB_REAL].allocd) {
		ast_log(LOG_ERROR, "Span %d: Got an outgoing call but we already had a call. Ignoring Call.\n", wat->span + 1);
		sig_wat_unlock_private(wat->pvt);
		return -1;
	}
	
	c = strchr(rdest, '/');
	if (c) {
		c++;
	}

	if (!c) {
		ast_log(LOG_ERROR, "Span :%d Invalid destination\n", p->wat->span+1);
		sig_wat_unlock_private(wat->pvt);
		return -1;
		
	}

	wat->pvt->subs[WAT_CALL_SUB_REAL].allocd = 1;
	wat->pvt->subs[WAT_CALL_SUB_REAL].wat_call_id = i;
	wat->pvt->subs[WAT_CALL_SUB_REAL].owner = ast;
	wat->pvt->owner = ast;

	wat->pvt->remotehangup = 0;

	memset(&con_event, 0, sizeof(con_event));

	ast_copy_string(con_event.called_num.digits, c, sizeof(con_event.called_num.digits));

	wat_con_req(p->wat->wat_span_id, i, &con_event);
	ast_setstate(ast, AST_STATE_DIALING);
	sig_wat_unlock_private(wat->pvt);
	return 0;
}

int sig_wat_answer(struct sig_wat_chan *p, struct ast_channel *ast)
{
	int res = 0;

	sig_wat_open_media(p);
	res = wat_con_cfm(p->wat->wat_span_id, p->subs[WAT_CALL_SUB_REAL].wat_call_id);
	
	ast_setstate(ast, AST_STATE_UP);
	return res;
}

int sig_wat_hangup(struct sig_wat_chan *p, struct ast_channel *ast)
{	
	struct sig_wat_span *wat;
	int res = 0;

	wat = p->wat;
	ast_assert(wat != NULL);

	ast_verb(3, "Span %d: Call Hung up\n", wat->span + 1);

	if (!wat->pvt->subs[WAT_CALL_SUB_REAL].allocd) {
		ast_log(LOG_NOTICE, "Span %d: Call already hung-up\n", wat->span + 1);
		return -1;
	}

	if (wat->pvt->remotehangup) {
		wat_rel_cfm(wat->wat_span_id, wat->pvt->subs[WAT_CALL_SUB_REAL].wat_call_id);
		memset(&wat->pvt->subs[WAT_CALL_SUB_REAL], 0, sizeof(wat->pvt->subs[0]));
		wat->pvt->owner = NULL;
	} else {
		wat_rel_req(wat->wat_span_id, wat->pvt->subs[WAT_CALL_SUB_REAL].wat_call_id);
	}

	return res;
}


static void sig_wat_deadlock_avoidance_private(struct sig_wat_chan *p)
{
	if (p->calls->deadlock_avoidance_private) {
		p->calls->deadlock_avoidance_private(p->chan_pvt);
	} else {
		/* Fallback to the old way if callback not present. */
		WAT_DEADLOCK_AVOIDANCE(p);
	}
}

/*!
 * \internal
 * \brief Obtain the sig_wat owner channel lock if the owner exists.
 *
 * \param wat WAT span control structure.
 *
 * \note Assumes the wat->lock is already obtained.
 * \note Assumes the sig_wat_lock_private(wat->pvt) is already obtained.
 *
 * \return Nothing
 */
static void sig_wat_lock_owner(struct sig_wat_span *wat)
{
	for (;;) {
		if (!wat->pvt->owner) {
			/* There is no owner lock to get. */
			break;
		}
		if (!ast_channel_trylock(wat->pvt->owner)) {
			/* We got the lock */
			break;
		}
		/* We must unlock the PRI to avoid the possibility of a deadlock */
		ast_mutex_unlock(&wat->lock);
		sig_wat_deadlock_avoidance_private(wat->pvt);
		ast_mutex_lock(&wat->lock);
	}
}

/*!
 * \internal
 * \brief Queue the given frame onto the owner channel.
 *
 * \param wat WAT span control structure.
 * \param frame Frame to queue onto the owner channel.
 *
 * \note Assumes the wat->lock is already obtained.
 * \note Assumes the sig_wat_lock_private(pri->pvts[chanpos]) is already obtained.
 *
 * \return Nothing
 */

static void wat_queue_frame(struct sig_wat_span *wat, struct ast_frame *frame)
{
	sig_wat_lock_owner(wat);
	if (wat->pvt->owner) {
		ast_queue_frame(wat->pvt->owner, frame);
		ast_channel_unlock(wat->pvt->owner);
	}
}

/*!
 * \internal
 * \brief Queue a control frame of the specified subclass onto the owner channel.
 *
 * \param wat WAT span control structure.
 * \param subclass Control frame subclass to queue onto the owner channel.
 *
 * \note Assumes the wat->lock is already obtained.
 * \note Assumes the sig_wat_lock_private(pri->pvts[chanpos]) is already obtained.
 *
 * \return Nothing
 */
static void wat_queue_control(struct sig_wat_span *wat, int subclass)
{
	struct ast_frame f = {AST_FRAME_CONTROL, };
	struct sig_wat_chan *p = wat->pvt;

	if (p->calls->queue_control) {
		p->calls->queue_control(p->chan_pvt, subclass);
	}

#if ASTERISK_VERSION_NUM > 10800
	f.subclass.integer = subclass;
#else
	f.subclass = subclass;
#endif

	wat_queue_frame(wat, &f);
}

static void sig_wat_open_media(struct sig_wat_chan *p)
{
	if (p->calls->open_media) {
		p->calls->open_media(p->chan_pvt);
	}
}

static void sig_wat_unlock_private(struct sig_wat_chan *p)
{
	if (p->calls->unlock_private)
		p->calls->unlock_private(p->chan_pvt);
}

static void sig_wat_lock_private(struct sig_wat_chan *p)
{
	if (p->calls->lock_private)
		p->calls->lock_private(p->chan_pvt);
}

static void sig_wat_handle_sigchan_exception(struct sig_wat_span *wat)
{
	if (wat->calls->handle_sig_exception) {
		wat->calls->handle_sig_exception(wat);
	}
	return;
}

static void sig_wat_set_dialing(struct sig_wat_chan *p, int is_dialing)
{
	if (p->calls->set_dialing) {
		p->calls->set_dialing(p->chan_pvt, is_dialing);
	}
}

static int sig_wat_set_echocanceller(struct sig_wat_chan *p, int enable)
{
	if (p->calls->set_echocanceller)
		return p->calls->set_echocanceller(p->chan_pvt, enable);
	else
		return -1;
}

static void sig_wat_handle_sigchan_data(struct sig_wat_span *wat)
{
	char buf[1024];
	int res;
	
	res = read(wat->fd, buf, sizeof(buf));
	if (!res) {
		if (errno != EAGAIN) {
			ast_log(LOG_ERROR, "Span %d:Read on %d failed: %s\n", wat->span + 1, wat->fd, strerror(errno));
			return;
		}
	}
	wat_span_process_read(wat->wat_span_id, buf, res);
	return;
}

static void *wat_sigchannel(void *vwat)
{
	struct sig_wat_span *wat = vwat;
	struct pollfd fds[1];
	int32_t next;
	uint32_t lowest;
	int res;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	for(;;) {
		fds[0].fd = wat->fd;
		fds[0].events = POLLIN | POLLPRI;
		fds[0].revents = 0;

		lowest = 1000;

		next = wat_span_schedule_next(wat->wat_span_id);
		if (next < 0 || next > lowest) {
			next = lowest;
		}

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		pthread_testcancel();
		res = poll(fds, 1, next);
		pthread_testcancel();
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

		if (res == 0) {
			/* Timeout, do nothing */
		} else if (res > 0) {
			/* There is something to read */
			if (fds[0].revents & POLLPRI) {
				sig_wat_handle_sigchan_exception(wat);
			}

			if (fds[0].revents & POLLIN) {
				sig_wat_handle_sigchan_data(wat);
			}
		} else if (errno != EINTR) {
			ast_log(LOG_WARNING, "poll returned error %d (%s)\n", errno, strerror(errno));
		}

		wat_span_run(wat->wat_span_id);
	}
	/* Never reached */
	return NULL;
}

static void wat_set_new_owner(struct sig_wat_chan *p, struct ast_channel *new_owner)
{
	p->owner = new_owner;
	if (p->calls->set_new_owner) {
		p->calls->set_new_owner(p->chan_pvt, new_owner);
	}
}

static struct ast_channel *sig_wat_new_ast_channel(struct sig_wat_chan *p, int state, int startpbx, int sub, const struct ast_channel *requestor)
{
	struct ast_channel *c = NULL;
	if (p->calls->new_ast_channel) {
		c = p->calls->new_ast_channel(p->chan_pvt, state, startpbx, sub, requestor);
	} else {
		return NULL;
	}

	if (!c) {
		return NULL;
	}

	p->subs[sub].owner = c;
	if (!p->owner) {
		wat_set_new_owner(p, c);
	}

	return c;
}

int sig_wat_start_wat(struct sig_wat_span *wat)
{
	ast_assert(!wat_spans[wat->wat_span_id]);

	wat_spans[wat->wat_span_id] = wat;

	wat_span_config(wat->wat_span_id, &wat->wat_cfg);
	wat_span_start(wat->wat_span_id);

	if (ast_pthread_create_background(&wat->master, NULL, wat_sigchannel, wat)) {
		if (wat->fd > 0) {
			close(wat->fd);
			wat->fd = -1;
		}
		ast_log(LOG_ERROR, "Span %d:Unable to spawn D-channnel:%s\n", wat->span + 1, strerror(errno));
		return -1;
	}
	ast_log(LOG_DEBUG, "Started wat span %d\n", wat->wat_span_id);
	return 0;
}

void sig_wat_stop_wat(struct sig_wat_span *wat)
{
	wat_span_stop(wat->wat_span_id);
	wat_span_unconfig(wat->wat_span_id);
	ast_log(LOG_DEBUG, "Stopped wat span %d\n", wat->wat_span_id);
}

void sig_wat_load(int maxspans)
{
	wat_interface_t wat_intf;

	wat_spans = ast_calloc(maxspans, sizeof(void *));

	memset(&wat_intf, 0, sizeof(wat_intf));

	wat_intf.wat_span_write = sig_wat_span_write;
	wat_intf.wat_span_sts = sig_wat_span_sts;
	wat_intf.wat_log = (wat_log_func_t)sig_wat_log;
	wat_intf.wat_log_span = (wat_log_span_func_t)sig_wat_log_span;
	wat_intf.wat_malloc = sig_wat_malloc;
	wat_intf.wat_calloc = sig_wat_calloc;
	wat_intf.wat_free = sig_wat_free;
	wat_intf.wat_assert = sig_wat_assert;

	wat_intf.wat_con_ind = sig_wat_con_ind;
	wat_intf.wat_con_sts = sig_wat_con_sts;
	wat_intf.wat_rel_ind = sig_wat_rel_ind;
	wat_intf.wat_rel_cfm = sig_wat_rel_cfm;
	wat_intf.wat_sms_ind = sig_wat_sms_ind;
	wat_intf.wat_sms_sts = sig_wat_sms_sts;

	if (wat_register(&wat_intf)) {
		ast_log(LOG_ERROR, "Unable to register to libwat\n");
		return;
	}
	ast_verb(3, "Registered libwat\n");
	return;	
}

void sig_wat_unload(void)
{
	if (wat_spans) ast_free(wat_spans);
}

void sig_wat_init_wat(struct sig_wat_span *wat)
{
	memset(wat, 0, sizeof(*wat));
	ast_mutex_init(&wat->lock);

	wat->master = AST_PTHREADT_NULL;
	wat->fd = -1;
	return;
}

void sig_wat_chan_delete(void *pvt_data)
{
	ast_free(pvt_data);
}

struct sig_wat_chan *sig_wat_chan_new(void *pvt_data, struct sig_wat_callback *callback, struct sig_wat_span *wat, int channo)
{
	struct sig_wat_chan *p;

	p = ast_calloc(1, sizeof(*p));
	if (!p) {
		return p;
	}

	p->calls = callback;
	p->chan_pvt = pvt_data;

	p->wat = wat;

	return p;
}

void wat_event_alarm(struct sig_wat_span *wat)
{
	wat->sigchanavail &= ~(SIGCHAN_NOTINALARM | SIGCHAN_UP);
	if (wat->pvt->calls->set_alarm) {
		wat->pvt->calls->set_alarm(wat->pvt->chan_pvt, 1);
	}
	return;
}

void wat_event_noalarm(struct sig_wat_span *wat)
{
	wat->sigchanavail |= SIGCHAN_NOTINALARM;
	if (wat->pvt->calls->set_alarm) {
		wat->pvt->calls->set_alarm(wat->pvt->chan_pvt, 0);
	}
	return;
}

static void build_span_status(char *s, size_t len, int sigchanavail)
{
	if (!s || len < 1) {
		return;
	}
	snprintf(s, len, "%s %s",
			(sigchanavail & SIGCHAN_NOTINALARM) ? "" : "In Alarm, ",
			(sigchanavail & SIGCHAN_UP) ? "Up": "Down");
}

char *sig_wat_show_span(char *dest, struct sig_wat_span *wat)
{
	char status[30];
	const wat_sim_info_t *sim_info = NULL;
	unsigned len = 0;

	build_span_status(status, sizeof(status), wat->sigchanavail);
	
	sim_info = wat_span_get_sim_info(wat->wat_span_id);
	if (sim_info == NULL) {
		len += sprintf(&dest[len], "Span %d:Failed to get SIM information\n", wat->span +1);
	}

	if (sim_info && strlen(sim_info->subscriber.digits) > 0) {
		len += sprintf(&dest[len], "WAT span %d: %5s (%14s)\n", wat->wat_span_id, status, sim_info->subscriber.digits);
	} else {
		len += sprintf(&dest[len], "WAT span %d: %5s\n", wat->wat_span_id, status);
	}

	return dest;
}

char *sig_wat_show_span_verbose(char *dest, struct sig_wat_span *wat)
{	
	char status[256];
	const wat_chip_info_t *chip_info = NULL;
	const wat_sim_info_t *sim_info = NULL;
	const wat_sig_info_t *sig_info = NULL;
	const wat_net_info_t *net_info = NULL;
	const wat_pin_stat_t *pin_status = NULL;
	const char *last_error = NULL;
	wat_alarm_t alarm = WAT_ALARM_NONE;

	unsigned len = 0;
	
	build_span_status(status, sizeof(status), wat->sigchanavail);

	len += sprintf(&dest[len], "WAT span %d\n", wat->span + 1);
	len += sprintf(&dest[len], "   Signalling:%s\n", status);

	last_error = wat_span_get_last_error(wat->wat_span_id);
	if (last_error != NULL) {
		len += sprintf(&dest[len], "   Last Error:%s\n\n", last_error);
	}

	alarm = wat_span_get_alarms(wat->wat_span_id);
	if (alarm != WAT_ALARM_NONE) {
		len += sprintf(&dest[len], "   Alarm:%s\n\n", wat_decode_alarm(alarm));
	}

	pin_status = wat_span_get_pin_info(wat->wat_span_id);
	if (pin_status == NULL) {
		len += sprintf(&dest[len], "Span %d:Failed to get PIN status\n", wat->span + 1);
	} else if (*pin_status != WAT_PIN_READY) {
		len += sprintf(&dest[len], "   PIN Error:%s\n\n", wat_decode_pin_status(*pin_status));
	}

	net_info = wat_span_get_net_info(wat->wat_span_id);
	if (net_info == NULL) {
		len += sprintf(&dest[len], "Span %d:Failed to get Network information\n", wat->span +1);
	} else {
		len += sprintf(&dest[len], "   Status: %s\n", wat_net_stat2str(net_info->stat));
		len += sprintf(&dest[len], "   Operator: %s\n\n", net_info->operator_name);
	}

	sig_info = wat_span_get_sig_info(wat->wat_span_id);
	if (sig_info == NULL) {
		len += sprintf(&dest[len], "Span %d:Failed to get Signal information\n", wat->span +1);
	} else {
		char tmp[30];
		len += sprintf(&dest[len], "   Signal strength: %s\n", wat_decode_rssi(tmp, sig_info->rssi));
		len += sprintf(&dest[len], "   Signal BER: %s\n\n", wat_decode_ber(sig_info->ber));
	}

	if (alarm != WAT_ALARM_NO_SIGNAL) {
		sim_info = wat_span_get_sim_info(wat->wat_span_id);
		if (sim_info == NULL) {
			len += sprintf(&dest[len], "Span %d:Failed to get SIM information\n", wat->span +1);
		} else {
			len += sprintf(&dest[len], "   Subscriber: %s type:%d plan:%d <%s> \n",
											sim_info->subscriber.digits,
											sim_info->subscriber.type,
											sim_info->subscriber.plan,
											sim_info->subscriber_type);

			len += sprintf(&dest[len], "   SMSC: %s type:%d plan:%d \n",
											sim_info->smsc.digits,
											sim_info->smsc.type,
											sim_info->smsc.plan);

			len += sprintf(&dest[len], "   IMSI: %s\n\n", sim_info->imsi);
		}
	}

	chip_info = wat_span_get_chip_info(wat->wat_span_id);
	if (chip_info == NULL) {
		len += sprintf(&dest[len], "Span %d:Failed to get Chip information\n", wat->span +1);
	} else {
		len += sprintf(&dest[len], "   Model: %s\n", chip_info->model);
		len += sprintf(&dest[len], "   Manufacturer: %s\n", chip_info->manufacturer);
		len += sprintf(&dest[len], "   Revision: %s\n", chip_info->revision);
		len += sprintf(&dest[len], "   Serial: %s\n", chip_info->serial);
	}

	return dest;
}

WAT_AT_CMD_RESPONSE_FUNC(sig_wat_at_response)
{
	int i = 0;
	while (tokens[i]) {
		ast_verb(1, "AT response: %s\n", tokens[i]);
		i++;
	}
	return i;
}

WAT_AT_CMD_RESPONSE_FUNC(sig_wat_dtmf_response)
{
	struct sig_wat_span *wat = NULL;
	int i = 0;
#if ASTERISK_VERSION_NUM >= 10800
	char x = 0;
#endif
	while (tokens[i]) {
		i++;
	}

	wat = wat_spans[span_id];

	ast_assert(wat != NULL);

	ast_mutex_lock(&wat->lock);

	wat->dtmf_count--;

	sig_wat_lock_private(wat->pvt);

	if (!wat->pvt->owner || !wat->pvt->subs[WAT_CALL_SUB_REAL].allocd) {
		goto done;
	}

	if (wat->dtmf_count) {
		/* DTMF still pending, do not enable digit detection back again just yet */
		goto done;
	}
#if ASTERISK_VERSION_NUM >= 10800
	sig_wat_lock_owner(wat);

	x = 1;
	ast_channel_setoption(wat->pvt->owner, AST_OPTION_DIGIT_DETECT, &x, sizeof(char), 0);

	ast_channel_unlock(wat->pvt->owner);
#endif /* ASTERISK_VERSION_NUM >= 10800 */
done:
	sig_wat_unlock_private(wat->pvt);

	ast_mutex_unlock(&wat->lock);

	return i;
}

void sig_wat_exec_at(struct sig_wat_span *wat, const char *at_cmd)
{
	wat_cmd_req(wat->wat_span_id, at_cmd, sig_wat_at_response, wat);
}

int sig_wat_send_sms(struct sig_wat_span *wat, wat_sms_event_t *event, const char *action_id)
{
	int i;
	struct sig_wat_sms *wat_sms;

	sig_wat_lock_private(wat->pvt);
	
	/* Find a free SMS Id */
	for (i = 1; i < ARRAY_LEN(wat->smss); i++) {
		if (!wat->smss[i]) {
			break;
		}
	}

	if (i >= ARRAY_LEN(wat->smss)) {
		ast_log(LOG_ERROR, "Span :%d Max pending SMS reached\n", wat->span + 1);
		sig_wat_unlock_private(wat->pvt);
		return -1;
	}

	wat_sms = ast_malloc(sizeof(*wat_sms));
	if (!wat_sms) {
		sig_wat_unlock_private(wat->pvt);
		return -1;
	}

	wat->smss[i] = wat_sms;
	sig_wat_unlock_private(wat->pvt);

	memset(wat_sms, 0, sizeof(*wat_sms));

	memcpy(&wat_sms->sms_event, event, sizeof(*event));

	wat_sms->wat_sms_id = i;

	if (!ast_strlen_zero(action_id)) {
		wat_sms->action_id = ast_strdup(action_id);
	}

	if (wat_sms_req(wat->wat_span_id, wat_sms->wat_sms_id, &wat_sms->sms_event)) {
		ast_verb(1, "Span %d: Failed to send sms\n", wat->span + 1);
	}
	return 0;
}


int sig_wat_digit_begin(struct sig_wat_chan *p, struct ast_channel *ast, char digit)
{
	struct sig_wat_span *wat;	
	int count = 0;
	char dtmf[2] = { digit, '\0' };

	wat = p->wat;

	ast_assert(wat != NULL);

	ast_mutex_lock(&wat->lock);
	wat->dtmf_count++;
	count = wat->dtmf_count;
	ast_mutex_unlock(&wat->lock);

#if ASTERISK_VERSION_NUM >= 10800
	/* Disable DTMF detection while we play DTMF because the GSM module will play back some sort of feedback tone */
	if (count == 1) {
		char x = 0;
		ast_channel_setoption(wat->pvt->owner, AST_OPTION_DIGIT_DETECT, &x, sizeof(char), 0);
	}
#endif /* ASTERISK_VERSION_NUM >= 10800 */
	wat_send_dtmf(wat->wat_span_id, wat->pvt->subs[WAT_CALL_SUB_REAL].wat_call_id, dtmf, sig_wat_dtmf_response, wat);

	return 0;
}

int action_watshowspans(struct mansession *s, const struct message *m)
{
	int span = 0;
	int num_spans = 0;
	char action_id[256];

	const char *span_string = astman_get_header(m, "Span");
	const char *id = astman_get_header(m, "ActionID");
	
	if (!ast_strlen_zero(id)) {
		snprintf(action_id, sizeof(action_id), "ActionID: %s\r\n", id);
	} else {
		action_id[0] = '\0';
	}
	
	if (!ast_strlen_zero(span_string)) {
		char dest[30];
		span = atoi(span_string);
		if ((span < 1) || (span > WAT_NUM_SPANS)) {
			astman_send_error(s, m, "No such span");
			goto done;
		}
		num_spans = 1;
		astman_send_ack(s, m, sig_wat_show_span(dest, &wats[span].wat));
		goto done;
	}

	for (span = 0; span < WAT_NUM_SPANS; span++) {
		if (wats[span].wat.wat_span_id) {
			char dest[30];
			num_spans++;

			astman_send_ack(s, m, sig_wat_show_span(dest, &wats[span].wat));
		}
	}

	if (!num_spans) {
		astman_send_error(s, m, "No WAT spans configured\n");
	}
	
done:
	astman_append(s, "Event: %sComplete\r\n"
	"Items: %d\r\n"
			"%s"
			"\r\n",
			"WATShowSpans",
			num_spans,
			action_id);
	return 0;	
}

int action_watshowspan(struct mansession *s, const struct message *m)
{
	int span = 0;
	int num_spans = 0;
	char action_id[256];

	const char *span_string = astman_get_header(m, "Span");
	const char *id = astman_get_header(m, "ActionID");

	if (!ast_strlen_zero(id)) {
		snprintf(action_id, sizeof(action_id), "ActionID: %s\r\n", id);
	} else {
		action_id[0] = '\0';
	}
	
	if (!ast_strlen_zero(span_string)) {
		char dest[200];
		span = atoi(span_string);
		if ((span < 1) || (span > WAT_NUM_SPANS)) {
			astman_send_error(s, m, "No such span");
			goto done;
		}
		num_spans = 1;
		astman_send_ack(s, m, sig_wat_show_span_verbose(dest, &wats[span].wat));
		goto done;
	}

	for (span = 0; span < WAT_NUM_SPANS; span++) {
		if (wats[span].wat.wat_span_id) {
			char dest[200];
			num_spans++;

			astman_send_ack(s, m, sig_wat_show_span_verbose(dest, &wats[span].wat));
		}
	}
	if (!num_spans) {
		astman_send_error(s, m, "No WAT spans configured\n");
	}

done:
	astman_append(s, "Event: %sComplete\r\n"
						"Items: %d\r\n"
						"%s"
						"\r\n",
						"WATShowSpan",
						num_spans,
						action_id);
	return 0;
}

int action_watsendsms(struct mansession *s, const struct message *m)
{
	int span;
	wat_sms_event_t event;
	const char *id, *span_string;
	const char *to_number, *to_plan, *to_type;
	const char *smsc_number, *smsc_plan, *smsc_type;
	const char *reject_duplicates, *reply_path, *status_report_request, *reference_number, *validity_period_type, *validity_period_value;
	const char *class, *concatenate_reference_id, *concatenate_total_messages, *concatenate_sequence_num;
	const char *content, *content_type, *content_transfer_encoding;

	wat_sms_type_t type = WAT_SMS_TXT;

	memset(&event, 0, sizeof(event));

	id = astman_get_header(m, "ActionID");
	if (ast_strlen_zero(id)) {
		id = NULL;
	}

	span_string = astman_get_header(m, "Span");
	if (ast_strlen_zero(span_string)) {
		astman_send_error(s, m, "Missing Span header");
		return 0;
	}
	
	span = atoi(span_string);
	if ((span < 1) || (span > WAT_NUM_SPANS)) {
		astman_send_error(s, m, "No such span");
		return 0;
	}

	to_number = astman_get_header(m, "To-Number");
	if (!ast_strlen_zero(to_number)) {
		memcpy(event.to.digits, to_number, sizeof(event.to.digits));
	} else {
		astman_send_error(s, m, "Missing To-Number header");
		return 0;
	}

	to_plan = astman_get_header(m, "To-Plan");
	if (!ast_strlen_zero(to_plan)) {
		event.to.plan = wat_str2wat_number_plan(to_plan);
	} else {
		event.to.plan = WAT_NUMBER_PLAN_ISDN;
	}

	to_type = astman_get_header(m, "To-Type");
	if (!ast_strlen_zero(to_plan)) {
		event.to.type = wat_str2wat_number_type(to_type);
	} else {
		event.to.type = WAT_NUMBER_TYPE_NATIONAL;
	}

	smsc_number = astman_get_header(m, "X-SMS-SMSC-Number");
	if (!ast_strlen_zero(smsc_number)) {
		memcpy(event.pdu.smsc.digits, smsc_number, sizeof(event.pdu.smsc.digits));

		smsc_plan = astman_get_header(m, "X-SMS-SMSC-Plan");
		if (!ast_strlen_zero(smsc_plan)) {
			event.pdu.smsc.plan = wat_str2wat_number_plan(smsc_plan);
		} else {
			event.pdu.smsc.type = WAT_NUMBER_PLAN_ISDN;
		}
		
		smsc_type = astman_get_header(m, "X-SMS-SMSC-Type");
		if (!ast_strlen_zero(smsc_type)) {
			event.pdu.smsc.type = wat_str2wat_number_type(smsc_type);
		} else {
			event.pdu.smsc.type = WAT_NUMBER_TYPE_NATIONAL;
		}
	}
	
	reject_duplicates = astman_get_header(m, "X-SMS-Reject-Duplicates");
	if (!ast_strlen_zero(reject_duplicates)) {
		event.pdu.sms.submit.tp_rd = ast_true(reject_duplicates);
	}
	
	reply_path = astman_get_header(m, "X-SMS-Reply-Path");
	if (!ast_strlen_zero(reply_path)) {
		event.pdu.sms.submit.tp_rp = ast_true(reply_path);
	}
	
	status_report_request = astman_get_header(m, "X-SMS-Status-Report-Request");
	if (!ast_strlen_zero(status_report_request)) {
		event.pdu.sms.submit.tp_srr = ast_true(status_report_request);
	}
	
	reference_number = astman_get_header(m, "X-SMS-Reference-Number");
	if (!ast_strlen_zero(reference_number)) {
		event.pdu.tp_message_ref = atoi(reference_number);
	}
	
	validity_period_type = astman_get_header(m, "X-SMS-Validity-Period-Type");
	if (!ast_strlen_zero(validity_period_type)) {
		event.pdu.sms.submit.vp.type = wat_str2wat_sms_pdu_vp_type(validity_period_type);

		validity_period_value = astman_get_header(m, "X-SMS-Validity-Period");
		if (ast_strlen_zero(validity_period_value)) {
			astman_send_error(s, m, "X-SMS-Validity-Period not specified");
			return -1;
		}

		switch(event.pdu.sms.submit.vp.type) {
			case WAT_SMS_PDU_VP_NOT_PRESENT:
				break;
			case WAT_SMS_PDU_VP_ABSOLUTE:
				astman_send_error(s, m, "Absolute Validity Period not implemented yet");
				break;
			case WAT_SMS_PDU_VP_RELATIVE:
				event.pdu.sms.submit.vp.data.relative = atoi(validity_period_value);
				break;
			case WAT_SMS_PDU_VP_ENHANCED:
				astman_send_error(s, m, "Enhanced Validity Period not implemented yet");
				break;
			case WAT_SMS_PDU_VP_INVALID:
				astman_send_error(s, m, "Invalid Validity Period type");
				return -1;
		}
	} else {
		event.pdu.sms.submit.vp.type = WAT_SMS_PDU_VP_RELATIVE;
		event.pdu.sms.submit.vp.data.relative = 0xAB;
	}
	
	class = astman_get_header(m, "X-SMS-Class");
	if (!ast_strlen_zero(class)) {
		event.pdu.dcs.msg_class = wat_str2wat_sms_pdu_dcs_msg_cls(class);
	} else {
		event.pdu.dcs.msg_class = WAT_SMS_PDU_DCS_MSG_CLASS_ME_SPECIFIC;
	}

	concatenate_reference_id = astman_get_header(m, "X-SMS-Concat-Reference-ID");
	if (!ast_strlen_zero(concatenate_reference_id)) {
		event.pdu.udh.refnr = atoi(concatenate_reference_id);
	}

	concatenate_total_messages = astman_get_header(m, "X-SMS-Concat-Total-Messages");
	if (!ast_strlen_zero(concatenate_total_messages)) {
		event.pdu.udh.total = atoi(concatenate_total_messages);
	}
	
	concatenate_sequence_num = astman_get_header(m, "X-SMS-Concat-Sequence-Number");
	if (!ast_strlen_zero(concatenate_sequence_num)) {
		event.pdu.udh.seq = atoi(concatenate_sequence_num);
	}
	
	content = astman_get_header(m, "Content");
	if (!ast_strlen_zero(content)) {
		event.content.len = strlen(content);
		strncpy(event.content.data, content, sizeof(event.content.data));
	} else {
		astman_send_error(s, m, "Missing Content header");
		return -1;
	}
	
	content_type = astman_get_header(m, "Content-type");
	if (!ast_strlen_zero(content_type)) {
		char *p = NULL;

		type = WAT_SMS_PDU;
		p = strstr(content_type, "charset");
		if (p == NULL) {
			p = strstr(content_type, "Charset");
		}
		if (p == NULL) {
			ast_log(LOG_ERROR, "Span %d: Invalid \"Content-Type\" format (%s)\n", span + 1, content_type);
			return -1;
		}
		p+=strlen("charset=");

		event.content.charset = wat_str2wat_sms_content_charset(p);
	}

	content_transfer_encoding = astman_get_header(m, "Content-Transfer-Encoding");
	if (!ast_strlen_zero(content_transfer_encoding)) {
		/* format: base64, hex */
		
		event.content.encoding = wat_str2wat_sms_content_encoding(content_transfer_encoding);
	}

	event.type = type;

	if (sig_wat_send_sms(&wats[span-1].wat, &event, id) != 0) {
		astman_send_error(s, m, "Failed to send SMS");	
	}

	return 0;
}


static char *wat_complete_span_helper(const char *line, const char *word, int pos, int state, int rpos)
{
	int which, span;
	char *ret = NULL;

	if (pos != rpos)
		return ret;

	for (which = span = 0; span < WAT_NUM_SPANS; span++) {
		if (wats[span].wat.wat_span_id && ++which > state) {
			if (asprintf(&ret, "%d", span + 1) < 0) {	/* user indexes start from 1 */
				ast_log(LOG_WARNING, "asprintf() failed: %s\n", strerror(errno));
			}
			break;
		}
	}
	return ret;
}

static char *wat_complete_span_4(const char *line, const char *word, int pos, int state)
{
	return wat_complete_span_helper(line,word,pos,state,3);
}

char *handle_wat_send_sms(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int span;
	wat_sms_event_t event;
	memset(&event, 0, sizeof(event));
	
	switch (cmd) {
		case CLI_INIT:
			e->command = "wat send sms";
			e->usage =
					"Usage: wat send sms <span> <number> <sms>\n"
					"       Send a sms on <span> <number> <sms>\n";
			return NULL;
		case CLI_GENERATE:
			return NULL;
	}

	if (a->argc < 6)
		return CLI_SHOWUSAGE;

	span = atoi(a->argv[3]);
	if ((span < 1) || (span > WAT_NUM_SPANS)) {
		ast_cli(a->fd, "Invalid span '%s'.  Should be a number from %d to %d\n", a->argv[3], 1, WAT_NUM_SPANS);
		return CLI_SUCCESS;
	}

	if (!wats[span-1].wat.wat_span_id) {
		ast_cli(a->fd, "No WAT running on span %d\n", span);
		return CLI_SUCCESS;
	}

	event.type = WAT_SMS_TXT;
	strncpy(event.to.digits, a->argv[4], sizeof(event.to.digits));
	strncpy(event.content.data, a->argv[5], sizeof(event.content.data));
	event.content.len = strlen(event.content.data);

	sig_wat_send_sms(&wats[span-1].wat, &event, NULL);
	return CLI_SUCCESS;
}

char *handle_wat_show_spans(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int span;
	int num_spans = 0;

	switch (cmd) {
		case CLI_INIT:
			e->command = "wat show spans";
			e->usage =
					"Usage: wat show spans\n"
					"       Displays WAT span information\n";
			return NULL;
		case CLI_GENERATE:
			return NULL;
	}

	if (a->argc != 3)
		return CLI_SHOWUSAGE;

	for (span = 0; span < WAT_NUM_SPANS; span++) {
		if (wats[span].wat.wat_span_id) {
			char dest[50];
			num_spans++;

			ast_cli(a->fd, "%s", sig_wat_show_span(dest, &wats[span].wat));
		}
	}
	if (!num_spans) {
		ast_cli(a->fd, "No WAT spans configured\n");
	}
	return CLI_SUCCESS;
}

char *handle_wat_show_span(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char dest[1000];
	int span;

	switch (cmd) {
		case CLI_INIT:
			e->command = "wat show span";
			e->usage =
					"Usage: wat show span <span>\n"
					"       Displays GSM Information on a given WAT span\n";
			return NULL;
		case CLI_GENERATE:
			return wat_complete_span_4(a->line, a->word, a->pos, a->n);
	}

	if (a->argc < 4)
		return CLI_SHOWUSAGE;
	
	span = atoi(a->argv[3]);
	if ((span < 1) || (span > WAT_NUM_SPANS)) {
		ast_cli(a->fd, "Invalid span '%s'.  Should be a number from %d to %d\n", a->argv[3], 1, WAT_NUM_SPANS);
		return CLI_SUCCESS;
	}
	
	if (!wats[span-1].wat.wat_span_id) {
		ast_cli(a->fd, "No WAT running on span %d\n", span);
		return CLI_SUCCESS;
	}

	ast_cli(a->fd, "%s", sig_wat_show_span_verbose(dest, &wats[span-1].wat));

	return CLI_SUCCESS;
}

char *handle_wat_debug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	uint32_t debug_mask = 0;
	switch (cmd) {
		case CLI_INIT:
			e->command = "wat debug";
			e->usage =
				"Usage: wat debug <debug-str>\n"
				"	Valid debug strings: all, uart_raw, uart_dump, call_state, span_state, at_parse, at_handle, sms_encode, sms_decode\n"
				"	The debug string can be a comma separated list of any of those values\n";
			return NULL;
		case CLI_GENERATE:
			return NULL;
	}

	if (a->argc < 3) {
		return CLI_SHOWUSAGE;
	}

	debug_mask = wat_str2debug(a->argv[2]);
	wat_set_debug(debug_mask);
	ast_cli(a->fd, "WAT debug set to: %s (0x%X)\n", a->argv[1], debug_mask);

	return CLI_SUCCESS;
}

char *handle_wat_version(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	unsigned char current = 0;
	unsigned char revision = 0;
	unsigned char age = 0;

	switch (cmd) {
		case CLI_INIT:
			e->command = "wat show version";
			e->usage =
					"Usage: wat show version\n"
					"	Show the libwat version\n";
			return NULL;
		case CLI_GENERATE:
			return NULL;
	}

	wat_version(&current, &revision, &age);
	ast_cli(a->fd, "libwat version: %d.%d.%d\n", current, revision, age);

	return CLI_SUCCESS;
}

char *handle_wat_exec_at(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int span = 0;

	switch (cmd) {
		case CLI_INIT:
			e->command = "wat exec";
			e->usage =
					"Usage: wat exec <span> <AT command>\n"
					"       Executes an arbitrary AT command in the given WAT span\n";
			return NULL;
		case CLI_GENERATE:
			return wat_complete_span_4(a->line, a->word, a->pos, a->n);
	}

	if (a->argc < 4)
		return CLI_SHOWUSAGE;
	span = atoi(a->argv[2]);
	if ((span < 1) || (span > WAT_NUM_SPANS)) {
		ast_cli(a->fd, "Invalid span '%s'.  Should be a number from %d to %d\n", a->argv[2], 1, WAT_NUM_SPANS);
		return CLI_SUCCESS;
	}
	if (!wats[span-1].wat.wat_span_id) {
		ast_cli(a->fd, "No WAT running on span %d\n", span);
		return CLI_SUCCESS;
	}

	sig_wat_exec_at(&wats[span-1].wat, a->argv[3]);

	return CLI_SUCCESS;
}


#if defined(ASTERISK_COMPILING_TRUNK)
#undef ASTERISK_VERSION_NUM
#endif

#endif /* HAVE_WAT */
