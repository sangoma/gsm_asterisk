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

#include "sig_wat.h"

#define SIGCHAN_NOTINALARM  (1 << 0)
#define SIGCHAN_UP          (1 << 1)

void sig_wat_alarm(unsigned char span_id, wat_alarm_t alarm);
void *sig_wat_malloc(size_t size);
void *sig_wat_calloc(size_t nmemb, size_t size);
void sig_wat_free(void *ptr);
void sig_wat_log(unsigned char loglevel, char *fmt, ...);
void sig_wat_assert(char *message);
void sig_wat_span_write(unsigned char span_id, void *buffer, unsigned len);

void sig_wat_call_incoming(unsigned char span_id, uint8_t call_id, wat_con_event_t *con_event);
void sig_wat_call_answer(unsigned char span_id, uint8_t call_id, wat_cmd_status_t *status);
void sig_wat_call_hangup(unsigned char span_id, uint8_t call_id, wat_rel_event_t *rel_event);
void sig_wat_call_release(unsigned char span_id, uint8_t call_id, wat_cmd_status_t *status);
void sig_wat_sms_incoming(unsigned char span_id, uint8_t call_id, wat_sms_event_t *sms_event);
void sig_wat_sms_complete(unsigned char span_id, uint8_t sms_id, wat_cmd_status_t *status);
void sig_wat_command_complete(unsigned char span_id, wat_cmd_status_t *status);

static void sig_wat_handle_sigchan_exception(struct sig_wat_span *wat);
static void sig_wat_handle_sigchan_data(struct sig_wat_span *wat);
static void sig_wat_lock_private(struct sig_wat_chan *p);
static void sig_wat_unlock_private(struct sig_wat_chan *p);

static void sig_wat_set_caller_id(struct sig_wat_call *call);
static void sig_wat_open_media(struct sig_wat_chan *p);
static struct ast_channel *sig_wat_new_ast_channel(struct sig_wat_chan *p, int state, int sub, const struct ast_channel *requestor);

struct sig_wat_span **wat_ids;

void sig_wat_alarm(unsigned char span_id, wat_alarm_t alarm)
{
	WAT_NOT_IMPL
}

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
	return;
}

void sig_wat_assert(char *message)
{
	ast_log(LOG_ERROR, "%s", message);
	ast_assert(0);
}

void sig_wat_span_write(unsigned char span_id, void *buffer, unsigned len)
{
	int res;
	struct sig_wat_span *wat = wat_ids[span_id];
	
	ast_assert(wat);
	
	res = write(wat->fd, buffer, len);
	if (res < 0) {
		if (errno != EAGAIN) {
			ast_log(LOG_ERROR, "Span %d:Write failed: %s\n", wat->span, strerror(errno));
		}
	}
	if (res != len) {
		ast_log(LOG_ERROR, "Span %d:Short write %d (len:%d)\n", wat->span, res, len);
	}
}

void sig_wat_call_incoming(unsigned char span_id, uint8_t call_id, wat_con_event_t *con_event)
{
	int sub;
	struct sig_wat_call *call;
	struct sig_wat_span *wat = wat_ids[span_id];
	
	ast_assert(wat);
	
	sig_wat_lock_private(wat->pvt);

	/* DAVIDY: Check if we need to lock pvt->lock ??? */
	if (wat->pvt->call) {
		ast_log(LOG_ERROR, "Span %d: Got CRING/RING but we already had a call. Dropping Call.\n", wat->span);
		sig_wat_unlock_private(wat->pvt);
		return;
	}

	/* Create a new call */
	call = ast_malloc(sizeof(*call));
	memset(call, 0, sizeof(*call));

	call->chan = wat->pvt;
	call->wat_call_id = call_id;

	sig_wat_new_ast_channel(wat->pvt, AST_STATE_RING, con_event->sub, NULL);
	
	/* Mark the channel as in use */
	wat->pvt->call = call;

	if (con_event->calling_num.validity == WAT_NUMBER_VALIDITY_VALID) {
		strcpy(call->cid_num, con_event->calling_num.digits);
		/* TODO: Set the TON/NPI properly */
		//call->cid_ton = con_event->calling_num.type;

		sig_wat_set_caller_id(call);
	}
	
	sig_wat_unlock_private(wat->pvt);

	
	return;
}

void sig_wat_call_answer(unsigned char span_id, uint8_t call_id, wat_cmd_status_t *status)
{
	WAT_NOT_IMPL
}

void sig_wat_call_hangup(unsigned char span_id, uint8_t call_id, wat_rel_event_t *rel_event)
{
	struct sig_wat_span *wat = wat_ids[span_id];
	
	ast_assert(wat);
	
	sig_wat_lock_private(wat->pvt);

	if (!wat->pvt->call) {
		ast_log(LOG_ERROR, "Span %d: Got hangup, but there was not call.\n", wat->span);
		sig_wat_unlock_private(wat->pvt);
		return;
	}
	if (wat->pvt->owner) {
		wat->pvt->owner->hangupcause = rel_event->cause;
		wat->pvt->owner->_softhangup |= AST_SOFTHANGUP_DEV;
	} else {
		/* Proceed with the hangup even though we do not have an owner */
		wat_rel_cfm(span_id, call_id);
		ast_free(wat->pvt->call);
		wat->pvt->call = NULL;
	}
	sig_wat_unlock_private(wat->pvt);
	return;
}

void sig_wat_call_release(unsigned char span_id, uint8_t call_id, wat_cmd_status_t *status)
{
	struct sig_wat_span *wat = wat_ids[span_id];
	
	ast_assert(wat);
	
	sig_wat_lock_private(wat->pvt);

	if (!wat->pvt->call) {
		ast_log(LOG_ERROR, "Span %d: Got Release, but there was not call.\n", wat->span);
		sig_wat_unlock_private(wat->pvt);
		return;
	}

	ast_verb(3, "Span %d: Channel got release\n", wat->span);

	ast_free(wat->pvt->call);
	wat->pvt->call = NULL;

	sig_wat_unlock_private(wat->pvt);
	return;
}

void sig_wat_sms_incoming(unsigned char span_id, uint8_t call_id, wat_sms_event_t *sms_event)
{
	WAT_NOT_IMPL
}

void sig_wat_sms_complete(unsigned char span_id, uint8_t sms_id, wat_cmd_status_t *status)
{
	WAT_NOT_IMPL
}

void sig_wat_command_complete(unsigned char span_id, wat_cmd_status_t *status)
{
	WAT_NOT_IMPL
}

int sig_wat_call(struct sig_wat_chan *p, struct ast_channel *ast, char *rdest)
{
#if 0
	int i;
	
	struct sig_wat_call *call;
	struct sig_wat_span *wat;
	wat_con_event_t con_event;

	wat = p->wat;

	sig_wat_lock_private(wat->pvt);
	
	/* Find a free call ID */

	for (i = 0x8; i < WAT_MAX_CALLS_PER_SPAN; i++) {
		if (!wat_ids[span_id].call_ids[i]) {
			goto found_call_id;
		}
	}

	ast_log(LOG_ERROR, "Span :%d Failed to find a free call ID\n", p->wat->span);
	sig_wat_unlock_private(wat->pvt);	
	return -1;


	/* 
	DAVIDY THIS IS WRONG!!!! need to store CALLS in either SUB_REAL, SUB_WAITING or SUB_THREEWAY
found_call_id:
	*/

	if (wat->pvt->call) {
		ast_log(LOG_ERROR, "Span %d: Got an outgoing call but we already had a call. Ignoring Call.\n", wat->span);
		sig_wat_unlock_private(wat->pvt);
		return -1;
	}

	/* Create a new call */
	call = ast_malloc(sizeof(*call));
	memset(call, 0, sizeof(*call));

	call->chan = wat->pvt;
	call->wat_call_id = call_id;

	sig_wat_new_ast_channel(wat->pvt, AST_STATE_RING, con_event->sub, NULL);
	
	/* Mark the channel as in use */
	wat->pvt->call = call;


	wat_ids[span_id].call_ids[i] = 
	memset(&con_event, 0, sizeof(con_event));
			
	sprintf(con_event.called_num.digits, "6474024627");

	wat_con_req(p->wat->wat_span_id, i, &con_event);
	ast_setstate(ast, AST_STATE_DIALING);
#endif
	return 0;
}

int sig_wat_answer(struct sig_wat_chan *p, struct ast_channel *ast)
{
	int res = 0;

	//sig_pri_set_dialing(p, 0);
	sig_wat_open_media(p);
	res = wat_con_cfm(p->wat->wat_span_id, p->call->wat_call_id);
	
	ast_setstate(ast, AST_STATE_UP);
	return res;
}

int sig_wat_hangup(struct sig_wat_chan *p, struct ast_channel *ast)
{
	int res = 0;

	/* TODO: See if there is more to do here */
	res = wat_rel_req(p->wat->wat_span_id, p->call->wat_call_id);
	
	return res;
}

static void sig_wat_open_media(struct sig_wat_chan *p)
{
	if (p->calls->open_media) {
		p->calls->open_media(p->chan_pvt);
	}
	
}

static void sig_wat_set_caller_id(struct sig_wat_call *call)
{
	struct sig_wat_chan *p;
	struct ast_party_caller caller;

	p = call->chan;
	ast_assert(p);
	
	if (p->calls->set_callerid) {
		ast_party_caller_init(&caller);

		caller.id.number.str = call->cid_num;
		caller.id.number.plan = call->cid_ton;
		caller.id.number.valid = 1;

		p->calls->set_callerid(p->chan_pvt, &caller);
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

static void sig_wat_handle_sigchan_data(struct sig_wat_span *wat)
{
	char buf[1024];
	int res;
	
	res = read(wat->fd, buf, sizeof(buf));
	if (!res) {
		if (errno != EAGAIN) {
			ast_log(LOG_ERROR, "Span %d:Read on %d failed: %s\n", wat->span, wat->fd, strerror(errno));
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

static struct ast_channel *sig_wat_new_ast_channel(struct sig_wat_chan *p, int state, int sub, const struct ast_channel *requestor)
{
	struct ast_channel *c;
	if (p->calls->new_ast_channel) {
		c = p->calls->new_ast_channel(p->chan_pvt, state, sub, requestor);
	} else {
		return NULL;
	}

	if (!c) {
		return NULL;
	}

	if (!p->owner) {
		p->owner = c;
	}

	return c;
}

int sig_wat_start_wat(struct sig_wat_span *wat)
{
	wat_span_config_t span_config;

	ast_assert(!wat_ids[wat->wat_span_id]);

	wat_ids[wat->wat_span_id] = wat;

	wat_span_config(wat->wat_span_id, &wat->wat_cfg);
	wat_span_start(wat->wat_span_id);

	if (ast_pthread_create_background(&wat->master, NULL, wat_sigchannel, wat)) {
		if (wat->fd > 0) {
			close(wat->fd);
			wat->fd = -1;
		}
		ast_log(LOG_ERROR, "Span %d:Unable to spawn D-channnel:%s\n", wat->span, strerror(errno));
		return -1;
	}
	return 0;
}

void sig_wat_stop_wat(struct sig_wat_span *wat)
{
	wat_span_stop(wat->wat_span_id);
}

void sig_wat_load(int maxspans)
{
	wat_interface_t wat_intf;

	wat_ids = malloc(maxspans*sizeof(void*));
	memset(wat_ids, 0, maxspans*sizeof(void*));

	memset(&wat_intf, 0, sizeof(wat_intf));

	wat_intf.wat_span_write = sig_wat_span_write;
	wat_intf.wat_log = sig_wat_log;
	wat_intf.wat_malloc = sig_wat_malloc;
	wat_intf.wat_calloc = sig_wat_calloc;
	wat_intf.wat_free = sig_wat_free;
	wat_intf.wat_assert = sig_wat_assert;

	wat_intf.wat_alarm = sig_wat_alarm;
	wat_intf.wat_con_ind = sig_wat_call_incoming;
	wat_intf.wat_con_cfm = sig_wat_call_answer;
	wat_intf.wat_rel_ind = sig_wat_call_hangup;
	wat_intf.wat_rel_cfm = sig_wat_call_release;
	wat_intf.wat_sms_ind = sig_wat_sms_incoming;
	wat_intf.wat_sms_cfm = sig_wat_sms_complete;
	wat_intf.wat_cmd_cfm = sig_wat_command_complete;

	if (wat_register(&wat_intf)) {
		ast_log(LOG_ERROR, "Unable to register to libwat\n");
		return;
	}
	ast_verb(3, "Registered libwat\n");
	return;	
}

void sig_wat_unload(void)
{
	if (wat_ids) free(wat_ids);
}

void sig_wat_init_wat(struct sig_wat_span *wat)
{
	memset(wat, 0, sizeof(*wat));
	ast_mutex_init(&wat->lock);

	wat->master = AST_PTHREADT_NULL;
	wat->fd = -1;
	return;
}

struct sig_wat_chan *sig_wat_chan_new(void *pvt_data, struct sig_wat_callback *callback, struct sig_wat_span *wat, int channo)
{
	struct sig_wat_chan *p;

	p = ast_calloc(1, sizeof(*p));
	if (!p)
		return p;

	//p->prioffset = channo;
	//p->mastertrunkgroup = trunkgroup;

	p->calls = callback;
	p->chan_pvt = pvt_data;

	p->wat = wat;

	return p;
}

void wat_event_alarm(struct sig_wat_span *wat, int before_start_wat)
{
	wat->sigchanavail &= ~(SIGCHAN_NOTINALARM | SIGCHAN_UP);
	return;
}

void wat_event_noalarm(struct sig_wat_span *wat, int before_start_wat)
{
	wat->sigchanavail |= SIGCHAN_NOTINALARM;
	return;
}

#endif /* HAVE_WAT */
