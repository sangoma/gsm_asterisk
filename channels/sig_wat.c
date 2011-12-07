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

#include "sig_wat.h"

#define SIGCHAN_NOTINALARM  (1 << 0)
#define SIGCHAN_UP          (1 << 1)

#define WAT_DEADLOCK_AVOIDANCE(p) \
	do { \
		sig_wat_unlock_private(p); \
		usleep(1); \
		sig_wat_lock_private(p); \
} while (0)


#define WAT_NOT_IMPL ast_log(LOG_WARNING, "Function not implemented (%s:%s:%d)\n", __FILE__, __FUNCTION__, __LINE__);

void sig_wat_alarm(unsigned char span_id, wat_alarm_t alarm);
void *sig_wat_malloc(size_t size);
void *sig_wat_calloc(size_t nmemb, size_t size);
void sig_wat_free(void *ptr);
void sig_wat_log(unsigned char loglevel, char *fmt, ...);
void sig_wat_log_span(unsigned char span_id, unsigned char loglevel, char *fmt, ...);
void sig_wat_assert(char *message);
int sig_wat_span_write(unsigned char span_id, void *buffer, unsigned len);
void sig_wat_status_change(unsigned char span_id, wat_sigstatus_t status);

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

struct sig_wat_span **wat_spans;
struct sig_wat_sms **wat_smss;

void sig_wat_alarm(unsigned char span_id, wat_alarm_t alarm)
{
	if (alarm == WAT_ALARM_NONE) {
		ast_log(LOG_NOTICE, "Span %d:Alarms cleared\n", span_id);
	} else {
		ast_log(LOG_WARNING, "Span %d:Alarm (%s)\n", span_id, wat_decode_alarm(alarm));
	}
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

void sig_wat_status_change(unsigned char span_id, wat_sigstatus_t status)
{
	struct sig_wat_span *wat = wat_spans[span_id];
	
	ast_assert(wat != NULL);
	
	if (status == WAT_SIGSTATUS_UP) {
		ast_verb(2, "Span %d:Signalling up\n", wat->span + 1);
		wat->sigchanavail |= SIGCHAN_UP;
	} else {
		ast_verb(2, "Span %d:Signalling down\n", wat->span + 1);
		wat->sigchanavail &= ~SIGCHAN_UP;
	}

}

void sig_wat_con_ind(unsigned char span_id, uint8_t call_id, wat_con_event_t *con_event)
{
	struct sig_wat_span *wat;
	struct ast_channel *chan;


	wat = wat_spans[span_id];
	ast_assert(wat != NULL);
	ast_assert(con_event->sub < WAT_CALL_SUB_INVALID);

	ast_verb(3, "Span %d: Call Incoming (%s)\n",
									wat->span + 1,
									(con_event->sub == WAT_CALL_SUB_REAL) ? "Real":
									(con_event->sub == WAT_CALL_SUB_CALLWAIT) ? "Call Waiting":
									(con_event->sub == WAT_CALL_SUB_THREEWAY) ? "3-way":"Invalid");

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

	if (wat->pvt->use_callerid) {
		/* TODO: Set plan etc.. properly */
		strcpy(wat->pvt->cid_num, con_event->calling_num.digits);
	}

	if (ast_exists_extension(NULL, wat->pvt->context, "s", 1, wat->pvt->cid_num)) {
		sig_wat_unlock_private(wat->pvt);
		chan = sig_wat_new_ast_channel(wat->pvt, AST_STATE_RING, 0, con_event->sub, NULL);
		sig_wat_lock_private(wat->pvt);
		if (chan && !ast_pbx_start(chan)) {
			ast_verb(3, "Accepting call from '%s', span %d\n", wat->pvt->cid_num, wat->span);
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
		ast_verb(3, "No \'s' extension in context '%s'\n", wat->pvt->context);
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
	ast_assert(wat != NULL);
	ast_verb(3, "Span %d: SMS received\n %s\n", wat->span + 1, sms_event->message);
}

void sig_wat_sms_sts(unsigned char span_id, uint8_t sms_id, wat_sms_status_t *sms_status)
{
	struct sig_wat_span *wat = wat_spans[span_id];	
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
	ast_free(wat->smss[sms_id]);
	wat->smss[sms_id] = NULL;
	sig_wat_unlock_private(wat->pvt);
	return;
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
		ast_log(LOG_ERROR, "Span :%d Failed to find a free call ID\n", p->wat->span+1);
		sig_wat_unlock_private(wat->pvt);
		return -1;
	}

	if (wat->pvt->subs[WAT_CALL_SUB_REAL].allocd) {
		ast_log(LOG_ERROR, "Span %d: Got an outgoing call but we already had a call. Ignoring Call.\n", wat->span);
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

	f.subclass.integer = subclass;
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
	struct ast_channel *c;
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
	return 0;
}

void sig_wat_stop_wat(struct sig_wat_span *wat)
{
	wat_span_stop(wat->wat_span_id);
}

void sig_wat_load(int maxspans)
{
	wat_interface_t wat_intf;

	wat_spans = malloc(maxspans * sizeof(void*));
	memset(wat_spans, 0, maxspans * sizeof(void*));

	memset(&wat_intf, 0, sizeof(wat_intf));

	wat_intf.wat_span_write = sig_wat_span_write;
	wat_intf.wat_sigstatus_change = sig_wat_status_change;
	wat_intf.wat_log = (wat_log_func_t)sig_wat_log;
	wat_intf.wat_log_span = (wat_log_span_func_t)sig_wat_log_span;
	wat_intf.wat_malloc = sig_wat_malloc;
	wat_intf.wat_calloc = sig_wat_calloc;
	wat_intf.wat_free = sig_wat_free;
	wat_intf.wat_assert = sig_wat_assert;

	wat_intf.wat_alarm = sig_wat_alarm;
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
	if (wat_spans) free(wat_spans);
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
	return;
}

void wat_event_noalarm(struct sig_wat_span *wat)
{
	wat->sigchanavail |= SIGCHAN_NOTINALARM;
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

void sig_wat_cli_show_spans(int fd, int span, struct sig_wat_span *wat)
{	
	char status[30];
	const wat_sim_info_t *sim_info = NULL;

	build_span_status(status, sizeof(status), wat->sigchanavail);
	
	sim_info = wat_span_get_sim_info(wat->wat_span_id);
	if (sim_info == NULL) {
		ast_cli(fd, "Span %d:Failed to get SIM information\n", wat->span +1);
	}

	if (sim_info && strlen(sim_info->subscriber.digits) > 0) {
		ast_cli(fd, "WAT span %d: %5s (%14s)\n", span, status, sim_info->subscriber.digits);
	} else {
		ast_cli(fd, "WAT span %d: %5s\n", span, status);
	}
}

void sig_wat_cli_show_span(int fd, struct sig_wat_span *wat)
{
	char status[256];
	const wat_chip_info_t *chip_info = NULL;
	const wat_sim_info_t *sim_info = NULL;
	const wat_sig_info_t *sig_info = NULL;
	const wat_net_info_t *net_info = NULL;
	const wat_pin_stat_t *pin_status = NULL;	
	const char *last_error = NULL;
	wat_alarm_t alarm = WAT_ALARM_NONE;
	
	build_span_status(status, sizeof(status), wat->sigchanavail);

	ast_cli(fd, "WAT span %d\n", wat->span + 1);
	ast_cli(fd, "   Signalling:%s\n", status);

	last_error = wat_span_get_last_error(wat->wat_span_id);
	if (last_error != NULL) {
		ast_cli(fd, "   Last Error:%s\n\n", last_error);
	}

	alarm = wat_span_get_alarms(wat->wat_span_id);
	if (alarm != WAT_ALARM_NONE) {
		ast_cli(fd, "   Alarm:%s\n\n", wat_decode_alarm(alarm));
	}

	pin_status = wat_span_get_pin_info(wat->wat_span_id);
	if (pin_status == NULL) {
		ast_cli(fd, "Span %d:Failed to get PIN status\n", wat->span + 1);
	} else if (*pin_status != WAT_PIN_READY) {
		ast_cli(fd, "   PIN Error:%s\n\n", wat_decode_pin_status(*pin_status));
	}

	if (alarm != WAT_ALARM_NO_SIGNAL) {
		net_info = wat_span_get_net_info(wat->wat_span_id);
		if (net_info == NULL) {
			ast_cli(fd, "Span %d:Failed to get Network information\n", wat->span +1);
		} else {
			ast_cli(fd, "   Status: %s\n", wat_net_stat2str(net_info->stat));
			ast_cli(fd, "   Operator: %s\n\n", net_info->operator_name);
		}

		sig_info = wat_span_get_sig_info(wat->wat_span_id);
		if (sig_info == NULL) {
			ast_cli(fd, "Span %d:Failed to get Signal information\n", wat->span +1);
		} else {
			char dest[30];
			ast_cli(fd, "   Signal strength: %s\n", wat_decode_rssi(dest, sig_info->rssi));
			ast_cli(fd, "   Signal BER: %s\n\n", wat_decode_ber(sig_info->ber));
		}

		sim_info = wat_span_get_sim_info(wat->wat_span_id);
		if (sim_info == NULL) {
			ast_cli(fd, "Span %d:Failed to get SIM information\n", wat->span +1);
		} else {
			ast_cli(fd, "   Subscriber: %s type:%d plan:%d <%s> \n",
					sim_info->subscriber.digits,
	 				sim_info->subscriber.type,
					sim_info->subscriber.plan,
					sim_info->subscriber_type);

			ast_cli(fd, "   IMSI: %s\n\n", sim_info->imsi);
		}
	}

	chip_info = wat_span_get_chip_info(wat->wat_span_id);
	if (chip_info == NULL) {
		ast_cli(fd, "Span %d:Failed to get Chip information\n", wat->span +1);
	} else {
		ast_cli(fd, "   Manufacturer Name: %s\n", chip_info->manufacturer_name);
		ast_cli(fd, "   Manufacturer ID: %s\n", chip_info->manufacturer_id);
		ast_cli(fd, "   Revision ID: %s\n", chip_info->revision);
		ast_cli(fd, "   Serial Number: %s\n", chip_info->serial);
	}

	return;
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
	char x = 0;
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

	sig_wat_lock_owner(wat);

	x = 1;
	ast_channel_setoption(wat->pvt->owner, AST_OPTION_DIGIT_DETECT, &x, sizeof(char), 0);

	ast_channel_unlock(wat->pvt->owner);

done:
	sig_wat_unlock_private(wat->pvt);

	ast_mutex_unlock(&wat->lock);

	return i;
}

void sig_wat_cli_exec_at(int fd, struct sig_wat_span *wat, const char *at_cmd)
{
	wat_cmd_req(wat->wat_span_id, at_cmd, sig_wat_at_response, wat);
}

void sig_wat_cli_send_sms(int fd, struct sig_wat_span *wat, const char *dest, const char *sms)
{
	int i;
	struct sig_wat_sms *wat_sms;

	if (strlen(sms) > WAT_MAX_SMS_SZ) {
		ast_log(LOG_ERROR, "Span %d: SMS exceeds maximum length (len:%zd max:%d)\n", wat->span + 1, strlen(sms), WAT_MAX_SMS_SZ);
		return;
	}
	
	sig_wat_lock_private(wat->pvt);
	
	/* Find a free SMS Id */
	for (i = 1; i < ARRAY_LEN(wat->smss); i++) {
		if (!wat->smss[i]) {
			break;
		}
	}

	if (i >= ARRAY_LEN(wat->smss)) {
		ast_log(LOG_ERROR, "Span :%d Failed to find a free SMS ID\n", wat->span + 1);
		sig_wat_unlock_private(wat->pvt);
		return;
	}

	wat_sms = ast_malloc(sizeof(*wat_sms));
	if (!wat_sms) {
		sig_wat_unlock_private(wat->pvt);
		return;
	}

	wat->smss[i] = wat_sms;
	sig_wat_unlock_private(wat->pvt);

	memset(wat_sms, 0, sizeof(*wat_sms));

	wat_sms->wat_sms_id = i;

	wat_sms->sms_event.type = WAT_SMS_TXT;
	wat_sms->sms_event.len = strlen(sms);
	strncpy(wat_sms->sms_event.called_num.digits, dest, sizeof(wat_sms->sms_event.called_num.digits));
	strncpy(wat_sms->sms_event.message, sms, sizeof(wat_sms->sms_event.message));

	ast_verb(3, "Span %d: Sending sms len:%d (id:%d)\n", wat->span + 1, wat_sms->sms_event.len, wat_sms->wat_sms_id);
	ast_verb(5, "<begin>\n%s\n<end>\n\n", wat_sms->sms_event.message);

	if (wat_sms_req(wat->wat_span_id, wat_sms->wat_sms_id, &wat_sms->sms_event)) {
		ast_verb(1, "Span %d: Failed to send sms\n", wat->span + 1);
	}
	return;
}


int sig_wat_digit_begin(struct sig_wat_chan *p, struct ast_channel *ast, char digit)
{
	struct sig_wat_span *wat;
	char x = 0;
	int count = 0;
	char dtmf[2] = { digit, '\0' };

	wat = p->wat;

	ast_assert(wat != NULL);

	ast_mutex_lock(&wat->lock);
	wat->dtmf_count++;
	count = wat->dtmf_count;
	ast_mutex_unlock(&wat->lock);

	/* Disable DTMF detection while we play DTMF because the GSM module will play back some sort of feedback tone */
	if (count == 1) {
		x = 0;
		ast_channel_setoption(wat->pvt->owner, AST_OPTION_DIGIT_DETECT, &x, sizeof(char), 0);
	}
	wat_send_dtmf(wat->wat_span_id, wat->pvt->subs[WAT_CALL_SUB_REAL].wat_call_id, dtmf, sig_wat_dtmf_response, wat);

	return 0;
}

#endif /* HAVE_WAT */
