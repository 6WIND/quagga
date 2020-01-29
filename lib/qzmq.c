/*
 * libzebra ZeroMQ bindings
 * Copyright (C) 2015  David Lamparter, for NetDEF, Inc.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Quagga is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with Quagga; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>
#include <zmq.h>

#include "thread.h"
#include "memory.h"
#include "qzmq.h"
#include "log.h"

/* libzmq's context */
void *qzmq_context = NULL;

void qzmq_init (void)
{
  qzmq_context = zmq_ctx_new ();
}

void qzmq_finish (void)
{
  zmq_ctx_term (qzmq_context);
  qzmq_context = NULL;
}

/* read callback integration */
struct qzmq_cb {
  struct thread *thread;
  void *zmqsock;
  void *arg;

#if 0
  void (*cb_buf)(void *arg, void *zmqsock, const uint8_t *buf, size_t len);
#endif
  void (*cb_msg)(void *arg, void *zmqsock, zmq_msg_t *msg);
};


static int qzmq_read_msg (struct thread *t)
{
  struct qzmq_cb *cb = THREAD_ARG (t);
  zmq_msg_t msg;
  int ret;
  struct qzc_sock *ctxt;

  ctxt = cb->zmqsock;
  cb->thread = NULL;

  while (1)
    {
      zmq_pollitem_t polli = { .socket = ctxt->zmq, .events = ZMQ_POLLIN };
      ret = zmq_poll (&polli, 1, 0);

      if (ret < 0)
        goto out_err;
      if (!(polli.revents & ZMQ_POLLIN))
        break;

      if (zmq_msg_init (&msg))
        goto out_err;
      ret = zmq_msg_recv (&msg, ctxt->zmq, ZMQ_NOBLOCK);
      if (ret < 0)
        {
          if (errno == EAGAIN)
            break;

          zmq_msg_close (&msg);
          goto out_err;
        }
      cb->cb_msg (cb->arg, ctxt, &msg);
      zmq_msg_close (&msg);
    }

  /* update ctxt if necessary */
  t->u.fd = ctxt->fd;
  cb->thread = funcname_thread_add_read (t->master, qzmq_read_msg, cb,
        t->u.fd, t->funcname, t->schedfrom, t->schedfrom_line);
  return 0;

out_err:
  zlog_err ("ZeroMQ error: %s(%d)", strerror (errno), errno);
  return 0;
}

#if 0
static int qzmq_read_buf (struct thread *t)
{
  return 0;
}

struct qzmq_cb *funcname_qzmq_thread_read_buf (
        struct thread_master *master,
        void (*func)(void *arg, void *zmqsock, const uint8_t *buf, size_t len),
        void *arg, void *zmqsock, debugargdef)
{
  int fd;
  size_t fd_len = sizeof (fd);
  struct qzmq_cb *cb;

  if (zmq_getsockopt (zmqsock, ZMQ_FD, &fd, &fd_len))
    return NULL;

  cb = XCALLOC (MTYPE_ZEROMQ_CB, sizeof (struct qzmq_cb));
  if (!cb)
    return NULL;

  cb->arg = arg;
  cb->zmqsock = zmqsock;
  cb->cb_buf = func;
  cb->thread = funcname_thread_add_read (master, qzmq_read_buf, cb, fd,
                                         funcname, schedfrom, fromln);
  return cb;
}
#endif

struct qzmq_cb *funcname_qzmq_thread_read_msg (
        struct thread_master *master,
        void (*func)(void *arg, void *zmqsock, zmq_msg_t *msg),
        void *arg, void *zmqsock, debugargdef)
{
  int fd;
  size_t fd_len = sizeof (fd);
  struct qzmq_cb *cb;
  struct qzc_sock *ctxt = zmqsock;

  if (zmq_getsockopt (ctxt->zmq, ZMQ_FD, &fd, &fd_len))
    return NULL;

  ctxt->fd = fd;
  cb = XCALLOC (MTYPE_ZEROMQ_CB, sizeof (struct qzmq_cb));
  if (!cb)
    return NULL;

  cb->arg = arg;
  cb->zmqsock = zmqsock;
  cb->cb_msg = func;
  cb->thread = funcname_thread_add_read (master, qzmq_read_msg, cb, fd,
                                         funcname, schedfrom, fromln);
  return cb;
}

void qzmq_thread_cancel (struct qzmq_cb *cb)
{
  if (cb->thread) {
    thread_cancel (cb->thread);
    XFREE (MTYPE_ZEROMQ_CB, cb);
  }
}
