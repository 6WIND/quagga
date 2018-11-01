/*
 * Copyright (C) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "qzmq.h"
#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "log.h"

#include "qzc.h"

#include "qzc.capnp.h"

static int qzc_debug = 0;
int qzc_simulate_delay = 0;
int qzc_simulate_random = 5;
#define REQUEST_RETRIES     5

static int qzcserver_reconnect_count;

static struct qzc_wkn *wkn_first = NULL;

void qzc_wkn_reg(struct qzc_wkn *wkn)
{
	wkn->next = wkn_first;
	wkn_first = wkn;
}

static struct qzc_wkn *qzc_wkn_find(uint64_t wid)
{
	struct qzc_wkn *wkn;
	for (wkn = wkn_first; wkn; wkn = wkn->next)
		if (wkn->wid == wid)
			return wkn;
	return NULL;
}

static struct hash *nodes = NULL;

static unsigned int qzc_key (void *data)
{
  struct qzc_node *node = data;
  return (unsigned int)node->nid;
}

static int qzc_cmp (const void *a, const void *b)
{
  const struct qzc_node *na = a, *nb = b;
  return na->nid == nb->nid;
}

void qzc_node_reg(struct qzc_node *node, struct qzc_nodetype *type)
{
  node->type = type;
  do
    {
      node->nid  = (uint64_t)random();
      node->nid ^= (uint64_t)random() << 32;
    }
  while (hash_get (nodes, node, hash_alloc_intern) != node);
}

void qzc_node_unreg(struct qzc_node *node)
{
  hash_release (nodes, node);
}

static struct qzc_node *qzc_node_get(uint64_t id)
{
  struct qzc_node dummy = { .nid = id };
  return hash_lookup (nodes, &dummy);
}

static void qzc_wknresolve (struct QZCRequest *req, struct QZCReply *rep,
                            struct capn_segment *cs)
{
  struct QZCWKNResolveReq wknreq;
  struct QZCWKNResolveRep wknrep;
  memset(&wknrep, 0, sizeof(wknrep));

  read_QZCWKNResolveReq(&wknreq, req->wknresolve);

  struct qzc_wkn *wkn = qzc_wkn_find(wknreq.wid);
  wknrep.wid = wknreq.wid;
  wknrep.nid = wkn ? wkn->resolve() : 0;
  rep->error = !wkn;

  rep->which = QZCReply_wknresolve;
  rep->wknresolve = new_QZCWKNResolveRep(cs);
  write_QZCWKNResolveRep(&wknrep, rep->wknresolve);
}

static void qzc_nodeinforeq (struct QZCRequest *req, struct QZCReply *rep,
                             struct capn_segment *cs)
{
  struct QZCNodeInfoReq nireq;
  struct QZCNodeInfoRep nirep;
  struct qzc_node *node;
  memset(&nirep, 0, sizeof(nirep));

  read_QZCNodeInfoReq(&nireq, req->nodeinforeq);
  node = qzc_node_get(nireq.nid);

  rep->error = !node;
  nirep.nid = nireq.nid;
  nirep.tid = node ? node->type->tid : 0;

  rep->which = QZCReply_nodeinforep;
  rep->nodeinforep = new_QZCNodeInfoRep(cs);
  write_QZCNodeInfoRep(&nirep, rep->nodeinforep);
}

static void qzc_get (struct QZCRequest *req, struct QZCReply *rep,
                     struct capn_segment *cs)
{
  struct QZCGetReq greq;
  struct QZCGetRep grep;
  struct qzc_node *node;

  read_QZCGetReq(&greq, req->get);
  node = qzc_node_get(greq.nid);

  rep->which = QZCReply_get;
  rep->get = new_QZCGetRep(cs);

  memset(&grep, 0, sizeof(grep));
  grep.nid = greq.nid;
  grep.elem = greq.elem;

  if (!node || !node->type || !node->type->get)
    {
      rep->error = 1;
      goto out;
    }

  rep->error = 0;

  void *entity = ((char *)node) - node->type->node_member_offset;
  node->type->get(entity,
                  &greq, &grep, cs);

out:
  write_QZCGetRep(&grep, rep->get);
}

static void qzc_create (struct QZCRequest *req, struct QZCReply *rep,
                     struct capn_segment *cs)
{
  struct QZCCreateReq creq;
  struct QZCCreateRep crep;
  struct qzc_node *node;
  memset(&crep, 0, sizeof(crep));

  rep->error = 1;

  read_QZCCreateReq(&creq, req->create);
  node = qzc_node_get(creq.parentnid);

  rep->which = QZCReply_create;
  rep->create = new_QZCCreateRep(cs);

  if (!node || !node->type || !node->type->createchild)
    goto out;

  rep->error = 0;

  void *entity = ((char *)node) - node->type->node_member_offset;
  node->type->createchild(entity, &creq, &crep, cs);

out:
  write_QZCCreateRep(&crep, rep->create);
}

static void qzc_set (struct QZCRequest *req, struct QZCReply *rep,
                     struct capn_segment *cs, bool unset)
{
  struct QZCSetReq sreq;
  struct QZCSetRep srep;
  struct qzc_node *node;

  read_QZCSetReq(&sreq, req->set);
  node = qzc_node_get(sreq.nid);

  rep->which = QZCReply_set;
  rep->set = new_QZCSetRep(cs);

  memset(&srep, 0, sizeof(srep));
  srep.nid = sreq.nid;
  srep.elem = sreq.elem;

  if (!node || !node->type || !(unset ? node->type->unset : node->type->set))
    {
      rep->error = 1;
      goto out;
    }

  rep->error = 0;

  void *entity = ((char *)node) - node->type->node_member_offset;
  if (unset)
    node->type->unset(entity, &sreq, &srep, cs);
  else
    node->type->set(entity, &sreq, &srep, cs);

out:
  write_QZCSetRep(&srep, rep->set);
}

static void qzc_del (struct QZCRequest *req, struct QZCReply *rep,
                     struct capn_segment *cs)
{
  struct QZCDelReq dreq;
  struct qzc_node *node;

  read_QZCDelReq(&dreq, req->del);
  node = qzc_node_get(dreq.nid);

  rep->which = QZCReply_del;

  if (!node || !node->type || !node->type->destroy)
    {
      rep->error = 1;
      return;
    }

  rep->error = 0;

  void *entity = ((char *)node) - node->type->node_member_offset;
  node->type->destroy(entity, &dreq, cs);
}

void qzc_configure_simulation_delay (unsigned int delay,
                                     unsigned int occurence)
{
  qzc_simulate_delay = delay;
  if (occurence)
    qzc_simulate_random = occurence;
}

static void qzc_callback (void *arg, void *zmqsock, zmq_msg_t *msg)
{
  int64_t more = 0;
  size_t more_size;
  int ret;
  static int simulate_counter;

  void *data = zmq_msg_data (msg);
  size_t size = zmq_msg_size (msg);

  struct capn ctx;
  capn_init_mem(&ctx, data, size, 0);

  struct QZCRequest req;
  struct QZCReply rep;

  QZCRequest_ptr root;
  root.p = capn_getp(capn_root(&ctx), 0, 1);
  read_QZCRequest(&req, root);

  struct capn rc;
  capn_init_malloc(&rc);
  struct capn_segment *cs = capn_root(&rc).seg;
  struct qzc_sock *ctxt = zmqsock;

  rep.error = 0;
  switch (req.which)
    {
    case QZCRequest_ping:
      rep.which = QZCReply_pong;
      break;
    case QZCRequest_wknresolve:
      qzc_wknresolve(&req, &rep, cs);
      break;
    case QZCRequest_nodeinforeq:
      qzc_nodeinforeq(&req, &rep, cs);
      break;
    case QZCRequest_get:
      qzc_get(&req, &rep, cs);
      break;
    case QZCRequest_create:
      qzc_create(&req, &rep, cs);
      break;
    case QZCRequest_set:
      qzc_set(&req, &rep, cs, false);
      break;
    case QZCRequest_unset:
      qzc_set(&req, &rep, cs, true);
      break;
    case QZCRequest_del:
      qzc_del(&req, &rep, cs);
      break;
    };

  QZCReply_ptr rp = new_QZCReply(cs);
  write_QZCReply(&rep, rp);
  capn_setp(capn_root(&rc), 0, rp.p);

  uint8_t buf[4096];
  ssize_t rs = capn_write_mem(&rc, buf, sizeof(buf), 0);
  int retries_left = REQUEST_RETRIES;

  capn_free(&ctx);
  capn_free(&rc);

  if(qzc_debug)
    zlog_debug ("QZC request type %d, response type %d, %zd bytes, error=%d", req.which, rep.which, rs, rep.error);
  /* introduce some heavy work */
  if (qzc_simulate_delay && 0 == (simulate_counter % qzc_simulate_random)) {
    sleep(qzc_simulate_delay);
  }

  while (retries_left) {
    if (qzc_simulate_delay && 0 == (simulate_counter % qzc_simulate_random)) {
      ret = -1;
    } else
      ret = zmq_send (ctxt->zmq, buf, rs, 0);
    if (ret >= 0)
      break;
    zlog_err ("%s : zmq_send failed: %s (%d).retry", __func__, zmq_strerror (errno), errno);
    retries_left--;
  }
  simulate_counter++;

  if (ret < 0) {
    void *qzc_sock;
    uint64_t socket_size = QZC_SOCKET_SIZE_USER;
    int fd;
    size_t fd_len = sizeof (fd);

    zlog_err ("%s : zmq_send failed: resetting connection", __func__);

    qzc_sock = zmq_socket (qzmq_context, ZMQ_REP);
    if (!qzc_sock)
      {
        zlog_err ("%s : zmq_socket failed: %s (%d)",
                  __func__, strerror (errno), errno);
        return;
      }
    if (ctxt->limit)
      zmq_setsockopt (qzc_sock, ZMQ_RCVHWM, &ctxt->limit, sizeof(uint32_t));
    zmq_setsockopt (qzc_sock, ZMQ_RCVBUF, &socket_size,
                    sizeof(socket_size));
    zmq_setsockopt (qzc_sock, ZMQ_SNDBUF, &socket_size,
                    sizeof(socket_size));
    zmq_close (ctxt->zmq);

    if (zmq_bind (qzc_sock, ctxt->path))
      {
        zlog_err ("%s : zmq_bind failed: %s (%d)",
                  __func__, strerror (errno), errno);
        zmq_close (qzc_sock);
        return;
      }
    /* reuse old context */
    ctxt->zmq = qzc_sock;

    if (zmq_getsockopt (ctxt->zmq, ZMQ_FD, &fd, &fd_len)) {
        zlog_err ("%s : zmq_getsockopt failed: %s (%d)",
                  __func__, strerror (errno), errno);
        zmq_close (qzc_sock);
        return;
    }
    qzcserver_reconnect_count++;
    /* update fd */
    ctxt->fd = fd;
    /* relaunch thread */
    if(ctxt->cb)
      qzmq_thread_cancel (ctxt->cb);
    return;
  }

  do
    {
      more_size = sizeof (more);
      ret = zmq_getsockopt (ctxt->zmq, ZMQ_RCVMORE, &more, &more_size);

      if (!more)
        break;

      ret = zmq_msg_recv (msg, ctxt->zmq, ZMQ_NOBLOCK);
      if (ret < 0)
        {
          zlog_err ("zmq_msg_recv failed: %s (%d)", strerror (errno), errno);
          break;
        }
    }
  while (1);
}

int qzcserver_get_nb_reconnect(void)
{
  return qzcserver_reconnect_count;
}

void qzc_init (void)
{
  qzmq_init ();
  if(!nodes)
    nodes = hash_create (qzc_key, qzc_cmp);
}

void qzc_finish (void)
{
  hash_free (nodes);
  nodes = NULL;

  qzmq_finish();
}

struct qzc_sock *qzc_bind (struct thread_master *master, const char *url,
                           uint32_t limit)
{
  void *qzc_sock;
  struct qzc_sock *ret;
  uint64_t socket_size = QZC_SOCKET_SIZE_USER;

  qzc_sock = zmq_socket (qzmq_context, ZMQ_REP);

  if (!qzc_sock)
    {
      zlog_err ("zmq_socket failed: %s (%d)", strerror (errno), errno);
      return NULL;
    }

  if (limit)
    zmq_setsockopt (qzc_sock, ZMQ_RCVHWM, &limit, sizeof(limit));
  zmq_setsockopt (qzc_sock, ZMQ_RCVBUF, &socket_size,
                  sizeof(socket_size));
  zmq_setsockopt (qzc_sock, ZMQ_SNDBUF, &socket_size,
                  sizeof(socket_size));

  if (zmq_bind (qzc_sock, url))
    {
      zlog_err ("zmq_bind failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }

  ret = XCALLOC(MTYPE_QZC_SOCK, sizeof(struct qzc_sock));
  ret->path = XSTRDUP(MTYPE_QZC_SOCK, url);
  ret->limit = limit;
  ret->zmq = qzc_sock;
  ret->thread_master = master;
  ret->cb = qzmq_thread_read_msg (master, qzc_callback, NULL, ret);
  return ret;
}

void qzc_close (struct qzc_sock *sock)
{
  if (sock->cb)
    qzmq_thread_cancel (sock->cb);
  zmq_close (sock->zmq);
  if (sock->path) {
    XFREE(MTYPE_QZC_SOCK, sock->path);
    sock->path = NULL;
  }
  XFREE(MTYPE_QZC_SOCK, sock);
}

