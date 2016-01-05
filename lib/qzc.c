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
  struct QZCGet greq, grep;
  struct qzc_node *node;

  read_QZCGet(&greq, req->get);
  node = qzc_node_get(greq.nid);

  rep->which = QZCReply_get;
  rep->get = new_QZCGet(cs);

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
  write_QZCGet(&grep, rep->get);
}

static void qzc_create (struct QZCRequest *req, struct QZCReply *rep,
                     struct capn_segment *cs)
{
  struct QZCCreateReq creq;
  struct QZCCreateRep crep;
  struct qzc_node *node;

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

static void qzc_callback (void *arg, void *zmqsock, zmq_msg_t *msg)
{
  int64_t more = 0;
  size_t more_size;
  int ret;

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
    };

  QZCReply_ptr rp = new_QZCReply(cs);
  write_QZCReply(&rep, rp);
  capn_setp(capn_root(&rc), 0, rp.p);

  uint8_t buf[4096];
  ssize_t rs = capn_write_mem(&rc, buf, sizeof(buf), 0);
  capn_free(&ctx);
  capn_free(&rc);

  zlog_info ("QZC request type %d, response type %d, %zd bytes, error=%d", req.which, rep.which, rs, rep.error);
  zmq_send (zmqsock, buf, rs, 0);

  do
    {
      more_size = sizeof (more);
      ret = zmq_getsockopt (zmqsock, ZMQ_RCVMORE, &more, &more_size);

      if (!more)
        break;

      ret = zmq_msg_recv (msg, zmqsock, ZMQ_NOBLOCK);
      if (ret < 0)
        {
          zlog_err ("zmq_msg_recv failed: %s (%d)", strerror (errno), errno);
          break;
        }
    }
  while (1);
}

void qzc_init (void)
{
  qzmq_init ();

  nodes = hash_create (qzc_key, qzc_cmp);
}

void *qzc_bind (struct thread_master *master, const char *url)
{
  void *qzc_sock;

  qzc_sock = zmq_socket (qzmq_context, ZMQ_REP);

  if (!qzc_sock)
    {
      zlog_err ("zmq_socket failed: %s (%d)", strerror (errno), errno);
      return NULL;
    }

  if (zmq_bind (qzc_sock, url))
    {
      zlog_err ("zmq_bind failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }

  qzmq_thread_read_msg (master, qzc_callback, NULL, qzc_sock);
  return qzc_sock;
}
