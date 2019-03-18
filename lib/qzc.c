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

DEFINE_MTYPE_STATIC(LIB, QZC_SOCK, "QZC Socket")
DEFINE_MTYPE_STATIC(LIB, QZC_REP, "QZC Socket")

/* This file local debug flag. */

static struct QZCReply *qzcclient_msg_to_reply(zmq_msg_t *msg);
static struct capn *rc_table_get_entry(void *data, size_t size);
static void rc_table_init();

static struct qzc_wkn *wkn_first = NULL;

#define QZC_SOCKET_SIZE_USER 200000
#define RC_TABLE_NB_ELEM 50
#define REQUEST_RETRIES     5
struct capn rc_table[RC_TABLE_NB_ELEM];
int rc_table_index = 0;
int rc_table_cnt = 0;
int rc_table_index_free = 0;
int rc_table_inited = 0;
int qzc_debug = 0;
int qzc_simulate_delay = 0;
int qzc_simulate_random = 5;

static int qzcclient_reconnect_count;
static int qzcclient_recv_failed;
static int qzcserver_reconnect_count;
/*
 * manages capnproto allocations for some routines
 * that need delayed free.
 * this is the case of qzcclient_do routine
 */
static void rc_table_init()
{
  int i=0;

  if(rc_table_inited)
    return;
  for (i=0; i<RC_TABLE_NB_ELEM; i++)
    memset(&rc_table[i], 0, sizeof(struct capn));
  rc_table_inited = 1;
}
/*
 * manages capnproto allocations for some routines
 * that need delayed free.
 * this is the case of qzcclient_do routine
 */
static struct capn *rc_table_get_entry(void *data, size_t size)
{
  struct capn *rc;
  rc = &rc_table[rc_table_index];
  if(data)
    capn_init_mem(rc, data, size, 0);
  else
    capn_init_malloc(rc);
  rc_table_cnt++;
  rc_table_index++;
  if(rc_table_index == RC_TABLE_NB_ELEM)
    {
      rc_table_index = 0;
    }
  if(rc_table_cnt >= RC_TABLE_NB_ELEM)
    {
      capn_free(&rc_table[rc_table_index_free]);
      rc_table_index_free++;
      if(rc_table_index_free == RC_TABLE_NB_ELEM)
        rc_table_index_free = 0;
    }
  return rc;
}

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
  memset(&grep, 0, sizeof(grep));

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
  struct qzc_node *node;

  read_QZCSetReq(&sreq, req->set);
  node = qzc_node_get(sreq.nid);

  rep->which = QZCReply_set;

  if (!node || !node->type || !(unset ? node->type->unset : node->type->set))
    {
      rep->error = 1;
      return;
    }

  rep->error = 0;

  void *entity = ((char *)node) - node->type->node_member_offset;
  if (unset)
    node->type->unset(entity, &sreq, cs);
  else
    node->type->set(entity, &sreq, cs);
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
    int val = 0;

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
    zmq_setsockopt (qzc_sock, ZMQ_LINGER, &val, sizeof(val));
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
#if 1
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
#endif
}

void qzc_init (void)
{
  qzmq_init ();
  if(!nodes)
    nodes = hash_create (qzc_key, qzc_cmp);
  rc_table_init();
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
  int val = 0;

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
  if (zmq_setsockopt (qzc_sock, ZMQ_LINGER, &val, sizeof(val)))
    {
      zlog_err ("zmq_setsockopt failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }

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
  if(sock->cb)
    qzmq_thread_cancel (sock->cb);
  zmq_close (sock->zmq);
  if (sock->path) {
    XFREE(MTYPE_QZC_SOCK, sock->path);
    sock->path = NULL;
  }
  XFREE(MTYPE_QZC_SOCK, sock);
}

int qzc_setsockopt(struct qzc_sock *sock, int option,
                   const void *optval, size_t optvallen)
{
  if (!sock || !sock->zmq)
    return 0;

  if (zmq_setsockopt(sock->zmq, option, optval, optvallen))
    {
      zlog_err ("zmq_setsockopt failed: %s (%d)", strerror (errno), errno);
      return -1;
    }

  return 0;
}

capn_ptr 
qzc_msg_to_notification(zmq_msg_t *msg, struct capn *rc)
{
  void *data;
  size_t size;

  data = zmq_msg_data (msg);
  size = zmq_msg_size (msg);

  capn_init_mem(rc, data, size, 0);

  return capn_getp(capn_root(rc), 0, 1);
}

static struct QZCReply *qzcclient_msg_to_reply(zmq_msg_t *msg)
{
  void *data;
  size_t size;
  QZCReply_ptr root;
  struct QZCReply *rep;
  struct capn *ctx;

  data = zmq_msg_data (msg);
  size = zmq_msg_size (msg);

  rep = XCALLOC(MTYPE_QZC_REP, sizeof(struct QZCReply));
  ctx = rc_table_get_entry(data, size);
  root.p = capn_getp(capn_root(ctx), 0, 1);
  read_QZCReply(rep, root);
  zmq_msg_close(msg);
  return rep;
}

struct qzc_sock *qzcclient_connect (const char *url, uint32_t limit)
{
  void *qzc_sock;
  struct qzc_sock *ret;
  uint64_t socket_size = QZC_SOCKET_SIZE_USER;
  int val;

  qzc_sock = zmq_socket (qzmq_context, ZMQ_REQ);
  if (!qzc_sock)
    {
      zlog_err ("zmq_socket failed: %s (%d)", strerror (errno), errno);
      return NULL;
    }
  if (limit)
    zmq_setsockopt (qzc_sock, ZMQ_SNDHWM, &limit, sizeof(limit));
  zmq_setsockopt (qzc_sock, ZMQ_RCVBUF, &socket_size,
                  sizeof(socket_size));
  zmq_setsockopt (qzc_sock, ZMQ_SNDBUF, &socket_size,
                  sizeof(socket_size));
  val = 0;
  zmq_setsockopt (qzc_sock, ZMQ_LINGER, &val, sizeof (val));

  if (zmq_connect (qzc_sock, url))
    {
      zlog_err ("zmq_bind failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }
  ret = XCALLOC(MTYPE_QZC_SOCK, sizeof(*ret));
  ret->zmq = qzc_sock;
  ret->cb = NULL;
  ret->path = XSTRDUP(MTYPE_QZC_SOCK, url);
  ret->limit = limit;
  return ret;
}

struct qzc_sock *qzcclient_subscribe (struct thread_master *master, const char *url,
                                      void (*func)(void *arg, void *zmqsock, void *msg),
                                      uint32_t limit)
{
  void *qzc_sock;
  struct qzc_sock *ret;
  void (*func2)(void *arg, void *zmqsock, struct zmq_msg_t *msg);
  int val = 0;

  qzc_sock = zmq_socket (qzmq_context, ZMQ_SUB);

  if (!qzc_sock)
    {
      zlog_err ("zmq_socket failed: %s (%d)", strerror (errno), errno);
      return NULL;
    }
  if (zmq_connect (qzc_sock, url))
    {
      zlog_err ("zmq_connect failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }
  if (zmq_setsockopt (qzc_sock, ZMQ_SUBSCRIBE,"",0))
    {
      zlog_err ("zmq_setsockopt failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }
  if (zmq_setsockopt (qzc_sock, ZMQ_LINGER, &val, sizeof(val)))
    {
      zlog_err ("zmq_setsockopt failed: %s (%d)", strerror (errno), errno);
      zmq_close (qzc_sock);
      return NULL;
    }

  if (limit)
    zmq_setsockopt (qzc_sock, ZMQ_RCVHWM, &limit, sizeof(limit));
  func2 = func;
  ret = XCALLOC(MTYPE_QZC_SOCK, sizeof(struct qzc_sock));
  ret->zmq = qzc_sock;
  ret->limit = limit;
  ret->cb = qzmq_thread_read_msg (master, func2, NULL, ret);
  return ret;
}

/* send QZCrequest and return QZCreply or NULL if timeout */
struct QZCReply *
qzcclient_do(struct qzc_sock **p_sock,
             struct QZCRequest *req_ptr)
{
  struct capn *rc;
  struct capn_segment *cs;
  struct QZCRequest *req, rq;
  struct QZCReply *rep;
  QZCRequest_ptr p;
  zmq_msg_t msg;
  uint8_t buf[4096];
  ssize_t rs;
  int ret;
  struct qzc_sock *sock;
  static int simulate_counter;

  if (!p_sock || *p_sock == NULL) {
    zlog_err ("%s: sock null", __func__);
    return NULL;
  }
  sock = *p_sock;
  rc = rc_table_get_entry(NULL, 0);
  cs = capn_root(rc).seg;
  memset(buf, 0, 4096);
  if(req_ptr == NULL)
    {
      /* ping request */
      memset(&rq, 0, sizeof(struct QZCRequest));
      req = &rq;
    }
  else
    {
      req = req_ptr;
    }
  p = new_QZCRequest(cs);
  write_QZCRequest( req, p);
  capn_setp(capn_root(rc), 0, p.p);
  rs = capn_write_mem(rc, buf, sizeof(buf), 0);

  /* introduce polling algorithm to check
   * if there is a response */
  {
#define REQUEST_TIMEOUT 2500
    int retries_left = REQUEST_RETRIES;
    int rc;
    struct qzc_sock *zmq_sock_new;

    while (retries_left) {
      zmq_pollitem_t items [] = { { sock->zmq, 0, ZMQ_POLLIN, 0 } };

      ret = zmq_send (sock->zmq, buf, rs, 0);
      if (ret < 0)
        {
          zlog_err ("zmq_send failed: %s (%d)", zmq_strerror (errno), errno);
          goto qzcclient_reset_retry;
        }
      rc = zmq_poll(items, 1, REQUEST_TIMEOUT);
      if (rc == -1) {
        zlog_err ("zmq_poll failed: %s (%d)", zmq_strerror (errno), errno);
        qzcclient_recv_failed++;
        continue;
      }
      if (items[0].revents & ZMQ_POLLIN) {
        if (zmq_msg_init (&msg))
          {
            zlog_err ("zmq_msg_init failed: %s (%d)", zmq_strerror (errno), errno);
            return NULL;
          }
        ret = zmq_msg_recv (&msg, sock->zmq, ZMQ_DONTWAIT);
        if (ret < 0)
          {
            zlog_err ("zmq_msg_recv failed. resending: %s (%d)",
                      zmq_strerror (errno), errno);
            qzcclient_recv_failed++;
            continue;
          }
        /* will read message */
        break;
      }
      else {
      qzcclient_reset_retry:
        if (--retries_left == 0) {
          if (zmq_msg_init (&msg))
            {
              zlog_err ("zmq_msg_init failed: %s (%d)", zmq_strerror (errno), errno);
              return NULL;
            }
          zlog_err ("%s: server seems to be offline. cancel", __func__);
          ret = -1;
          break;
        }
        zlog_err ("%s: server seems to be delayed. retry (%u)", __func__, retries_left);
	qzcclient_reconnect_count++;
        zmq_close(sock->zmq);
        zmq_sock_new = qzcclient_connect(sock->path, sock->limit);
        /* free old p_sock */
        if (sock->path)
	  XFREE(MTYPE_QZC_SOCK, sock->path);
        sock->path = NULL;
        sock->limit = 0;
        XFREE(MTYPE_QZC_SOCK, sock);
        /* update passed param */
        sock = zmq_sock_new;
        *p_sock = zmq_sock_new;
      }
    }
  }
  /* introduce some heavy work */
  if (qzc_simulate_delay && 0 == (simulate_counter % qzc_simulate_random)) {
    sleep(qzc_simulate_delay);
  }
  simulate_counter++;
  if(ret < 0)
    {
      return NULL;
    }
  rep = qzcclient_msg_to_reply(&msg);
  if(rep == NULL)
    {
      if(qzc_debug)
        zlog_debug ("qzcclient_send. no message reply");
    }
  if(rep->error)
    {
      zlog_err ("qzcclient_send. reply message error: (%d)", rep->error);
    }
  return rep;
}

/*
 * qzc client API. send QZCCreateReq
 * and return created node identifier if operation success
 * return 0 if set operation fails
 */
uint64_t
qzcclient_createchild (struct qzc_sock **sock,
                       uint64_t *nid, int elem, capn_ptr *p, uint64_t *type_data)

{
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCCreateReq creq;
  struct QZCCreateRep crep;
  struct capn rc;
  struct capn_segment *cs;

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  req.which = QZCRequest_create;
  req.create = new_QZCCreateReq(cs);
  memset(&creq, 0, sizeof(struct QZCCreateReq));
  creq.parentnid = *nid;
  creq.parentelem = elem;
  creq.datatype = *type_data;
  creq.data = *p;
  write_QZCCreateReq(&creq, req.create);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL || rep->error)
    {
      return 0;
    }
  memset(&crep, 0, sizeof(struct QZCCreateRep));
  read_QZCCreateRep(&crep, rep->create);
  if(qzc_debug)
    zlog_debug ("CREATE nid:%llx/%d => %llx",(long long unsigned int)*nid, elem, (long long unsigned int)crep.newnid); 
  XFREE(MTYPE_QZC_REP, rep);
  capn_free(&rc);
  return crep.newnid;
}

/*
 * qzc client API. send a QZCSetReq message
 * return 1 if set operation is successfull
 */
int
qzcclient_setelem (struct qzc_sock **sock, uint64_t *nid,
                   int elem, capn_ptr *data, uint64_t *type_data,
                   capn_ptr *ctxt, uint64_t *type_ctxt)
{
  struct capn rc;
  struct capn_segment *cs;
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCSetReq sreq;
  int ret = 1;

  /* have to use  local capn_segment - otherwise segfault */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;

  req.which = QZCRequest_set;
  req.set = new_QZCSetReq(cs);
  memset(&sreq, 0, sizeof(struct QZCSetReq));
  sreq.nid = *nid;
  sreq.elem = elem;
  sreq.datatype = *type_data;
  sreq.data = *data;
  if(ctxt)
    {
      sreq.ctxdata = *ctxt;
      sreq.ctxtype = *type_ctxt;
    }
  write_QZCSetReq(&sreq, req.set);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL)
    {
      ret = 0;
    } else
  XFREE(MTYPE_QZC_REP, rep);
  capn_free(&rc);
  return ret;
}

uint64_t
qzcclient_wkn(struct qzc_sock **sock, uint64_t *wkn)
{
  struct QZCRequest req;
  struct QZCWKNResolveReq wknreq;
  struct capn rc;
  struct capn_segment *cs;
  struct QZCReply *rep;
  struct QZCWKNResolveRep wknrep;

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  req.wknresolve = new_QZCWKNResolveReq(cs);
  req.which = QZCRequest_wknresolve;

  memset(&wknreq, 0, sizeof(wknreq));
  wknreq.wid = *wkn;
  write_QZCWKNResolveReq(&wknreq, req.wknresolve);

  rep = qzcclient_do(sock, &req);
  if (rep == NULL)
    {
      return 0;
    }

  memset(&wknrep, 0, sizeof(wknrep));
  read_QZCWKNResolveRep(&wknrep, rep->wknresolve);
  XFREE(MTYPE_QZC_REP, rep);
  capn_free(&rc);
  return wknrep.nid;
}

/*
 * qzc client API. send QZCDelRequest
 * return 0 if set operation fails, 1 otherwise.
 */
int
qzcclient_deletenode (struct qzc_sock **sock, uint64_t *nid)
{
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCDelReq dreq;
  struct capn rc;
  struct capn_segment *cs;
  int ret = 1;

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  req.which = QZCRequest_del;
  req.del = new_QZCDelReq(cs);
  memset(&dreq, 0, sizeof(struct QZCDelReq));
  dreq.nid = *nid;
  write_QZCDelReq(&dreq, req.del);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL || rep->error)
    ret = 0;
  else
    {
      if(qzc_debug)
        zlog_debug ("DELETE nid:%llx",(long long unsigned int)*nid);
    }
  if(rep)
    XFREE(MTYPE_QZC_REP, rep);
  capn_free(&rc);
  return ret;
}

/*
 * qzc client API. send a QZCGetReq message
 * return NULL if error; QZCGetRep pointer otherwise
 */
struct QZCGetRep *qzcclient_getelem (struct qzc_sock **sock, uint64_t *nid,\
                                     int elem, \
                                     capn_ptr *ctxt, uint64_t *ctxt_type, \
                                     capn_ptr *iter, uint64_t *iter_type)
{
  struct capn *rc;
  struct capn_segment *cs;  
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCGetReq greq;
  struct QZCGetRep *grep;

  grep = XCALLOC(MTYPE_QZC_REP, sizeof(struct QZCGetRep));

  /* have to use  local capn_segment - otherwise segfault */
  rc = rc_table_get_entry(NULL, 0);
  cs = capn_root(rc).seg;

  req.which = QZCRequest_get;
  req.get = new_QZCGetReq(cs);
  memset(&greq, 0, sizeof(struct QZCGetReq));
  greq.nid = *nid;
  greq.elem = elem;
  if(ctxt != NULL)
    {
      greq.ctxtype = *ctxt_type;
      greq.ctxdata = *ctxt; 
    }
  if(iter_type)
    {
      if(iter == NULL)
        greq.itertype = 0;
      else
        {
          greq.itertype = *iter_type;
          greq.iterdata = *iter;
        }
    }
  write_QZCGetReq(&greq, req.get);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL)
    {
      return NULL;
    }
  read_QZCGetRep(grep, rep->get);
  XFREE(MTYPE_QZC_REP, rep);
  if(qzc_debug)
    zlog_debug ("GET nid:%llx/%d => %llx",(long long unsigned int)*nid, elem, (long long unsigned int)grep->datatype); 
  return grep;
}

/*
 * qzc client API. send a QZCUnSetReq message
 * return 1 if set operation is successfull
 */
int
qzcclient_unsetelem (struct qzc_sock **sock, uint64_t *nid, int elem, \
                     capn_ptr *data, uint64_t *type_data, \
                     capn_ptr *ctxt, uint64_t *type_ctxt)
{
  struct capn rc;
  struct capn_segment *cs;
  struct QZCRequest req;
  struct QZCReply *rep;
  struct QZCSetReq sreq;
  int ret = 1;

  /* have to use  local capn_segment - otherwise segfault */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  req.which = QZCRequest_unset;
  req.unset = new_QZCSetReq(cs);
  memset(&sreq, 0, sizeof(struct QZCSetReq));
  sreq.nid = *nid;
  sreq.elem = elem;
  sreq.datatype = *type_data;
  sreq.data = *data;
  if(ctxt)
    {
      sreq.ctxdata = *ctxt;
      sreq.ctxtype = *type_ctxt;
    }
  write_QZCSetReq(&sreq, req.unset);
  rep = qzcclient_do(sock, &req);
  if (rep == NULL || rep->error)
    {
      ret = 0;
    }
  if (rep)
    XFREE(MTYPE_QZC_REP, rep);
  capn_free(&rc);
  return ret;
}

void
qzcclient_qzcgetrep_free(struct QZCGetRep *rep)
{
  if(rep)
    XFREE(MTYPE_QZC_REP, rep);
}

void
qzcclient_qzcreply_free(struct QZCReply *rep)
{
  if(rep)
    XFREE(MTYPE_QZC_REP, rep);

}

int qzcclient_get_nb_reconnect(void)
{
  return qzcclient_reconnect_count;
}

int qzcserver_get_nb_reconnect(void)
{
  return qzcserver_reconnect_count;
}
