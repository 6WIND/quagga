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

#ifndef _QZC_H
#define _QZC_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#include <zmq.h>
#include "qzc.capnp.h"

struct qzc_nodetype {
	uint64_t tid;
	ptrdiff_t node_member_offset;
	void (*get)(void *entity, struct QZCGetReq *req, struct QZCGetRep *rep,
			struct capn_segment *seg);
	void (*createchild)(void *parent, struct QZCCreateReq *req,
			struct QZCCreateRep *rep, struct capn_segment *seg);
	void (*set)(void *entity, struct QZCSetReq *req,
			struct capn_segment *seg);
	void (*unset)(void *entity, struct QZCSetReq *req,
			struct capn_segment *seg);
	void (*destroy)(void *entity, struct QZCDelReq *req,
			struct capn_segment *seg);
};

struct qzc_node {
	uint64_t nid;
	struct qzc_nodetype *type;
};

#define QZC_NODE \
	struct qzc_node qzc_node;

#define QZC_NODE_REG(n, structname) \
	qzc_node_reg(&n->qzc_node, &qzc_t_ ## structname);
#define QZC_NODE_UNREG(n) \
	qzc_node_unreg(&n->qzc_node);

void qzc_node_reg(struct qzc_node *node, struct qzc_nodetype *type);
void qzc_node_unreg(struct qzc_node *node);

#define EXT_QZC_NODETYPE(structname) \
	extern struct qzc_nodetype qzc_t_ ## structname;
#define QZC_NODETYPE(structname, id) \
	struct qzc_nodetype qzc_t_ ## structname = { \
		.tid = id, \
		.node_member_offset = \
			(ptrdiff_t)offsetof(struct structname, qzc_node) \
	};
void qzc_nodetype_init(struct qzc_nodetype *type);

struct qzc_sock;

void qzc_init(void);
void qzc_finish(void);
struct qzc_sock *qzc_bind(struct thread_master *master, const char *url);

void qzc_close(struct qzc_sock *sock);

struct qzc_wkn {
	uint64_t wid;
	uint64_t (*resolve)(void);

	struct qzc_wkn *next;
};
void qzc_wkn_reg(struct qzc_wkn *wkn);

capn_ptr 
qzc_msg_to_notification(zmq_msg_t *msg, struct capn *rc);

struct qzc_sock *qzcclient_connect (const char *url);
struct qzc_sock *qzcclient_subscribe (struct thread_master *master, const char *url,
                                void (*func)(void *arg, void *zmqsock, struct zmq_msg_t *msg));
struct QZCReply *qzcclient_do(struct qzc_sock *sock,
                              struct QZCRequest *req_ptr);
uint64_t
qzcclient_wkn(struct qzc_sock *sock, uint64_t *wkn);

uint64_t
qzcclient_createchild (struct qzc_sock *sock,
                       uint64_t *nid, int elem,
                       capn_ptr *p, uint64_t *dtypeid);

int
qzcclient_setelem (struct qzc_sock *sock, uint64_t *nid,
                   int elem, capn_ptr *data, uint64_t *type_data,
                   capn_ptr *ctxt, uint64_t *type_ctxt);

int
qzcclient_deletenode (struct qzc_sock *sock, uint64_t *nid);

struct QZCGetRep *qzcclient_getelem (struct qzc_sock *sock, uint64_t *nid,\
                                     int elem, \
                                     capn_ptr *ctxt, uint64_t *ctxt_type,\
                                     capn_ptr *iter, uint64_t *iter_type);

int
qzcclient_unsetelem (struct qzc_sock *sock, uint64_t *nid, int elem, \
                     capn_ptr *data, uint64_t *type_data, \
                     capn_ptr *ctxt, uint64_t *type_ctxt);

void
qzcclient_qzcreply_free(struct QZCReply *rep);

void
qzcclient_qzcgetrep_free(struct QZCGetRep *rep);

#endif /* _QZC_H */
