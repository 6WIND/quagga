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
#ifdef HAVE_CCAPNPROTO
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#include "qzc.capnp.h"

struct qzc_nodetype {
	uint64_t tid;
	ptrdiff_t node_member_offset;
	void (*get)(void *entity, struct QZCGetReq *req, struct QZCGetRep *rep,
			struct capn_segment *seg);
	void (*createchild)(void *parent, struct QZCCreateReq *req,
			struct QZCCreateRep *rep, struct capn_segment *seg);
	void (*set)(void *entity, struct QZCSetReq *req, struct QZCSetRep *rep,
			struct capn_segment *seg);
	void (*unset)(void *entity, struct QZCSetReq *req, struct QZCSetRep *rep,
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
struct qzc_sock *qzc_bind(struct thread_master *master,
                          const char *url, uint32_t limit);
void qzc_close(struct qzc_sock *sock);

struct qzc_wkn {
	uint64_t wid;
	uint64_t (*resolve)(void);

	struct qzc_wkn *next;
};
void qzc_wkn_reg(struct qzc_wkn *wkn);

#define QZC_CLIENT_ZMQ_LIMIT_TX     1500000
#define QZC_CLIENT_ZMQ_LIMIT_RX     1500000
void qzc_configure_simulation_delay (unsigned int delay,
                                     unsigned int occurence);
#else

#define QZC_NODE
#define QZC_NODE_REG(n, structname)
#define QZC_NODE_UNREG(n)
#define EXT_QZC_NODETYPE(structname)
#define QZC_NODETYPE(structname, id)

#endif /* HAVE_CCAPNPROTO */
#endif /* _QZC_H */
