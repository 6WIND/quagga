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

#ifndef _QUAGGA_QZMQ_H
#define _QUAGGA_QZMQ_H

#include "thread.h"
#include <zmq.h>

/* libzmq's context */
extern void *qzmq_context;

extern void qzmq_init (void);
extern void qzmq_finish (void);

#define debugargdef const char *funcname, const char *schedfrom, int fromln

#define qzmq_thread_read_msg(m,f,a,z) funcname_qzmq_thread_read_msg( \
                             m,f,a,z,#f,__FILE__,__LINE__)

struct qzmq_cb;

struct qzc_sock {
        void *zmq;
        struct qzmq_cb *cb;
        char *path;
        uint32_t limit;
        void * thread_master;
        int fd;
};

extern struct qzmq_cb *funcname_qzmq_thread_read_msg (
        struct thread_master *master,
        void (*func)(void *arg, void *zmqsock, zmq_msg_t *msg),
        void *arg, void *zmqsock, debugargdef);

extern void qzmq_thread_cancel (struct qzmq_cb *cb);

#if 0
#define qzmq_thread_read_buf(m,f,a,z) funcname_qzmq_thread_read_buf(m,f,a,z,#f,__FILE__,__LINE__)
extern struct qzmq_cb *funcname_qzmq_thread_read_buf (
        struct thread_master *master,
        void (*func)(void *arg, void *zmqsock, const uint8_t *buf, size_t len),
        void *arg, void *zmqsock, debugargdef);
#endif

#endif
