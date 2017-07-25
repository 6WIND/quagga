/* THRIFT related values and structures.
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of GNU Quagga.
 *
 * GNU Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_THRIFT_H
#define _ZEBRA_THRIFT_H

#include "qthriftd/qthrift_memory.h"

#define QTHRIFT_VTY_PORT            2611

struct qthrift
{
  /* Thrift socket. */
  int sock;

  char *name;

  /* Thrift clients */
  struct list *peer;

  /* Thrift threads. */
  struct thread *t_read;
  struct thread *t_write;

  /* thrift server context */
  struct qthrift_vpnservice *qthrift_vpnservice;
};

/* Thrift Remote structure. */
struct qthrift_peer
{
  /* qthrift structure pointer */
  struct qthrift *qthrift;

  /* Peer information */
  int fd;			/* File descriptor */

  /* Threads. */
  struct thread *t_read;
  
  /* thrift context for one thrift connexion */
  struct qthrift_vpnservice_client *peer;

  /* information about peer */
  struct sockaddr_storage peerIp;
};

#include "qthriftd/qthrift_master.h"

/* Prototypes. */
extern void qthrift_init (void);
extern void qthrift_master_init (void);
extern void qthrift_terminate (void);
extern void qthrift_reset (void);
extern void  qthrift_create_context (struct qthrift **thrift_val);
struct qthrift_peer *
qthrift_peer_lookup (struct qthrift *qthrift, union sockunion *su);
struct qthrift_peer *qthrift_peer_create_accept(struct qthrift *qthrift);

extern int qthrift_delete (struct qthrift *);

extern void qthrift_bgp_configurator_create(struct qthrift *qthrift);
extern void qthrift_bgp_configurator_server_terminate(void);

#endif /* _ZEBRA_THRIFT_H */
