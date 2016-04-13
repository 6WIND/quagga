/* qthrift daemon program
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

#include <zebra.h>
#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "command.h"
#include "sockunion.h"
#include "sockopt.h"
#include "network.h"
#include "memory.h"
#include "str.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
#include "workqueue.h"

#include "qthrift_thrift_wrapper.h"
#include "qthriftd/bgp_configurator.h"
#include "qthriftd/bgp_updater.h"
#include "qthriftd/qthrift_bgp_configurator.h"
#include "qthriftd/qthrift_vpnservice.h"
#include "qthriftd/qthrift_vty.h"
#include "qthriftd/qthrift_debug.h"
#include "qthriftd/qthriftd.h"
#include "qthriftd/qthrift_network.h"
#include "qthriftd/qthrift_debug.h"

/* qthrift process wide configuration.  */
static struct qthrift_master qthrift_master;

/* qthrift process wide configuration pointer to export.  */
struct qthrift_master *tm;

struct qthrift_peer *qthrift_peer_create_accept(struct qthrift *qthrift)
{
  struct qthrift_peer *peer;

  /* Allocate new peer. */
  peer = XCALLOC (MTYPE_QTHRIFT, sizeof (struct qthrift_peer));
  memset (peer, 0, sizeof (struct qthrift_peer));

  peer->qthrift = qthrift;
  listnode_add_sort (qthrift->peer, peer);
  return peer;
}

static struct qthrift *
qthrift_create (void)
{
  struct qthrift *qthrift;

  if ( (qthrift = XCALLOC (MTYPE_QTHRIFT, sizeof (struct qthrift))) == NULL)
    return NULL;
  memset (qthrift, 0, sizeof(struct qthrift));
  qthrift->peer = list_new();
  return qthrift;
}


/* Delete BGP instance. */
int
qthrift_delete (struct qthrift *qthrift)
{
  struct listnode *node, *nnode;
  struct qthrift_peer *peer;

  for (ALL_LIST_ELEMENTS (qthrift->peer, node, nnode, peer))
    {
      list_delete_node (qthrift->peer, node);
      if(peer->fd)
        {
          if (IS_QTHRIFT_DEBUG)
            zlog_info("qthrift_delete : close connection (fd %d)", peer->fd);
          qthrift_vpnservice_terminate_client(peer->peer);
          XFREE(MTYPE_QTHRIFT, peer->peer);
          peer->peer = NULL;
          peer->fd=0;
        }
      XFREE(MTYPE_QTHRIFT, peer);
    }
  qthrift_vpnservice_terminate_thrift_bgp_updater_client (qthrift->qthrift_vpnservice);
  qthrift_vpnservice_terminate_thrift_bgp_configurator_server (qthrift->qthrift_vpnservice);
  qthrift_vpnservice_terminate(qthrift->qthrift_vpnservice);
  if(qthrift->qthrift_vpnservice)
    XFREE(MTYPE_QTHRIFT, qthrift->qthrift_vpnservice);
  qthrift->qthrift_vpnservice = NULL;
  return 0;
}

void
qthrift_master_init (void)
{
  memset (&qthrift_master, 0, sizeof (struct qthrift_master));

  tm = &qthrift_master;
  tm->listen_sockets = list_new ();
  tm->master = thread_master_create ();
  tm->qthrift_listen_port = QTHRIFT_LISTEN_PORT;
  tm->qthrift_notification_port = QTHRIFT_NOTIFICATION_PORT;
  tm->qthrift_notification_address = strdup(QTHRIFT_CLIENT_ADDRESS);
}


/* Called from VTY commands. */
void  qthrift_create_context (struct qthrift **qthrift_val)
{
  struct qthrift *qthrift;
  qthrift = qthrift_create ();
  *qthrift_val = qthrift;

  tm->qthrift = qthrift;

  qthrift->qthrift_vpnservice = XCALLOC(MTYPE_QTHRIFT, sizeof(struct qthrift_vpnservice));
  qthrift_vpnservice_setup(qthrift->qthrift_vpnservice);
  qthrift_vpnservice_set_thrift_bgp_configurator_server_port (qthrift->qthrift_vpnservice, tm->qthrift_listen_port);
  qthrift_vpnservice_set_thrift_bgp_updater_client_port (qthrift->qthrift_vpnservice, tm->qthrift_notification_port);

  /* creation of thrift contexts - configurator and updater */
  qthrift_server_socket(qthrift);

  /* run bgp_configurator_server */ 
  if(qthrift_server_listen (qthrift) < 0)
    {
      exit(1);
    }
  return ;
}

void
qthrift_init (void)
{
  /* BGP VTY commands installation.  */
  qthrift_vty_init ();

  /* BGP debug initialisation */
  qthrift_debug_init ();
}

void
qthrift_terminate (void)
{
}
