/* qthrift core structures and API
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

#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "log.h"
#include "linklist.h"
#include "command.h"
#include "qzmq.h"
#include "qzc.h"
#include "capn.h"
#include "bgpd/bgp.bcapnp.h"
#include "qzc.capnp.h"
#include "qthriftd/qthrift_memory.h"
#include "qthriftd/qthrift_thrift_wrapper.h"
#include "qthriftd/bgp_configurator.h"
#include "qthriftd/bgp_updater.h"
#include "qthriftd/qthrift_bgp_configurator.h"
#include "qthriftd/qthrift_bgp_updater.h"
#include "qthriftd/qthrift_vpnservice.h"
#include "qthriftd/qthrift_bgp_configurator.h"
#include "qthriftd/qthriftd.h"
#include "qthriftd/qthrift_debug.h"

static void qthrift_vpnservice_callback (void *arg, void *zmqsock, void *msg);

static void qthrift_transport_check_response(struct qthrift_vpnservice *setup, gboolean response);
static int qthrift_vpnservice_setup_bgp_updater_client_retry (struct thread *thread);
static int qthrift_vpnservice_setup_bgp_updater_client_monitor (struct thread *thread);
int qthrift_monitor_retry_job_in_progress;
static gboolean qthrift_transport_current_status = FALSE;

static void qthrift_transport_check_response(struct qthrift_vpnservice *setup, gboolean response)
{
  if(qthrift_monitor_retry_job_in_progress)
    return;
  if (qthrift_transport_current_status != response)
    {
      if (IS_QTHRIFT_DEBUG_NOTIFICATION)
        zlog_debug("bgpUpdater check connection with %s:%u %s",
                   tm->qthrift_notification_address,
                   setup->qthrift_notification_port,
                   response == TRUE?"OK":"NOK");
    }
  qthrift_transport_current_status = response;
  if(response == FALSE)
    {
      setup->bgp_update_retries++;
      setup->bgp_updater_client_thread = NULL;
      THREAD_TIMER_MSEC_ON(tm->master, setup->bgp_updater_client_thread, \
                           qthrift_vpnservice_setup_bgp_updater_client_retry, \
                           setup, 1000);
    }
  else
    {
      setup->bgp_update_monitor++;
      setup->bgp_updater_client_thread = NULL;
      THREAD_TIMER_MSEC_ON(tm->master, setup->bgp_updater_client_thread,\
                           qthrift_vpnservice_setup_bgp_updater_client_monitor,\
                           setup, 5000);

    }
  qthrift_monitor_retry_job_in_progress = 1;
}

/* returns status from recv with MSG_PEEK option
 * this permits knowing if socket is available or not.
 * values returned: -1 + EAGAIN => nothing to read, but socket is ok
 *                  0, no errno => nothing to read, but socket is ok
 *                 -1, EAGAIN => nothing to read, but socket is still ok
 *                 -1, ENOTCONN => socket got disconnected
 */
static int qthrift_vpnservice_bgp_updater_check_connection (struct qthrift_vpnservice *setup)
{
  ThriftTransport *transport = NULL;
  ThriftSocket *tsocket = NULL;
  int fd = 0;
  int ret;
  char buffer[32];

  if(!setup)
    return 0;
  if (setup->bgp_updater_transport)
    transport = setup->bgp_updater_transport->transport;
  if (transport)
    tsocket = THRIFT_SOCKET (transport);
  if (tsocket)
    fd = tsocket->sd;
  if (fd == 0)
    ret = 0;
  else
    ret = recv(fd, buffer, 32, MSG_PEEK | MSG_DONTWAIT);
  return ret;
}

static int qthrift_vpnservice_setup_bgp_updater_client_retry (struct thread *thread)
{
  struct qthrift_vpnservice *setup;
  GError *error = NULL;
  gboolean response;

  setup = THREAD_ARG (thread);
  assert (setup);
  thrift_transport_close (setup->bgp_updater_transport->transport, &error);
  response = thrift_transport_open (setup->bgp_updater_transport->transport, &error);
  qthrift_monitor_retry_job_in_progress = 0;
  qthrift_transport_check_response(setup, response);
  return 0;
}

/* detects if remote peer is present or not
 * either relaunch monitor or retry to reconnect
 */
static int qthrift_vpnservice_setup_bgp_updater_client_monitor (struct thread *thread)
{
  struct qthrift_vpnservice *setup;
  GError *error = NULL;
  gboolean response;
  int ret;

  setup = THREAD_ARG (thread);
  assert (setup);
  ret = qthrift_vpnservice_bgp_updater_check_connection (setup);
  if (ret == 0 ||
      (ret < 0 && errno != ENOTCONN))
    {
      qthrift_monitor_retry_job_in_progress = 0;
      qthrift_transport_check_response(setup, 1);
      return 0;
    }
  thrift_transport_close (setup->bgp_updater_transport->transport, &error);
  response = thrift_transport_open (setup->bgp_updater_transport->transport, &error);
  qthrift_monitor_retry_job_in_progress = 0;
  qthrift_transport_check_response(setup, response);
  return 0;
}

/* callback function for capnproto bgpupdater notifications */
static void qthrift_vpnservice_callback (void *arg, void *zmqsock, void *message)
{
  struct capn rc;
  capn_ptr p;
  struct bgp_event_vrf ss;
  struct bgp_event_vrf *s;
  static gboolean client_ready;
  struct qthrift_vpnservice *ctxt = NULL;
  struct bgp_event_shut tt;
  struct bgp_event_shut *t;
  bool announce;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      return;
    }
  ctxt->bgp_update_total++;
  /* if first time or previous failure, try to reconnect to client */
  if((ctxt->bgp_updater_client == NULL) || (qthrift_transport_current_status == FALSE))
    {
      if(ctxt->bgp_updater_client)
        qthrift_vpnservice_terminate_thrift_bgp_updater_client(ctxt);
      /* start the retry mecanism */
      client_ready = qthrift_vpnservice_setup_thrift_bgp_updater_client(ctxt);
      qthrift_transport_check_response(ctxt, client_ready);
      if(client_ready == FALSE)
        {
          if(IS_QTHRIFT_DEBUG_NOTIFICATION)
            zlog_debug ("bgp->sdnc message failed to be sent");
          ctxt->bgp_update_lost_msgs++;
          return;
        }
    }
  p = qzc_msg_to_notification((zmq_msg_t * )message, &rc);
  s = &ss;
  memset(s, 0, sizeof(struct bgp_event_vrf));
  qcapn_BGPEventVRFRoute_read(s, p);
  if (s->announce != BGP_EVENT_SHUT)
    {
      announce = (s->announce & BGP_EVENT_MASK_ANNOUNCE)?TRUE:FALSE;
      if (announce == TRUE)
        {
          char vrf_rd_str[RD_ADDRSTRLEN], pfx_str[INET6_BUFSIZ];
          struct prefix *p = (struct prefix *)&(s->prefix);

          prefix_rd2str(&s->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
          inet_ntop (p->family, &p->u.prefix, pfx_str, INET6_BUFSIZ);
          qthrift_bgp_updater_on_update_push_route(vrf_rd_str, pfx_str, (const gint32)s->prefix.prefixlen, \
                                                                  inet_ntoa(s->nexthop), s->label);
        }
      else
        {
          char vrf_rd_str[RD_ADDRSTRLEN], pfx_str[INET6_BUFSIZ], nh_str[INET6_BUFSIZ];
          struct prefix *p = (struct prefix *)&(s->prefix);

          inet_ntop (p->family, &p->u.prefix, pfx_str, INET6_BUFSIZ);
          prefix_rd2str(&s->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
          inet_ntop (p->family, &s->nexthop, nh_str, INET6_BUFSIZ);
          qthrift_bgp_updater_on_update_withdraw_route(vrf_rd_str, pfx_str, (const gint32)s->prefix.prefixlen, nh_str, s->label);
        }
    }
  else
    {
      char ip_str[INET6_BUFSIZ];
      t = &tt;
      memset(t, 0, sizeof(struct bgp_event_shut));
      t->peer.s_addr = s->nexthop.s_addr;
      t->type = (uint8_t)s->label;
      t->subtype = (uint8_t)s->prefix.prefix.s_addr;
      inet_ntop (AF_INET,&(t->peer), ip_str, INET6_BUFSIZ);
      qthrift_bgp_updater_on_notification_send_event(ip_str, t->type, t->subtype);
    }
  capn_free(&rc);
  if(client_ready == FALSE)
    ctxt->bgp_update_lost_msgs++;
  return;
}

#define SBIN_DIR "/sbin"

void qthrift_vpnservice_setup(struct qthrift_vpnservice *setup)
{
  char bgpd_location_path[128];
  char *ptr = bgpd_location_path;

  setup->qthrift_listen_port = QTHRIFT_LISTEN_PORT;
  setup->qthrift_notification_port = QTHRIFT_NOTIFICATION_PORT;
  setup->zmq_sock = XSTRDUP(MTYPE_QTHRIFT, ZMQ_SOCK);
  setup->zmq_subscribe_sock = XSTRDUP(MTYPE_QTHRIFT, ZMQ_NOTIFY);
  ptr+=cmd_get_path_prefix_dir(bgpd_location_path, 128);
  ptr+=sprintf(ptr, "%s/bgpd",SBIN_DIR);
  setup->bgpd_execution_path = XSTRDUP(MTYPE_QTHRIFT, bgpd_location_path);
  qthrift_vpnservice_setup_thrift_bgp_cache(setup);
}

void qthrift_vpnservice_setup_thrift_bgp_cache( struct qthrift_vpnservice *setup)
{
  setup->bgp_vrf_list = list_new();
  setup->bgp_peer_list = list_new();
  setup->bgp_get_routes_list = list_new();
}


void qthrift_vpnservice_terminate(struct qthrift_vpnservice *setup)
{
  if(!setup)
    return;
  setup->qthrift_listen_port = 0;
  setup->qthrift_notification_port = 0;
  XFREE(MTYPE_QTHRIFT, setup->zmq_sock);
  setup->zmq_sock = NULL;
  XFREE(MTYPE_QTHRIFT, setup->zmq_subscribe_sock);
  setup->zmq_subscribe_sock = NULL;
  XFREE(MTYPE_QTHRIFT, setup->bgpd_execution_path);
  setup->bgpd_execution_path = NULL;
}

void qthrift_vpnservice_terminate_thrift_bgp_updater_client (struct qthrift_vpnservice *setup)
{
  GError *error = NULL;

  if(!setup)
    return;
  thrift_transport_close (setup->bgp_updater_transport->transport, &error);
  if(setup->bgp_updater_client)
    g_object_unref(setup->bgp_updater_client);
  setup->bgp_updater_client = NULL;
  if(setup->bgp_updater_protocol)
    g_object_unref(setup->bgp_updater_protocol);
  setup->bgp_updater_protocol = NULL;
  if(setup->bgp_updater_transport)
    g_object_unref(setup->bgp_updater_transport);
  setup->bgp_updater_transport = NULL;
  if(setup->bgp_updater_socket)
    g_object_unref(setup->bgp_updater_socket);
  setup->bgp_updater_socket = NULL;
}

gboolean qthrift_vpnservice_setup_thrift_bgp_updater_client (struct qthrift_vpnservice *setup)
{
  GError *error = NULL;
  gboolean response;

  if(!setup->bgp_updater_socket)
    setup->bgp_updater_socket =
      g_object_new (THRIFT_TYPE_SOCKET,
                    "hostname",  tm->qthrift_notification_address,
                    "port",      setup->qthrift_notification_port,
                    NULL);
  if(!setup->bgp_updater_transport)
    setup->bgp_updater_transport =
      g_object_new (THRIFT_TYPE_FRAMED_TRANSPORT,
                    "transport", setup->bgp_updater_socket,
                    NULL);
  if(!setup->bgp_updater_protocol)
    setup->bgp_updater_protocol  =
      g_object_new (THRIFT_TYPE_BINARY_PROTOCOL,
                    "transport", setup->bgp_updater_transport,
                    NULL);
  /* In the C (GLib) implementation of Thrift, service methods on the
     server are accessed via a generated client class that implements
     the service interface. In this tutorial, we access a Calculator
     service through an instance of CalculatorClient, which implements
     CalculatorIf. */
  if(!setup->bgp_updater_client)
    setup->bgp_updater_client = 
      g_object_new (TYPE_BGP_UPDATER_CLIENT,
                    "input_protocol",  setup->bgp_updater_protocol,
                    "output_protocol", setup->bgp_updater_protocol,
                    NULL);
  response = thrift_transport_open (setup->bgp_updater_transport->transport, &error);
  qthrift_transport_check_response(setup, response);
  return response;
}

void qthrift_vpnservice_setup_thrift_bgp_configurator_server (struct qthrift_vpnservice *setup)
{
  /* Create our server socket, which binds to the specified port and
     listens for client connections */
  setup->bgp_configurator_server_transport =
    g_object_new (THRIFT_TYPE_SERVER_SOCKET,
                  "port", setup->qthrift_listen_port,
                  NULL);
  /* Create an instance of our handler, which provides the service's
     methods' implementation */
  setup->bgp_configurator_handler =
      g_object_new (TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER, NULL);

  /* Create an instance of the service's processor, automatically
     generated by the Thrift compiler, which parses incoming messages
     and dispatches them to the appropriate method in the handler */
  setup->bgp_configurator_processor = g_object_new (TYPE_BGP_CONFIGURATOR_PROCESSOR,
                                  "handler", setup->bgp_configurator_handler,
                                  NULL);
}

void qthrift_vpnservice_terminate_thrift_bgp_configurator_server (struct qthrift_vpnservice *setup)
{
  if(!setup)
    return;
  g_object_unref(setup->bgp_configurator_handler);
  setup->bgp_configurator_handler = NULL;
  g_object_unref(setup->bgp_configurator_processor);
  setup->bgp_configurator_processor = NULL;
  g_object_unref(setup->bgp_configurator_server_transport);
  setup->bgp_configurator_server_transport = NULL;
}

void qthrift_vpnservice_get_context (struct qthrift_vpnservice **setup)
{
  if(!tm->qthrift)
    *setup = NULL;
  *setup = tm->qthrift->qthrift_vpnservice;
}

u_int16_t qthrift_vpnservice_get_thrift_bgp_configurator_server_port (struct qthrift_vpnservice *setup)
{
  return setup->qthrift_listen_port;
}

void qthrift_vpnservice_set_thrift_bgp_configurator_server_port (struct qthrift_vpnservice *setup, \
                                                                 u_int16_t thrift_listen_port)
{
  setup->qthrift_listen_port = thrift_listen_port;
}

u_int16_t qthrift_vpnservice_get_thrift_bgp_updater_client_port (struct qthrift_vpnservice *setup)
{
  return setup->qthrift_notification_port;
}

void qthrift_vpnservice_set_thrift_bgp_updater_client_port (struct qthrift_vpnservice *setup, uint16_t thrift_notif_port)
{
  setup->qthrift_notification_port = thrift_notif_port;
}

void qthrift_vpnservice_terminate_client(struct qthrift_vpnservice_client *peer)
{
  if(peer == NULL)
    return;
  /* peer destroy */
  thrift_transport_close(peer->transport, NULL);
  g_object_unref(peer->transport_buffered);
  g_object_unref(peer->protocol);
  peer->protocol = NULL;
  g_object_unref(peer->simple_server);
  peer->simple_server = NULL;
  peer->server = NULL;
}

void qthrift_vpnservice_setup_client(struct qthrift_vpnservice_client *peer,
                                     struct qthrift_vpnservice *server, \
                                     ThriftTransport *transport)
{
  if(!peer)
    return;
  peer->transport = transport;
  peer->transport_buffered =
    g_object_new (THRIFT_TYPE_BUFFERED_TRANSPORT,
                  "transport", transport,
                  NULL);
  peer->protocol =
    g_object_new (THRIFT_TYPE_BINARY_PROTOCOL,
                  "transport", peer->transport_buffered,
                  NULL);
  /* Create the server itself */
  peer->simple_server =
    g_object_new (THRIFT_TYPE_SIMPLE_SERVER,
                  "processor",  server->bgp_configurator_processor,
                  NULL);
  if(peer->simple_server && &(peer->simple_server->parent))
    peer->server = &(peer->simple_server->parent);
  return;
}

void qthrift_vpnservice_terminate_qzc(struct qthrift_vpnservice *setup)
{
  if(!setup)
    return;
  if(setup->qzc_subscribe_sock)
    qzc_close (setup->qzc_subscribe_sock);
  setup->qzc_subscribe_sock = NULL;
  if(setup->qzc_sock)
      qzc_close (setup->qzc_sock);
  setup->qzc_sock = NULL;

  qzmq_finish();
}

void qthrift_vpnservice_setup_qzc(struct qthrift_vpnservice *setup)
{
  qzc_init ();
  if(setup->zmq_subscribe_sock && setup->qzc_subscribe_sock == NULL )
    setup->qzc_subscribe_sock = qzcclient_subscribe(tm->master, \
                                                    setup->zmq_subscribe_sock, \
                                                    qthrift_vpnservice_callback);
}

void qthrift_vpnservice_terminate_bgp_context(struct qthrift_vpnservice *setup)
{
  if(!setup->bgp_context)
    return;
  if(setup->bgp_context->proc)
    {
      zlog_info ("sending SIGINT signal to Bgpd (%d)",setup->bgp_context->proc);
      kill(setup->bgp_context->proc, SIGINT);
      setup->bgp_context->proc = 0;
    }
  if(setup->bgp_context)
    {
      XFREE(MTYPE_QTHRIFT, setup->bgp_context);
      setup->bgp_context = NULL;
    }
  return;
}

void qthrift_vpnservice_setup_bgp_context(struct qthrift_vpnservice *setup)
{
  setup->bgp_context=XCALLOC(MTYPE_QTHRIFT, sizeof(struct qthrift_vpnservice_bgp_context));
}

struct qthrift_vpnservice_bgp_context *qthrift_vpnservice_get_bgp_context(struct qthrift_vpnservice *setup)
{
  return setup->bgp_context;
}

void qthrift_vpnservice_terminate_thrift_bgp_cache (struct qthrift_vpnservice *setup)
{
  struct listnode *node, *nnode;
  struct qthrift_vpnservice_cache_bgpvrf *entry_bgpvrf;
  struct qthrift_vpnservice_cache_peer *entry_peer;

  for (ALL_LIST_ELEMENTS(setup->bgp_vrf_list, node, nnode, entry_bgpvrf))
    {
      listnode_delete(setup->bgp_vrf_list, entry_bgpvrf);
      XFREE (MTYPE_QTHRIFT, entry_bgpvrf);
    }
  setup->bgp_vrf_list = NULL;
  for (ALL_LIST_ELEMENTS(setup->bgp_peer_list, node, nnode, entry_peer))
    {
      listnode_delete(setup->bgp_peer_list, entry_peer);
      XFREE (MTYPE_QTHRIFT, entry_peer);
    }
  setup->bgp_peer_list = NULL;
}
