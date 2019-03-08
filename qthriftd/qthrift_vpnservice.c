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

#include "prefix.h"
#include "table.h"

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
#include "qthriftd/qthrift_network.h"
#include "qthriftd/vpnservice_types.h"

static void qthrift_vpnservice_callback (void *arg, void *zmqsock, void *msg);
 
void qthrift_transport_change_status(struct qthrift_vpnservice *setup, gboolean response);
void qthrift_transport_cancel_monitor(struct qthrift_vpnservice *setup);
void qthrift_transport_check_response(struct qthrift_vpnservice *setup, gboolean response);
static int qthrift_vpnservice_setup_bgp_updater_client_retry (struct thread *thread);
static int qthrift_vpnservice_setup_bgp_updater_client_monitor (struct thread *thread);
static void qthrift_transport_configures_cloexec(ThriftTransport *transport);
int qthrift_monitor_retry_job_in_progress = 0;
qthrift_status qthrift_transport_current_status;

unsigned int notification_socket_errno[QTHRIFT_MAX_ERRNO];

static void qthrift_update_notification_socket_errno(int err) {
  if (err >= QTHRIFT_MAX_ERRNO)
    return;
  notification_socket_errno[err]++;
}

void qthrift_transport_change_status(struct qthrift_vpnservice *setup, gboolean response)
{
  if ((qthrift_transport_current_status == QTHRIFT_TO_SDN_UNKNOWN) ||
      ((response == TRUE) && (qthrift_transport_current_status == QTHRIFT_TO_SDN_FALSE)) ||
      ((response == FALSE) && (qthrift_transport_current_status == QTHRIFT_TO_SDN_TRUE)))
    {
      zlog_info("bgpUpdater check connection with %s:%u %s",
                tm->qthrift_notification_address,
                setup->qthrift_notification_port,
                response == TRUE?"OK":"NOK");
      if (response == TRUE) {
        qthrift_transport_current_status = QTHRIFT_TO_SDN_TRUE;
        qthrift_bgp_updater_on_start_config_resync_notification_quick (setup, FALSE);
      } else {
        qthrift_transport_current_status = QTHRIFT_TO_SDN_FALSE;
      }
    }
}
void qthrift_transport_cancel_monitor(struct qthrift_vpnservice *setup)
{
  if (setup->bgp_updater_client_thread)
    {
      THREAD_TIMER_OFF(setup->bgp_updater_client_thread);
      setup->bgp_updater_client_thread = NULL;
    }
  qthrift_monitor_retry_job_in_progress = 0;
}

void qthrift_transport_check_response(struct qthrift_vpnservice *setup, gboolean response)
{
  if(qthrift_monitor_retry_job_in_progress)
    return;
  qthrift_transport_change_status (setup, response);
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

int qthrift_vpnservice_get_bgp_updater_socket (struct qthrift_vpnservice *setup)
{
  ThriftTransport *transport = NULL;
  ThriftSocket *tsocket = NULL;

  if(!setup)
    return 0;
  if (setup->bgp_updater_transport)
    transport = setup->bgp_updater_transport->transport;
  if (transport)
    tsocket = THRIFT_SOCKET (transport);
  if (tsocket)
    return tsocket->sd;
  return 0;
}

static gboolean qthrift_vpnservice_bgp_updater_select_connection (struct qthrift_vpnservice *setup)
{
  int ret = 0;
  int fd = qthrift_vpnservice_get_bgp_updater_socket(setup);
  fd_set wrfds;
  struct timeval tout;
  int optval, optlen;

  if (fd == 0 || fd == THRIFT_INVALID_SOCKET)
    return FALSE;
  if (setup->bgp_updater_client_need_select == FALSE)
    return FALSE;

  FD_ZERO(&wrfds);
  FD_SET(fd, &wrfds);

  tout.tv_sec = 0;
  tout.tv_usec = 0;

  ret = select(FD_SETSIZE, NULL, &wrfds, NULL, &tout);
  if (ret <= 0)
    return FALSE;

  optval = -1;
  optlen = sizeof (optval);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, (socklen_t *)&optlen) < 0)
    return FALSE;
  if (optval != 0)
    return FALSE;

  return TRUE;
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
  int ret = 0;
  int fd = qthrift_vpnservice_get_bgp_updater_socket(setup);
  char buffer[32];

  if (setup->bgp_updater_select_in_progress == TRUE)
    return 0;
  if (fd != 0 && fd != THRIFT_INVALID_SOCKET)
    ret = recv(fd, buffer, 32, MSG_PEEK | MSG_DONTWAIT);
  if (ret == 0)
    {
      qthrift_update_notification_socket_errno(ENOTCONN);
      return -1;
    }
  else
    {
      if (ret == -1)
        {
          qthrift_update_notification_socket_errno(errno);
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
          /* other cases : EBADF, ECONNREFUSED, EFAULT, EINTR, EINVAL,
           * EINOMEM, ENOTCONN, ENOTSOCK
           * should fall on error
           */
          return -1;
        }
    }
  return ret;
}

static int qthrift_vpnservice_setup_bgp_updater_client_retry (struct thread *thread)
{
  struct qthrift_vpnservice *setup;
  gboolean response;

  setup = THREAD_ARG (thread);
  assert (setup);
  if (qthrift_vpnservice_bgp_updater_select_connection(setup))
    {
      qthrift_monitor_retry_job_in_progress = 0;
      qthrift_transport_check_response(setup, TRUE);
      return 0;
    }
  qthrift_client_transport_close(setup->bgp_updater_transport->transport);
  setup->bgp_updater_client_need_select = FALSE;
  response = qthrift_client_transport_open (setup->bgp_updater_transport->transport,
                                            &setup->bgp_updater_client_need_select);
  if (response == FALSE)
    {
      zlog_err ("%s: qthrift_client_transport_open error\n", __func__);
    }
  qthrift_transport_configures_cloexec(setup->bgp_updater_transport->transport);
  qthrift_monitor_retry_job_in_progress = 0;
  qthrift_transport_check_response(setup, response);
  return 0;
}

static void qthrift_transport_configures_cloexec(ThriftTransport *transport)
{
  ThriftSocket *tsocket = NULL;
  int fd = 0;
  if (transport)
    tsocket = THRIFT_SOCKET (transport);
  if (tsocket)
    fd = tsocket->sd;
  if (fd != 0 && fd != -1) {
    if (fcntl (tsocket->sd, F_SETFD, FD_CLOEXEC) == -1)
       zlog_err ("qthrift_transport_configures_cloexec : fcntl failed (%s)", safe_strerror (errno));
  }
}

/* detects if remote peer is present or not
 * either relaunch monitor or retry to reconnect
 */
static int qthrift_vpnservice_setup_bgp_updater_client_monitor (struct thread *thread)
{
  struct qthrift_vpnservice *setup;
  gboolean response;
  int ret;
  setup = THREAD_ARG (thread);
  assert (setup);
  ret = qthrift_vpnservice_bgp_updater_check_connection (setup);
  if (ret < 0)
    {
      qthrift_client_transport_close(setup->bgp_updater_transport->transport);
      setup->bgp_updater_client_need_select = FALSE;
      response = qthrift_client_transport_open (setup->bgp_updater_transport->transport,
                                                &setup->bgp_updater_client_need_select);
      if (response == FALSE)
        {
          zlog_err ("%s: qthrift_client_transport_open error\n", __func__);
        }
      qthrift_transport_configures_cloexec(setup->bgp_updater_transport->transport);
      qthrift_monitor_retry_job_in_progress = 0;
      qthrift_transport_check_response(setup, response);
      return 0;
    }
  qthrift_monitor_retry_job_in_progress = 0;
  qthrift_transport_check_response(setup, 1);
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
  if (qthrift_silent_leave)
    {
      return;
    }


  ctxt->bgp_update_total++;
  /* if first time or previous failure, try to reconnect to client */
  if((ctxt->bgp_updater_client == NULL) ||
     (qthrift_transport_current_status == QTHRIFT_TO_SDN_UNKNOWN) ||
     (qthrift_transport_current_status == QTHRIFT_TO_SDN_FALSE))
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
          struct qthrift_vpnservice_cache_bgpvrf *entry;

          prefix_rd2str(&s->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
          inet_ntop (p->family, &p->u.prefix, pfx_str, INET6_BUFSIZ);
          /* if qthrift launched with specific option, let withdraw messages
           * reach the sdn controller
           */
          if (!qthrift_withdraw_permit) {
            struct prefix_rd prd_local;

            memset(&prd_local, 0, sizeof(struct prefix_rd));
            prefix_str2rd (vrf_rd_str, &prd_local);
            /* if vrf not found, silently don't send message to sdn controller */
            entry = qthrift_bgp_configurator_find_vrf(ctxt, &prd_local, NULL);
            if (!entry) {
              if (IS_QTHRIFT_DEBUG_NOTIFICATION)
                zlog_debug ("RD %s not present. Cancel onUpdateWithdrawRoute() for %s",
                            vrf_rd_str, pfx_str);
              capn_free(&rc);
              return;
            }
          }
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
  qthrift_vpnservice_setup_bgp_context(setup);
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
  if (!setup->bgp_updater_transport)
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
  qthrift_client_transport_close(setup->bgp_updater_transport->transport);
  setup->bgp_updater_client_need_select = FALSE;
  setup->bgp_updater_select_in_progress = FALSE;
  response = qthrift_client_transport_open (setup->bgp_updater_transport->transport,
                                            &setup->bgp_updater_client_need_select);
  if (response == FALSE)
    {
      zlog_err ("%s: qthrift_client_transport_open error\n", __func__);
    }
  qthrift_transport_configures_cloexec(setup->bgp_updater_transport->transport);
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
  GError *error = NULL;
  if(peer == NULL)
    return;
  /* peer destroy */
  thrift_transport_flush(peer->transport, &error);
  if (error != NULL)
    {
      zlog_err("Unable to flush thrift socket: %s\n", error->message);
      g_error_free (error);
      error = NULL;
    }
  thrift_transport_close(peer->transport, &error);
  if (error != NULL)
    {
      zlog_err("Unable to close thrift socket: %s\n", error->message);
      g_error_free (error);
    }
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
    {
      int val = 0;
      qzc_setsockopt(setup->qzc_subscribe_sock, ZMQ_LINGER, &val, sizeof(val));
      qzc_close (setup->qzc_subscribe_sock);
      setup->qzc_subscribe_sock = NULL;
    }

  if(setup->qzc_sock)
    {
      int val = 0;
      qzc_setsockopt(setup->qzc_sock, ZMQ_LINGER, &val, sizeof(val));
      qzc_close (setup->qzc_sock);
      setup->qzc_sock = NULL;
    }

  qzmq_finish();
}

void qthrift_vpnservice_setup_qzc(struct qthrift_vpnservice *setup)
{
  qzc_init ();
  if(setup->zmq_subscribe_sock && setup->qzc_subscribe_sock == NULL )
    setup->qzc_subscribe_sock = qzcclient_subscribe(tm->master, \
                                                    setup->zmq_subscribe_sock, \
                                                    qthrift_vpnservice_callback,
                                                    QZC_CLIENT_ZMQ_LIMIT_RX);
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
  if (setup->bgp_context)
    return;
  setup->bgp_context=XCALLOC(MTYPE_QTHRIFT, sizeof(struct qthrift_vpnservice_bgp_context));
  setup->bgp_context->logFile = strdup (BGP_DEFAULT_LOG_FILE);
  setup->bgp_context->logLevel = strdup (BGP_DEFAULT_LOG_LEVEL);
  /* configure default file log settings to qthrift daemon too */
  set_log_file_with_level(setup->bgp_context->logFile, setup->bgp_context->logLevel);
}

#define ERROR_BGP_MULTIPATH_SET g_error_new(1, BGP_ERR_ACTIVE, "BGP multipath already configured for afi/safi");
#define ERROR_BGP_MULTIPATH_UNSET g_error_new(1, BGP_ERR_INACTIVE, "BGP multipath already unconfigured for afi/safi");

gboolean qthrift_vpnservice_set_bgp_context_multipath (struct qthrift_vpnservice_bgp_context *bgp,
                                                       afi_t afi, safi_t safi, uint8_t on,
                                                       gint32* _return, GError **error)
{
  if (on && bgp->multipath_on[afi][safi])
    {
      *_return = BGP_ERR_ACTIVE;
      *error = ERROR_BGP_MULTIPATH_SET;
      return FALSE;
    }
  if ((on == 0) && bgp->multipath_on[afi][safi] == 0)
    {
      *_return = BGP_ERR_INACTIVE;
      *error = ERROR_BGP_MULTIPATH_UNSET;
      return FALSE;
    }
  bgp->multipath_on[afi][safi] = 1;
  return TRUE;
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
  struct route_node *rn;

  THREAD_TIMER_OFF(setup->config_stale_thread);

  for (ALL_LIST_ELEMENTS(setup->bgp_vrf_list, node, nnode, entry_bgpvrf))
    {
      /* Clear static route table */
      qthrift_clear_vrf_route_table(entry_bgpvrf);

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

void qthrift_config_stale_timer_flush(struct qthrift_vpnservice *setup, bool donotflush)
{
  struct qthrift_vpnservice_cache_bgpvrf *vrf;
  struct listnode *node, *nnode;
  struct qthrift_cache_peer *peer;

  if (donotflush) {
    zlog_err ("ODL/Bgp connection configuration synchronization failed, "
              "stale timer expired after %d seconds, not REMOVE any "
              "stale configuration below.", qthrift_stalemarker_timer);
  }
  for (ALL_LIST_ELEMENTS(setup->bgp_vrf_list, node, nnode, vrf))
    {
      if (CHECK_FLAG(vrf->flags, BGP_CONFIG_FLAG_STALE))
        {
          if (donotflush)
            {
              if (IS_QTHRIFT_DEBUG)
                {
                  char rdstr[RD_ADDRSTRLEN];
                  struct route_node *rn;

                  /* delete the static routes marked as STALE */
                  for (rn = route_top (vrf->route[AFI_IP]); rn; rn = route_next (rn))
                    {
                      struct qthrift_bgp_static *bs;

                      if ((bs = rn->info) != NULL)
                        {
                          if (CHECK_FLAG(bs->flags, BGP_CONFIG_FLAG_STALE))
                            {
                              char pfx_str[INET6_BUFSIZ];
                              char vrf_rd_str[RD_ADDRSTRLEN];

                              prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
                              prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
                              zlog_err ("Stale route(prefix %s, rd %s) should be withdrawn", pfx_str, vrf_rd_str);
                            }
                        }
                    }
                  prefix_rd2str(&(vrf->outbound_rd), rdstr, RD_ADDRSTRLEN);
                  zlog_err ("Stale vrf %s(%llx) should be deleted", rdstr,
                              (long long unsigned int)vrf->bgpvrf_nid);
                }
            }
          else
            qthrift_delete_stale_vrf(setup, vrf);
        }
      else /* vrf is not STALE, while static route is STALE */
        {
          struct route_node *rn;
          /* delete the static routes marked as STALE */
          for (rn = route_top (vrf->route[AFI_IP]); rn; rn = route_next (rn))
            {
              struct qthrift_bgp_static *bs;

              if ((bs = rn->info) != NULL)
                {
                  if (CHECK_FLAG(bs->flags, BGP_CONFIG_FLAG_STALE))
                    {
                      if (donotflush)
                        {
                          if (IS_QTHRIFT_DEBUG)
                            {
                              char pfx_str[INET6_BUFSIZ];
                              char vrf_rd_str[RD_ADDRSTRLEN];

                              prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
                              prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
                              zlog_err ("Stale route(prefix %s, rd %s) should be withdrawn", pfx_str, vrf_rd_str);
                            }
                        }
                      else
                        {
                              qthrift_delete_stale_route(setup, rn);
                              XFREE(MTYPE_QTHRIFT, bs);
                              rn->info = NULL;
                              route_unlock_node(rn);
                        }
                    }
                }
            }
        }
    }

  for (ALL_LIST_ELEMENTS(setup->bgp_peer_list, node, nnode, peer))
    {
      if (CHECK_FLAG(peer->flags, BGP_CONFIG_FLAG_STALE))
        {
          if (donotflush)
            {
              if (IS_QTHRIFT_DEBUG)
                {
                  zlog_info ("Stale peer %s(%llx) should be deleted",
                             peer->peerIp, (long long unsigned int)peer->peer_nid);
                }
            }
          else
            qthrift_delete_stale_peer(setup, peer);
        }
    }
}

static int qthrift_config_stale_timer_expire (struct thread *thread)
{
  struct qthrift_vpnservice *setup;

  setup = THREAD_ARG (thread);
  assert (setup);
  qthrift_config_stale_timer_flush(setup, TRUE);
  return 0;
}

/* called when TCP 6644 connection to BGP Updater server is disconnected */
void qthrift_config_stale_set(struct qthrift_vpnservice *setup)
{
  struct listnode *node, *nnode;
  struct qthrift_vpnservice_cache_bgpvrf *vrf;
  struct qthrift_cache_peer *peer;

  if (!qthrift_config_stale_timer_expire)
    return;
  if (!setup)
    return;
  if (qthrift_vpnservice_get_bgp_context(setup) == NULL ||
      qthrift_vpnservice_get_bgp_context(setup)->asNumber == 0)
    return;

  /* lookup in cache context, and set QBGP_CONFIG_STALE flag */
  for (ALL_LIST_ELEMENTS(setup->bgp_vrf_list, node, nnode, vrf))
    {
      struct route_node *rn;

      if (IS_QTHRIFT_DEBUG)
        {
          char rdstr[RD_ADDRSTRLEN];
          prefix_rd2str(&(vrf->outbound_rd), rdstr, RD_ADDRSTRLEN);
          zlog_debug ("VRF %s set to STALE state", rdstr);
        }
      SET_FLAG (vrf->flags, BGP_CONFIG_FLAG_STALE);

      for (rn = route_top (vrf->route[AFI_IP]); rn; rn = route_next (rn))
        {
          struct qthrift_bgp_static *bs;

          if ((bs = rn->info) != NULL)
            {
              if (IS_QTHRIFT_DEBUG)
                {
                  char rdstr[RD_ADDRSTRLEN];
                  char pfx_str[INET6_BUFSIZ];

                  prefix_rd2str(&(vrf->outbound_rd), rdstr, RD_ADDRSTRLEN);
                  prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
                  zlog_debug ("Route(prefix %s, rd %s) set to STALE state", pfx_str, rdstr);
                }
              SET_FLAG(bs->flags, BGP_CONFIG_FLAG_STALE);
            }
        }
    }

  for (ALL_LIST_ELEMENTS(setup->bgp_peer_list, node, nnode, peer))
    {
      if (IS_QTHRIFT_DEBUG)
        zlog_debug ("Peer %s set to STALE state", peer->peerIp);
      SET_FLAG (peer->flags, BGP_CONFIG_FLAG_STALE);
    }

  THREAD_TIMER_OFF(setup->config_stale_thread);
  THREAD_TIMER_MSEC_ON(tm->master, setup->config_stale_thread, \
                       qthrift_config_stale_timer_expire, \
                       setup, qthrift_stalemarker_timer * 1000);
}
