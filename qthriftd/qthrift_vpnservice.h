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
#ifndef _QTHRIFT_VPNSERVICE_H
#define _QTHRIFT_VPNSERVICE_H

#include "bgpd.h"
#include "prefix.h"
#include "linklist.h"

#define QTHRIFT_LISTEN_PORT	 7644
#define QTHRIFT_NOTIFICATION_PORT 6644
#define QTHRIFT_CLIENT_ADDRESS "0.0.0.0"
#define QTHRIFT_SELECT_TIME_SEC 10
#define ZMQ_SOCK "ipc:///tmp/qzc-vpn2bgp"
#define ZMQ_NOTIFY "ipc:///tmp/qzc-notify"

#define BGPD_ARGS_STRING_1  "-p"
#define BGPD_ARGS_STRING_3  "-Z"

struct qthrift_vpnservice_client
{
  ThriftProcessor *processor;
  ThriftTransport *transport;
  ThriftBufferedTransport *transport_buffered;
  ThriftProtocol *protocol;
  ThriftServer *server;
  ThriftSimpleServer *simple_server;
};

#define BGP_DEFAULT_LOG_FILE "/opt/quagga/var/log/quagga/qthriftd.init.log"
#define BGP_DEFAULT_LOG_LEVEL "debugging"
struct qthrift_vpnservice_bgp_context
{
  as_t asNumber;
  gint32 proc;
  char *logFile;
  char *logLevel;
  uint8_t multipath_on[AFI_MAX][SAFI_MAX];
};

/* qthrift cache contexts */
struct qthrift_vpnservice_cache_bgpvrf
{
  uint64_t bgpvrf_nid;
  struct prefix_rd outbound_rd;
};

struct qthrift_cache_peer
{
  uint64_t peer_nid;
  as_t asNumber;
  char *peerIp;
};

struct qthrift_vpnservice
{
  /* configuration part */
  /* qthrift listen port number.  */
  u_int16_t  qthrift_listen_port;

  /* qthrift notification port number.  */
  u_int16_t  qthrift_notification_port;

  /* qthrift BGP Contexts */
  ThriftServerTransport *bgp_configurator_server_transport;
  BgpConfiguratorProcessor *bgp_configurator_processor;
  InstanceBgpConfiguratorHandler *bgp_configurator_handler;

  /* qthrift Update Contexts */
  BgpUpdaterIf *bgp_updater_client;
  struct thread *bgp_updater_client_thread;
  gboolean bgp_updater_client_need_select;
  gboolean bgp_updater_select_in_progress;
  ThriftSocket *bgp_updater_socket;
  ThriftFramedTransport *bgp_updater_transport;
  ThriftProtocol *bgp_updater_protocol;

  /* bgp context */
  struct qthrift_vpnservice_bgp_context *bgp_context;

  /* CapnProto Path */
  char      *zmq_sock;

  /* CapnProto Subscribe Path */
  char      *zmq_subscribe_sock;

  /* BGPD binay execution path */
  char     *bgpd_execution_path;

  /* QZC internal contexts */
  struct qzc_sock *qzc_sock;
  struct qzc_sock **p_qzc_sock;
  struct qzc_sock *qzc_subscribe_sock;

  /* Thrift Cache Context */
  struct list *bgp_vrf_list;
  struct list *bgp_peer_list;

  /* Cache Context for getRoutes */
  struct list *bgp_get_routes_list;

  /* Thrift Update Statistics */
  u_int32_t bgp_update_lost_msgs;
  u_int32_t bgp_update_thrift_lost_msgs;
  u_int32_t bgp_update_monitor;
  u_int32_t bgp_update_retries;
  u_int32_t bgp_update_total;
  u_int32_t bgp_update_thrift_retries;
  u_int32_t bgp_update_thrift_retries_successfull;
};

enum _qthrift_status
  {
    QTHRIFT_TO_SDN_UNKNOWN,
    QTHRIFT_TO_SDN_TRUE,
    QTHRIFT_TO_SDN_FALSE
  };
typedef enum _qthrift_status qthrift_status;

#define QTHRIFT_MAX_ERRNO 132
extern unsigned int notification_socket_errno[];

void qthrift_vpnservice_terminate(struct qthrift_vpnservice *setup);
void qthrift_vpnservice_terminate_thrift_bgp_configurator_server(struct qthrift_vpnservice *setup);
void qthrift_vpnservice_terminate_thrift_bgp_updater_client(struct qthrift_vpnservice *setup);
gboolean qthrift_vpnservice_setup_thrift_bgp_updater_client (struct qthrift_vpnservice *setup);
void qthrift_vpnservice_setup_thrift_bgp_configurator_server(struct qthrift_vpnservice *setup);
void qthrift_vpnservice_setup(struct qthrift_vpnservice *setup);

void qthrift_vpnservice_get_context (struct qthrift_vpnservice **setup);
u_int16_t qthrift_vpnservice_get_thrift_bgp_configurator_server_port (struct qthrift_vpnservice *setup);
void qthrift_vpnservice_set_thrift_bgp_updater_client_port (struct qthrift_vpnservice *setup, \
                                                            u_int16_t thrift_notif_port);
u_int16_t qthrift_vpnservice_get_thrift_bgp_updater_client_port (struct qthrift_vpnservice *setup);
void qthrift_vpnservice_set_thrift_bgp_configurator_server_port (struct qthrift_vpnservice *setup, \
                                                                 u_int16_t thrift_listen_port);
void qthrift_vpnservice_setup_client(struct qthrift_vpnservice_client *peer,\
                                     struct qthrift_vpnservice *setup,  \
                                     ThriftTransport *transport);

void qthrift_vpnservice_terminate_client(struct qthrift_vpnservice_client *peer);

void qthrift_vpnservice_terminate_qzc(struct qthrift_vpnservice *setup);
void qthrift_vpnservice_setup_qzc(struct qthrift_vpnservice *setup);
struct qthrift_vpnservice_bgp_context *qthrift_vpnservice_get_bgp_context(struct qthrift_vpnservice *setup);
void qthrift_vpnservice_setup_bgp_context(struct qthrift_vpnservice *setup);
void qthrift_vpnservice_terminate_bgp_context(struct qthrift_vpnservice *setup);
void qthrift_vpnservice_terminate_thrift_bgp_cache (struct qthrift_vpnservice *setup);
void qthrift_vpnservice_setup_thrift_bgp_cache( struct qthrift_vpnservice *setup);
gboolean qthrift_vpnservice_set_bgp_context_multipath (struct qthrift_vpnservice_bgp_context *bgp,
                                                       afi_t afi, safi_t safi, uint8_t on,
                                                       gint32 *_return, GError **error);
void qthrift_vpnservice_apply_multipath (struct qthrift_vpnservice_bgp_context *bgp);
extern int qthrift_vpnservice_get_bgp_updater_socket (struct qthrift_vpnservice *setup);
extern uint64_t
qthrift_bgp_configurator_find_vrf(struct qthrift_vpnservice *ctxt, struct prefix_rd *rd, gint32* _return);

#endif /* _QTHRIFT_VPNSERVICE_H */
