/* qthrift thrift network interface
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
#include "sockunion.h"
#include "sockopt.h"
#include "memory.h"
#include "log.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "privs.h"
#include "linklist.h"
#include "network.h"
#include "filter.h"
#include <glib-object.h>
#include "qthriftd/qthrift_thrift_wrapper.h"
#include "qthriftd/qthriftd.h"
#include "qthriftd/qthrift_debug.h"
#include "qthriftd/qthrift_network.h"
#include "qthriftd/bgp_configurator.h"
#include "qthriftd/bgp_updater.h"
#include "qthriftd/qthrift_bgp_configurator.h"
#include "qthriftd/qthrift_bgp_updater.h"
#include "qthriftd/qthrift_vpnservice.h"

/* qthrift listening socket. */
struct qthrift_listener
{
  /* opaque pointer to qthrift structure */
  void *qthrift;
  struct thread *thread;
};

/* Update BGP socket send buffer size */
#define QTHRIFT_SOCKET_SNDBUF_SIZE    65536

static void
qthrift_update_sock_send_buffer_size (int fd)
{
  int size = QTHRIFT_SOCKET_SNDBUF_SIZE;
  int optval;
  socklen_t optlen = sizeof(optval);

  if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen) < 0)
    {
      zlog_err("getsockopt of SO_SNDBUF failed %s\n", safe_strerror(errno));
      return;
    }
  if (optval < size)
    {
      if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0)
        {
          zlog_err("Couldn't increase send buffer: %s\n", safe_strerror(errno));
        }
    }
}

/* Accept bgp connection. */
int 
qthrift_accept (struct thread *thread)
{
  struct qthrift_listener *listener = THREAD_ARG(thread);
  struct qthrift_peer *peer, *peer2;
  GError *error = NULL;
  struct qthrift *qthrift = (struct qthrift *)(listener->qthrift);
  ThriftTransport *transport;
  ThriftSocket *socket;
  struct listnode *node, *nnode;
  socklen_t len;

  /* Register accept thread. */
  if( THREAD_FD (thread) < 0)
    {
      zlog_err ("accept_sock is negative value %d", THREAD_FD (thread));
      return -1;
    }
  THREAD_OFF(listener->thread);
  THREAD_READ_ON (tm->master, listener->thread, qthrift_accept, listener, THREAD_FD(thread));

  transport = thrift_server_socket_accept(qthrift->qthrift_vpnservice->bgp_configurator_server_transport,
                                          &error);
  if (transport == NULL)
    {
      zlog_err ("[Error] qthrift server socket accept failed (%s)", safe_strerror (errno));
      return -1;
    }
  peer = qthrift_peer_create_accept(qthrift);
  socket = THRIFT_SOCKET (transport);
  peer->fd = socket->sd;
  len = sizeof(struct sockaddr_storage);
  getpeername(peer->fd, (struct sockaddr*)&peer->peerIp, &len);
  qthrift_update_sock_send_buffer_size (socket->sd);
  if(IS_QTHRIFT_DEBUG){
    char ipstr[INET6_ADDRSTRLEN];
    int port;
    if (peer->peerIp.ss_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)&peer->peerIp;
      port = ntohs(s->sin_port);
      inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
    } else {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)&peer->peerIp;
      port = ntohs(s->sin6_port);
      inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
    }
    zlog_info("qthrift_accept : new connection (fd %d) from %s:%u", socket->sd, ipstr, port);
  }
  //set_nonblocking (socket->sd);
  if (fcntl (socket->sd, F_SETFD, FD_CLOEXEC) == -1)
    zlog_err ("qthriftd accept : fcntl failed (%s)", safe_strerror (errno));

  peer->peer = XCALLOC(MTYPE_QTHRIFT, \
                       sizeof(struct qthrift_vpnservice_client));
  qthrift_vpnservice_setup_client(peer->peer,
                                  qthrift->qthrift_vpnservice,
                                  transport);
  /* run a thread for reading on accepted socket */
  THREAD_READ_ON (tm->master, peer->t_read, qthrift_read_packet, peer, peer->fd);

  /* close previous thrift connections */
  for (ALL_LIST_ELEMENTS (qthrift->peer, node, nnode, peer2))
    {
      if (peer == peer2)
        continue;
      if (peer->peerIp.ss_family == peer2->peerIp.ss_family)
        {
          if (peer->peerIp.ss_family == AF_INET)
            {
              struct sockaddr_in *update = (struct sockaddr_in *)&peer->peerIp;
              struct sockaddr_in *orig = (struct sockaddr_in *)&peer2->peerIp;
              if (update->sin_addr.s_addr == orig->sin_addr.s_addr)
                {
                  zlog_info("qthrift_accept : a new connection from same src IP. Ignoring it (fd %d)", peer2->fd);
                  continue;
                }
            } 
          else
            {
              struct sockaddr_in6 *update = (struct sockaddr_in6 *)&peer->peerIp;
              struct sockaddr_in6 *orig = (struct sockaddr_in6 *)&peer2->peerIp;
              if (0 == memcpy (&(update->sin6_addr), &(orig->sin6_addr), sizeof (struct sockaddr_in6)))
                {
                  zlog_info("qthrift_accept : a new connection from same src IP. Ignoring it (fd %d)", peer2->fd);
                  continue;
                }
            }
        }
      THREAD_OFF(peer2->t_read);
      list_delete_node (qthrift->peer, node);
      if(peer2->fd)
        {
          if (IS_QTHRIFT_DEBUG)
            zlog_info("qthrift_accept : close connection (fd %d)", peer2->fd);
          qthrift_vpnservice_terminate_client(peer2->peer);
          XFREE(MTYPE_QTHRIFT, peer2->peer);
          peer2->peer = NULL;
          peer2->fd=0;
        }
      XFREE(MTYPE_QTHRIFT, peer2);
    }

  return 0;
}

/* BGP read utility function. */
extern int
qthrift_read_packet (struct thread *thread)
{
  GError *error = NULL;
  struct qthrift_peer *peer = THREAD_ARG(thread);
  gboolean response;
  struct listnode *node;

  response = thrift_dispatch_processor_process (peer->peer->server->processor,\
                                     peer->peer->protocol,\
                                     peer->peer->protocol,\
                                     &error);
  if (error != NULL)
    {
      if(IS_QTHRIFT_DEBUG)
        zlog_info("qthriftd_read_packet: close connection (fd %d)", peer->fd);
      g_clear_error (&error);
      qthrift_vpnservice_terminate_client(peer->peer); 
      XFREE(MTYPE_QTHRIFT, peer->peer);
      peer->peer = NULL;
      peer->fd = 0;
      node = listnode_lookup(peer->qthrift->peer, peer);
      if(node)
        list_delete_node (peer->qthrift->peer, node);
      XFREE(MTYPE_QTHRIFT, peer);
   }
  else 
    {
      peer->t_read = thread_add_read(tm->master, qthrift_read_packet, peer, peer->fd);
    }
  return 0;
}

int
qthrift_server_listen (struct qthrift *qthrift)
{
  struct qthrift_listener *listener;
  GError *error = NULL;
  gboolean ret;

  ret = thrift_server_socket_listen( qthrift->qthrift_vpnservice->bgp_configurator_server_transport, &error);
  if(ret == TRUE)
    {
      ThriftServerSocket *tsocket = \
        THRIFT_SERVER_SOCKET (qthrift->qthrift_vpnservice->bgp_configurator_server_transport);

      if (fcntl (tsocket->sd, F_SETFD, FD_CLOEXEC) == -1)
        zlog_err ("qthrift_server_listen : fcntl failed (%s)", safe_strerror (errno));

      listener = XMALLOC (MTYPE_QTHRIFT, sizeof(*listener));
      listener->qthrift = qthrift;
      listener->thread = NULL;
      THREAD_READ_ON (tm->master, listener->thread, qthrift_accept, listener, tsocket->sd);
      listnode_add (tm->listen_sockets, listener);
      return 0;
    }
  zlog_err("qthrift_server_listen : %s (%d)", error?error->message:"", errno);
  return -1;
}

void
qthrift_close (void)
{
  struct listnode *node, *next;
  struct qthrift_listener *listener;
  struct qthrift *qthrift;
  GError *error = NULL;

  for (ALL_LIST_ELEMENTS (tm->listen_sockets, node, next, listener))
    {
      thread_cancel (listener->thread);
      qthrift = listener->qthrift;
      if(qthrift->qthrift_vpnservice->bgp_configurator_server_transport)
        {
          thrift_server_socket_close(qthrift->qthrift_vpnservice->bgp_configurator_server_transport, &error);
          g_object_unref(qthrift->qthrift_vpnservice->bgp_configurator_server_transport);
          qthrift->qthrift_vpnservice->bgp_configurator_server_transport = NULL;
        }
      listnode_delete (tm->listen_sockets, listener);
      XFREE (MTYPE_QTHRIFT, listener);
    }
}

void qthrift_server_socket(struct qthrift *qthrift)
{
#if (!GLIB_CHECK_VERSION (2, 36, 0))
  g_type_init ();
#endif
  qthrift_vpnservice_setup_thrift_bgp_configurator_server(qthrift->qthrift_vpnservice);
  return;
}

gboolean qthrift_client_transport_open (ThriftTransport *transport, gboolean *needselect)
{
  struct sockaddr_in pin;
  int err;
  ThriftSocket *tsocket = THRIFT_SOCKET (transport);
  struct hostent *hp = NULL;
  int onoff, val;

  if (tsocket->sd != THRIFT_INVALID_SOCKET)
    return FALSE;

  if ((hp = gethostbyname (tsocket->hostname)) == NULL && (err = h_errno))
    {
      /* host lookup failed, bail out with an error */
      zlog_err ("host lookup failed for %s:%d - %s",
                tsocket->hostname, tsocket->port,
                hstrerror (err));
      return FALSE;
    }

  /* create a socket structure */
  memset (&pin, 0, sizeof(pin));
  pin.sin_family = AF_INET;
  pin.sin_addr.s_addr = ((struct in_addr *) (hp->h_addr))->s_addr;
  pin.sin_port = htons (tsocket->port);
  /* create the socket */
  if ((tsocket->sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      zlog_err ("failed to create socket for host %s:%d - %s",
                tsocket->hostname, tsocket->port,
                strerror(errno));
      return FALSE;
    }
  {
    struct linger sl;
 
    sl.l_onoff = 1;
    sl.l_linger = 0;
    setsockopt(tsocket->sd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
  }
  /* set non blocking */
  set_nonblocking (tsocket->sd);
  zlog_info ("opened socket %u", tsocket->sd);

  /* open a connection */
  if (connect (tsocket->sd, (struct sockaddr *) &pin, sizeof(pin)) == -1)
    {
      if (errno == EINPROGRESS)
        {
          *needselect = TRUE;
        }
      zlog_err ("failed to connect to host %s:%d - %s",
                tsocket->hostname, tsocket->port, strerror(errno));
      return FALSE;
    }
  onoff = 0;
  if (setsockopt (tsocket->sd, IPPROTO_TCP, TCP_CORK, &onoff, sizeof(onoff)))
    {
      zlog_info("Couldn't disable TCP_CORK option: %u\n", errno);
    }
  val = 1;
  if (setsockopt (tsocket->sd, IPPROTO_TCP, TCP_NODELAY, (char *) &val, sizeof (val)) < 0)
    {
      zlog_info("Couldn't set TCP_NODELAY option: %u\n", errno);
    }
  zlog_info ("connected socket %u with host %s:%d", tsocket->sd,
             tsocket->hostname, tsocket->port);
  return TRUE;
}

void qthrift_client_transport_close(ThriftTransport *transport)
{
  ThriftSocket *tsocket = NULL;

  if (!transport)
    return;
  tsocket = THRIFT_SOCKET (transport);
  zlog_err("trying to close socket %u", tsocket->sd);
  if (tsocket && tsocket->sd != THRIFT_INVALID_SOCKET)
    {
      zlog_err("closing socket %u", tsocket->sd);
      close (tsocket->sd);
    }
  tsocket->sd = THRIFT_INVALID_SOCKET;
}
