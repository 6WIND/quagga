/*
 * BFDD - bfd_net.c   
 *
 * Copyright (C) 2007   Jaroslaw Adam Gralak
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>

#include "thread.h"
#include "vty.h"
#include "log.h"
#include "if.h"
#include "prefix.h"
#include "privs.h"
#include "sockopt.h"
#include "sockunion.h"

#include "bfd.h"
#include "bfdd/bfdd.h"
#include "bfdd/bfd_net.h"
#include "bfdd/bfd_debug.h"
#include "bfdd/bfd_packet.h"

extern struct bfd_lport *bfd_lport;
extern struct zebra_privs_t bfdd_privs;

/* Get unique local port
   "The source port MUST be in the range 49152 through 65535.  The same UDP
   source port number MUST be used for all BFD Control packets
   associated with a particular session.  The source port number SHOULD
   be unique among all BFD sessions on the system.  If more than 16384
   BFD sessions are simultaneously active, UDP source port numbers MAY
   be reused on multiple sessions, but the number of distinct uses of
   the same UDP source port number SHOULD be minimized." */

static uint16_t
bfd_getlport (struct bfd_neigh *neighp)
{

  uint16_t *port = NULL;
  if (neighp->lport)
    return neighp->lport;

  switch (bfd_check_neigh_family (neighp))
    {
    case AF_INET:
      port = &bfd_lport->v4;
#ifdef HAVE_IPV6
    case AF_INET6:
      port = &bfd_lport->v6;
#endif /* HAVE_IPV6 */
    }

  if ((*port >= (BFD_SOURCEPORT_MIN - 1)) && (*port < BFD_SOURCEPORT_MAX))
    return ++(*port);
  else
    {
      *port = BFD_SOURCEPORT_MIN;
      return ++(*port);
    }
}

/* Get remote port based on neighbor flags */
static uint16_t
bfd_getrport (struct bfd_neigh *neighp)
{
  if (bfd_flag_1hop_check (neighp))
    {
      if (bfd_flag_echo_check (neighp))
	return BFD_PORT_1HOP_ECHO;
      else
	return BFD_PORT_1HOP;
    }
  else
    return BFD_PORT_MHOP;
}

/* Create a UDP socket for a given family */
static int
bfd_sock (int family)
{
  int sock;
  if ((sock = socket (family, SOCK_DGRAM, 0)) < 0)
    {
      zlog_err ("%s: cannot create family=%d socket: %s", __func__, family,
		safe_strerror (errno));
      abort ();
    }
  return sock;
}

/* Wrapping function for connect */
static int
bfd_connect (int sock, struct sockaddr *sa, socklen_t len)
{
  /*
     if (bfdd_privs.change (ZPRIVS_RAISE))
     zlog_err ("%s: cannot raise privs",__func__);
   */
  if (connect (sock, sa, len) < 0)
    {
      int save_errno = errno;
      /*
         if (bfdd_privs.change (ZPRIVS_LOWER))
         zlog_err ("%s: cannot lower privs",__func__);
       */
      if (sa->sa_family == AF_INET)
	zlog_err ("%s: cannot bind socket %d to %s port %d: %s", __func__,
		  sock, inet_ntoa (((struct sockaddr_in *) sa)->sin_addr),
		  (int) ntohs (((struct sockaddr_in *) sa)->sin_port),
		  safe_strerror (save_errno));
#ifdef HAVE_IPV6
      else if (sa->sa_family == AF_INET6)
	zlog_err ("%s: cannot bind socket %d to %s port %d: %s", __func__,
		  sock, inet6_ntoa (((struct sockaddr_in6 *) sa)->sin6_addr),
		  (int) ntohs (((struct sockaddr_in6 *) sa)->sin6_port),
		  safe_strerror (save_errno));
#endif /* HAVE_IPV6 */
      else
	abort ();

      close (sock);
      return -1;
    }
  /*
     if (bfdd_privs.change (ZPRIVS_LOWER))
     zlog_err ("%s: cannot lower privs", __func__);
   */
  return 0;
}

/* Wrapping function for bind */
static int
bfd_bind (int sock, struct sockaddr *sa, socklen_t len)
{
  if (bfdd_privs.change (ZPRIVS_RAISE))
    zlog_err ("%s: cannot raise privs", __func__);

  if (bind (sock, sa, len) < 0)
    {
      int save_errno = errno;
      if (bfdd_privs.change (ZPRIVS_LOWER))
	zlog_err ("%s: cannot lower privs", __func__);

      if (sa->sa_family == AF_INET)
	zlog_err ("%s: cannot bind socket %d to %s port %d: %s", __func__,
		  sock, inet_ntoa (((struct sockaddr_in *) sa)->sin_addr),
		  (int) ntohs (((struct sockaddr_in *) sa)->sin_port),
		  safe_strerror (save_errno));
#ifdef HAVE_IPV6
      else if (sa->sa_family == AF_INET6)
	zlog_err ("%s: cannot bind socket %d to %s port %d: %s", __func__,
		  sock, inet6_ntoa (((struct sockaddr_in6 *) sa)->sin6_addr),
		  (int) ntohs (((struct sockaddr_in6 *) sa)->sin6_port),
		  safe_strerror (save_errno));
#endif /* HAVE_IPV6 */
      else
	abort ();

      close (sock);
      return -1;
    }
  if (bfdd_privs.change (ZPRIVS_LOWER))
    zlog_err ("%s: cannot lower privs", __func__);
  return 0;
}

void
bfd_sockclose (int sock)
{
  if (close (sock) < 0)
    zlog_err ("%s: close error: %s", __func__, safe_strerror (errno));
}

/* Initialise socket for sending BFD packets */
void
bfd_sendsock_init (struct bfd_neigh *neighp)
{
  int ttl = 255;
  int tos = 192;

  switch (bfd_check_neigh_family (neighp))
    {
    case AF_INET:
      {

	struct sockaddr_in loc;
	struct sockaddr_in rem;

	memset (&loc, 0, sizeof (struct sockaddr_in));
	memset (&rem, 0, sizeof (struct sockaddr_in));

	neighp->sock = bfd_sock (AF_INET);

	rem.sin_family = AF_INET;
	rem.sin_addr.s_addr = neighp->su_remote->sin.sin_addr.s_addr;
	rem.sin_port = htons (bfd_getrport (neighp));

	loc.sin_family = AF_INET;
	loc.sin_addr.s_addr = neighp->su_local->sin.sin_addr.s_addr;
	loc.sin_port = htons (bfd_getlport (neighp));

	setsockopt (neighp->sock, IPPROTO_IP, IP_TOS, &tos, sizeof (tos));
	sockopt_ttl (AF_INET, neighp->sock, ttl);
	sockopt_reuseaddr (neighp->sock);
	sockopt_reuseport (neighp->sock);

	bfd_bind (neighp->sock, (struct sockaddr *) &loc, sizeof (loc));
	bfd_connect (neighp->sock, (struct sockaddr *) &rem, sizeof (rem));
	break;
      }
#ifdef HAVE_IPV6
    case AF_INET6:
      {
	struct sockaddr_in6 loc6;
	struct sockaddr_in6 rem6;

	memset (&loc6, 0, sizeof (struct sockaddr_in6));
	memset (&rem6, 0, sizeof (struct sockaddr_in6));

	neighp->sock = bfd_sock (AF_INET6);


	rem6.sin6_family = AF_INET6;
	memcpy (&rem6.sin6_addr, neighp->su_remote->sin6.sin6_addr.s6_addr,
		sizeof (struct in6_addr));
	rem6.sin6_port = htons (bfd_getrport (neighp));

	loc6.sin6_family = AF_INET6;
	memcpy (&loc6.sin6_addr, neighp->su_local->sin6.sin6_addr.s6_addr,
		sizeof (struct in6_addr));
	loc6.sin6_port = htons (bfd_getlport (neighp));

	//setsockopt(neighp->sock,IPPROTO_IP,IP_TOS, &tos, sizeof(tos));
	sockopt_ttl (AF_INET6, neighp->sock, ttl);
	sockopt_reuseaddr (neighp->sock);
	sockopt_reuseport (neighp->sock);

	bfd_bind (neighp->sock, (struct sockaddr *) &loc6, sizeof (loc6));
	bfd_connect (neighp->sock, (struct sockaddr *) &rem6, sizeof (rem6));
	break;
      }
#endif /* HAVE_IPV6 */
    default:
      abort ();
    }

  return;
}

/* Initialize server socket */
int
bfd_server_socket_init (int family, uint16_t port)
{
  int ret;
  struct sockaddr_in addr;
  struct sockaddr_in6 addr6;
  int on = 1;
  int sock = -1;

  switch (family)
    {
    case AF_INET:
      memset (&addr, 0, sizeof (struct sockaddr_in));
      addr.sin_family = AF_INET;
      addr.sin_addr = bfd_srv_addr.ipv4_addr;
//#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
//      addr.sin_len = sizeof (struct sockaddr_in);
//#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
      addr.sin_port = htons (port);
      if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
	{
	  zlog_err ("bfd_socket_init: Cannot create UDP v4 socket: %s",
		    safe_strerror (errno));
	  exit (1);
	}
      if ((ret =
	   setsockopt (sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof (on))) < 0)
	zlog_warn ("Can't set IP_PKTINFO option for fd %d to %d: %s", sock,
		   on, safe_strerror (errno));
      if ((ret =
	   setsockopt (sock, IPPROTO_IP, IP_RECVTTL, &on, sizeof (on))) < 0)
	zlog_warn ("Can't set IP_RECVTTL option for fd %d to %d: %s", sock,
		   on, safe_strerror (errno));

      sockopt_reuseaddr (sock);
      sockopt_reuseport (sock);

      if (bfdd_privs.change (ZPRIVS_RAISE))
	zlog_err ("bfd_socket_init: could not raise privs");
      if ((ret = bind (sock, (struct sockaddr *) &addr, sizeof (addr))) < 0)
	{
	  int save_errno = errno;
	  if (bfdd_privs.change (ZPRIVS_LOWER))
	    zlog_err ("bfd_socket_init: could not lower privs");
	  zlog_err ("bfd_socket_init: Can't bind socket %d to %s port %d: %s",
		    sock, inet_ntoa (addr.sin_addr),
		    (int) ntohs (addr.sin_port), safe_strerror (save_errno));
	  close (sock);
	  return ret;
	}
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      memset (&addr6, 0, sizeof (struct sockaddr_in6));
      addr6.sin6_family = AF_INET6;
      addr6.sin6_addr = bfd_srv_addr.ipv6_addr;
      addr6.sin6_port = htons (port);
      if ((sock = socket (AF_INET6, SOCK_DGRAM, 0)) < 0)
	{
	  zlog_err ("bfd_socket_init: Cannot create UDP v6 socket: %s",
		    safe_strerror (errno));
	  exit (1);
	}

      /* FIXME: requires "linux/in6.h" but this might break portability, 
         so no TTL check for v6 by default */
      /*
         if ((ret = setsockopt (sock, IPPROTO_IPV6, 
         IPV6_RECVPKTINFO, &on, sizeof (on))) < 0)
         zlog_warn ("Can't set IPV6_RECVPKTINFO option for fd %d to %d: %s",
         sock,on,safe_strerror(errno));
         if ((ret = setsockopt (sock, IPPROTO_IPV6, 
         IPV6_RECVHOPLIMIT, &on, sizeof (on))) < 0)
         zlog_warn ("Can't set IP_RECVTTL option for fd %d to %d: %s",
         sock,on,safe_strerror(errno));
       */
#define IPV6_NOTTL_CHECK
      setsockopt_ifindex (AF_INET6, sock, 1);
      sockopt_reuseaddr (sock);
      sockopt_reuseport (sock);

      if (bfdd_privs.change (ZPRIVS_RAISE))
	zlog_err ("bfd_socket_init: could not raise privs");
      if ((ret = bind (sock, (struct sockaddr *) &addr6, sizeof (addr6))) < 0)
	{
	  int save_errno = errno;
	  if (bfdd_privs.change (ZPRIVS_LOWER))
	    zlog_err ("bfd_socket_init: could not lower privs");
	  zlog_err ("bfd_socket_init: Can't bind socket %d to %s port %d: %s",
		    sock, inet6_ntoa (addr6.sin6_addr),
		    (int) ntohs (addr6.sin6_port),
		    safe_strerror (save_errno));
	  close (sock);
	  return ret;
	}
      break;
#endif
    default:
      zlog_err ("bfd_socket_init: family not supported");
    }

  if (bfdd_privs.change (ZPRIVS_LOWER))
    zlog_err ("bfd_socket_init: could not lower privs");
  return sock;
}

void bfd_sock_restart(void)
{
	THREAD_OFF(bfd->t_read4_1hop);
	THREAD_OFF(bfd->t_read4_mhop);
	if (bfd->sock4_1hop_echo) {
		close(bfd->sock4_1hop_echo);
		bfd->sock4_1hop_echo = 0;
	}
	if (bfd->sock4_1hop) {
		close(bfd->sock4_1hop);
		bfd->sock4_1hop = 0;
	}
	if (bfd->sock4_mhop) {
		close(bfd->sock4_mhop);
		bfd->sock4_mhop = 0;
	}
	bfd->sock4_1hop = bfd_server_socket_init (AF_INET, BFD_PORT_1HOP);
	bfd->sock4_mhop = bfd_server_socket_init (AF_INET, BFD_PORT_MHOP);
	bfd->sock4_1hop_echo = bfd_server_socket_init (AF_INET, BFD_PORT_1HOP_ECHO);
	BFD_READ_ON (bfd->t_read4_1hop, bfd_read4_1hop, bfd->sock4_1hop);
	BFD_READ_ON (bfd->t_read4_mhop, bfd_read4_mhop, bfd->sock4_mhop);

#ifdef HAVE_IPV6
	THREAD_OFF(bfd->t_read6_1hop);
	THREAD_OFF(bfd->t_read6_mhop);
	if (bfd->sock6_1hop_echo) {
		close(bfd->sock6_1hop_echo);
		bfd->sock6_1hop_echo = 0;
	}
	if (bfd->sock6_1hop) {
		close(bfd->sock6_1hop);
		bfd->sock6_1hop = 0;
	}
	if (bfd->sock6_mhop) {
		close(bfd->sock6_mhop);
		bfd->sock6_mhop = 0;
	}
	bfd->sock6_1hop = bfd_server_socket_init (AF_INET6, BFD_PORT_1HOP);
	bfd->sock6_mhop = bfd_server_socket_init (AF_INET6, BFD_PORT_MHOP);
	bfd->sock6_1hop_echo = bfd_server_socket_init (AF_INET6, BFD_PORT_1HOP_ECHO);
	BFD_READ_ON (bfd->t_read6_1hop, bfd_read6_1hop, bfd->sock6_1hop);
	BFD_READ_ON (bfd->t_read6_mhop, bfd_read6_mhop, bfd->sock6_mhop);
#endif /* HAVE_IPV6 */

}

/* Receive IPv4 packet */
static int
bfd_recvmsg4 (int sock, u_char * buf, int size, struct sockaddr_in *from,
	      struct in_addr *to, unsigned int *ifindex, u_char * ttl)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr *ptr;
  char adata[1024];

  msg.msg_name = (void *) from;
  msg.msg_namelen = sizeof (struct sockaddr_in);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = size;

  ret = recvmsg (sock, &msg, 0);
  if (ret < 0)
    return ret;

  for (ptr = ZCMSG_FIRSTHDR (&msg); ptr != NULL;
       ptr = CMSG_NXTHDR (&msg, ptr))
    {
      if (ptr->cmsg_level == IPPROTO_IP && ptr->cmsg_type == IP_PKTINFO)
	{
	  struct in_pktinfo *pktinfo;
	  pktinfo = (struct in_pktinfo *) CMSG_DATA (ptr);
	  *ifindex = (unsigned int) pktinfo->ipi_ifindex;
	  to->s_addr = ((struct in_addr *) &pktinfo->ipi_spec_dst)->s_addr;
	}
      if (ptr->cmsg_level == IPPROTO_IP && ptr->cmsg_type == IP_TTL)
	*ttl = (*(u_char *) CMSG_DATA (ptr));
    }
  return ret;
}

#ifdef HAVE_IPV6
/* Receive IPv6 packet */
static int
bfd_recvmsg6 (int sock, u_char * buf, int size, struct sockaddr_in6 *from,
	      struct in6_addr *to, unsigned int *ifindex, u_char * ttl)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr *ptr;
  char adata[1024];

  msg.msg_name = (void *) from;
  msg.msg_namelen = sizeof (struct sockaddr_in6);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = size;

  ret = recvmsg (sock, &msg, 0);
  if (ret < 0)
    return ret;

  for (ptr = ZCMSG_FIRSTHDR (&msg); ptr != NULL;
       ptr = CMSG_NXTHDR (&msg, ptr))
    if (ptr->cmsg_level == IPPROTO_IPV6 && ptr->cmsg_type == IPV6_PKTINFO)
      {
	struct in6_pktinfo *pktinfo;
	pktinfo = (struct in6_pktinfo *) CMSG_DATA (ptr);
	*ifindex = (unsigned int) pktinfo->ipi6_ifindex;
	memcpy (to, &pktinfo->ipi6_addr, sizeof (pktinfo->ipi6_addr));
/*
    if(ptr->cmsg_level == IPPROTO_IPV6 && ptr->cmsg_type == IPV6_HOPLIMIT)
      *ttl = (*(u_char*) CMSG_DATA(ptr));
*/
      }
  return ret;
}
#endif

static int
bfd_read4 (int sock, uint16_t port)
{

  union bfd_buf bfd_buf;
  struct bfd_packet *bp;
  unsigned int ifindex;
  u_char ttl;
  socklen_t fromlen;
  struct sockaddr_in from;
  struct in_addr to;
  int len;
  union sockunion rem, loc;

  memset (&to, 0, sizeof (struct in_addr));
  memset (&from, 0, sizeof (struct sockaddr_in));
  fromlen = sizeof (struct sockaddr_in);

  len =
    bfd_recvmsg4 (sock, (u_char *) & bfd_buf.buf, sizeof (bfd_buf.buf), &from,
		  &to, &ifindex, &ttl);

  bp = &bfd_buf.bfd_packet;

  loc.sin.sin_family = AF_INET;
  loc.sin.sin_port = htons (port);
  loc.sin.sin_addr.s_addr = to.s_addr;
  rem.sin.sin_family = AF_INET;
  rem.sin.sin_port = from.sin_port;
  rem.sin.sin_addr.s_addr = from.sin_addr.s_addr;

  return bfd_pkt_recv (&loc, &rem, bp, ifindex, ttl, len);
}

#ifdef HAVE_IPV6
static int
bfd_read6 (int sock, uint16_t port)
{
  union bfd_buf bfd_buf;
  struct bfd_packet *bp;
  unsigned int ifindex;
  u_char ttl;
  socklen_t fromlen;
  struct sockaddr_in6 from;
  struct in6_addr to;
  int len;
  union sockunion rem, loc;

  memset (&to, 0, sizeof (struct in6_addr));
  memset (&from, 0, sizeof (struct sockaddr_in6));
  fromlen = sizeof (struct sockaddr_in6);

  len =
    bfd_recvmsg6 (sock, (u_char *) & bfd_buf.buf, sizeof (bfd_buf.buf), &from,
		  &to, &ifindex, &ttl);

  bp = &bfd_buf.bfd_packet;

  loc.sin6.sin6_family = AF_INET6;
  loc.sin6.sin6_port = htons (port);
  memcpy (&loc.sin6.sin6_addr, &to, sizeof (struct in6_addr));
  rem.sin6.sin6_family = AF_INET6;
  rem.sin6.sin6_port = from.sin6_port;
  memcpy (&rem.sin6.sin6_addr, &from.sin6_addr, sizeof (struct in6_addr));

  return bfd_pkt_recv (&loc, &rem, bp, ifindex, ttl, len);
}
#endif /* HAVE_IPV6 */

/* Read threads - responsible for serving server sockets */
int
bfd_read4_1hop (struct thread *t)
{
  int ret = bfd_read4 (THREAD_FD (t), BFD_PORT_1HOP);
  bfd->t_read4_1hop = NULL;
  BFD_READ_ON (bfd->t_read4_1hop, bfd_read4_1hop, bfd->sock4_1hop);
  return ret;
}

#ifdef HAVE_IPV6
int
bfd_read6_1hop (struct thread *t)
{
  int ret = bfd_read6 (THREAD_FD (t), BFD_PORT_1HOP);
  bfd->t_read6_1hop = NULL;
  BFD_READ_ON (bfd->t_read6_1hop, bfd_read6_1hop, bfd->sock6_1hop);
  return ret;
}
#endif /* HAVE_IPV6 */

int
bfd_read4_mhop (struct thread *t)
{
  int ret = bfd_read4 (THREAD_FD (t), BFD_PORT_MHOP);
  bfd->t_read4_mhop = NULL;
  BFD_READ_ON (bfd->t_read4_mhop, bfd_read4_mhop, bfd->sock4_mhop);
  return ret;
}

#ifdef HAVE_IPV6
int
bfd_read6_mhop (struct thread *t)
{
  int ret = bfd_read6 (THREAD_FD (t), BFD_PORT_MHOP);
  bfd->t_read6_mhop = NULL;
  BFD_READ_ON (bfd->t_read6_mhop, bfd_read6_mhop, bfd->sock6_mhop);
  return ret;
}
#endif /* HAVE_IPV6 */
