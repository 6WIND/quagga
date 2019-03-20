/*
 * BFDD - bfd_packet.c   
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
#include "table.h"
#include "privs.h"
#include "sockunion.h"

#include "bfd.h"
#include "bfdd/bfdd.h"
#include "bfdd/bfd_fsm.h"
#include "bfdd/bfd_debug.h"
#include "bfdd/bfd_zebra.h"
#include "bfdd/bfd_interface.h"
#include "bfdd/bfd_packet.h"


int
bfd_pkt_recv (union sockunion *loc, union sockunion *rem,
	      struct bfd_packet *bp, unsigned int ifindex, int ttl, int len)
{

  struct bfd_neigh key, *neighp;
  struct interface *ifp;
  uint16_t lport;
  uint16_t rport;
  int ret = BFD_ERR;

  if (len < 0)
    {
      zlog_info ("bfd_recvmsg failed: %s", safe_strerror (errno));
      return len;
    }

  lport = ntohs (loc->sin.sin_port);
  rport = ntohs (rem->sin.sin_port);

  if (BFD_IF_DEBUG_NET)
    {
      char buf_loc[SU_ADDRSTRLEN];
      char buf_rem[SU_ADDRSTRLEN];
      zlog_debug ("RECV packet from %s:%u to %s:%u on %s",
		  sockunion2str (rem, buf_rem, SU_ADDRSTRLEN), rport,
		  sockunion2str (loc, buf_loc, SU_ADDRSTRLEN), lport,
		  ifindex2ifname (ifindex));
    }
  /* If we operate in "Signle Hop" mode:
     "All received BFD Control packets that are demultiplexed to the
     session MUST be discarded if the received TTL or Hop Count is not
     equal to 255." */
#define IPV6_NOTTL_CHECK
#ifndef IPV6_NOTTL_CHECK
  if ((lport == BFD_PORT_1HOP) && (ttl < 255))
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: wrong ttl value for 1-hop session (ttl<255).",
		    __func__);
      return BFD_ERR;
    }
#else
  if ((sockunion_family (loc) == AF_INET) &&
      (lport == BFD_PORT_1HOP) && (ttl < 255))
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: wrong ttl value for 1-hop session (ttl<255).",
		    __func__);
      return BFD_ERR;
    }
#endif

  /* "The source port MUST be in the range 49152 through 65535." */
#ifdef STRICT_NEIGHBOR_CHECK
  if (rport < BFD_SOURCEPORT_MIN)
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: source port not within allowed range.", __func__);
      return BFD_ERR;
    }
#endif

  /* Check if incoming interface is known */
  ifp = if_lookup_by_index (ifindex);
  if (ifp == NULL)
    {
      if (BFD_IF_DEBUG_NET)
	{
	  char buf_rem[SU_ADDRSTRLEN];
	  zlog_debug ("%s: cannot find interface for packet from %s port %d",
		      __func__, sockunion2str (rem, buf_rem, SU_ADDRSTRLEN), rport);
	}
      return -1;
    }
  /* "If the version number is not correct (1), 
     the packet MUST be discarded." */
  if (bp->vers != 1)
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: wrong packet version (%d!=1).", __func__, bp->vers);
      return BFD_ERR;
    }

  /* "If the Length field is less than the minimum correct value (24 if
     the A bit is clear, or 26 if the A bit is set), the packet MUST be
     discarded." */
  if (((bp->length < BFD_PACKET_SIZE_NOAUTH) && (bp->a == 0))
      || ((bp->length < BFD_PACKET_SIZE_AUTH) && (bp->a == 1)))
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: too short packet (length=%d,A=%d).", __func__,
		    bp->length, bp->a);
      return BFD_ERR;
    }

  /* "If the Length field is greater than the payload of the
     encapsulating protocol, the packet MUST be discarded." */
  if (bp->length > len)
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug
	  ("%s: length value from packet suggest that packet is longer "
	   "than payload of the encapsulating protocol "
	   "(packet length=%d, payload length=%d).",
	   __func__, bp->length, len);
      return BFD_ERR;
    }

  /* "If the Detect Mult field is zero, the packet MUST be discarded." */
  if (bp->multiplier == 0)
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: illegal Detection Multiplier (equal to zero).",
		    __func__);
      return BFD_ERR;
    }

  /* "If the Multipoint (M) bit is nonzero, the packet MUST be discarded." */
  if (bp->m)
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: Non-zero value of M-bit detected.", __func__);
      return BFD_ERR;
    }

  /* "A BFD Control packet MUST NOT have both 
     the Poll (P) and Final (F) bits set." */
#ifdef STRICT_NEIGHBOR_CHECK
  if ((bp->p) && (bp->f))
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: P and F-bit set together are not allowed.",
		    __func__);
      return BFD_ERR;
    }
#endif

  /* "If the My Discriminator field is zero, the packet MUST be discarded." */
  if (bp->mydisc == 0)
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug ("%s: illegal My Discriminator (equal to zero).",
		    __func__);
      return BFD_ERR;
    }

  /* "If the Your Discriminator field is zero and the State field is not
     Down or AdminDown, the packet MUST be discarded." */
  if ((bp->yourdisc == 0)
      && (!(bp->sta == BFD_STATE_DOWN || bp->sta == BFD_STATE_ADMINDOWN)))
    {
      if (BFD_IF_DEBUG_NET)
	zlog_debug
	  ("%s: Your discriminator field is equal to zero "
	   "while state is not Down or AdminDown.", __func__);
      return BFD_ERR;
    }

  /* "If the Your Discriminator field is nonzero, it MUST be used to select 
     the session with which this BFD packet is associated.  
     If no session is found, the packet MUST be discarded." */
  if (bp->yourdisc != 0)
    {
      key.ldisc = ntohl (bp->yourdisc);
      if (!
	  (neighp = (struct bfd_neigh *) hash_lookup (neightbl->ldisc, &key)))
	{
	  if (BFD_IF_DEBUG_NET)
	    zlog_debug ("%s: No session exists (0x%08x/%d).", __func__,
			key.ldisc, key.ldisc);
	  return BFD_ERR;
	}
    }
  /* "If the Your Discriminator field is zero, the session MUST be
     selected based on some combination of other fields, possibly
     including source addressing information, the My Discriminator
     field, and the interface over which the packet was received.  The
     exact method of selection is application-specific and is thus
     outside the scope of this specification.  If a matching session is
     not found, a new session may be created, or the packet may be
     discarded.  This choice is outside the scope of this
     specification. */
  else
    {
      struct prefix p_loc, p_rem;
      struct prefix *lp = sockunion2hostprefix (loc, &p_loc);
      struct prefix *rp = sockunion2hostprefix (rem, &p_rem);

      if (!(neighp = bfd_find_neigh (rp, lp, 0)))
	{
	  if (BFD_IF_DEBUG_NET)
	    {
	      char buf_loc[SU_ADDRSTRLEN];
	      char buf_rem[SU_ADDRSTRLEN];
	      zlog_debug
	        ("%s: Unable to demultiplex session src=%s:%d/dst=%s:%d on intf=%s.",
		 __func__, sockunion2str (rem, buf_rem, SU_ADDRSTRLEN),
		 ntohs (rem->sin.sin_port),
		 sockunion2str (loc, buf_loc, SU_ADDRSTRLEN),
		 ntohs (loc->sin.sin_port),
		 ifindex2ifname (ifindex));
	    }
	  return BFD_ERR;
	}
    }

  if (bp->length > BFD_PACKET_SIZE_NOAUTH)
    {
      /* If the A bit is set and no authentication is in use (bfd.AuthType
         is zero), the packet MUST be discarded." */
      if ((bp->a == 1) && (bp->authtype == 0))
	{
	  if (BFD_IF_DEBUG_NET)
	    zlog_debug ("%s: A-bit set but no authentication in use.",
			__func__);
	  return BFD_ERR;
	}

      /* "If the A bit is clear and authentication is in use (bfd.AuthType
         is nonzero), the packet MUST be discarded." */
      if ((bp->a == 0) && (bp->authtype != 0))
	{
	  if (BFD_IF_DEBUG_NET)
	    zlog_debug ("%s: A-bit clear but authentication in use.",
			__func__);
	  return BFD_ERR;
	}
    }

  /* Collect remote's neighbor flags, but first clear local storage  */
  neighp->rbits = 0;

  /* "Set bfd.RemoteDemandMode to the value of the Demand (D) bit." */
  if (bp->d)
    neighp->rbits |= BFD_BIT_D;
  if (bp->a)
    neighp->rbits |= BFD_BIT_A;
  if (bp->c)
    neighp->rbits |= BFD_BIT_C;
  if (bp->p)
    neighp->rbits |= BFD_BIT_P;
  else if (bp->f)
    neighp->rbits |= BFD_BIT_F;


  /* "If the A bit is set, the packet MUST be authenticated under the
     rules of section 6.7, based on the authentication type in use
     (bfd.AuthType.)  This may cause the packet to be discarded." */
  if (bp->a)
    ;				/* TODO */

  /* "Set bfd.RemoteDiscr to the value of My Discriminator." */
  neighp->rdisc = ntohl (bp->mydisc);

  /* "Set bfd.RemoteState to the value of the State (Sta) field." */
  neighp->rstate = bp->sta;

  /* "Set bfd.RemoteMinRxInterval to the value of Required Min RX
     Interval." */
  neighp->rreqminrx = ntohl (bp->reqminrx);

  /* Grab some additional data from neighbor */
  neighp->rdesmintx = ntohl (bp->desmintx);
  neighp->rreqminechorx = ntohl (bp->reqminechorx);
  neighp->rmulti = bp->multiplier;
  neighp->rdiag = bp->diag;
  neighp->rlen = bp->length;
  neighp->rver = bp->vers;

  /* "If the Required Min Echo RX Interval field is zero, the
     transmission of Echo packets, if any, MUST cease." */
  if (neighp->rreqminechorx == 0)
    {
      /* TODO */
    }

  /* "If a Poll Sequence is being transmitted by the local system and
     the Final (F) bit in the received packet is set, the Poll Sequence
     MUST be terminated." */
  if (bp->f)
    neighp->lbits &= ~BFD_BIT_P;
  else if (bp->p)
    neighp->lbits |= BFD_BIT_F;

  /* If a valid packet has been received from remote system
     and local system is passive (i.e. configured as passive 
     and without running t_hello thread) - start periodic
     transmission of contol packets.                       */
  if (bfd_flag_passive_check (neighp) && !neighp->t_hello)
    BFD_TIMER_MSEC_ON (neighp->t_hello, bfd_pkt_xmit,
		       bfd->ldesmintx);

  /* Recveive interval negotiation  for "Detection Time" */
  neighp->negrxint =
    neighp->lreqminrx >
    neighp->rdesmintx ? neighp->lreqminrx : neighp->rdesmintx;

  /* Calculating the Detection time */
  neighp->dtime = neighp->rmulti * neighp->negrxint;

  /* Enter FSM */
  switch (bp->sta)
    {
    case BFD_STATE_ADMINDOWN:
      ret = bfd_event (neighp, FSM_E_RecvAdminDown);
      break;
    case BFD_STATE_DOWN:
      ret = bfd_event (neighp, FSM_E_RecvDown);
      break;
    case BFD_STATE_INIT:
      ret = bfd_event (neighp, FSM_E_RecvInit);
      break;
    case BFD_STATE_UP:
      ret = bfd_event (neighp, FSM_E_RecvUp);
      break;
    }

  if (ret == BFD_OK)
    {
      /* "If the packet was not discarded, it has been received for purposes
         of the Detection Time expiration" */
      BFD_TIMER_OFF (neighp->t_timer);

      /* If remote system do not operate in demand mode 
         and session is not being deleted start the timer thread */
      if (!bfd_neigh_check_rbit_d (neighp) && !neighp->del)
	BFD_TIMER_MSEC_ON (neighp->t_timer, bfd_fsm_timer,
			   MSEC (neighp->dtime));

      /* Update statistics only if delete flag is not set */
      if (!neighp->del)
	{
	  neighp->last_recv = time (NULL);
	  neighp->recv_cnt++;
	}
    }

  return ret;
}

static int
bfd_hello_send (struct bfd_neigh *neighp)
{
  struct bfd_packet packet;

  memset (&packet, 0, sizeof (struct bfd_packet));

  /* Build a packet */
  packet.vers = BFD_PROTOCOL_VERSION;
  packet.diag = neighp->ldiag;
  packet.sta = neighp->lstate;
  packet.p = bfd_neigh_check_lbit_p (neighp);
  packet.f = bfd_neigh_check_lbit_f (neighp);
  packet.c = bfd_neigh_check_lbit_c (neighp);
  packet.a = bfd_neigh_check_lbit_a (neighp);
  packet.d = bfd_neigh_check_lbit_d (neighp);
  packet.m = bfd_neigh_check_lbit_m (neighp);
  packet.multiplier = neighp->lmulti;
  packet.length = bfd_neigh_check_lplen (neighp);
  packet.mydisc = htonl (neighp->ldisc);
  packet.yourdisc = htonl (neighp->rdisc);
  packet.desmintx = htonl (neighp->ldesmintx_a);
  packet.reqminrx = htonl (neighp->lreqminrx_a);
  packet.reqminechorx = htonl (neighp->lreqminechorx);


/* TODO
  packet.authtype = ;
  packet.authlen  = ;
  packet,authdata = ;
*/

  /* FIXME: we are not interested is processing 
     errros from udp connected socket */
  return write (neighp->sock, &packet, packet.length);
}

/* Function is responsible for periodic BFD CPs transmission */
int
bfd_pkt_xmit (struct thread *thread)
{
  int ret;
  struct bfd_neigh *neighp = THREAD_ARG (thread);

  neighp->t_hello = NULL;

  /* Transmit interval negotiation */
  neighp->negtxint =
    neighp->rreqminrx >
    neighp->ldesmintx ? neighp->rreqminrx : neighp->ldesmintx;

  /* Jittering xmit intervals */
  if (neighp->rmulti == 1)
    neighp->txint = bfd_jtimer_mult_is1 (neighp->negtxint);
  else
    neighp->txint = bfd_jtimer_mult_isnot1 (neighp->negtxint);

  /* Reschedule myself */
  BFD_TIMER_MSEC_ON (neighp->t_hello, bfd_pkt_xmit, BFD_TXINT (neighp));

  ret = bfd_hello_send (neighp);

  if (bfd_neigh_check_lbit_f (neighp))
    neighp->lbits &= ~BFD_BIT_F;

  /* Statistics */
  neighp->last_xmit = time (NULL);
  neighp->xmit_cnt++;

  return ret;
}
