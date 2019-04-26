/*
 * BFDD - bfd_zebra.c   
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

#include "command.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "log.h"
#include "sockunion.h"
#include "zclient.h"
#include "routemap.h"
#include "thread.h"
#include "hash.h"
#include "table.h"

#include "bfd.h"
#include "bfdd/bfdd.h"
#include "bfdd/bfd_zebra.h"
#include "bfdd/bfd_debug.h"
#include "bfdd/bfd_interface.h"
#include "bfdd/bfd_fsm.h"
#include "bfdd/bfd_packet.h"

#include "zebra/zserv.h"
#include "zebra/zserv_bfd.h"

extern struct thread_master *master;

/* All information about zebra. */
struct zclient *zclient = NULL;

/* bfdd's interface node. */
struct cmd_node interface_node = {
  INTERFACE_NODE,
  "%s(config-if)# ",
  1
};

void
bfd_zclient_reset (void)
{
  zclient_reset (zclient);
};


DEFUN (bfd_interval,
       bfd_interval_cmd,
       "bfd interval <200-30000> min_rx <200-30000> multiplier <1-20>",
       "BFD configuration\n"
       "desired transmit interval\n"
       "msec\n"
       "required minimum receive interval\n"
       "msec\n" "detection multiplier\n")
{
  struct bfd_if_info *bii =
    (struct bfd_if_info *) ((struct interface *) vty->index)->info;

  u_int32_t interval = BFD_IF_INTERVAL_DFT;
  u_int32_t minrx = BFD_IF_MINRX_DFT;
  u_int32_t multi = BFD_IF_MULTIPLIER_DFT;

  interval = atoi (argv[0]);
  minrx = atoi (argv[1]);
  multi = atoi (argv[2]);

  if ((interval < BFD_IF_INTERVAL_MIN) || (interval > BFD_IF_INTERVAL_MAX))
    {
      vty_out (vty, "Interval is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if ((minrx < BFD_IF_MINRX_MIN) || (minrx > BFD_IF_MINRX_MAX))
    {
      vty_out (vty, "Min_rx is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if ((multi < BFD_IF_MULTIPLIER_MIN) || (multi > BFD_IF_MULTIPLIER_MAX))
    {
      vty_out (vty, "Multiplier is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bii->interval = interval;
  bii->minrx = minrx;
  bii->multiplier = multi;

  return CMD_SUCCESS;
};

static int
bfd_passive_interface (struct vty *vty, int set)
{
  struct bfd_if_info *bii =
    (struct bfd_if_info *) ((struct interface *) vty->index)->info;
  if (bii)
    {
      bii->passive = set;
      return CMD_SUCCESS;
    }
  return CMD_WARNING;
}

DEFUN (bfd_passive,
       bfd_passive_cmd,
       "bfd passive",
       "BFD configuration\n" "Don't send BFD control packets first.\n")
{
  return bfd_passive_interface (vty, 1);
};

DEFUN (no_bfd_passive,
       no_bfd_passive_cmd,
       "no bfd passive",
       NO_STR "BFD configuration\n" "Don't send BFD control packets first.\n")
{
  return bfd_passive_interface (vty, 0);
};


DEFUN (show_bfd_neighbors,
       show_bfd_neighbors_cmd,
       "show bfd neighbors", SHOW_STR BFD_STR "Show BFD neighbors\n")
{
  bfd_sh_bfd_neigh (vty, BFD_SH_NEIGH, show_all, NULL);
  return CMD_SUCCESS;
};

DEFUN (show_bfd_neighbors_peer,
       show_bfd_neighbors_peer_cmd,
       "show bfd neighbors (A.B.C.D|X:X::X:X)", SHOW_STR BFD_STR "Show BFD neighbors\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")
{
  bfd_sh_bfd_neigh (vty, BFD_SH_NEIGH, show_peer, argv[0]);
  return CMD_SUCCESS;
};

DEFUN (show_bfd_neighbors_details,
       show_bfd_neighbors_details_cmd,
       "show bfd neighbors details", SHOW_STR BFD_STR "Show BFD neighbors\n")
{
  bfd_sh_bfd_neigh (vty, BFD_SH_NEIGH_DET, show_all, NULL);
  return CMD_SUCCESS;
};

DEFUN (show_bfd_neighbors_peer_details,
       show_bfd_neighbors_peer_details_cmd,
       "show bfd neighbors (A.B.C.D|X:X::X:X) details",
       SHOW_STR BFD_STR "Show BFD neighbors\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")
{
  bfd_sh_bfd_neigh (vty, BFD_SH_NEIGH_DET, show_peer, argv[0]);
  return CMD_SUCCESS;
};

DEFUN (clear_bfd_neighbors_stats,
       clear_bfd_neighbors_stats_cmd,
       "clear bfd neighbors stats",
       CLEAR_STR
       "BFD information\n"
       "BFD neighbors\n"
       "Statistics\n")
{
  bfd_clear_bfd_neigh (vty, NULL);
  return CMD_SUCCESS;
};

DEFUN (clear_bfd_neighbors_peer_stats,
       clear_bfd_neighbors_peer_stats_cmd,
       "clear bfd neighbors (A.B.C.D|X:X::X:X) stats",
       CLEAR_STR
       "BFD information\n"
       "BFD neighbors\n"
       "Remote neighbor IP address\n"
       "Remote neighbor IPv6 address\n"
       "Statistics\n")
{
  bfd_clear_bfd_neigh (vty, argv[0]);
  return CMD_SUCCESS;
};

DEFUN (bfd_rx_interval,
       bfd_rx_interval_cmd,
       "bfd rx-interval <20-30000> tx-interval <200-60000> threshold <1-20> (single-hop|multihop)",
       "BFD configuration\n"
       "desired receive interval\n"
       "msec\n"
       "desired transmit interval\n"
       "msec\n"
       "failure threshold\n"
       "failure threshold value\n"
       "BFD session mode\n"
       "BFD session mode\n")
{
  u_int32_t rx_interval = BFD_IF_MINRX_DFT;
  u_int32_t tx_interval = BFD_IF_INTERVAL_DFT;
  u_int32_t multi = BFD_IF_MULTIPLIER_DFT;

  rx_interval = atoi (argv[0]);
  tx_interval = atoi (argv[1]);
  multi = atoi (argv[2]);

  if ((rx_interval < BFD_IF_MINRX_MIN) || (rx_interval > BFD_IF_MINRX_MAX))
    {
      vty_out (vty, "Rx interval is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if ((tx_interval < BFD_IF_INTERVAL_MIN) || (tx_interval > BFD_IF_INTERVAL_MAX))
    {
      vty_out (vty, "Tx interval is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if ((multi < BFD_IF_MULTIPLIER_MIN) || (multi > BFD_IF_MULTIPLIER_MAX))
    {
      vty_out (vty, "Failure threshold is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bfd->rx_interval = rx_interval;
  bfd->tx_interval = tx_interval;
  bfd->failure_threshold = multi;

  if (strncmp (argv[3], "s", 1) == 0)
    bfd->multihop = 0;
  else
    bfd->multihop = 1;

  bfd_if_info_update();

  return CMD_SUCCESS;
}

DEFUN (bfd_debounce_timer,
       bfd_debounce_timer_cmd,
       "bfd debounce-down <100-5000> debounce-up <1000-10000>",
       "BFD configuration\n"
       "Debounce down timer\n"
       "msec\n"
       "Debounce up timer\n"
       "msec\n")
{
  bfd->debounce_down = atoi (argv[0]);
  bfd->debounce_up = atoi (argv[1]);

  return CMD_SUCCESS;
}

DEFUN (bfd_lreqminrx,
       bfd_lreqminrx_cmd,
       "bfd lreqminrx <0-30000>",
       "BFD configuration\n"
       "Local required min rx interval\n"
       "msec\n")
{
  bfd->lreqminrx = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (bfd_ldesmintx,
       bfd_ldesmintx_cmd,
       "bfd ldesmintx <0-60000>",
       "BFD configuration\n"
       "Local desired min tx interval\n"
       "msec\n")
{
  bfd->ldesmintx = atoi (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (show_bfd_global_config,
       show_bfd_global_config_cmd,
       "show bfd global-config", SHOW_STR BFD_STR "Show BFD global config\n")
{
  vty_out (vty, "config-version: %d%s", bfd->config_data_version, VTY_NEWLINE);
  vty_out (vty, "rx-interval:    %u%s", bfd->rx_interval, VTY_NEWLINE);
  vty_out (vty, "tx-interval:    %u%s", bfd->tx_interval, VTY_NEWLINE);
  vty_out (vty, "threshold:      %u%s", bfd->failure_threshold, VTY_NEWLINE);
  vty_out (vty, "multihop:       %s%s", bfd->multihop ? "yes" : "no", VTY_NEWLINE);
  vty_out (vty, "debounce-down:  %u%s", bfd->debounce_down, VTY_NEWLINE);
  vty_out (vty, "debounce-up:    %u%s", bfd->debounce_up, VTY_NEWLINE);
  vty_out (vty, "lreqminrx:      %u%s", bfd->lreqminrx, VTY_NEWLINE);
  vty_out (vty, "ldesmintx:      %u%s", bfd->ldesmintx, VTY_NEWLINE);

  if (bfd->underlay_limit_enable)
    vty_out (vty, "bfd underlay limit: enabled%s", VTY_NEWLINE);
  else
    vty_out (vty, "bfd underlay limit: disabled%s", VTY_NEWLINE);
  if (bfd->never_send_down_event)
    vty_out (vty, "bfd underlay limit timeout: never%s", VTY_NEWLINE);
  else
    vty_out (vty, "bfd underlay limit timeout: %u%s",
             bfd->underlay_limit_timeout, VTY_NEWLINE);

  return CMD_SUCCESS;
};

void
bfd_sh_bfd_neigh_tbl (struct vty *vty, int mode,
		      struct route_table *neightable, int *header,
		      enum show_type type, union sockunion *su)
{
  struct route_node *node, *subnode;

  for (node = route_top (neightable); node != NULL; node = route_next (node))
    if (!node->info)
      continue;
    else
      for (subnode =
	   route_top (((struct bfd_addrtreehdr *) node->info)->info);
	   subnode != NULL; subnode = route_next (subnode))
	if (!subnode->info)
	  continue;
	else
	  {
	    char buf[INET6_ADDRSTRLEN];
	    char rbuf[INET6_ADDRSTRLEN];
	    char lbuf[INET6_ADDRSTRLEN];
	    struct interface *ifp;
	    struct bfd_neigh *neighp = (struct bfd_neigh *) subnode->info;

	    if ((type == show_peer) && su &&
	        !sockunion_same (neighp->su_remote, su))
	      continue;

	    snprintf (lbuf, sizeof (lbuf), "%s",
		      sockunion2str (neighp->su_local, buf, sizeof (buf)));
	    snprintf (rbuf, sizeof (rbuf), "%s",
		      sockunion2str (neighp->su_remote, buf, sizeof (buf)));

	    if (*header || (mode == BFD_SH_NEIGH_DET))
	      {
		vty_out (vty,
			 "OutAddr          NeighAddr         LD/RD Holdown(mult) State     Int%s",
			 VTY_NEWLINE);
		*header = 0;
	      }
	    ifp = if_lookup_by_index_vrf(neighp->ifindex,VRF_DEFAULT);
	    vty_out (vty, "%-16s %-16s %3u/%-3u %4u(%d) %9s %8s%s",
		     lbuf, rbuf, neighp->ldisc, neighp->rdisc,
		     MSEC (neighp->dtime), neighp->rmulti,
		     bfd_state_str[neighp->lstate],
		     ifp ? ifp->name : "", VTY_NEWLINE);

	    if (mode == BFD_SH_NEIGH_DET)
	      {
		char timebuf[BFD_UPTIME_LEN];

		vty_out (vty,
			 "Local Diag: %u, Demand mode: %u, Poll bit: %u%s",
			 neighp->ldiag, bfd_neigh_check_lbit_d (neighp),
			 bfd_neigh_check_lbit_p (neighp), VTY_NEWLINE);
		if (neighp->status == FSM_S_Up)
		  {
		    vty_out (vty,
			     "Session up time: %s%s",
			     bfd_neigh_uptime (neighp->uptime, timebuf, BFD_UPTIME_LEN),
			     VTY_NEWLINE);
		  }
		else if (neighp->status == FSM_S_Down)
		  {
		    vty_out (vty,
			     "Session down time: %s%s",
			     bfd_neigh_uptime (neighp->uptime, timebuf, BFD_UPTIME_LEN),
			     VTY_NEWLINE);
		  }
		vty_out (vty,
			 "Session mode: %s%s",
			 bfd_flag_1hop_check (neighp) ?
					"Single Hop" : "Multiple Hops",
			 VTY_NEWLINE);
		if (neighp->underlay_limit_state == UNDERLAY_LIMIT_STATE_NEVER_SEND)
		  {
		    vty_out (vty,
			     "Underlay limit called, never send BFD_NEIGH_DOWN msg%s",
			     VTY_NEWLINE);
		  }
		else if (neighp->underlay_limit_state == UNDERLAY_LIMIT_STATE_DELAY_SEND)
		  {
		    vty_out (vty,
			     "Underlay limit called, BFD_NEIGH_DOWN msg is delayed%s",
			     VTY_NEWLINE);
		  }
		else if (neighp->underlay_limit_state == UNDERLAY_LIMIT_STATE_DELAY_SENT)
		  {
		    vty_out (vty,
			     "Underlay limit called, BFD_NEIGH_DOWN msg was sent%s",
			     VTY_NEWLINE);
		  }
		vty_out (vty, "Received MinTxInt: %u, MinRxInt: %u, Multiplier: %u%s",
			 MSEC(neighp->ldesmintx), MSEC(neighp->lreqminrx), neighp->lmulti,
			 VTY_NEWLINE);
		vty_out (vty,
			 "Received MinTxInt: %u, Received MinRxInt: %u, Received Multiplier: %u%s",
			 MSEC(neighp->rdesmintx), MSEC(neighp->rreqminrx), neighp->rmulti, VTY_NEWLINE);
		vty_out (vty,
			 "Holdown (hits): %u(%u), Hello (hits): %u(%u)%s",
			 MSEC (neighp->dtime), neighp->timer_cnt,
			 MSEC (neighp->negrxint), neighp->recv_cnt,
			 VTY_NEWLINE);
		vty_out (vty,
			 "UP event:   %-10u BFD_NEIGH_UP msg:   %u%s",
			 neighp->up_cnt, neighp->notify_up_cnt, VTY_NEWLINE);
		vty_out (vty,
			 "DOWN event: %-10u BFD_NEIGH_DOWN msg: %u%s",
			 neighp->down_cnt, neighp->notify_down_cnt, VTY_NEWLINE);

		vty_out (vty, "Rx Count: %u%s", neighp->recv_cnt,
			 VTY_NEWLINE);
		vty_out (vty, "Tx Count: %u%s", neighp->xmit_cnt,
			 VTY_NEWLINE);
		vty_out (vty, "Discard Count: %u%s", neighp->discard_cnt,
			 VTY_NEWLINE);
		vty_out (vty,
			 "Last packet: Version: %u               - Diagnostic: %u%s",
			 neighp->rver, neighp->rdiag, VTY_NEWLINE);
		vty_out (vty,
			 "             State bit: %-9s     - Demand bit: %u%s",
			 bfd_state_str[neighp->rstate],
			 bfd_neigh_check_rbit_d (neighp), VTY_NEWLINE);
		vty_out (vty,
			 "             Poll bit: %-5u          - Final bit: %u%s",
			 bfd_neigh_check_rbit_p (neighp),
			 bfd_neigh_check_rbit_f (neighp), VTY_NEWLINE);
		vty_out (vty,
			 "             C bit: %-5u             - Auth bit: %u%s",
			 bfd_neigh_check_rbit_c (neighp),
			 bfd_neigh_check_rbit_a (neighp), VTY_NEWLINE);
		vty_out (vty,
			 "             Multiplier: %-5u        - Length: %u%s",
			 neighp->rmulti, neighp->rlen, VTY_NEWLINE);
		vty_out (vty,
			 "             My Discr: %-5u          - Your Discr: %-5u%s",
			 neighp->ldisc, neighp->rdisc, VTY_NEWLINE);
		vty_out (vty,
			 "             Min tx interval: %-7u - Min rx interval: %u%s",
			 MSEC(neighp->rdesmintx), MSEC(neighp->rreqminrx), VTY_NEWLINE);
		vty_out (vty, "             Min Echo interval: %u%s%s",
			 neighp->rreqminechorx, VTY_NEWLINE, VTY_NEWLINE);
	      }
	  }
  if ((type == show_peer) && (*header == 1))
    vty_out (vty, "%% No such neighbor%s", VTY_NEWLINE);
}

void
bfd_sh_bfd_neigh (struct vty *vty, int mode, enum show_type type,
		  const char *ip_str)
{
  int header = 1;

  if (ip_str)
    {
      union sockunion su;
      int ret = str2sockunion (ip_str, &su);
      if (ret < 0)
        {
          vty_out (vty, "%% Malformed address: %s%s", ip_str, VTY_NEWLINE);
          return;
        }

      if (sockunion_family(&su) == AF_INET)
        bfd_sh_bfd_neigh_tbl (vty, mode, neightbl->v4->raddr, &header, type, &su);
#ifdef HAVE_IPV6
      else
        bfd_sh_bfd_neigh_tbl (vty, mode, neightbl->v6->raddr, &header, type, &su);
#endif /* HAVE_IPV6 */
      return;
    }

  bfd_sh_bfd_neigh_tbl (vty, mode, neightbl->v4->raddr, &header, type, NULL);
#ifdef HAVE_IPV6
  bfd_sh_bfd_neigh_tbl (vty, mode, neightbl->v6->raddr, &header, type, NULL);
#endif /* HAVE_IPV6 */
}

static void
bfd_clear_one_bfd_neigh (struct bfd_neigh *neighp)
{
  if (!neighp)
    return;

  neighp->timer_cnt = 0;
  neighp->up_cnt = 0;
  neighp->notify_up_cnt = 0;
  neighp->down_cnt = 0;
  neighp->notify_down_cnt = 0;
  neighp->recv_cnt = 0;
  neighp->xmit_cnt = 0;
}

void
bfd_clear_bfd_neigh_tbl (struct vty *vty, struct route_table *neightable,
			 union sockunion *su)
{
  struct route_node *node, *subnode;
  int found = 0;

  for (node = route_top (neightable); node != NULL; node = route_next (node))
    if (!node->info)
      continue;
    else
      for (subnode =
	   route_top (((struct bfd_addrtreehdr *) node->info)->info);
	   subnode != NULL; subnode = route_next (subnode))
	if (!subnode->info)
	  continue;
	else
	  {
	    struct bfd_neigh *neighp = (struct bfd_neigh *) subnode->info;

	    if (su && !sockunion_same (neighp->su_remote, su))
	      continue;

	    bfd_clear_one_bfd_neigh (neighp);
	    found = 1;
	  }

  if (su && !found)
    vty_out (vty, "%% No such neighbor%s", VTY_NEWLINE);
}

void
bfd_clear_bfd_neigh (struct vty *vty, const char *ip_str)
{
  if (ip_str)
    {
      union sockunion su;
      int ret = str2sockunion (ip_str, &su);
      if (ret < 0)
        {
          vty_out (vty, "%% Malformed address: %s%s", ip_str, VTY_NEWLINE);
          return CMD_WARNING;
        }

      if (sockunion_family(&su) == AF_INET)
        bfd_clear_bfd_neigh_tbl (vty, neightbl->v4->raddr, &su);
#ifdef HAVE_IPV6
      else
        bfd_clear_bfd_neigh_tbl (vty, neightbl->v6->raddr, &su);
#endif /* HAVE_IPV6 */
      return;
    }

  bfd_clear_bfd_neigh_tbl (vty, neightbl->v4->raddr, NULL);
#ifdef HAVE_IPV6
  bfd_clear_bfd_neigh_tbl (vty, neightbl->v6->raddr, NULL);
#endif /* HAVE_IPV6 */
}

/* Configuration write function for bfdd. */
static int
config_write_interface (struct vty *vty)
{
  int write = 0;
  struct listnode *node;
  struct interface *ifp;
  struct bfd_if_info *bii;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
      /* IF name */
      vty_out (vty, "interface %s%s", ifp->name, VTY_NEWLINE);
      write++;
      /* IF desc */
      if (ifp->desc)
	{
	  vty_out (vty, " description %s%s", ifp->desc, VTY_NEWLINE);
	  write++;
	}
      if (ifp->info)
	{
	  bii = ifp->info;
	  if ((bii->interval != BFD_IF_INTERVAL_DFT)
	      || (bii->minrx != BFD_IF_MINRX_DFT)
	      || (bii->multiplier != BFD_IF_MULTIPLIER_DFT))
	    vty_out (vty, " bfd interval %u min_rx %u multiplier %u%s",
		     bii->interval, bii->minrx, bii->multiplier, VTY_NEWLINE);
	  if (bii->passive)
	    vty_out (vty, " bfd passive%s", VTY_NEWLINE);
	}
    }
  return 0;
}

static int
ipv4_bfd_neigh_up (int command, struct zclient *zclient, zebra_size_t length)
{
  struct bfd_cneigh *cneighp;

  cneighp = ipv4_bfd_neigh_updown_read (zclient->ibuf);

  if (BFD_IF_DEBUG_ZEBRA)
    BFD_ZEBRA_LOG_DEBUG_NOARG ("rcvd: ipv4_bfd_neigh_up")
      bfd_cneigh_free (cneighp);
  return 0;
}

static int
ipv4_bfd_neigh_down (int command, struct zclient *zclient,
		     zebra_size_t length)
{
  struct bfd_cneigh *cneighp;

  cneighp = ipv4_bfd_neigh_updown_read (zclient->ibuf);

  if (BFD_IF_DEBUG_ZEBRA)
    BFD_ZEBRA_LOG_DEBUG_NOARG ("rcvd: ipv4_bfd_neigh_down")
      bfd_cneigh_free (cneighp);
  return 0;
}

static int
ipv4_bfd_cneigh_add (int command, struct zclient *zclient,
		     zebra_size_t length)
{
  int ret;
  struct bfd_cneigh *cneighp;

  cneighp = ipv4_bfd_cneigh_adddel_read (zclient->ibuf);

  if (BFD_IF_DEBUG_ZEBRA)
    BFD_ZEBRA_LOG_DEBUG_NOARG ("rcvd: ipv4_bfd_cneigh_add")
      ret = bfd_neigh_add (bfd_cneigh_to_neigh (cneighp));
  bfd_cneigh_free (cneighp);
  return ret;

}

static int
ipv4_bfd_cneigh_del (int command, struct zclient *zclient,
		     zebra_size_t length)
{
  int ret;
  struct bfd_cneigh *cneighp;

  cneighp = ipv4_bfd_cneigh_adddel_read (zclient->ibuf);

  if (BFD_IF_DEBUG_ZEBRA)
    BFD_ZEBRA_LOG_DEBUG_NOARG ("rcvd: ipv4_bfd_cneigh_del")
      ret = bfd_cneigh_del (cneighp);
  bfd_cneigh_free (cneighp);
  return ret;
}


#ifdef HAVE_IPV6
static int
ipv6_bfd_neigh_up (int command, struct zclient *zclient, zebra_size_t length)
{
  struct bfd_cneigh *cneighp;

  cneighp = ipv6_bfd_neigh_updown_read (zclient->ibuf);

  if (BFD_IF_DEBUG_ZEBRA)
    BFD_ZEBRA_LOG_DEBUG_NOARG ("rcvd: ipv6_bfd_neigh_up")
      bfd_cneigh_free (cneighp);
  return 0;
}

static int
ipv6_bfd_neigh_down (int command, struct zclient *zclient,
		     zebra_size_t length)
{
  struct bfd_cneigh *cneighp;

  cneighp = ipv6_bfd_neigh_updown_read (zclient->ibuf);

  if (BFD_IF_DEBUG_ZEBRA)
    BFD_ZEBRA_LOG_DEBUG_NOARG ("rcvd: ipv6_bfd_neigh_down")
      bfd_cneigh_free (cneighp);
  return 0;
}

static int
ipv6_bfd_cneigh_add (int command, struct zclient *zclient,
		     zebra_size_t length)
{
  int ret;
  struct bfd_cneigh *cneighp;

  cneighp = ipv6_bfd_cneigh_adddel_read (zclient->ibuf);

  if (BFD_IF_DEBUG_ZEBRA)
    BFD_ZEBRA_LOG_DEBUG_NOARG ("rcvd: ipv6_bfd_cneigh_add")
      ret = bfd_neigh_add (bfd_cneigh_to_neigh (cneighp));
  bfd_cneigh_free (cneighp);
  return ret;

}

static int
ipv6_bfd_cneigh_del (int command, struct zclient *zclient,
		     zebra_size_t length)
{
  int ret;
  struct bfd_cneigh *cneighp;

  cneighp = ipv6_bfd_cneigh_adddel_read (zclient->ibuf);

  if (BFD_IF_DEBUG_ZEBRA)
    BFD_ZEBRA_LOG_DEBUG_NOARG ("rcvd: ipv6_bfd_cneigh_del")
      ret = bfd_cneigh_del (cneighp);
  bfd_cneigh_free (cneighp);
  return ret;
}
#endif /* HAVE_IPV6 */


static int
bfd_interface_add (int command, struct zclient *zclient, zebra_size_t length,
		   vrf_id_t vrf_id)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf, vrf_id);

  if (BFD_IF_DEBUG_ZEBRA)
    zlog_debug ("Zebra rcvd: interface add %s", ifp->name);

  return 0;
}

static int
bfd_interface_delete (int command, struct zclient *zclient,
		      zebra_size_t length, vrf_id_t vrf_id)
{
  struct stream *s;
  struct interface *ifp;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s, vrf_id);
  ifp->ifindex = IFINDEX_INTERNAL;

  if (BFD_IF_DEBUG_ZEBRA)
    zlog_debug ("Zebra rcvd: interface delete %s", ifp->name);

  return 0;
}

static int
bfd_interface_up (int command, struct zclient *zclient, zebra_size_t length,
		  vrf_id_t vrf_id)
{
  struct stream *s;
  struct interface *ifp;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s, vrf_id);

  if (!ifp)
    return 0;

  if (BFD_IF_DEBUG_ZEBRA)
    zlog_debug ("Zebra rcvd: interface %s up", ifp->name);

  return 0;
}

static int
bfd_interface_down (int command, struct zclient *zclient, zebra_size_t length,
		    vrf_id_t vrf_id)
{
  struct stream *s;
  struct interface *ifp;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s, vrf_id);
  if (!ifp)
    return 0;

  if (BFD_IF_DEBUG_ZEBRA)
    zlog_debug ("Zebra rcvd: interface %s down", ifp->name);
  return 0;
}

static int
bfd_interface_address_add (int command, struct zclient *zclient,
			   zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *ifc;

  ifc = zebra_interface_address_read (command, zclient->ibuf, vrf_id);

  if (ifc == NULL)
    return 0;

  if (BFD_IF_DEBUG_ZEBRA)
    {
      char buf[128];
      prefix2str (ifc->address, buf, sizeof (buf));
      zlog_debug ("Zebra rcvd: interface %s address add %s",
		  ifc->ifp->name, buf);
    }
  return 0;
}

static int
bfd_interface_address_delete (int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *ifc;

  ifc = zebra_interface_address_read (command, zclient->ibuf, vrf_id);

  if (ifc == NULL)
    return 0;

  if (BFD_IF_DEBUG_ZEBRA)
    {
      char buf[128];
      prefix2str (ifc->address, buf, sizeof (buf));
      zlog_debug ("Zebra rcvd: interface %s address delete %s",
		  ifc->ifp->name, buf);
    }

  connected_free (ifc);

  return 0;
}

void
bfd_signal_neigh_updown (struct bfd_neigh *neighp, int cmd)
{
  struct prefix p_rem, p_loc;
  struct prefix *raddr = sockunion2hostprefix (neighp->su_remote, &p_rem);
  struct prefix *laddr = sockunion2hostprefix (neighp->su_local, &p_loc);
  uint32_t flags = bfd_neigh_check_rbit_c (neighp) ? BFD_CNEIGH_FLAGS_CBIT : 0;

  if (bfd_check_neigh_family (neighp) == AF_INET)
    zapi_ipv4_bfd_neigh_updown (zclient,
				cmd,
				(struct prefix_ipv4 *) raddr,
				(struct prefix_ipv4 *) laddr,
				neighp->ifindex,
				flags);
#ifdef HAVE_IPV6
  else
    zapi_ipv6_bfd_neigh_updown (zclient,
				cmd,
				(struct prefix_ipv6 *) raddr,
				(struct prefix_ipv6 *) laddr,
				neighp->ifindex,
				flags);
#endif /* HAVE_IPV6 */
}

/* Configuration write function for bfdd. */
static int
bfd_config_write (struct vty *vty)
{
  int write = 0;
  int write_interval = 0, write_debounce_timer = 0;
  int write_ldesmintx = 0, write_lreqminrx = 0;
  int write_underlay_limit = 0;

  if (bfd->rx_interval != BFD_IF_MINRX_DFT ||
      bfd->tx_interval != BFD_IF_INTERVAL_DFT ||
      bfd->failure_threshold != BFD_IF_MULTIPLIER_DFT ||
      bfd->multihop != 0)
    write_interval = 1;

  if (bfd->debounce_down != DEFAULT_BFD_DEBOUNCE_DOWN ||
      bfd->debounce_up != DEFAULT_BFD_DEBOUNCE_UP)
    write_debounce_timer = 1;

  if (bfd->ldesmintx != BFD_LDESMINTX_DFT)
    write_ldesmintx = 1;

  if (bfd->lreqminrx != BFD_LREQMINRX_DFT)
    write_lreqminrx = 1;

  if (bfd->underlay_limit_enable)
    write_underlay_limit = 1;

  if (write_interval || write_debounce_timer ||
      write_ldesmintx || write_lreqminrx ||
      write_underlay_limit)
    vty_out (vty, "bfd%s", VTY_NEWLINE);

  if (write_interval)
    {
      vty_out (vty, " bfd rx-interval %u tx-interval %u threshold %u %s%s",
               bfd->rx_interval, bfd->tx_interval, bfd->failure_threshold,
               bfd->multihop ? "multihop" : "single-hop", VTY_NEWLINE);
      write++;
    }

  if (write_debounce_timer)
    {
      vty_out (vty, " bfd debounce-down %u debounce-up %u%s",
               bfd->debounce_down, bfd->debounce_up, VTY_NEWLINE);
      write++;
    }

  if (write_ldesmintx)
    {
      vty_out (vty, " bfd ldesmintx %u%s", bfd->ldesmintx, VTY_NEWLINE);
      write++;
    }

  if (write_lreqminrx)
    {
      vty_out (vty, " bfd lreqminrx %u%s", bfd->lreqminrx, VTY_NEWLINE);
      write++;
    }

  if (write_underlay_limit)
    {
      vty_out (vty, " bfd underlay limit%s", VTY_NEWLINE);
      write++;
      if (bfd->never_send_down_event)
        {
          vty_out (vty, " bfd underlay limit timeout never%s", VTY_NEWLINE);
          write++;
        }
      else if (bfd->underlay_limit_timeout != DEFAULT_BFD_UNDERLAY_LIMIT_TIMEOUT)
        {
          vty_out (vty, " bfd underlay limit timeout %u%s",
                   bfd->underlay_limit_timeout, VTY_NEWLINE);
          write++;
        }
    }

  return write;
}

/* BFD node structure. */
static struct cmd_node bfd_node =
{
  BFD_NODE,
  "%s(config-bfd)# ",
  1,
};

DEFUN (router_bfd,
       router_bfd_cmd,
       "bfd",
       "Bidirectional Forwarding Detection\n")
{
  vty->node = BFD_NODE;
  return CMD_SUCCESS;
}

DEFUN (bfd_underlay_limit,
       bfd_underlay_limit_cmd,
       "bfd underlay limit",
       "BFD configuration\n"
       "configure specific behaviour when under underlay\n"
       "limit the number of peerdown() events\n")
{
  bfd->underlay_limit_enable = 1;
  return CMD_SUCCESS;
}

DEFUN (no_bfd_underlay_limit,
       no_bfd_underlay_limit_cmd,
       "no bfd underlay limit",
       NO_STR
       "BFD configuration\n"
       "configure specific behaviour when under underlay\n"
       "limit the number of peerdown() events\n")
{
  bfd->underlay_limit_enable = 0;
  return CMD_SUCCESS;
}

DEFUN (bfd_underlay_limit_timeout,
       bfd_underlay_limit_timeout_cmd,
       "bfd underlay limit timeout (<0-65535>|never)",
       "BFD configuration\n"
       "configure specific behaviour when under underlay\n"
       "limit the number of peerdown() events\n"
       "timer in seconds before peerdown() event is sent to above layer\n"
       "timeout value\n")
{
  u_int16_t timeout;

  if (strncmp (argv[0], "never", 5) == 0)
    {
      bfd->never_send_down_event = 1;
    }
  else
    {
      VTY_GET_INTEGER_RANGE ("underlay-limit-timeout", timeout, argv[0], 0, 65535);
      bfd->underlay_limit_timeout = timeout;
      bfd->never_send_down_event = 0;
    }
  return CMD_SUCCESS;
}

DEFUN (no_bfd_underlay_limit_timeout,
       no_bfd_underlay_limit_timeout_cmd,
       "no bfd underlay limit timeout",
       NO_STR
       "BFD configuration\n"
       "configure specific behaviour when under underlay\n"
       "limit the number of peerdown() events\n"
       "timer in seconds before peerdown() event is sent to above layer\n")
{
  bfd->never_send_down_event = DEFAULT_BFD_UNDERLAY_LIMIT_TIMEOUT;
  return CMD_SUCCESS;
}

/* Initialization of BFD interface. */
static void
bfd_vty_cmd_init (void)
{

#if 0
  /* Initialize Zebra interface data structure */
  if_init ();
#endif

  /* Install interface node. */
  install_node (&interface_node, config_write_interface);
  /* Install bfd top node. */
  install_node (&bfd_node, bfd_config_write);

  install_element (CONFIG_NODE, &router_bfd_cmd);

  install_element (VIEW_NODE, &show_bfd_neighbors_details_cmd);
  install_element (ENABLE_NODE, &show_bfd_neighbors_details_cmd);
  install_element (VIEW_NODE, &show_bfd_neighbors_peer_details_cmd);
  install_element (ENABLE_NODE, &show_bfd_neighbors_peer_details_cmd);

  install_element (VIEW_NODE, &show_bfd_neighbors_cmd);
  install_element (ENABLE_NODE, &show_bfd_neighbors_cmd);
  install_element (VIEW_NODE, &show_bfd_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_bfd_neighbors_peer_cmd);

  install_element (ENABLE_NODE, &clear_bfd_neighbors_stats_cmd);
  install_element (ENABLE_NODE, &clear_bfd_neighbors_peer_stats_cmd);

  install_element (CONFIG_NODE, &interface_cmd);
  install_element (CONFIG_NODE, &no_interface_cmd);
  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &bfd_interval_cmd);
  install_element (INTERFACE_NODE, &bfd_passive_cmd);
  install_element (INTERFACE_NODE, &no_bfd_passive_cmd);

  /* Install default VTY commands to new nodes.  */
  install_default (BFD_NODE);

  install_element (BFD_NODE, &bfd_rx_interval_cmd);
  install_element (BFD_NODE, &bfd_debounce_timer_cmd);
  install_element (BFD_NODE, &bfd_lreqminrx_cmd);
  install_element (BFD_NODE, &bfd_ldesmintx_cmd);

  install_element (BFD_NODE, &bfd_underlay_limit_cmd);
  install_element (BFD_NODE, &no_bfd_underlay_limit_cmd);
  install_element (BFD_NODE, &bfd_underlay_limit_timeout_cmd);
  install_element (BFD_NODE, &no_bfd_underlay_limit_timeout_cmd);

  install_element (VIEW_NODE, &show_bfd_global_config_cmd);
  install_element (ENABLE_NODE, &show_bfd_global_config_cmd);
};


void
bfd_vty_init (void)
{
  bfd_vty_cmd_init ();
  bfd_vty_debug_init ();
};

static void
bfd_zebra_connected (struct zclient *zclient)
{
  zclient_send_requests (zclient, VRF_DEFAULT);
  zapi_bfd_register(zclient);
}

void
bfd_zebra_init (void)
{
  zclient = zclient_new (master);
  zclient_init (zclient, ZEBRA_ROUTE_BFD);	/* FIXME */

  /* Callback functions */
  zclient->zebra_connected = bfd_zebra_connected;
  zclient->interface_add = bfd_interface_add;
  zclient->interface_delete = bfd_interface_delete;
  zclient->interface_address_add = bfd_interface_address_add;
  zclient->interface_address_delete = bfd_interface_address_delete;
  zclient->interface_up = bfd_interface_up;
  zclient->interface_down = bfd_interface_down;
  zclient->ipv4_bfd_cneigh_add = ipv4_bfd_cneigh_add;
  zclient->ipv4_bfd_cneigh_del = ipv4_bfd_cneigh_del;
  zclient->ipv4_bfd_neigh_up = ipv4_bfd_neigh_up;
  zclient->ipv4_bfd_neigh_down = ipv4_bfd_neigh_down;
#ifdef HAVE_IPV6
  zclient->ipv6_bfd_cneigh_add = ipv6_bfd_cneigh_add;
  zclient->ipv6_bfd_cneigh_del = ipv6_bfd_cneigh_del;
  zclient->ipv6_bfd_neigh_up = ipv6_bfd_neigh_up;
  zclient->ipv6_bfd_neigh_down = ipv6_bfd_neigh_down;
#endif /* HAVE_IPV6 */
}

void
bfd_zebra_destroy(void)
{
  if (zclient == NULL)
    return;

  zclient_stop(zclient);
  zclient_free(zclient);
  zclient = NULL;
}
