/*
 * BFDD - bfdd.c
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
#include "command.h"
#include "log.h"
#include "memory.h"
#include "linklist.h"
#include "if.h"
#include "hash.h"
#include "stream.h"
#include "prefix.h"
#include "table.h"
#include "privs.h"
#include "sockopt.h"
#include "sockunion.h"
#include "zclient.h"

#include "bfd.h"
#include "bfdd/bfdd.h"
#include "bfdd/bfd_fsm.h"
#include "bfdd/bfd_debug.h"
#include "bfdd/bfd_zebra.h"
#include "bfdd/bfd_interface.h"
#include "bfdd/bfd_packet.h"
#include "bfdd/bfd_net.h"

#ifdef HAVE_CCAPNPROTO
#include "bfd.bcapnp.h"
#include "bfdd.ndef.hi"
#endif /* HAVE_CCAPNPROTO */

extern struct zclient *zclient;

struct bfd_lport *bfd_lport;
struct neightbl *neightbl;
struct bfd *bfd = NULL;
uint32_t mydisc = 0;


/* Create a new BFD structure */
static void
bfd_new (void)
{
  bfd = XCALLOC (MTYPE_BFD, sizeof (struct bfd));
  bfd->sock4_1hop = bfd_server_socket_init (AF_INET, BFD_PORT_1HOP);
  bfd->sock4_mhop = bfd_server_socket_init (AF_INET, BFD_PORT_MHOP);
  bfd->sock4_1hop_echo = bfd_server_socket_init (AF_INET, BFD_PORT_1HOP_ECHO);
#ifdef HAVE_IPV6
  bfd->sock6_1hop = bfd_server_socket_init (AF_INET6, BFD_PORT_1HOP);
  bfd->sock6_mhop = bfd_server_socket_init (AF_INET6, BFD_PORT_MHOP);
  bfd->sock6_1hop_echo =
    bfd_server_socket_init (AF_INET6, BFD_PORT_1HOP_ECHO);
#endif /* HAVE_IPV6 */

  /* Set up queue for waiting neighbors */
  bfd->wqueue = list_new ();
  bfd->debug = 0;		/* No debug by default */

  bfd->config_data_version = 1;
  bfd->rx_interval = BFD_IF_MINRX_DFT;
  bfd->failure_threshold = BFD_IF_MULTIPLIER_DFT;
  bfd->tx_interval = BFD_IF_INTERVAL_DFT;
  bfd->debounce_down = DEFAULT_BFD_DEBOUNCE_DOWN;
  bfd->debounce_up = DEFAULT_BFD_DEBOUNCE_UP;
  bfd->multihop = 0;

  bfd->ldesmintx = BFD_LDESMINTX_DFT;
  bfd->lreqminrx = BFD_LREQMINRX_DFT;

  bfd->passive_startup_only = 1;
  bfd->global_info.interval = BFD_IF_INTERVAL_DFT;
  bfd->global_info.minrx = BFD_IF_MINRX_DFT;
  bfd->global_info.multiplier = BFD_IF_MULTIPLIER_DFT;
  bfd->global_info.enabled = 1;
  bfd->global_info.passive = 1;

  bfd->nr_all_neighs = 0;
  bfd->nr_available_neighs = 0;
  bfd->underlay_limit_enable = 0;
  bfd->never_send_down_event = 0;
  bfd->underlay_limit_timeout = DEFAULT_BFD_UNDERLAY_LIMIT_TIMEOUT;

  QZC_NODE_REG(bfd, bfd)
}

/* Init BFD address header tree structure */
static struct bfd_addrtreehdr *
bfd_addrtreehdr_init (void)
{
  struct bfd_addrtreehdr *addrtreehdr =
    XMALLOC (MTYPE_BFD_ADDRTREEHDR, sizeof (struct bfd_addrtreehdr));
  addrtreehdr->count = 0;
  addrtreehdr->info = route_table_init ();
  return addrtreehdr;
}

/* Free BFD address header tree structure */
static void
bfd_addrtreehdr_free (struct bfd_addrtreehdr *hdrp)
{
  XFREE (MTYPE_BFD_ADDRTREEHDR, hdrp);
}


/* Makes my discriminator hash (part of neighbor database) */
static uint32_t
bfd_mydischash_make (void *np)
{
  return ((struct bfd_neigh *) np)->ldisc;
}

/* If two cneigh have same values then return 1 else return 0. */
static int
bfd_mydischash_neigh_cmp (const void *np1, const void *np2)
{
  const struct bfd_neigh *neighp1 = np1;
  const struct bfd_neigh *neighp2 = np2;

  if (neighp1 == NULL && neighp2 == NULL)
    return 1;
  if (neighp1 == NULL || neighp2 == NULL)
    return 0;

  if (neighp1->ldisc == neighp2->ldisc)
    return 1;
  else
    return 0;
}

/* Compare neighbors based on local and remote addresses */
static int
bfd_neigh_cmp (struct bfd_neigh *neighp1, struct bfd_neigh *neighp2)
{
  int ret;

  ret = sockunion_cmp (neighp1->su_local, neighp2->su_local);
  if (ret)
    return ret;

  ret = sockunion_cmp (neighp1->su_remote, neighp2->su_remote);
  if (ret)
    return ret;

  return 0;
}

/* 
   Neighbors' (sessions') database diagram

   struct neightbl_________
   |struct neighstruct *v4 |---> struct neighstruct________
   |struct neighstruct *v6 |     |struct route_table *raddr|--->N
   |struct hash *ldisc     |-\   |_________________________|   / \
   |_______________________| |                                N   N
                             |                               / \ / \
                             |                              |
     /-----------------------/                              V     [node]
     |                                                      struct route_node
     |                       struct bfd_addrtreehdr____ <---|void *info     |
     |                       |int count                |    |...            |
     |                 S<----|struct route_table *info |    |_______________|
     |                / \    |_________________________|
     |               S   S
     |              / \ / \
     |                     |
     |                     V   [subnode]
     V                     struct route_node
     struct bfd_neigh <----|void *info     |
     |...           |      |...            |
     |______________|      |_______________|
*/

/* Initialization of neighbors' table */
static void
bfd_neightbl_init (void)
{
  neightbl = XMALLOC (MTYPE_BFD_NEIGHTBL, sizeof (struct neightbl));

  neightbl->ldisc =
    hash_create_size (BFD_NEIGH_HASH_SIZE, bfd_mydischash_make,
		      bfd_mydischash_neigh_cmp);
  neightbl->v4 = XMALLOC (MTYPE_BFD_NEIGHSTRUCT, sizeof (struct neighstruct));
  neightbl->v4->raddr = route_table_init ();
#ifdef HAVE_IPV6
  neightbl->v6 = XMALLOC (MTYPE_BFD_NEIGHSTRUCT, sizeof (struct neighstruct));
  neightbl->v6->raddr = route_table_init ();
#endif /* HAVE_IPV6 */
}

/* Initialize local port structure responsible 
   for delivery of unique port numbers */
static void
bfd_lport_init (void)
{
  bfd_lport = XMALLOC (MTYPE_BFD_LPORT, sizeof (struct bfd_lport));
  bfd_lport->v4 = BFD_SOURCEPORT_MIN - 1;
  bfd_lport->v6 = BFD_SOURCEPORT_MIN - 1;
}

/* Startup initialization */
void
bfd_init (void)
{
  bfd_new ();

  bfd_neightbl_init ();
  bfd_lport_init ();

  /* Start listening for incoming BFD CP */
  BFD_READ_ON (bfd->t_read4_1hop, bfd_read4_1hop, bfd->sock4_1hop);
  BFD_READ_ON (bfd->t_read4_mhop, bfd_read4_mhop, bfd->sock4_mhop);

#ifdef HAVE_IPV6
  BFD_READ_ON (bfd->t_read6_1hop, bfd_read6_1hop, bfd->sock6_1hop);
  BFD_READ_ON (bfd->t_read6_mhop, bfd_read6_mhop, bfd->sock6_mhop);
#endif /* HAVE_IPV6 */
}

void
bfd_terminate (void)
{
  QZC_NODE_UNREG(bfd)
  //TODO, free other resources and thread
}
/* Get unique local discriminator */
static uint32_t
bfd_get_mydisc (void)
{
  if (mydisc == 0)
    mydisc++;
  return mydisc++;
}

static uint32_t
bfd_xmitauthseq_init (void)
{
  return rand () % UINT32_MAX;
}


/* Do initialization of bfd_neigh structure based on the data from candidate */
struct bfd_neigh *
bfd_neigh_init (struct bfd_cneigh *cneighp)
{
  struct bfd_neigh *neighp =
    XMALLOC (MTYPE_BFD_NEIGH, sizeof (struct bfd_neigh));

  /* Local and Remote session state */
  neighp->lstate = BFD_STATE_DOWN;	/* "MUST be initialized to Down." */
  neighp->rstate = BFD_STATE_DOWN;	/* "MUST be initialized to Down." */

  /* Local and remote diagnostic 
     "This MUST be initialized to zero (No Diagnostic.)" */
  neighp->ldiag = BFD_DIAG_NODIAG;
  neighp->rdiag = BFD_DIAG_NODIAG;

  /* Intervals
     "This MUST be initialized to a value of 
     at least one second (1,000,000 microseconds)" */
  neighp->ldesmintx = USEC (bfd->ldesmintx);
  neighp->ldesmintx_a = USEC (bfd->ldesmintx);
  /* This variable MUST be initialized to 1." */
  neighp->rreqminrx = BFD_RREQMINRX_DFT;
  neighp->negtxint = 0;
  neighp->negrxint = 0;
  neighp->txint = USEC (bfd->ldesmintx);	/* for 1st xmitted pkt */

  neighp->lreqminrx = USEC (bfd->lreqminrx);
  neighp->lreqminrx_a = USEC (bfd->lreqminrx);
  neighp->rdesmintx = BFD_RREQMINRX_DFT;

  /* "If this value is zero, the transmitting system does 
     not support the receipt of BFD Echo packets." */
  neighp->lreqminechorx = BFD_REQMINECHORX_DFT;
  neighp->rreqminechorx = BFD_REQMINECHORX_DFT;

  neighp->lmulti = BFD_DFT_MULTI;
  neighp->rmulti = BFD_DFT_MULTI;

  neighp->dtime = 0;

  /* Authentication - i.e. no authentication */
  neighp->authtype = BFD_AUTH_NOAUTH;
  neighp->xmitauthseq = bfd_xmitauthseq_init ();
  neighp->authseqknown = 0;

  neighp->llen = 0;
  neighp->rlen = 0;
  neighp->lver = 1;		/* Supported version of BFD */
  neighp->rver = 1;

  /* Local and remote BFD CP flags (bits) */
  neighp->lbits = 0;
  if (!force_cbit_to_unset &&
      CHECK_FLAG (cneighp->flags, BFD_CNEIGH_FLAGS_CBIT))
    neighp->lbits |= BFD_BIT_C;
  neighp->rbits = 0;

  /* FSM status and old status
     "Down state means that the session is down (or has just been created.)" */
  neighp->status = FSM_S_Down;
  neighp->ostatus = FSM_S_Down;

  /* Timer threads */
  neighp->t_timer = NULL;
  neighp->t_hello = NULL;
  neighp->t_session = NULL;
  neighp->t_admindown = NULL;
  neighp->t_delete = NULL;
  neighp->t_debounce_up = NULL;
  neighp->t_debounce_down = NULL;
  neighp->t_underlay_limit = NULL;
  neighp->underlay_limit_state = UNDERLAY_LIMIT_STATE_NORMAL;
  neighp->wanted_state = BFD_NEIGH_UP;

  /* Use the same set of flags as candidate */
  neighp->flags = cneighp->flags;
  if (bfd->multihop)
    SET_FLAG (neighp->flags, BFD_CNEIGH_FLAGS_MULTIHOP);
  neighp->notify = 0;
  neighp->del = 0;

  neighp->ifindex = cneighp->ifindex;

  neighp->sock = -1;
  neighp->lport = 0;
  neighp->su_local = hostprefix2sockunion (&cneighp->laddr);
  neighp->su_remote = hostprefix2sockunion (&cneighp->raddr);

  /* Local and Remote discriminators */
  if (neighp->su_local->sa.sa_family == AF_INET)
    neighp->ldisc = ntohl(sockunion2ip(neighp->su_remote));
  else
    neighp->ldisc = bfd_get_mydisc ();	/* Get unique local discriminator */
  neighp->rdisc = 0;		/* "MUST be initialized to zero." */

  /* Statistics */
  neighp->uptime = 0;
  neighp->last_xmit = 0;
  neighp->last_recv = 0;
  neighp->xmit_cnt = 0;
  neighp->recv_cnt = 0;
  neighp->discard_cnt = 0;
  neighp->orecv_cnt = 0;
  neighp->timer_cnt = 0;
  neighp->down_cnt = 0;
  neighp->up_cnt = 0;
  neighp->notify_down_cnt = 0;
  neighp->notify_up_cnt = 0;

  return neighp;
}

static void
bfd_neigh_free (struct bfd_neigh *neighp)
{
  if (neighp->sock > 0)
    bfd_sockclose (neighp->sock);
  sockunion_free (neighp->su_local);
  sockunion_free (neighp->su_remote);
  XFREE (MTYPE_BFD_NEIGH, neighp);
}

/* Create new neighbor(session) from given candidate neighbor */
struct bfd_neigh *
bfd_cneigh_to_neigh (struct bfd_cneigh *cneighp)
{
  struct bfd_neigh *neighp = bfd_neigh_init (cneighp);
  return neighp;
}

/* Perform a lookup on neighbor table (database) using local/remote addresses
   and optionally interface index as a key */
struct bfd_neigh *
bfd_find_neigh (struct prefix *raddr, struct prefix *laddr,
		unsigned int ifindex)
{
  struct route_node *node, *subnode;
  struct bfd_addrtreehdr *hdrp;
  struct neighstruct *ns;

  if (raddr->family == AF_INET)
    ns = neightbl->v4;
#ifdef HAVE_IPV6
  else if (raddr->family == AF_INET6)
    ns = neightbl->v6;
#endif /* HAVE_IPV6 */
  else
    abort ();

  if ((node = route_node_lookup (ns->raddr, raddr)))
    {
      /* Paranoia */
      assert (node->info);
      hdrp = (struct bfd_addrtreehdr *) node->info;
      assert (hdrp->info);
      assert (hdrp->count);

      if ((subnode = route_node_lookup (hdrp->info, laddr)))
	{
	  if (ifindex)
	    {
	      if (((struct bfd_neigh *) subnode->info)->ifindex == ifindex)
		return (struct bfd_neigh *) subnode->info;
	      else
		return NULL;
	    }
	  return (struct bfd_neigh *) subnode->info;
	}
    }
  return NULL;
}

/* Lookup on neighbor database by neighbor 
   (only laddr/raddr is used as a key)*/
static struct bfd_neigh *
bfd_neightbl_neigh_lookup (struct bfd_neigh *neighp)
{
  struct prefix p1, p2;
  return bfd_find_neigh (sockunion2hostprefix (neighp->su_remote, &p1),
			 sockunion2hostprefix (neighp->su_local, &p2), 0);
}

/* Do lookup on neighbor's wait queue to check if 
   at least one neighbor with the same pair or local
   and remote address waits for addition / removal 
   to/from database. */
struct bfd_neigh *
bfd_wqueue_lookup (struct bfd_neigh *neighp)
{
  struct listnode *node;
  struct bfd_neigh *bnp;

  if (list_isempty (bfd->wqueue))
    return NULL;

  for (ALL_LIST_ELEMENTS_RO (bfd->wqueue, node, bnp))
    {
      if (!bfd_neigh_cmp (bnp, neighp))
	return bnp;
    }
  return NULL;
}

/* Big ugly function responsible for adding/removing neighbor from
   neighbor's database using as a key remote, and as a subkey local address */
static int
bfd_neightbl_raddr_adddel (int cmd, struct bfd_neigh *neighp)
{
  struct route_node *node, *subnode;
  struct bfd_addrtreehdr *hdrp;
  struct neighstruct *ns;
  struct prefix p1, p2;
  struct prefix *raddr = sockunion2hostprefix (neighp->su_remote, &p1);
  struct prefix *laddr = sockunion2hostprefix (neighp->su_local, &p2);

  /* Select appropriate table(database) based on family */
  if (PREFIX_FAMILY (raddr) == AF_INET)
    ns = neightbl->v4;
#ifdef HAVE_IPV6
  else
    ns = neightbl->v6;
#endif /* HAVE_IPV6 */

  if (BFD_IF_DEBUG_ZEBRA)
    {
      char rpbuf[BUFSIZ];
      char lpbuf[BUFSIZ];
      prefix2str (raddr, rpbuf, sizeof (rpbuf));
      prefix2str (laddr, lpbuf, sizeof (lpbuf));
      zlog_debug ("%s: cmd=%s <raddr=%s, laddr=%s, ifindex=%d, flags=%d>\n",
		  __func__, bfd_neigh_cmd_str[cmd], rpbuf, lpbuf,
		  neighp->ifindex, neighp->flags);
    }

  /* Do first lookup based on remote IP address */
  if ((node = route_node_lookup (ns->raddr, raddr)))
    {
      hdrp = (struct bfd_addrtreehdr *) node->info;
      /* 2nd lookup based on local address */
      if ((subnode = route_node_lookup (hdrp->info, laddr)))
	{
	  switch (cmd)
	    {
	    case BFD_NEIGH_ADD:
	      if (BFD_IF_DEBUG_ZEBRA)
		zlog_debug ("%s:(raddr) neighbor already exists", __func__);
	      return BFD_ERR;	/* Neighbor already exists */
	    case BFD_NEIGH_DEL:
	      if (BFD_IF_DEBUG_ZEBRA)
		zlog_debug ("%s:(raddr) removing subnode", __func__);

	      subnode->info = NULL;	/* we will free neighbor later */
#if 0
	      subnode->lock = 0;
	      route_node_delete (subnode);
#else
	      route_unlock_node (subnode);
#endif
	      hdrp->count--;

	      /* Check if any local address is attached to peer address, 
	         if not remove the peer addr node */
	      if (hdrp->count == 0)
		{
		  if (BFD_IF_DEBUG_ZEBRA)
		    zlog_debug ("%s:(raddr) removing node", __func__);
		  bfd_addrtreehdr_free (node->info);
		  node->info = NULL;
#if 0
		  node->lock = 0;
		  route_node_delete (node);
#else
		  route_unlock_node (node);
#endif
		}

	      if (bfd->nr_all_neighs)
		{
		  bfd->nr_all_neighs--;
		  if (BFD_IF_DEBUG_ZEBRA)
		    zlog_debug ("%s: total bfd neighbor count %u",
				__func__, bfd->nr_all_neighs);
		}
	      else
		{
		  if (BFD_IF_DEBUG_ZEBRA)
		    zlog_debug ("%s: bug report: here should not be reached",
				__func__);
		}
	      return BFD_OK;
	    }
	}
      else
	{
	  /* Neighbor already exists but a transport address (local binding) 
	     is different */
	  switch (cmd)
	    {
	    case BFD_NEIGH_ADD:
	      if (BFD_IF_DEBUG_ZEBRA)
		zlog_debug
		  ("%s:(raddr) neighbor already exists but local "
		   "binding is different - adding a new local address",
		   __func__);
	      hdrp = (struct bfd_addrtreehdr *) node->info;
	      hdrp->count++;
	      subnode = route_node_get (hdrp->info, laddr);	/* Add new laddr */
	      subnode->info = neighp;
	      bfd->nr_all_neighs++;
	      if (BFD_IF_DEBUG_ZEBRA)
	        zlog_debug ("%s: total bfd neighbor count %u",
			    __func__, bfd->nr_all_neighs);
	      return BFD_OK;
	    case BFD_NEIGH_DEL:
	      if (BFD_IF_DEBUG_ZEBRA)
		zlog_debug
		  ("%s:(raddr) unable to delete neighbor - laddr  not found",
		   __func__);
	    }
	}
    }
  else
    {
      switch (cmd)
	{
	case BFD_NEIGH_ADD:
	  if (BFD_IF_DEBUG_ZEBRA)
	    zlog_debug ("%s:(raddr) adding new neighbor", __func__);
	  node = route_node_get (ns->raddr, raddr);
	  node->info = bfd_addrtreehdr_init ();
	  hdrp = (struct bfd_addrtreehdr *) node->info;
	  hdrp->count++;
	  subnode = route_node_get (hdrp->info, laddr);
	  subnode->info = neighp;
	  bfd->nr_all_neighs++;
	  if (BFD_IF_DEBUG_ZEBRA)
	    zlog_debug ("%s: total bfd neighbor count %u",
			__func__, bfd->nr_all_neighs);
	  return BFD_OK;
	case BFD_NEIGH_DEL:
	  if (BFD_IF_DEBUG_ZEBRA)
	    zlog_debug ("%s:(raddr) unable to delete - neighbor not found",
			__func__);
	}
    }
  return BFD_ERR;
}

/* Add neighbor using local distriminator as a key to the database */
static int
bfd_neightbl_ldisc_add (struct bfd_neigh *neighp)
{
  struct bfd_neigh *find;

  for (int i = 0; i < BFD_NEIGH_MAX; i++)
    if ((find = (struct bfd_neigh *) hash_lookup (neightbl->ldisc, neighp)))
      {
	neighp->ldisc = bfd_get_mydisc ();
	if (BFD_IF_DEBUG_ZEBRA)
	  zlog_debug ("%s:(ldisc) Reassign: neighp->ldisc=%u\n", __func__,
		      neighp->ldisc);
      }
    else
      break;

  find =
    (struct bfd_neigh *) hash_get (neightbl->ldisc, neighp,
				   hash_alloc_intern);
  if (BFD_IF_DEBUG_ZEBRA)
    zlog_debug ("%s:(ldisc) Assign: neighp->ldisc=%u\n", __func__,
		neighp->ldisc);

  return BFD_OK;
}

/* Remove local discrinator of given neighbor from the database (hash) */
static int
bfd_neightbl_ldisc_del (struct bfd_neigh *neighp)
{
  struct bfd_neigh *find;
  struct bfd_neigh key, *ret;

  key.ldisc = neighp->ldisc;

  if ((find = (struct bfd_neigh *) hash_lookup (neightbl->ldisc, &key)))
    {
      ret = hash_release (neightbl->ldisc, find);
      assert (ret != NULL);
      if (BFD_IF_DEBUG_ZEBRA)
	zlog_debug ("%s:(ldisc) Delete\n", __func__);
      return 0;
    }
  else
    abort ();
}

static int
bfd_neigh_start (struct bfd_neigh *neighp)
{
  /* Create a socket */
  bfd_sendsock_init (neighp);
  /* Check if passive mode is desired, 
     if yes wait for first step from the remote system */
  bfd_neigh_if_passive_update (neighp);
  if (!bfd_flag_passive_check (neighp))
    bfd_fsm_neigh_add (neighp);
  else
    {
      if (bfd->passive_startup_only)
        bfd_event (neighp, FSM_E_RecvDown);
    }
  return BFD_OK;
}

/* Start neighbor but first check if everything is ok */
static int
bfd_neigh_trytostart (struct bfd_neigh *neighp)
{
  if (bfd_neigh_check (neighp))
    {
      if (BFD_IF_DEBUG_ZEBRA)
	BFD_LOG_DEBUG_NEIGH_ARG ("%s: unable to start bfd session this time",
				 __func__) return BFD_ERR;
    }
  if (BFD_IF_DEBUG_ZEBRA)
    BFD_LOG_DEBUG_NEIGH_ARG ("%s: starting bfd session", __func__)
      return bfd_neigh_start (neighp);
}

/* Add neighbor(newly created session) to the neighbor table(database). */
static int
bfd_neigh_db_add (struct bfd_neigh *neighp)
{
  if ((bfd_neightbl_raddr_add (neighp) < 0))
    abort ();			/* Something went wrong... */
  return bfd_neightbl_ldisc_add (neighp);
}

/* Add neighbor to database with conflict check to avoid
   collision with existing neighbor */
static int
bfd_neigh_db_add_cc (struct bfd_neigh *neighp)
{
  struct bfd_neigh *find = bfd_neightbl_neigh_lookup (neighp);

  /* Check if neighbor with the same laddr and raddr has been registered
     - if yes (it was registered), check if delete flag is set. If flag is set  
     it means that neighbor will be removed soon, if not we have inconsistency */
  if (find)
    {
      if (find->del)
	{
	  /* Neighbor has to wait until a previous one with the same
	     laddr/raddr pair will be deleted */
	  listnode_add (bfd->wqueue, neighp);
	  return 1;
	}
      else
	{
	  if (BFD_IF_DEBUG_ZEBRA)
	    zlog_debug ("%s: neighbor exist but delete flag is not set!",
			__func__);
	  abort ();
	}
    }
  else
    /* If we didn't find anything we can proceed to add neighbor */
    return bfd_neigh_db_add (neighp);
}

/* Candidate neighbor delete. Subroutine is called after receiving
   corresponding message from zebra. Function will start removal 
   process of bfd neighbor/session */
int
bfd_cneigh_del (struct bfd_cneigh *cneighp)
{
  struct bfd_neigh *neighp;

  /* Do a neighbor lookup */
  neighp =
    bfd_find_neigh (&cneighp->raddr, &cneighp->laddr, cneighp->ifindex);
  if (!neighp)
    {
      if (BFD_IF_DEBUG_ZEBRA)
	BFD_ZEBRA_LOG_DEBUG_ARG ("%s: unable to find neighbor", __func__)
	  return BFD_ERR;
    }
  return bfd_fsm_neigh_del (neighp);
}

/* Delete neighbor from database */
static int
bfd_neigh_db_del (struct bfd_neigh *neighp)
{
  /* Delete neighbor from database */
  if (bfd_neightbl_raddr_del (neighp) < 0)
    abort ();			/* Database inconsistency */
  bfd_neightbl_ldisc_del (neighp);
  return BFD_OK;
}


/* Delete neighbor. Function is called by fsm session's delete timer */
int
bfd_neigh_del (struct bfd_neigh *neighp)
{
  /* Check if any neighbor is waiting for this one to be deleted */
  struct bfd_neigh *find = bfd_wqueue_lookup (neighp);

  /* Remove neighbor from database */
  bfd_neigh_db_del (neighp);

  /* If we have waiting neighbor, remove it from waiting queue and 
     give it an opportunity to start session */
  if (find)
    {
      listnode_delete (bfd->wqueue, find);
      bfd_neigh_db_add (find);
      bfd_neigh_trytostart (find);
    }
  /* Delete unused neighbor permanently */
  bfd_neigh_free (neighp);
  return BFD_OK;
}

int
bfd_neigh_add (struct bfd_neigh *neighp)
{
  /* Try to add neighbor to the database */
  if (bfd_neigh_db_add_cc (neighp))
    {
      if (BFD_IF_DEBUG_ZEBRA)
	BFD_LOG_DEBUG_NEIGH_ARG ("%s: neighbor addition is postponed",
				 __func__) return BFD_ERR;
    }
  else
    {
      if (bfd_neigh_check (neighp))
	{
	  if (BFD_IF_DEBUG_ZEBRA)
	    BFD_LOG_DEBUG_NEIGH_ARG
	      ("%s: unable to start bfd session this time",
	       __func__) return BFD_ERR;
	}
      else
	{
	  if (BFD_IF_DEBUG_ZEBRA)
	    BFD_LOG_DEBUG_NEIGH_ARG ("%s: starting bfd session", __func__)
	      return bfd_neigh_start (neighp);
	}
    }
}

char *
bfd_neigh_uptime (time_t uptime2, char *buf, size_t len)
{
  time_t uptime1;
  struct tm *tm;

  /* Check buffer length. */
  if (len < BFD_UPTIME_LEN)
    {
      zlog_warn ("bfd_neigh_uptime (): buffer shortage %lu", (u_long)len);
      /* XXX: should return status instead of buf... */
      snprintf (buf, len, "<error> ");
      return buf;
    }

  /* If there is no connection has been done before print `never'. */
  if (uptime2 == 0)
    {
      snprintf (buf, len, "never   ");
      return buf;
    }

  /* Get current time. */
  uptime1 = time (NULL);
  uptime1 -= uptime2;
  tm = gmtime (&uptime1);

  /* Making formatted timer strings. */
#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND ONE_DAY_SECOND*7
#define ONE_YEAR_SECOND ONE_DAY_SECOND*365

  if (uptime1 < ONE_DAY_SECOND)
    snprintf (buf, len, "%02d:%02d:%02d",
	      tm->tm_hour, tm->tm_min, tm->tm_sec);
  else if (uptime1 < ONE_WEEK_SECOND)
    snprintf (buf, len, "%dd%02dh%02dm",
	      tm->tm_yday, tm->tm_hour, tm->tm_min);
  else if (uptime1 < ONE_YEAR_SECOND)
    snprintf (buf, len, "%02dw%dd%02dh",
	      tm->tm_yday/7, tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
  else
    snprintf (buf, len, "%02dy%02dw%dd",
	      tm->tm_year - 70, tm->tm_yday/7,
	      tm->tm_yday - ((tm->tm_yday/7) * 7));
  return buf;
}

#ifdef HAVE_CCAPNPROTO
#include "bfdd.ndef.i"
#endif /*HAVE_CCAPNPROTO */
