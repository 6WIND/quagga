/*
 * BFDD - bfd_interface.c   
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

#include "log.h"
#include "memory.h"
#include "if.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "hash.h"
#include "prefix.h"
#include "stream.h"
#include "sockunion.h"

#include "bfd.h"
#include "bfdd/bfd_interface.h"
#include "bfdd/bfdd.h"
#include "bfdd/bfd_debug.h"

/* rOUTINe responsible for creating a new bfd interface info
   structure */
struct bfd_if_info *
bfd_if_info_new ()
{
  struct bfd_if_info *bii;
  bii = XCALLOC (MTYPE_BFD_IF_INFO, sizeof (struct bfd_if_info));
  if (bii)
    {
      /* bfd interface default settings */
      bii->interval = bfd->tx_interval;
      bii->minrx = bfd->rx_interval;
      bii->multiplier = bfd->failure_threshold;
      bii->enabled = 1;
      bii->passive = 0;
    }
  else
    {
      zlog_err ("Can't malloc bfd interface");
      return NULL;
    }

  return bii;
}

/* Update bfd interface info for all current interfaces */
void bfd_if_info_update(void)
{
  struct listnode *node;
  struct interface *ifp;
  struct bfd_if_info *bii;

  bfd->global_info.interval = bfd->tx_interval;
  bfd->global_info.minrx = bfd->rx_interval;
  bfd->global_info.multiplier = bfd->failure_threshold;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
      if (ifp->info)
	{
	  bii = ifp->info;
          bii->interval = bfd->tx_interval;
          bii->minrx = bfd->rx_interval;
          bii->multiplier = bfd->failure_threshold;
	}
    }
}

/* Hooks for bfd interface information structure */
static int
bfd_if_new_hook (struct interface *ifp)
{
  ifp->info = bfd_if_info_new ();
  return 0;
}
static int
bfd_if_delete_hook (struct interface *ifp)
{
  XFREE (MTYPE_BFD_IF_INFO, ifp->info);
  ifp->info = NULL;
  return 0;
}

/* Initialize Zebra interface data structure. */
void
bfd_if_init ()
{
  if_add_hook (IF_NEW_HOOK, bfd_if_new_hook);
  if_add_hook (IF_DELETE_HOOK, bfd_if_delete_hook);
}

/* Check if interface is enabled */
static int
bfd_check_if_enabled (struct bfd_neigh *neighp)
{
  struct interface *ifp;

  if (neighp->ifindex == 0)
    return BFD_OK;

  ifp = if_lookup_by_index (neighp->ifindex);
  if (!ifp)
    if (!(ifp = if_lookup_by_sockunion_exact (neighp->su_local)))
      abort ();
  if (((struct bfd_if_info *) ifp->info)->enabled)
    return BFD_OK;
  else
    return BFD_ERR;
}

/* Check if interface over which neighbor will run is passive.
   In case interface is passive update neighbor's coresponding flag */
void
bfd_neigh_if_passive_update (struct bfd_neigh *neighp)
{
  struct bfd_if_info *bii = bfd_ifinfo_get (neighp);
  if (bii->passive)
    neighp->flags |= BFD_CNEIGH_FLAGS_PASSIVE;
}

/* Get bfd interface info structure for given neighbor */
struct bfd_if_info *
bfd_ifinfo_get (struct bfd_neigh *neighp)
{
  struct interface *ifp;

  if (neighp->ifindex == 0)
    return &bfd->global_info;

  ifp = if_lookup_by_index (neighp->ifindex);
  if (!ifp)
    if (!(ifp = if_lookup_by_sockunion_exact (neighp->su_local)))
      abort ();
  return (struct bfd_if_info *) ifp->info;
}

/* Check correctness of remote address i.e. if it is from
   the same subnet as one of our interfaces */
static int
bfd_neigh_raddr_check (union sockunion *su)
{
  struct interface *ifp = NULL;
  struct prefix p;

  if ((ifp = if_lookup_noexact_prefix (sockunion2hostprefix (su, &p))))
    if (if_is_operative (ifp))
      return BFD_OK;
  return BFD_ERR;
}

/* Check correctness of local address - do we have such an address or not*/
static int
bfd_neigh_laddr_check (union sockunion *su)
{
  struct interface *ifp = NULL;

  if (((su->sa.sa_family == AF_INET) &&
       (su->sin.sin_addr.s_addr == htonl(INADDR_ANY))) ||
      ((su->sa.sa_family == AF_INET6) &&
       IS_IPV6_ADDR_UNSPECIFIED (&su->sin6.sin6_addr)))
    return BFD_OK;

  if (su->sa.sa_family == AF_INET)
    ifp = if_lookup_exact_address (su->sin.sin_addr);
#ifdef HAVE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    ifp = if_lookup_exact_address6 (&su->sin6.sin6_addr);
#endif /* HAVE IPV6 */

  if (ifp)
    if (if_is_operative (ifp))
      return BFD_OK;
  return BFD_ERR;
}

/* Function check if socket union addresses are correct
   based on the mode in which neighbor is running i.e. 1HOP or MHOP*/
static int
bfd_neigh_addr_check (struct bfd_neigh *neighp)
{
  /* If neighbor is working in single hop mode 
     check IP addresses on both sides of connection */
  if (bfd_flag_1hop_check (neighp))
    {
#if 0
      if (bfd_neigh_raddr_check (neighp->su_remote) < 0)
	{
	  if (BFD_IF_DEBUG_ZEBRA)
	    BFD_LOG_DEBUG_NEIGH_ARG ("%s: remote address error(1hop)",
				     __func__) return -1;
	}
#endif
      if (bfd_neigh_laddr_check (neighp->su_local) < 0)
	{
	  if (BFD_IF_DEBUG_ZEBRA)
	    BFD_LOG_DEBUG_NEIGH_ARG ("%s: local address error(1hop)",
				     __func__) return -2;
	}
    }
  /* We have multihop neighbor - so let's check only local address */
  else
    {
      if (bfd_neigh_laddr_check (neighp->su_local) < 0)
	{
	  if (BFD_IF_DEBUG_ZEBRA)
	    BFD_LOG_DEBUG_NEIGH_ARG ("%s: local address error(mhop)",
				     __func__) return -3;
	}
    }
  return BFD_OK;
}


static int
bfd_neigh_if_check (struct bfd_neigh *neighp)
{
  /* Check if bfd is enabled on desired interface */
  if (bfd_check_if_enabled (neighp))
    {
      if (BFD_IF_DEBUG_ZEBRA)
	BFD_LOG_DEBUG_NEIGH_ARG ("%s: bfd not enable on interface %s",
				 __func__,
				 ifindex2ifname (neighp->
						 ifindex)) return BFD_ERR;
    }
  return BFD_OK;
}


int
bfd_neigh_check (struct bfd_neigh *neighp)
{
  return (bfd_neigh_addr_check (neighp) | bfd_neigh_if_check (neighp));
}
