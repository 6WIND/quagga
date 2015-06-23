/*
 * Router ID for zebra daemon.
 *
 * Copyright (C) 2004 James R. Leu 
 *
 * This file is part of Quagga routing suite.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "if.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "stream.h"
#include "command.h"
#include "memory.h"
#include "ioctl.h"
#include "connected.h"
#include "network.h"
#include "log.h"
#include "table.h"
#include "rib.h"
#include "logical_table.h"

#include "zebra/zserv.h"
#include "zebra/router-id.h"
#include "zebra/redistribute.h"

/* master zebra server structure */
extern struct zebra_t zebrad;

static struct connected *
router_id_find_node (struct list *l, struct connected *ifc)
{
  struct listnode *node;
  struct connected *c;

  for (ALL_LIST_ELEMENTS_RO (l, node, c))
    if (prefix_same (ifc->address, c->address))
      return c;

  return NULL;
}

static int
router_id_bad_address (struct connected *ifc)
{
  if (ifc->address->family != AF_INET)
    return 1;
  
  /* non-redistributable addresses shouldn't be used for RIDs either */
  if (!zebra_check_addr (ifc->address))
    return 1;
  
  return 0;
}

void
router_id_get (struct prefix *p, ltid_t ltid)
{
  struct listnode *node;
  struct connected *c;
  struct zebra_lt *zlt = lt_info_get (ltid);

  p->u.prefix4.s_addr = 0;
  p->family = AF_INET;
  p->prefixlen = 32;

  if (zlt->rid_user_assigned.u.prefix4.s_addr)
    p->u.prefix4.s_addr = zlt->rid_user_assigned.u.prefix4.s_addr;
  else if (!list_isempty (zlt->rid_lo_sorted_list))
    {
      node = listtail (zlt->rid_lo_sorted_list);
      c = listgetdata (node);
      p->u.prefix4.s_addr = c->address->u.prefix4.s_addr;
    }
  else if (!list_isempty (zlt->rid_all_sorted_list))
    {
      node = listtail (zlt->rid_all_sorted_list);
      c = listgetdata (node);
      p->u.prefix4.s_addr = c->address->u.prefix4.s_addr;
    }
}

static void
router_id_set (struct prefix *p, ltid_t ltid)
{
  struct prefix p2;
  struct listnode *node;
  struct zserv *client;
  struct zebra_lt *zlt;

  if (p->u.prefix4.s_addr == 0) /* unset */
    {
      zlt = lt_info_lookup (ltid);
      if (! zlt)
        return;
    }
  else /* set */
    zlt = lt_info_get (ltid);

  zlt->rid_user_assigned.u.prefix4.s_addr = p->u.prefix4.s_addr;

  router_id_get (&p2, ltid);

  for (ALL_LIST_ELEMENTS_RO (zebrad.client_list, node, client))
    zsend_router_id_update (client, &p2, ltid);
}

void
router_id_add_address (struct connected *ifc)
{
  struct list *l = NULL;
  struct listnode *node;
  struct prefix before;
  struct prefix after;
  struct zserv *client;
  struct zebra_lt *zlt = lt_info_get (ifc->ifp->ltid);

  if (router_id_bad_address (ifc))
    return;

  router_id_get (&before, zlt->ltid);

  if (!strncmp (ifc->ifp->name, "lo", 2)
      || !strncmp (ifc->ifp->name, "dummy", 5))
    l = zlt->rid_lo_sorted_list;
  else
    l = zlt->rid_all_sorted_list;
  
  if (!router_id_find_node (l, ifc))
    listnode_add_sort (l, ifc);

  router_id_get (&after, zlt->ltid);

  if (prefix_same (&before, &after))
    return;

  for (ALL_LIST_ELEMENTS_RO (zebrad.client_list, node, client))
    zsend_router_id_update (client, &after, zlt->ltid);
}

void
router_id_del_address (struct connected *ifc)
{
  struct connected *c;
  struct list *l;
  struct prefix after;
  struct prefix before;
  struct listnode *node;
  struct zserv *client;
  struct zebra_lt *zlt = lt_info_get (ifc->ifp->ltid);

  if (router_id_bad_address (ifc))
    return;

  router_id_get (&before, zlt->ltid);

  if (!strncmp (ifc->ifp->name, "lo", 2)
      || !strncmp (ifc->ifp->name, "dummy", 5))
    l = zlt->rid_lo_sorted_list;
  else
    l = zlt->rid_all_sorted_list;

  if ((c = router_id_find_node (l, ifc)))
    listnode_delete (l, c);

  router_id_get (&after, zlt->ltid);

  if (prefix_same (&before, &after))
    return;

  for (ALL_LIST_ELEMENTS_RO (zebrad.client_list, node, client))
    zsend_router_id_update (client, &after, zlt->ltid);
}

void
router_id_write (struct vty *vty)
{
  struct zebra_lt *zlt;
  lt_iter_t iter;

  for (iter = lt_first (); iter != LT_ITER_INVALID; iter = lt_next (iter))
    if ((zlt = lt_iter2info (iter)) != NULL)
      if (zlt->rid_user_assigned.u.prefix4.s_addr)
        {
          if (zlt->ltid == LTID_DEFAULT)
            vty_out (vty, "router-id %s%s",
                     inet_ntoa (zlt->rid_user_assigned.u.prefix4),
                     VTY_NEWLINE);
          else
            vty_out (vty, "router-id %s lt %u%s",
                     inet_ntoa (zlt->rid_user_assigned.u.prefix4),
                     zlt->ltid,
                     VTY_NEWLINE);
        }
}

DEFUN (router_id,
       router_id_cmd,
       "router-id A.B.C.D",
       "Manually set the router-id\n"
       "IP address to use for router-id\n")
{
  struct prefix rid;
  ltid_t ltid = LTID_DEFAULT;

  rid.u.prefix4.s_addr = inet_addr (argv[0]);
  if (!rid.u.prefix4.s_addr)
    return CMD_WARNING;

  rid.prefixlen = 32;
  rid.family = AF_INET;

  if (argc > 1)
    VTY_GET_INTEGER ("LT ID", ltid, argv[1]);

  router_id_set (&rid, ltid);

  return CMD_SUCCESS;
}

ALIAS (router_id,
       router_id_lt_cmd,
       "router-id A.B.C.D " LT_CMD_STR,
       "Manually set the router-id\n"
       "IP address to use for router-id\n"
       LT_CMD_HELP_STR)

DEFUN (no_router_id,
       no_router_id_cmd,
       "no router-id",
       NO_STR
       "Remove the manually configured router-id\n")
{
  struct prefix rid;
  ltid_t ltid = LTID_DEFAULT;

  rid.u.prefix4.s_addr = 0;
  rid.prefixlen = 0;
  rid.family = AF_INET;

  if (argc > 0)
    VTY_GET_INTEGER ("LT ID", ltid, argv[0]);

  router_id_set (&rid, ltid);

  return CMD_SUCCESS;
}

ALIAS (no_router_id,
       no_router_id_lt_cmd,
       "no router-id " LT_CMD_STR,
       NO_STR
       "Remove the manually configured router-id\n"
       LT_CMD_HELP_STR)

static int
router_id_cmp (void *a, void *b)
{
  const struct connected *ifa = (const struct connected *)a;
  const struct connected *ifb = (const struct connected *)b;

  return IPV4_ADDR_CMP(&ifa->address->u.prefix4.s_addr,&ifb->address->u.prefix4.s_addr);
}

void
router_id_cmd_init (void)
{
  install_element (CONFIG_NODE, &router_id_cmd);
  install_element (CONFIG_NODE, &no_router_id_cmd);
  install_element (CONFIG_NODE, &router_id_lt_cmd);
  install_element (CONFIG_NODE, &no_router_id_lt_cmd);
}

void
router_id_init (struct zebra_lt *zlt)
{
  zlt->rid_all_sorted_list = &zlt->_rid_all_sorted_list;
  zlt->rid_lo_sorted_list = &zlt->_rid_lo_sorted_list;

  memset (zlt->rid_all_sorted_list, 0, sizeof (zlt->_rid_all_sorted_list));
  memset (zlt->rid_lo_sorted_list, 0, sizeof (zlt->_rid_lo_sorted_list));
  memset (&zlt->rid_user_assigned, 0, sizeof (zlt->rid_user_assigned));

  zlt->rid_all_sorted_list->cmp = router_id_cmp;
  zlt->rid_lo_sorted_list->cmp = router_id_cmp;

  zlt->rid_user_assigned.family = AF_INET;
  zlt->rid_user_assigned.prefixlen = 32;
}
