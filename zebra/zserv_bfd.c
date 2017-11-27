/*
 * ZEBRA - zserv_bfd.c
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

#include "prefix.h"
#include "stream.h"
#include "memory.h"
#include "table.h"
#include "log.h"
#include "zclient.h"
#include "linklist.h"

#include "bfd.h"
#include "zebra/zserv.h"
#include "zebra/zserv_bfd.h"
#include "zebra/debug.h"

extern struct zebra_t zebrad;

struct cneightbl *cneightbl;
struct zserv *bfd_client = NULL;

struct bfd_addrtreehdr
{
  int count;			/* Number of nodes in radix tree */
  struct route_table *info;	/* BFD subnode tree, 
				   for storing local addr part of socket */
};


struct cneightbl
{
  struct route_table *v4;
#ifdef HAVE_IPV6
  struct route_table *v6;
#endif				/* HAVE_IPV6 */
};

static struct bfd_addrtreehdr *
bfd_addrtreehdr_init (void)
{
  struct bfd_addrtreehdr *addrtreehdr =
    XMALLOC (MTYPE_BFD_ADDRTREEHDR, sizeof (struct bfd_addrtreehdr));
  addrtreehdr->count = 0;
  addrtreehdr->info = route_table_init ();
  return addrtreehdr;
}

static void
bfd_addrtreehdr_free (struct bfd_addrtreehdr *hdrp)
{
  XFREE (MTYPE_BFD_ADDRTREEHDR, hdrp);
}


/* BFD candidate neighbor init */
void
bfd_cneigh_init (void)
{
  cneightbl = XCALLOC (MTYPE_BFD_CNEIGHTBL, sizeof (struct cneightbl));
  cneightbl->v4 = route_table_init ();
#ifdef HAVE_IPV6
  cneightbl->v6 = route_table_init ();
#endif /* HAVE_IPV6 */
}

static int
zsend_bfd_cneigh_adddel (struct bfd_cneigh *cneighp, int header, int len)
{
  struct stream *s;

  if (bfd_client)
    s = bfd_client->obuf;
  else
    return -1;

  stream_reset (s);

  zserv_create_header (s, header, VRF_DEFAULT);

  stream_write (s, (u_char *) & cneighp->raddr.u.prefix, len);
  stream_write (s, (u_char *) & cneighp->laddr.u.prefix, len);

  stream_putl (s, cneighp->ifindex);

  stream_putl (s, cneighp->flags);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  return zebra_server_send_message (bfd_client);
}

static int
zsend_ipv4_bfd_cneigh_add (struct bfd_cneigh *cneighp)
{
  return zsend_bfd_cneigh_adddel (cneighp, ZEBRA_IPV4_BFD_CNEIGH_ADD,
				  IPV4_MAX_BYTELEN);
}

static int
zsend_ipv4_bfd_cneigh_del (struct bfd_cneigh *cneighp)
{
  return zsend_bfd_cneigh_adddel (cneighp, ZEBRA_IPV4_BFD_CNEIGH_DEL,
				  IPV4_MAX_BYTELEN);
}

#ifdef HAVE_IPV6
static int
zsend_ipv6_bfd_cneigh_add (struct bfd_cneigh *cneighp)
{
  return zsend_bfd_cneigh_adddel (cneighp, ZEBRA_IPV6_BFD_CNEIGH_ADD,
				  IPV6_MAX_BYTELEN);
}

static int
zsend_ipv6_bfd_cneigh_del (struct bfd_cneigh *cneighp)
{
  return zsend_bfd_cneigh_adddel (cneighp, ZEBRA_IPV6_BFD_CNEIGH_DEL,
				  IPV6_MAX_BYTELEN);
}
#endif /* HAVE_IPV6 */


static int
zsend_bfd_neigh_updown (struct zserv *client, struct bfd_cneigh *cneighp,
			int header, int len)
{
  struct stream *s = client->obuf;

  stream_reset (s);

  zserv_create_header (s, header, VRF_DEFAULT);

  stream_write (s, (u_char *) & cneighp->raddr.u.prefix, len);
  stream_write (s, (u_char *) & cneighp->laddr.u.prefix, len);

  stream_putl (s, cneighp->ifindex);

  stream_putl (s, cneighp->flags);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  return zebra_server_send_message (client);
}

static int
zsend_ipv4_bfd_neigh_up (struct zserv *client, struct bfd_cneigh *cneighp)
{
  return zsend_bfd_neigh_updown (client, cneighp, ZEBRA_IPV4_BFD_NEIGH_UP,
				 IPV4_MAX_BYTELEN);
}

static int
zsend_ipv4_bfd_neigh_down (struct zserv *client, struct bfd_cneigh *cneighp)
{
  return zsend_bfd_neigh_updown (client, cneighp, ZEBRA_IPV4_BFD_NEIGH_DOWN,
				 IPV4_MAX_BYTELEN);
}

#ifdef HAVE_IPV6
static int
zsend_ipv6_bfd_neigh_up (struct zserv *client, struct bfd_cneigh *cneighp)
{
  return zsend_bfd_neigh_updown (client, cneighp, ZEBRA_IPV6_BFD_NEIGH_UP,
				 IPV6_MAX_BYTELEN);
}

static int
zsend_ipv6_bfd_neigh_down (struct zserv *client, struct bfd_cneigh *cneighp)
{
  return zsend_bfd_neigh_updown (client, cneighp, ZEBRA_IPV6_BFD_NEIGH_DOWN,
				 IPV6_MAX_BYTELEN);
}
#endif /* HAVE_IPV6 */



/* When receive register message send list of candidate neighbors back */
int
zread_bfd_register (struct zserv *client, u_short length)
{
  bfd_client = client;
  zread_ipv4_bfd_cneigh_list (client, length);
#ifdef HAVE_IPV6
  zread_ipv6_bfd_cneigh_list (client, length);
#endif /* HAVE_IPV6 */
  return 0;
}

/* For list request send back the whole content of cneightable by creating
   one cneigh_add message for every position in the table */
static int
zread_bfd_cneigh_list (struct zserv *client, struct route_table *cneightable,
		       int family)
{
  struct route_node *node, *subnode;
  int ret;

  for (node = route_top (cneightable); node != NULL; node = route_next (node))
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
	    if (family == AF_INET)
	      ret = zsend_ipv4_bfd_cneigh_add (subnode->info);
	    else
	      ret = zsend_ipv6_bfd_cneigh_add (subnode->info);
	    if (!ret)
	      return -1;
	  }
  return 0;
}

/* On candidate neighbors list request send send list back */
int
zread_ipv4_bfd_cneigh_list (struct zserv *client, u_short length)
{
  return zread_bfd_cneigh_list (client, cneightbl->v4, AF_INET);
}

#ifdef HAVE_IPV6
int
zread_ipv6_bfd_cneigh_list (struct zserv *client, u_short length)
{
  return zread_bfd_cneigh_list (client, cneightbl->v6, AF_INET6);
}
#endif /* HAVE_IPV6 */


/* Extracts candidate neighbor structure from a stream */
static struct bfd_cneigh *
zread_bfd_cneigh_extract (struct zserv *client, int family, int bytelen,
			  u_char bitlen)
{
  struct stream *s;
  struct bfd_cneigh *cneighp;

  /* Get input stream.  */
  s = client->ibuf;

  /* Allocate memory for a candidate neighbor */
  cneighp = bfd_cneigh_new ();

  cneighp->raddr.family = family;
  cneighp->raddr.prefixlen = bitlen;
  stream_get (&cneighp->raddr.u.prefix, s, bytelen);

  cneighp->laddr.family = family;
  cneighp->laddr.prefixlen = bitlen;
  stream_get (&cneighp->laddr.u.prefix, s, bytelen);

  cneighp->ifindex = stream_getl (s);

  cneighp->flags = stream_getl (s);

  return cneighp;
}

#define zread_ipv4_bfd_cneigh_extract(C) \
zread_bfd_cneigh_extract(C,AF_INET,IPV4_MAX_BYTELEN,IPV4_MAX_PREFIXLEN)
#ifdef HAVE_IPV6
#define zread_ipv6_bfd_cneigh_extract(C) \
zread_bfd_cneigh_extract(C,AF_INET6,IPV6_MAX_BYTELEN,IPV6_MAX_PREFIXLEN)
#endif /* HAVE_IPV6 */

/*
   Candidate's database structure:

   struct cneightbl________
   |struct route_table *v4 |------------> N
   |struct route_table *v6 |             / \
   |_______________________|            N   N
                                       / \ / \
                                              |
                                              V    [node]
                                              struct route_node
                                              |void *info     |-------\
                                              |...            |       |
                                              |_______________|       |
                                                                      |
                                                                      |
                                                                      |
                                             struct bfd_addrtreehdr___V
                                      S <----|struct route_table *info |
                                     / \     |int count                |
                                    S   S    |_________________________|
                                   / \ / \
                                          |
                                          V   [subnode]
                                          struct route_node
               struct bfd_cneigh____ <----|void *info     |
   /-----------|struct list *clients|     |...            |
   |           |...                 |     |_______________|
   |           |____________________|
   V
   struct zserv *client1
   struct zserv *client2
   struct zserv *client3


*/
/*
   Function adds candidates to database, in order to do that 
   have to check if candidate was already registered or not.
   Possible scenarios are:
   - new candidate is registered 
   - candidate exists
   in 2nd case client will be added to the list of clients 
   that tracks state changes of this particular candidate neighbor */
static int
zread_bfd_cneigh_add (struct zserv *client, struct route_table *cneightable,
		      struct bfd_cneigh *cneighp,
		      int (*zsend_bfd_cneigh_add) (struct bfd_cneigh *))
{
  struct route_node *node, *subnode;
  struct listnode *listnode;
  struct zserv *zservp;
  struct bfd_addrtreehdr *hdrp;

  if (IS_ZEBRA_DEBUG_EVENT)
    {
      char rpbuf[BUFSIZ];
      char lpbuf[BUFSIZ];
      prefix2str (&cneighp->raddr, rpbuf, sizeof (rpbuf));
      prefix2str (&cneighp->laddr, lpbuf, sizeof (lpbuf));
      zlog_debug
	("%s: new candidate neighbor <raddr=%s, laddr=%s, ifindex=%d, flags=%d>\n",
	 __func__, rpbuf, lpbuf, cneighp->ifindex, cneighp->flags);
    }

  if ((node = route_node_lookup (cneightable, &cneighp->raddr)))
    {
      /* Peer address (raddr) found */
      assert (node->info);
      hdrp = (struct bfd_addrtreehdr *) node->info;
      assert (hdrp->info);
      assert (hdrp->count);

      if ((subnode = route_node_lookup (hdrp->info, &cneighp->laddr)))
	{
	  /* Local address found */
	  assert (subnode->info);
	  for (ALL_LIST_ELEMENTS_RO
	       (((struct bfd_cneigh *) subnode->info)->clients, listnode,
		zservp))
	    if (client == zservp)
	      {
		if (IS_ZEBRA_DEBUG_EVENT)
		  zlog_debug ("%s: neighbor already registered by client",
			      __func__);
		/* Since we have one copy of candidate neighbor already within database
		   we can free this one */
		bfd_cneigh_free (cneighp);
		return -1;	/* neighbor already registered by client */
	      }

	  /* Another client has registered the same candidate neighbor,
	     add client to the list so that every state change will be send to it */
	  listnode_add (((struct bfd_cneigh *) subnode->info)->clients,
			client);
	  if (IS_ZEBRA_DEBUG_EVENT)
	    zlog_debug ("%s: another client has registered the"
			"same neighbor - adding client to the list",
			__func__);
	  /* Since we have one copy of candidate neighbor already within database
	     we can free this one */
	  bfd_cneigh_free (cneighp);
	  return 0;
	}
      else
	{
	  if (IS_ZEBRA_DEBUG_EVENT)
	    zlog_debug ("%s: candidate neighbor already exists but local"
			"address is different - adding new local address ",
			__func__);

	  /* Candidate neighbor already exists but a transport address 
	     (local binding) is different */
	  hdrp = (struct bfd_addrtreehdr *) node->info;
	  hdrp->count++;
	  subnode = route_node_get (hdrp->info, &cneighp->laddr);	/* Add new laddr */
	  subnode->info = cneighp;
	  cneighp->clients = list_new ();
	  listnode_add (cneighp->clients, client);
	  /* Send "Add" message to bfdd */
	  zsend_bfd_cneigh_add (cneighp);
	  return 0;
	}
    }
  else
    {
      /* New neighbor */
      if (IS_ZEBRA_DEBUG_EVENT)
	{
	  char rpbuf[BUFSIZ];
	  char lpbuf[BUFSIZ];
	  prefix2str (&cneighp->raddr, rpbuf, sizeof (rpbuf));
	  prefix2str (&cneighp->laddr, lpbuf, sizeof (lpbuf));
	  zlog_debug
	    ("%s: new candidate neighbor <raddr=%s, laddr=%s, ifindex=%d, flags=%d>",
	     __func__, rpbuf, lpbuf, cneighp->ifindex, cneighp->flags);
	}
      node = route_node_get (cneightable, &cneighp->raddr);
      node->info = bfd_addrtreehdr_init ();
      hdrp = (struct bfd_addrtreehdr *) node->info;
      hdrp->count++;
      subnode = route_node_get (hdrp->info, &cneighp->laddr);
      subnode->info = cneighp;
      cneighp->clients = list_new ();
      listnode_add (cneighp->clients, client);
      /* Send "Add" message to bfdd */
      zsend_bfd_cneigh_add (cneighp);
      return 0;
    }
}

/* Preprocess candidate neighbor addition */
int
zread_ipv4_bfd_cneigh_add (struct zserv *client, u_short length)
{
  return zread_bfd_cneigh_add (client, cneightbl->v4,
			       zread_ipv4_bfd_cneigh_extract (client),
			       &zsend_ipv4_bfd_cneigh_add);
}

/* Preprocess candidate neighbor addition */
#ifdef HAVE_IPV6
int
zread_ipv6_bfd_cneigh_add (struct zserv *client, u_short length)
{
  return zread_bfd_cneigh_add (client, cneightbl->v6,
			       zread_ipv6_bfd_cneigh_extract (client),
			       &zsend_ipv6_bfd_cneigh_add);
}
#endif /* HAVE_IPV6 */

/* Remove candidate neighbor from candidate's database */
static int
zread_bfd_cneigh_del (struct zserv *client, struct route_table *cneightable,
		      struct bfd_cneigh *cneighp,
		      int (*zsend_bfd_cneigh_del) (struct bfd_cneigh *))
{
  struct route_node *node, *subnode;
  struct listnode *listnode;
  struct zserv *zservp;
  struct bfd_addrtreehdr *hdrp;

  if ((node = route_node_lookup (cneightable, &cneighp->raddr)))
    {
      /* Paranoia */
      assert (node->info);
      hdrp = (struct bfd_addrtreehdr *) node->info;
      assert (hdrp->info);
      assert (hdrp->count);

      if ((subnode = route_node_lookup (hdrp->info, &cneighp->laddr)))
	{
	  /* Tuple raddr/laddr has been found, proceede to remove client from "clients" list */
	  assert (subnode->info);
	  for (ALL_LIST_ELEMENTS_RO
	       (((struct bfd_cneigh *) subnode->info)->clients, listnode,
		zservp))
	    if (client == zservp)
	      {
		/* Found client - try to remove it from the list */
		listnode_delete (((struct bfd_cneigh *) subnode->info)->
				 clients, zservp);
		/* Check if candidate neighbor was registered by any other client if 
		   not remove the whole subnode i.e. (laddr) */
		if (listcount (((struct bfd_cneigh *) subnode->info)->clients)
		    == 0)
		  {
		    /* Proceed to remove laddr (subnode) */
		    ///list_free(((struct bfd_cneigh *)subnode->info)->clients);
		    zsend_bfd_cneigh_del (cneighp);	/* send update to bfdd */
		    bfd_cneigh_free (subnode->info);
		    subnode->info = NULL;
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
			if (IS_ZEBRA_DEBUG_EVENT)
			  zlog_debug ("%s: removing node", __func__);
			bfd_addrtreehdr_free (node->info);
			node->info = NULL;
#if 0
			node->lock = 0;
			route_node_delete (node);
#else
			route_unlock_node (node);
#endif
		      }
		  }
		return 0;
	      }
	  /* Client not found */
	  if (IS_ZEBRA_DEBUG_EVENT)
	    zlog_debug ("%s: client not found", __func__);
	  return -1;
	}
      /* laddr not found */
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog_debug ("%s: laddr not found", __func__);
      return -2;
    }
  else
    {
      /* raddr not found */
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog_debug ("%s: raddr not found", __func__);
      return -3;
    }
}

int
zread_ipv4_bfd_cneigh_del (struct zserv *client, u_short length)
{
  int ret;
  struct bfd_cneigh *cneighp = zread_ipv4_bfd_cneigh_extract (client);
  ret =
    zread_bfd_cneigh_del (client, cneightbl->v4, cneighp,
			  &zsend_ipv4_bfd_cneigh_del);
  bfd_cneigh_free (cneighp);
  return ret;
}

#ifdef HAVE_IPV6
int
zread_ipv6_bfd_cneigh_del (struct zserv *client, u_short length)
{
  int ret;
  struct bfd_cneigh *cneighp = zread_ipv6_bfd_cneigh_extract (client);
  ret =
    zread_bfd_cneigh_del (client, cneightbl->v6, cneighp,
			  &zsend_ipv6_bfd_cneigh_del);
  bfd_cneigh_free (cneighp);
  return ret;
}
#endif /* HAVE_IPV6 */

/* Process Up message */
static int
zread_bfd_neigh_up (struct zserv *client, struct route_table *cneightable,
		    struct bfd_cneigh *cneighp,
		    int (*zsend_bfd_neigh_up) (struct zserv *,
					       struct bfd_cneigh *))
{
  struct route_node *node, *subnode;
  struct listnode *listnode;
  struct zserv *zservp;
  struct bfd_addrtreehdr *hdrp;

  if ((node = route_node_lookup (cneightable, &cneighp->raddr)))
    {
      /* Paranoia */
      assert (node->info);
      hdrp = (struct bfd_addrtreehdr *) node->info;
      assert (hdrp->info);
      assert (hdrp->count);

      if ((subnode = route_node_lookup (hdrp->info, &cneighp->laddr)))
	{
	  /* Tuple raddr/laddr has been found */
	  assert (subnode->info);

	  /* Notify registered clients about the state change to "Up" */
	  for (ALL_LIST_ELEMENTS_RO
	       (((struct bfd_cneigh *) subnode->info)->clients, listnode,
		zservp))
	    {
	      if (client == zservp)	/* We don't want to notify ourselves */
		continue;
	      else
		zsend_bfd_neigh_up (zservp, cneighp);
	    }
	  /* Client not found */
	  if (IS_ZEBRA_DEBUG_EVENT)
	    zlog_debug ("%s: client not found", __func__);
	  return -1;
	}
      /* laddr not found */
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog_debug ("%s: laddr not found", __func__);
      return -2;
    }
  else
    {
      /* raddr not found */
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog_debug ("%s: raddr not found", __func__);
      return -3;
    }
  return 0;
}

int
zread_ipv4_bfd_neigh_up (struct zserv *client, u_short length)
{
  int ret;
  struct bfd_cneigh *cneighp = zread_ipv4_bfd_cneigh_extract (client);
  ret =
    zread_bfd_neigh_up (client, cneightbl->v4, cneighp,
			&zsend_ipv4_bfd_neigh_up);
  bfd_cneigh_free (cneighp);
  return ret;
}

#ifdef HAVE_IPV6
int
zread_ipv6_bfd_neigh_up (struct zserv *client, u_short length)
{
  int ret;
  struct bfd_cneigh *cneighp = zread_ipv6_bfd_cneigh_extract (client);
  ret =
    zread_bfd_neigh_up (client, cneightbl->v6, cneighp,
			&zsend_ipv6_bfd_neigh_up);
  bfd_cneigh_free (cneighp);
  return ret;
}
#endif /* HAVE_IPV6 */

/* Process Down message */
static int
zread_bfd_neigh_down (struct zserv *client, struct route_table *cneightable,
		      struct bfd_cneigh *cneighp,
		      int (*zsend_bfd_neigh_down) (struct zserv *,
						   struct bfd_cneigh *))
{
  struct route_node *node, *subnode;
  struct listnode *listnode;
  struct zserv *zservp;
  struct bfd_addrtreehdr *hdrp;

  if ((node = route_node_lookup (cneightable, &cneighp->raddr)))
    {
      /* Paranoia */
      assert (node->info);
      hdrp = (struct bfd_addrtreehdr *) node->info;
      assert (hdrp->info);
      assert (hdrp->count);

      if ((subnode = route_node_lookup (hdrp->info, &cneighp->laddr)))
	{
	  /* Tuple raddr/laddr has been found */
	  assert (subnode->info);

	  /* Notify registered clients about the state change to "Down" */
	  for (ALL_LIST_ELEMENTS_RO
	       (((struct bfd_cneigh *) subnode->info)->clients, listnode,
		zservp))
	    {
	      if (client == zservp)	/* We don't want to notify ourselves */
		continue;
	      else
		zsend_bfd_neigh_down (zservp, cneighp);
	    }
	  /* Client not found */
	  if (IS_ZEBRA_DEBUG_EVENT)
	    zlog_debug ("%s: client not found", __func__);
	  return -1;
	}
      /* laddr not found */
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog_debug ("%s: laddr not found", __func__);
      return -2;
    }
  else
    {
      /* raddr not found */
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog_debug ("%s: raddr not found", __func__);
      return -3;
    }
  return 0;
}

int
zread_ipv4_bfd_neigh_down (struct zserv *client, u_short length)
{
  int ret;
  struct bfd_cneigh *cneighp = zread_ipv4_bfd_cneigh_extract (client);
  ret =
    zread_bfd_neigh_down (client, cneightbl->v4, cneighp,
			  &zsend_ipv4_bfd_neigh_down);
  bfd_cneigh_free (cneighp);
  return ret;
}

#ifdef HAVE_IPV6
int
zread_ipv6_bfd_neigh_down (struct zserv *client, u_short length)
{
  int ret;
  struct bfd_cneigh *cneighp = zread_ipv6_bfd_cneigh_extract (client);
  ret =
    zread_bfd_neigh_down (client, cneightbl->v6, cneighp,
			  &zsend_ipv6_bfd_neigh_down);
  bfd_cneigh_free (cneighp);
  return ret;
}
#endif /* HAVE_IPV6 */
