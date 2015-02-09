/*
 * VRF functions.
 * Copyright (C) 2014 6WIND S.A.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "prefix.h"
#include "table.h"
#include "log.h"
#include "memory.h"

#define VRF_DEFAULT_NAME    "Default-IP-Routing-Table"

struct vrf
{
  /* Identifier, same as the vector index */
  vrf_id_t vrf_id;
  /* Name */
  char *name;

  /* Master list of interfaces belonging to this VRF */
  struct list *iflist;

  /* User data */
  void *info;
};

/* Holding VRF hooks  */
struct vrf_master
{
  int (*vrf_new_hook) (vrf_id_t, void **);
  int (*vrf_delete_hook) (vrf_id_t, void **);
  int (*vrf_enable_hook) (vrf_id_t, void **);
  int (*vrf_disable_hook) (vrf_id_t, void **);
} vrf_master = {0,};

/* VRF table */
struct route_table *vrf_table = NULL;

static int vrf_is_enabled (struct vrf *vrf);
static int vrf_enable (struct vrf *vrf);
static void vrf_disable (struct vrf *vrf);


/* Build the table key */
static void
vrf_build_key (vrf_id_t vrf_id, struct prefix *p)
{
  p->family = AF_INET;
  p->prefixlen = IPV4_MAX_BITLEN;
  p->u.prefix4.s_addr = vrf_id;
}

/* Get a VRF. If not found, create one. */
static struct vrf *
vrf_get (vrf_id_t vrf_id)
{
  struct prefix p;
  struct route_node *rn;
  struct vrf *vrf;

  vrf_build_key (vrf_id, &p);
  rn = route_node_get (vrf_table, &p);
  if (rn->info)
    {
      vrf = (struct vrf *)rn->info;
      route_unlock_node (rn); /* get */
      return vrf;
    }

  vrf = XCALLOC (MTYPE_VRF, sizeof (struct vrf));
  vrf->vrf_id = vrf_id;
  rn->info = vrf;

  /* Initialize interfaces. */
  if_init (vrf_id, &vrf->iflist);

  zlog_info ("VRF %u is created.", vrf_id);

  if (vrf_master.vrf_new_hook)
    (*vrf_master.vrf_new_hook) (vrf_id, &vrf->info);

  return vrf;
}

/* Delete a VRF. This is called in vrf_terminate(). */
static void
vrf_delete (struct vrf *vrf)
{
  zlog_info ("VRF %u is to be deleted.", vrf->vrf_id);

  if (vrf_is_enabled (vrf))
    vrf_disable (vrf);

  if (vrf_master.vrf_delete_hook)
    (*vrf_master.vrf_delete_hook) (vrf->vrf_id, &vrf->info);

  if_terminate (vrf->vrf_id, &vrf->iflist);

  if (vrf->name)
    XFREE (MTYPE_VRF_NAME, vrf->name);

  XFREE (MTYPE_VRF, vrf);
}

/* Look up a VRF by identifier. */
static struct vrf *
vrf_lookup (vrf_id_t vrf_id)
{
  struct prefix p;
  struct route_node *rn;
  struct vrf *vrf = NULL;

  vrf_build_key (vrf_id, &p);
  rn = route_node_lookup (vrf_table, &p);
  if (rn)
    {
      vrf = (struct vrf *)rn->info;
      route_unlock_node (rn); /* lookup */
    }
  return vrf;
}

/*
 * Check whether the VRF is enabled - that is, whether the VRF
 * is ready to allocate resources. Currently there's only one
 * type of resource: socket.
 */
static int
vrf_is_enabled (struct vrf *vrf)
{
  return vrf && vrf->vrf_id == VRF_DEFAULT;
}

/*
 * Enable a VRF - that is, let the VRF be ready to use.
 * The VRF_ENABLE_HOOK callback will be called to inform
 * that they can allocate resources in this VRF.
 *
 * RETURN: 1 - enabled successfully; otherwise, 0.
 */
static int
vrf_enable (struct vrf *vrf)
{
  /* Till now, only the default VRF can be enabled. */
  if (vrf->vrf_id == VRF_DEFAULT)
    {
      zlog_info ("VRF %u is enabled.", vrf->vrf_id);

      if (vrf_master.vrf_enable_hook)
        (*vrf_master.vrf_enable_hook) (vrf->vrf_id, &vrf->info);

      return 1;
    }

  return 0;
}

/*
 * Disable a VRF - that is, let the VRF be unusable.
 * The VRF_DELETE_HOOK callback will be called to inform
 * that they must release the resources in the VRF.
 */
static void
vrf_disable (struct vrf *vrf)
{
  if (vrf_is_enabled (vrf))
    {
      zlog_info ("VRF %u is to be disabled.", vrf->vrf_id);

      /* Till now, nothing to be done for the default VRF. */

      if (vrf_master.vrf_disable_hook)
        (*vrf_master.vrf_disable_hook) (vrf->vrf_id, &vrf->info);
    }
}


/* Add a VRF hook. Please add hooks before calling vrf_init(). */
void
vrf_add_hook (int type, int (*func)(vrf_id_t, void **))
{
  switch (type) {
  case VRF_NEW_HOOK:
    vrf_master.vrf_new_hook = func;
    break;
  case VRF_DELETE_HOOK:
    vrf_master.vrf_delete_hook = func;
    break;
  case VRF_ENABLE_HOOK:
    vrf_master.vrf_enable_hook = func;
    break;
  case VRF_DISABLE_HOOK:
    vrf_master.vrf_disable_hook = func;
    break;
  default:
    break;
  }
}

/* Return the iterator of the first VRF. */
vrf_iter_t
vrf_first (void)
{
  struct route_node *rn;

  for (rn = route_top (vrf_table); rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* top/next */
        return (vrf_iter_t)rn;
      }
  return VRF_ITER_INVALID;
}

/* Return the next VRF iterator to the given iterator. */
vrf_iter_t
vrf_next (vrf_iter_t iter)
{
  struct route_node *rn = NULL;

  /* Lock it first because route_next() will unlock it. */
  if (iter != VRF_ITER_INVALID)
    rn = route_next (route_lock_node ((struct route_node *)iter));

  for (; rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* next */
        return (vrf_iter_t)rn;
      }
  return VRF_ITER_INVALID;
}

/* Return the VRF iterator of the given VRF ID. If it does not exist,
 * the iterator of the next existing VRF is returned. */
vrf_iter_t
vrf_iterator (vrf_id_t vrf_id)
{
  struct prefix p;
  struct route_node *rn;

  vrf_build_key (vrf_id, &p);
  rn = route_node_get (vrf_table, &p);
  if (rn->info)
    {
      /* OK, the VRF exists. */
      route_unlock_node (rn); /* get */
      return (vrf_iter_t)rn;
    }

  /* Find the next VRF. */
  for (rn = route_next (rn); rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* next */
        return (vrf_iter_t)rn;
      }

  return VRF_ITER_INVALID;
}

/* Obtain the VRF ID from the given VRF iterator. */
vrf_id_t
vrf_iter2id (vrf_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct vrf *)rn->info)->vrf_id : VRF_DEFAULT;
}

/* Obtain the data pointer from the given VRF iterator. */
void *
vrf_iter2info (vrf_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct vrf *)rn->info)->info : NULL;
}

/* Obtain the interface list from the given VRF iterator. */
struct list *
vrf_iter2iflist (vrf_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct vrf *)rn->info)->iflist : NULL;
}

/* Get the data pointer of the specified VRF. If not found, create one. */
void *
vrf_info_get (vrf_id_t vrf_id)
{
  struct vrf *vrf = vrf_get (vrf_id);
  return vrf->info;
}

/* Look up the data pointer of the specified VRF. */
void *
vrf_info_lookup (vrf_id_t vrf_id)
{
  struct vrf *vrf = vrf_lookup (vrf_id);
  return vrf ? vrf->info : NULL;
}

/* Look up the interface list in a VRF. */
struct list *
vrf_iflist (vrf_id_t vrf_id)
{
   struct vrf * vrf = vrf_lookup (vrf_id);
   return vrf ? vrf->iflist : NULL;
}

/* Get the interface list of the specified VRF. Create one if not find. */
struct list *
vrf_iflist_get (vrf_id_t vrf_id)
{
   struct vrf * vrf = vrf_get (vrf_id);
   return vrf->iflist;
}

/*
 * VRF bit-map
 */

#define VRF_BITMAP_NUM_OF_GROUPS            8
#define VRF_BITMAP_NUM_OF_BITS_IN_GROUP \
    (UINT16_MAX / VRF_BITMAP_NUM_OF_GROUPS)
#define VRF_BITMAP_NUM_OF_BYTES_IN_GROUP \
    (VRF_BITMAP_NUM_OF_BITS_IN_GROUP / CHAR_BIT + 1) /* +1 for ensure */

#define VRF_BITMAP_GROUP(_id) \
    ((_id) / VRF_BITMAP_NUM_OF_BITS_IN_GROUP)
#define VRF_BITMAP_BIT_OFFSET(_id) \
    ((_id) % VRF_BITMAP_NUM_OF_BITS_IN_GROUP)

#define VRF_BITMAP_INDEX_IN_GROUP(_bit_offset) \
    ((_bit_offset) / CHAR_BIT)
#define VRF_BITMAP_FLAG(_bit_offset) \
    (((u_char)1) << ((_bit_offset) % CHAR_BIT))

struct vrf_bitmap
{
  u_char *groups[VRF_BITMAP_NUM_OF_GROUPS];
};

vrf_bitmap_t
vrf_bitmap_init (void)
{
  return (vrf_bitmap_t) XCALLOC (MTYPE_VRF_BITMAP, sizeof (struct vrf_bitmap));
}

void
vrf_bitmap_free (vrf_bitmap_t bmap)
{
  struct vrf_bitmap *bm = (struct vrf_bitmap *) bmap;
  int i;

  if (bmap == VRF_BITMAP_NULL)
    return;

  for (i = 0; i < VRF_BITMAP_NUM_OF_GROUPS; i++)
    if (bm->groups[i])
      XFREE (MTYPE_VRF_BITMAP, bm->groups[i]);

  XFREE (MTYPE_VRF_BITMAP, bm);
}

void
vrf_bitmap_set (vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
  struct vrf_bitmap *bm = (struct vrf_bitmap *) bmap;
  u_char group = VRF_BITMAP_GROUP (vrf_id);
  u_char offset = VRF_BITMAP_BIT_OFFSET (vrf_id);

  if (bmap == VRF_BITMAP_NULL)
    return;

  if (bm->groups[group] == NULL)
    bm->groups[group] = XCALLOC (MTYPE_VRF_BITMAP,
                                 VRF_BITMAP_NUM_OF_BYTES_IN_GROUP);

  SET_FLAG (bm->groups[group][VRF_BITMAP_INDEX_IN_GROUP (offset)],
            VRF_BITMAP_FLAG (offset));
}

void
vrf_bitmap_unset (vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
  struct vrf_bitmap *bm = (struct vrf_bitmap *) bmap;
  u_char group = VRF_BITMAP_GROUP (vrf_id);
  u_char offset = VRF_BITMAP_BIT_OFFSET (vrf_id);

  if (bmap == VRF_BITMAP_NULL || bm->groups[group] == NULL)
    return;

  UNSET_FLAG (bm->groups[group][VRF_BITMAP_INDEX_IN_GROUP (offset)],
              VRF_BITMAP_FLAG (offset));
}

int
vrf_bitmap_check (vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
  struct vrf_bitmap *bm = (struct vrf_bitmap *) bmap;
  u_char group = VRF_BITMAP_GROUP (vrf_id);
  u_char offset = VRF_BITMAP_BIT_OFFSET (vrf_id);

  if (bmap == VRF_BITMAP_NULL || bm->groups[group] == NULL)
    return 0;

  return CHECK_FLAG (bm->groups[group][VRF_BITMAP_INDEX_IN_GROUP (offset)],
                     VRF_BITMAP_FLAG (offset)) ? 1 : 0;
}

/* Initialize VRF module. */
void
vrf_init (void)
{
  struct vrf *default_vrf;

  /* Allocate VRF table.  */
  vrf_table = route_table_init ();

  /* The default VRF always exists. */
  default_vrf = vrf_get (VRF_DEFAULT);
  if (!default_vrf)
    {
      zlog_err ("vrf_init: failed to create the default VRF!");
      exit (1);
    }

  /* Set the default VRF name. */
  default_vrf->name = XSTRDUP (MTYPE_VRF_NAME, VRF_DEFAULT_NAME);

  /* Enable the default VRF. */
  if (!vrf_enable (default_vrf))
    {
      zlog_err ("vrf_init: failed to enable the default VRF!");
      exit (1);
    }
}

/* Terminate VRF module. */
void
vrf_terminate (void)
{
  struct route_node *rn;
  struct vrf *vrf;

  for (rn = route_top (vrf_table); rn; rn = route_next (rn))
    if ((vrf = rn->info) != NULL)
      vrf_delete (vrf);

  route_table_finish (vrf_table);
  vrf_table = NULL;
}

/* Create a socket for the VRF. */
int
vrf_socket (int domain, int type, int protocol, vrf_id_t vrf_id)
{
  int ret = -1;

  if (!vrf_is_enabled (vrf_lookup (vrf_id)))
    {
      errno = ENOSYS;
      return -1;
    }

  if (vrf_id == VRF_DEFAULT)
    ret = socket (domain, type, protocol);
  else
    errno = ENOSYS;

  return ret;
}

