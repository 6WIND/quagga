/*
 * LT functions.
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

#ifdef HAVE_NETNS
#undef  _GNU_SOURCE
#define _GNU_SOURCE

#include <sched.h>
#endif

#include "if.h"
#include "logical_table.h"
#include "prefix.h"
#include "table.h"
#include "log.h"
#include "memory.h"
#include "command.h"
#include "vty.h"

#ifdef HAVE_NETNS

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000 /* New network namespace (lo, device, names sockets, etc) */
#endif

#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
#ifdef __NR_setns
  return syscall(__NR_setns, fd, nstype);
#else
  errno = ENOSYS;
  return -1;
#endif
}
#endif /* HAVE_SETNS */

#define LT_RUN_DIR         "/var/run/netns"
#define LTID_DEFAULT_NAME    "/proc/self/ns/net"

#else /* !HAVE_NETNS */

#define LTID_DEFAULT_NAME    "Default-IP-Routing-Table"

#endif /* HAVE_NETNS */

struct lt
{
  /* Identifier, same as the vector index */
  ltid_t ltid;
  /* Name */
  char *name;
  /* File descriptor */
  int fd;

  /* Master list of interfaces belonging to this LT */
  struct list *iflist;

  /* User data */
  void *info;
};

/* Holding LT hooks  */
struct lt_master
{
  int (*lt_new_hook) (ltid_t, void **);
  int (*lt_delete_hook) (ltid_t, void **);
  int (*lt_enable_hook) (ltid_t, void **);
  int (*lt_disable_hook) (ltid_t, void **);
} lt_master = {0,};

/* LT table */
struct route_table *lt_table = NULL;

static int lt_is_enabled (struct lt *lt);
static int lt_enable (struct lt *lt);
static void lt_disable (struct lt *lt);


/* Build the table key */
static void
lt_build_key (ltid_t ltid, struct prefix *p)
{
  p->family = AF_INET;
  p->prefixlen = IPV4_MAX_BITLEN;
  p->u.prefix4.s_addr = ltid;
}

/* Get a LT. If not found, create one. */
static struct lt *
lt_get (ltid_t ltid)
{
  struct prefix p;
  struct route_node *rn;
  struct lt *lt;

  lt_build_key (ltid, &p);
  rn = route_node_get (lt_table, &p);
  if (rn->info)
    {
      lt = (struct lt *)rn->info;
      route_unlock_node (rn); /* get */
      return lt;
    }

  lt = XCALLOC (MTYPE_LT, sizeof (struct lt));
  lt->ltid = ltid;
  lt->fd = -1;
  rn->info = lt;

  /* Initialize interfaces. */
  if_init (ltid, &lt->iflist);

  zlog_info ("LT %u is created.", ltid);

  if (lt_master.lt_new_hook)
    (*lt_master.lt_new_hook) (ltid, &lt->info);

  return lt;
}

/* Delete a LT. This is called in lt_terminate(). */
static void
lt_delete (struct lt *lt)
{
  zlog_info ("LT %u is to be deleted.", lt->ltid);

  lt_disable (lt);

  if (lt_master.lt_delete_hook)
    (*lt_master.lt_delete_hook) (lt->ltid, &lt->info);

  if_terminate (lt->ltid, &lt->iflist);

  if (lt->name)
    XFREE (MTYPE_LT_NAME, lt->name);

  XFREE (MTYPE_LT, lt);
}

/* Look up a LT by identifier. */
static struct lt *
lt_lookup (ltid_t ltid)
{
  struct prefix p;
  struct route_node *rn;
  struct lt *lt = NULL;

  lt_build_key (ltid, &p);
  rn = route_node_lookup (lt_table, &p);
  if (rn)
    {
      lt = (struct lt *)rn->info;
      route_unlock_node (rn); /* lookup */
    }
  return lt;
}

/*
 * Check whether the LT is enabled - that is, whether the LT
 * is ready to allocate resources. Currently there's only one
 * type of resource: socket.
 */
static int
lt_is_enabled (struct lt *lt)
{
#ifdef HAVE_NETNS
  return lt && lt->fd >= 0;
#else
  return lt && lt->fd == -2 && lt->ltid == LTID_DEFAULT;
#endif
}

/*
 * Enable a LT - that is, let the LT be ready to use.
 * The LT_ENABLE_HOOK callback will be called to inform
 * that they can allocate resources in this LT.
 *
 * RETURN: 1 - enabled successfully; otherwise, 0.
 */
static int
lt_enable (struct lt *lt)
{

  if (!lt_is_enabled (lt))
    {
#ifdef HAVE_NETNS
      lt->fd = open (lt->name, O_RDONLY);
#else
      lt->fd = -2; /* Remember that lt_enable_hook has been called */
      errno = -ENOTSUP;
#endif

      if (!lt_is_enabled (lt))
        {
          zlog_err ("Can not enable LT %u: %s!",
                    lt->ltid, safe_strerror (errno));
          return 0;
        }

#ifdef HAVE_NETNS
      zlog_info ("LT %u is associated with NETNS %s.",
                 lt->ltid, lt->name);
#endif

      zlog_info ("LT %u is enabled.", lt->ltid);
      if (lt_master.lt_enable_hook)
        (*lt_master.lt_enable_hook) (lt->ltid, &lt->info);
    }

  return 1;
}

/*
 * Disable a LT - that is, let the LT be unusable.
 * The LT_DELETE_HOOK callback will be called to inform
 * that they must release the resources in the LT.
 */
static void
lt_disable (struct lt *lt)
{
  if (lt_is_enabled (lt))
    {
      zlog_info ("LT %u is to be disabled.", lt->ltid);

      if (lt_master.lt_disable_hook)
        (*lt_master.lt_disable_hook) (lt->ltid, &lt->info);

#ifdef HAVE_NETNS
      close (lt->fd);
#endif
      lt->fd = -1;
    }
}


/* Add a LT hook. Please add hooks before calling lt_init(). */
void
lt_add_hook (int type, int (*func)(ltid_t, void **))
{
  switch (type) {
  case LT_NEW_HOOK:
    lt_master.lt_new_hook = func;
    break;
  case LT_DELETE_HOOK:
    lt_master.lt_delete_hook = func;
    break;
  case LT_ENABLE_HOOK:
    lt_master.lt_enable_hook = func;
    break;
  case LT_DISABLE_HOOK:
    lt_master.lt_disable_hook = func;
    break;
  default:
    break;
  }
}

/* Return the iterator of the first LT. */
lt_iter_t
lt_first (void)
{
  struct route_node *rn;

  for (rn = route_top (lt_table); rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* top/next */
        return (lt_iter_t)rn;
      }
  return LT_ITER_INVALID;
}

/* Return the next LT iterator to the given iterator. */
lt_iter_t
lt_next (lt_iter_t iter)
{
  struct route_node *rn = NULL;

  /* Lock it first because route_next() will unlock it. */
  if (iter != LT_ITER_INVALID)
    rn = route_next (route_lock_node ((struct route_node *)iter));

  for (; rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* next */
        return (lt_iter_t)rn;
      }
  return LT_ITER_INVALID;
}

/* Return the LT iterator of the given LT ID. If it does not exist,
 * the iterator of the next existing LT is returned. */
lt_iter_t
lt_iterator (ltid_t ltid)
{
  struct prefix p;
  struct route_node *rn;

  lt_build_key (ltid, &p);
  rn = route_node_get (lt_table, &p);
  if (rn->info)
    {
      /* OK, the LT exists. */
      route_unlock_node (rn); /* get */
      return (lt_iter_t)rn;
    }

  /* Find the next LT. */
  for (rn = route_next (rn); rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* next */
        return (lt_iter_t)rn;
      }

  return LT_ITER_INVALID;
}

/* Obtain the LT ID from the given LT iterator. */
ltid_t
lt_iter2id (lt_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct lt *)rn->info)->ltid : LTID_DEFAULT;
}

/* Obtain the data pointer from the given LT iterator. */
void *
lt_iter2info (lt_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct lt *)rn->info)->info : NULL;
}

/* Obtain the interface list from the given LT iterator. */
struct list *
lt_iter2iflist (lt_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct lt *)rn->info)->iflist : NULL;
}

/* Get the data pointer of the specified LT. If not found, create one. */
void *
lt_info_get (ltid_t ltid)
{
  struct lt *lt = lt_get (ltid);
  return lt->info;
}

/* Look up the data pointer of the specified LT. */
void *
lt_info_lookup (ltid_t ltid)
{
  struct lt *lt = lt_lookup (ltid);
  return lt ? lt->info : NULL;
}

/* Look up the interface list in a LT. */
struct list *
lt_iflist (ltid_t ltid)
{
   struct lt * lt = lt_lookup (ltid);
   return lt ? lt->iflist : NULL;
}

/* Get the interface list of the specified LT. Create one if not find. */
struct list *
lt_iflist_get (ltid_t ltid)
{
   struct lt * lt = lt_get (ltid);
   return lt->iflist;
}

/*
 * LT bit-map
 */

#define LT_BITMAP_NUM_OF_GROUPS            8
#define LT_BITMAP_NUM_OF_BITS_IN_GROUP \
    (UINT16_MAX / LT_BITMAP_NUM_OF_GROUPS)
#define LT_BITMAP_NUM_OF_BYTES_IN_GROUP \
    (LT_BITMAP_NUM_OF_BITS_IN_GROUP / CHAR_BIT + 1) /* +1 for ensure */

#define LT_BITMAP_GROUP(_id) \
    ((_id) / LT_BITMAP_NUM_OF_BITS_IN_GROUP)
#define LT_BITMAP_BIT_OFFSET(_id) \
    ((_id) % LT_BITMAP_NUM_OF_BITS_IN_GROUP)

#define LT_BITMAP_INDEX_IN_GROUP(_bit_offset) \
    ((_bit_offset) / CHAR_BIT)
#define LT_BITMAP_FLAG(_bit_offset) \
    (((u_char)1) << ((_bit_offset) % CHAR_BIT))

struct lt_bitmap
{
  u_char *groups[LT_BITMAP_NUM_OF_GROUPS];
};

lt_bitmap_t
lt_bitmap_init (void)
{
  return (lt_bitmap_t) XCALLOC (MTYPE_LT_BITMAP, sizeof (struct lt_bitmap));
}

void
lt_bitmap_free (lt_bitmap_t bmap)
{
  struct lt_bitmap *bm = (struct lt_bitmap *) bmap;
  int i;

  if (bmap == LT_BITMAP_NULL)
    return;

  for (i = 0; i < LT_BITMAP_NUM_OF_GROUPS; i++)
    if (bm->groups[i])
      XFREE (MTYPE_LT_BITMAP, bm->groups[i]);

  XFREE (MTYPE_LT_BITMAP, bm);
}

void
lt_bitmap_set (lt_bitmap_t bmap, ltid_t ltid)
{
  struct lt_bitmap *bm = (struct lt_bitmap *) bmap;
  u_char group = LT_BITMAP_GROUP (ltid);
  u_char offset = LT_BITMAP_BIT_OFFSET (ltid);

  if (bmap == LT_BITMAP_NULL)
    return;

  if (bm->groups[group] == NULL)
    bm->groups[group] = XCALLOC (MTYPE_LT_BITMAP,
                                 LT_BITMAP_NUM_OF_BYTES_IN_GROUP);

  SET_FLAG (bm->groups[group][LT_BITMAP_INDEX_IN_GROUP (offset)],
            LT_BITMAP_FLAG (offset));
}

void
lt_bitmap_unset (lt_bitmap_t bmap, ltid_t ltid)
{
  struct lt_bitmap *bm = (struct lt_bitmap *) bmap;
  u_char group = LT_BITMAP_GROUP (ltid);
  u_char offset = LT_BITMAP_BIT_OFFSET (ltid);

  if (bmap == LT_BITMAP_NULL || bm->groups[group] == NULL)
    return;

  UNSET_FLAG (bm->groups[group][LT_BITMAP_INDEX_IN_GROUP (offset)],
              LT_BITMAP_FLAG (offset));
}

int
lt_bitmap_check (lt_bitmap_t bmap, ltid_t ltid)
{
  struct lt_bitmap *bm = (struct lt_bitmap *) bmap;
  u_char group = LT_BITMAP_GROUP (ltid);
  u_char offset = LT_BITMAP_BIT_OFFSET (ltid);

  if (bmap == LT_BITMAP_NULL || bm->groups[group] == NULL)
    return 0;

  return CHECK_FLAG (bm->groups[group][LT_BITMAP_INDEX_IN_GROUP (offset)],
                     LT_BITMAP_FLAG (offset)) ? 1 : 0;
}

#ifdef HAVE_NETNS
/*
 * LT realization with NETNS
 */

static char *
lt_netns_pathname (struct vty *vty, const char *name)
{
  static char pathname[PATH_MAX];
  char *result;

  if (name[0] == '/') /* absolute pathname */
    result = realpath (name, pathname);
  else /* relevant pathname */
    {
      char tmp_name[PATH_MAX];
      snprintf (tmp_name, PATH_MAX, "%s/%s", LT_RUN_DIR, name);
      result = realpath (tmp_name, pathname);
    }

  if (! result)
    {
      vty_out (vty, "Invalid pathname: %s%s", safe_strerror (errno),
               VTY_NEWLINE);
      return NULL;
    }
  return pathname;
}

DEFUN (lt_netns,
       lt_netns_cmd,
       "logical-table <1-65535> netns NAME",
       "Enable a Logical Table\n"
       "Specify the LT identifier\n"
       "Associate with a NETNS\n"
       "The file name in " LT_RUN_DIR ", or a full pathname\n")
{
  ltid_t ltid = LTID_DEFAULT;
  struct lt *lt = NULL;
  char *pathname = lt_netns_pathname (vty, argv[1]);

  if (!pathname)
    return CMD_WARNING;

  VTY_GET_INTEGER ("LT ID", ltid, argv[0]);
  lt = lt_get (ltid);

  if (lt->name && strcmp (lt->name, pathname) != 0)
    {
      vty_out (vty, "LT %u is already configured with NETNS %s%s",
               lt->ltid, lt->name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!lt->name)
    lt->name = XSTRDUP (MTYPE_LT_NAME, pathname);

  if (!lt_enable (lt))
    {
      vty_out (vty, "Can not associate LT %u with NETNS %s%s",
               lt->ltid, lt->name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (no_lt_netns,
       no_lt_netns_cmd,
       "no logical-table <1-65535> netns NAME",
       NO_STR
       "Disable a Logical Table\n"
       "Specify the LT identifier\n"
       "Delete an association with a NETNS\n"
       "The file name in " LT_RUN_DIR ", or a full pathname\n")
{
  ltid_t ltid = LTID_DEFAULT;
  struct lt *lt = NULL;
  char *pathname = lt_netns_pathname (vty, argv[1]);

  if (!pathname)
    return CMD_WARNING;

  VTY_GET_INTEGER ("LT ID", ltid, argv[0]);
  lt = lt_lookup (ltid);

  if (!lt)
    {
      vty_out (vty, "LT %u is not found%s", ltid, VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  if (lt->name && strcmp (lt->name, pathname) != 0)
    {
      vty_out (vty, "Incorrect NETNS file name%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  lt_disable (lt);

  if (lt->name)
    {
      XFREE (MTYPE_LT_NAME, lt->name);
      lt->name = NULL;
    }

  return CMD_SUCCESS;
}

/* LT node. */
static struct cmd_node lt_node =
{
  LT_NODE,
  "",       /* LT node has no interface. */
  1
};

/* LT configuration write function. */
static int
lt_config_write (struct vty *vty)
{
  struct route_node *rn;
  struct lt *lt;
  int write = 0;

  for (rn = route_top (lt_table); rn; rn = route_next (rn))
    if ((lt = rn->info) != NULL &&
        lt->ltid != LTID_DEFAULT && lt->name)
      {
        vty_out (vty, "lt %u netns %s%s", lt->ltid, lt->name, VTY_NEWLINE);
        write++;
      }

  return write;
}

#endif /* HAVE_NETNS */

/* Initialize LT module. */
void
lt_init (void)
{
  struct lt *default_lt;

  /* Allocate LT table.  */
  lt_table = route_table_init ();

  /* The default LT always exists. */
  default_lt = lt_get (LTID_DEFAULT);
  if (!default_lt)
    {
      zlog_err ("lt_init: failed to create the default LT!");
      exit (1);
    }

  /* Set the default LT name. */
  default_lt->name = XSTRDUP (MTYPE_LT_NAME, LTID_DEFAULT_NAME);

  /* Enable the default LT. */
  if (!lt_enable (default_lt))
    {
      zlog_err ("lt_init: failed to enable the default LT!");
      exit (1);
    }

#ifdef HAVE_NETNS
  /* Install LT commands. */
  install_node (&lt_node, lt_config_write);
  install_element (CONFIG_NODE, &lt_netns_cmd);
  install_element (CONFIG_NODE, &no_lt_netns_cmd);
#endif
}

/* Terminate LT module. */
void
lt_terminate (void)
{
  struct route_node *rn;
  struct lt *lt;

  for (rn = route_top (lt_table); rn; rn = route_next (rn))
    if ((lt = rn->info) != NULL)
      lt_delete (lt);

  route_table_finish (lt_table);
  lt_table = NULL;
}

/* Create a socket for the LT. */
int
lt_socket (int domain, int type, int protocol, ltid_t ltid)
{
  struct lt *lt = lt_lookup (ltid);
  int ret = -1;

  if (!lt_is_enabled (lt))
    {
      errno = ENOSYS;
      return -1;
    }

#ifdef HAVE_NETNS
  ret = (ltid != LTID_DEFAULT) ? setns (lt->fd, CLONE_NEWNET) : 0;
  if (ret >= 0)
    {
      ret = socket (domain, type, protocol);
      if (ltid != LTID_DEFAULT)
        setns (lt_lookup (LTID_DEFAULT)->fd, CLONE_NEWNET);
    }
#else
  ret = socket (domain, type, protocol);
#endif

  return ret;
}
