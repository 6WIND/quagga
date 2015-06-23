/*
 * LT related header.
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

#ifndef _ZEBRA_LT_H
#define _ZEBRA_LT_H

#include "linklist.h"

/* The default LT ID */
#define LTID_DEFAULT 0

/*
 * The command strings
 */

#define LT_CMD_STR         "lt <0-65535>"
#define LT_CMD_HELP_STR    "Specify the LT\nThe LT ID\n"

#define LT_ALL_CMD_STR         "lt all"
#define LT_ALL_CMD_HELP_STR    "Specify the LT\nAll LTs\n"

/*
 * LT hooks
 */

#define LT_NEW_HOOK        0   /* a new LT is just created */
#define LT_DELETE_HOOK     1   /* a LT is to be deleted */
#define LT_ENABLE_HOOK     2   /* a LT is ready to use */
#define LT_DISABLE_HOOK    3   /* a LT is to be unusable */

/*
 * Add a specific hook to LT module.
 * @param1: hook type
 * @param2: the callback function
 *          - param 1: the LT ID
 *          - param 2: the address of the user data pointer (the user data
 *                     can be stored in or freed from there)
 */
extern void lt_add_hook (int, int (*)(ltid_t, void **));

/*
 * LT iteration
 */

typedef void *              lt_iter_t;
#define LT_ITER_INVALID    NULL    /* invalid value of the iterator */

/*
 * LT iteration utilities. Example for the usage:
 *
 *   lt_iter_t iter = lt_first();
 *   for (; iter != LT_ITER_INVALID; iter = lt_next (iter))
 *
 * or
 *
 *   lt_iter_t iter = lt_iterator (<a given LT ID>);
 *   for (; iter != LT_ITER_INVALID; iter = lt_next (iter))
 */

/* Return the iterator of the first LT. */
extern lt_iter_t lt_first (void);
/* Return the next LT iterator to the given iterator. */
extern lt_iter_t lt_next (lt_iter_t);
/* Return the LT iterator of the given LT ID. If it does not exist,
 * the iterator of the next existing LT is returned. */
extern lt_iter_t lt_iterator (ltid_t);

/*
 * LT iterator to properties
 */
extern ltid_t lt_iter2id (lt_iter_t);
extern void *lt_iter2info (lt_iter_t);
extern struct list *lt_iter2iflist (lt_iter_t);

/*
 * Utilities to obtain the user data
 */

/* Get the data pointer of the specified LT. If not found, create one. */
extern void *lt_info_get (ltid_t);
/* Look up the data pointer of the specified LT. */
extern void *lt_info_lookup (ltid_t);

/*
 * Utilities to obtain the interface list
 */

/* Look up the interface list of the specified LT. */
extern struct list *lt_iflist (ltid_t);
/* Get the interface list of the specified LT. Create one if not find. */
extern struct list *lt_iflist_get (ltid_t);

/*
 * LT bit-map: maintaining flags, one bit per LT ID
 */

typedef void *              lt_bitmap_t;
#define LT_BITMAP_NULL     NULL

extern lt_bitmap_t lt_bitmap_init (void);
extern void lt_bitmap_free (lt_bitmap_t);
extern void lt_bitmap_set (lt_bitmap_t, ltid_t);
extern void lt_bitmap_unset (lt_bitmap_t, ltid_t);
extern int lt_bitmap_check (lt_bitmap_t, ltid_t);

/*
 * LT initializer/destructor
 */
/* Please add hooks before calling lt_init(). */
extern void lt_init (void);
extern void lt_terminate (void);

/*
 * LT utilities
 */

/* Create a socket serving for the given LT */
extern int lt_socket (int, int, int, ltid_t);

#endif /*_ZEBRA_LT_H*/

