/*
 * LIB - bfd.c
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


#include "zebra.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "bfd.h"

/* Allocate memory for candidate bfd neighbor structure */
struct bfd_cneigh *
bfd_cneigh_new ()
{
  return XCALLOC (MTYPE_BFD_CNEIGH, sizeof (struct bfd_cneigh));
}

/* Free memory for candidate bfd neighbor structure */
void
bfd_cneigh_free (struct bfd_cneigh *cneighp)
{
  if (cneighp->clients)
    {
      if (listcount (cneighp->clients))
	abort ();		/* We cannot free neighbor with non-empy client list */
      else
	/* Client list empty so let's remove it */
	list_free (cneighp->clients);
    }
  /* Remove candidate */
  XFREE (MTYPE_BFD_CNEIGH, cneighp);
}
