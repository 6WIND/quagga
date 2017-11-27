/*
 * LIB - bfd.h   
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


#ifndef _QUAGGA_BFD_H
#define _QUAGGA_BFD_H

#include "zebra.h"
#include "zebra/zserv.h"

/* Mulihop mode */
#define BFD_CNEIGH_FLAGS_MULTIHOP (1<< 0)
/* Passive mode - this flag can be set for candidate neighbor by a client 
   or as a result of setting interface to passive (logical OR) */
#define BFD_CNEIGH_FLAGS_PASSIVE  (1<< 1)
/* not supported */
#define BFD_CNEIGH_FLAGS_ECHO	  (1<< 2)
/* not supported */
#define BFD_CNEIGH_FLAGS_DEMAND   (1<< 3)

#define bfd_flag_1hop_check(X) ((X->flags & BFD_CNEIGH_FLAGS_MULTIHOP) ? 0 : 1)
#define bfd_flag_mhop_check(X) ((X->flags & BFD_CNEIGH_FLAGS_MULTIHOP) ? 1 : 0)
#define bfd_flag_passive_check(X) ((X->flags & BFD_CNEIGH_FLAGS_PASSIVE) ? 1 : 0)
#define bfd_flag_echo_check(X) ((X->flags & BFD_CNEIGH_FLAGS_ECHO) ? 1 : 0)
#define bfd_flag_demand_check(X) ((X->flags & BFD_CNEIGH_FLAGS_DEMAND) ? 1 : 0)

#define bfd_check_cneigh_family(CNEIGHP) PREFIX_FAMILY(&((CNEIGHP)->raddr))

/* Candidate neighbor structure */
struct bfd_cneigh
{
  struct prefix raddr;		/* Candiate neighbor address */
  struct prefix laddr;		/* Suggested address when multihop 
				   is desired */
  unsigned int ifindex;		/* Suggested interface when single 
				   hop desired */
  uint32_t flags;		/* Flags */
  struct list *clients;		/* Registered clients, 
				   that wants to track session */
};

/* Memory managment */
struct bfd_cneigh *bfd_cneigh_new (void);
void bfd_cneigh_free (struct bfd_cneigh *cneigh);

#endif /* QUAGGA_BFD_H */
