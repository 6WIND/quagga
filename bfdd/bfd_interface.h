/*
 * BFDD - bfd_interface.h
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


#ifndef _QUAGGA_BFD_INTERFACE_H
#define _QUAGGA_BFD_INTERFACE_H

#include "bfdd/bfdd.h"

/* in msec */
#define BFD_IF_INTERVAL_DFT	750
#define BFD_IF_INTERVAL_MIN	200
#define BFD_IF_INTERVAL_MAX	30000
#define BFD_IF_MINRX_DFT	500
#define BFD_IF_MINRX_MIN	200
#define BFD_IF_MINRX_MAX	30000

#define BFD_IF_MULTIPLIER_DFT	3
#define BFD_IF_MULTIPLIER_MIN	1
#define BFD_IF_MULTIPLIER_MAX	20

struct bfd_if_info
{
  int enabled;			/* enabled flag */
  int passive;			/* passive flag */
  uint32_t interval;		/* desmintx */
  uint32_t minrx;		/* reqminrx */
  uint32_t multiplier;
};


void bfd_if_init (void);
struct bfd_if_info *bfd_if_info_new (void);

struct bfd_if_info *bfd_ifinfo_get (struct bfd_neigh *neighp);
void bfd_neigh_if_passive_update (struct bfd_neigh *neighp);
int bfd_neigh_check (struct bfd_neigh *neighp);


#endif /* _QUAGGA_BFD_INTERFACE_H */
