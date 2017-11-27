/*
 * BFDD - bfd_zebra.h   
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


#ifndef _QUAGGA_BFD_ZEBRA_H
#define _QUAGGA_BFD_ZEBRA_H


#include "zebra.h"
#include "zclient.h"
#include "sockunion.h"

void bfd_vty_init (void);
void bfd_zebra_init (void);

void bfd_zclient_reset (void);

#define BFD_SH_NEIGH      0
#define BFD_SH_NEIGH_DET  1
void bfd_sh_bfd_neigh (struct vty *vty, int mode);
void bfd_sh_bfd_neigh_tbl (struct vty *vty, int mode,
			   struct route_table *neightable, int *header);

void bfd_signal_neigh_updown (struct bfd_neigh *neighp, int cmd);
#define bfd_signal_neigh_up(NEIGH) \
        bfd_signal_neigh_updown(NEIGH,BFD_NEIGH_UP)
#define bfd_signal_neigh_down(NEIGH) \
        bfd_signal_neigh_updown(NEIGH,BFD_NEIGH_DOWN)

#endif /* _QUAGGA_BFD_ZEBRA_H */
