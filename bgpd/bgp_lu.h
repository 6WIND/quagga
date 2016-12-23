/* MPLS-LU
   Copyright (C) 2016 6WIND

This file is part of GNU Quagga.

GNU Quagga is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Quagga is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Quagga; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGP_LU_H
#define _QUAGGA_BGP_LU_H

extern void bgp_labeled_unicast_init (void);
extern int bgp_nlri_parse_lu (struct peer *, struct attr *, struct bgp_nlri *);
extern void bgp_lu_init (void);
extern void peer_configure_label (struct peer *peer, afi_t afi, safi_t safi, int enable);

#endif /* _QUAGGA_BGP_LU_H */
