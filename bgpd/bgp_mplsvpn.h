/* MPLS-VPN
   Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGP_MPLSVPN_H
#define _QUAGGA_BGP_MPLSVPN_H

extern void bgp_mplsvpn_init (void);
extern int bgp_nlri_parse_vpn (struct peer *, struct attr *, struct bgp_nlri *);
extern int str2prefix_rd (const char *, struct prefix_rd *);
extern int str2labels (const char *str, uint32_t *labels, size_t *nlabels);
extern char *labels2str (char *str, size_t size, uint32_t *labels, size_t nlabels);
extern char *prefix_rd2str (struct prefix_rd *, char *, size_t);

#endif /* _QUAGGA_BGP_MPLSVPN_H */
