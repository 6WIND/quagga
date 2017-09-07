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

#define RD_TYPE_AS      0
#define RD_TYPE_IP      1
#define RD_TYPE_AS4     2

#define RD_ADDRSTRLEN  28

struct rd_as
{
  u_int16_t type;
  as_t as;
  u_int32_t val;
};

struct rd_ip
{
  u_int16_t type;
  struct in_addr ip;
  u_int16_t val;
};

#define LABEL_ENCODING_STANDARD 0
#define LABEL_ENCODING_FULL 1
extern u_int16_t decode_rd_type (u_char *pnt);
extern void bgp_mplsvpn_init (void);
extern int bgp_nlri_parse_vpn (struct peer *, struct attr *, struct bgp_nlri *);
extern void decode_rd_as (u_char *pnt, struct rd_as *rd_as);
extern void decode_rd_as4 (u_char *pnt, struct rd_as *rd_as);
extern void decode_rd_ip (u_char *pnt, struct rd_ip *rd_ip);
extern int str2prefix_rd (const char *, struct prefix_rd *);
extern int str2labels (const char *str, uint32_t *labels, size_t *nlabels, int type);
extern char *labels2str (char *str, size_t size, uint32_t *labels, size_t nlabels);
extern char *prefix_rd2str (struct prefix_rd *, char *, size_t);
extern int prefix_rd_cmp(struct prefix_rd *p1, struct prefix_rd *p2);

#endif /* _QUAGGA_BGP_MPLSVPN_H */
