/* E-VPN attribute handling structure file
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

#ifndef _QUAGGA_BGP_ATTR_EVPN_H
#define _QUAGGA_BGP_ATTR_EVPN_H

#include "prefix.h"

struct bgp_vrf;

/* value of first byte of ESI */
#define ESI_TYPE_ARBITRARY 0 /* */
#define ESI_TYPE_LACP      1 /* <> */
#define ESI_TYPE_BRIDGE    2 /* <Root bridge Mac-6B>:<Root Br Priority-2B>:00 */
#define ESI_TYPE_MAC       3 /* <Syst Mac Add-6B>:<Local Discriminator Value-3B> */
#define ESI_TYPE_ROUTER    4 /* <RouterId-4B>:<Local Discriminator Value-4B> */
#define ESI_TYPE_AS        5 /* <AS-4B>:<Local Discriminator Value-4B> */
#define MAX_ESI {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}

#define MAX_ET 0xffffffff
u_long eth_tag_id;

#if defined(ETHER_ADDR_LEN)
#define MAC_LEN ETHER_ADDR_LEN
#else
#define MAC_LEN 6
#endif

union gw_addr {
  struct in_addr ipv4;
#ifdef HAVE_IPV6
  struct in6_addr ipv6;
#endif /* HAVE_IPV6 */
};

struct bgp_route_evpn
{
  uint32_t eth_t_id;
  struct eth_segment_id eth_s_id;
  union gw_addr gw_ip;
#define EVPN_ETHERNET_AD_PER_ESI 1
#define EVPN_ETHERNET_AD_PER_EVI 2
#define EVPN_ETHERNET_MP_UNREACH 4
  uint8_t auto_discovery_type;
};

struct bgp_evpn_ad
{
  struct bgp *bgp;
  struct peer *peer;

  /* RD used by A/D */
  struct prefix_rd prd;
  uint32_t eth_t_id;
  uint32_t label;
  struct eth_segment_id eth_s_id;

  /* if withdraw message, then type is set to BGP_EVPN_AD_TYPE_MP_UNREACH */
  struct attr *attr;
#define BGP_EVPN_AD_TYPE_MP_REACH 0
#define BGP_EVPN_AD_TYPE_MP_UNREACH 1
  u_int16_t type;
  u_int16_t status;
};  

extern int str2esi (const char *str, struct eth_segment_id *id);
extern int str2mac (const char *str, char *mac);
extern char *esi2str (struct eth_segment_id *id);
extern char *mac2str (char *mac);
extern char *ecom_mac2str(char *ecom_mac);
extern int bgp_evpn_ad_update(struct bgp_evpn_ad *ad, struct in_addr *nexthop, u_int32_t label);
extern int bgp_evpn_ad_cmp(struct bgp_evpn_ad *ad1,
                    struct peer *peer,
                    struct prefix_rd *prd,
                    struct eth_segment_id *esi,
                    u_int32_t ethtag);
extern void bgp_evpn_ad_free(struct bgp_evpn_ad* ad);
extern struct bgp_evpn_ad* bgp_evpn_ad_new(struct peer *peer,
                                           struct bgp_vrf *vrf,
                                           struct eth_segment_id *esi,
                                           u_int32_t ethtag,
                                           u_int32_t label);
extern int bgp_evpn_ad_update(struct bgp_evpn_ad *ad, struct in_addr *nexthop, u_int32_t label);

extern void bgp_evpn_ad_display (struct bgp_evpn_ad *ad, char *buf, int size);

struct bgp_evpn_ad* bgp_evpn_ad_new_from_update(struct peer *peer,
                                                struct prefix_rd *prd,
                                                struct bgp_route_evpn *evpn,
                                                struct prefix *p,
                                                u_int32_t label,
                                                struct attr *attr);

struct bgp_info *bgp_evpn_new_bgp_info_from_ad(struct bgp_info *ri, struct bgp_evpn_ad *ad);

struct bgp_evpn_ad* bgp_evpn_ad_duplicate_from_ad(struct bgp_evpn_ad *evpn);

#endif /* _QUAGGA_BGP_ATTR_EVPN_H */
