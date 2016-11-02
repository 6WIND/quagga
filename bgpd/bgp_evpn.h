/* MPLS-VPN
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

#ifndef _QUAGGA_BGP_EVPN_H
#define _QUAGGA_BGP_EVPN_H

#include "lib/prefix.h"

extern void bgp_ethernetvpn_init (void);
extern int bgp_nlri_parse_evpn (struct peer *peer, struct attr *attr,
                                struct bgp_nlri *packet, int withdraw);

/* EVPN route types as per RFC7432 and
 * as per draft-ietf-bess-evpn-prefix-advertisement-02
 */
#define EVPN_ETHERNET_AUTO_DISCOVERY 1
#define EVPN_MACIP_ADVERTISEMENT 2
#define EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG 3
#define EVPN_ETHERNET_SEGMENT 4
#define EVPN_IP_PREFIX 5

#define EVPN_ETHERNET_AD_PER_ESI 1
#define EVPN_ETHERNET_AD_PER_EVI 2
#define EVPN_ETHERNET_MP_UNREACH 4
#define EVPN_MAX_ET 0xffffffff

extern void
bgp_evpn_process_imports2 (struct bgp *bgp, struct bgp_evpn_ad *old, struct bgp_evpn_ad *new);

struct bgp_evpn_ad * bgp_evpn_process_auto_discovery(struct peer *peer,
                                     struct prefix_rd *prd,
                                     struct bgp_route_evpn *evpn,
                                     struct prefix *p,
                                     u_int32_t label,
                                     struct attr *attr);

struct bgp_evpn_ad* bgp_evpn_ad_new(struct peer *peer,
                                    struct bgp_vrf *vrf,
                                    struct eth_segment_id *esi,
                                    u_int32_t ethtag,
                                    u_int32_t label);
void bgp_evpn_ad_free(struct bgp_evpn_ad* ad);
int bgp_evpn_ad_cmp(struct bgp_evpn_ad *ad1,
                    struct peer *peer,
                    struct prefix_rd *prd,
                    struct eth_segment_id *esi,
                    u_int32_t ethtag);

int bgp_evpn_ad_update(struct bgp_evpn_ad *ad, struct in_addr *nexthop, u_int32_t label);

void
bgp_evpn_auto_discovery_new_entry (struct bgp_vrf *vrf,
                                   struct bgp_info *ri);
#endif /* _QUAGGA_BGP_EVPN_H */
