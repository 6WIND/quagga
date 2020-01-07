/* E-VPN header for packet handling
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

struct bgp_route_evpn;

extern void bgp_ethernetvpn_init (void);
extern int bgp_nlri_parse_evpn (struct peer *peer, struct attr *attr,
                                struct bgp_nlri *packet, int withdraw);

extern int peer_evpn_auto_discovery_set (struct peer *peer, struct bgp_vrf *vrf,
                                         struct attr * attr, struct eth_segment_id *esi,
                                         u_int32_t ethtag, u_int32_t label);
extern int peer_evpn_auto_discovery_unset (struct peer *peer, struct bgp_vrf *vrf,
                                           struct attr * attr, struct eth_segment_id *esi,
                                           u_int32_t ethtag, u_int32_t label);

extern struct bgp_evpn_ad *bgp_evpn_process_auto_discovery(struct peer *peer,
                                                           struct prefix_rd *prd,
                                                           struct bgp_route_evpn *evpn,
                                                           struct prefix *p,
                                                           u_int32_t label,
                                                           struct attr *attr);
void bgp_evpn_process_remove_auto_discovery(struct bgp *bgp,
                                            struct peer *peer,
                                            struct prefix_rd *prd,
                                            struct bgp_evpn_ad *ad);
extern void bgp_vrf_peer_notification (struct peer *peer, int down);

/* propagates a change in the RT configured for each RD
 */
void
bgp_evpn_process_imports (struct bgp *bgp, struct bgp_evpn_ad *old, struct bgp_evpn_ad *new);

void
bgp_evpn_auto_discovery_new_entry (struct bgp_vrf *vrf,
                                   struct bgp_info *ri);

/* EVPN route types as per RFC7432 and
 * as per draft-ietf-bess-evpn-prefix-advertisement-02
 */
#define EVPN_ETHERNET_AUTO_DISCOVERY 1
#define EVPN_MACIP_ADVERTISEMENT 2
#define EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG 3
#define EVPN_ETHERNET_SEGMENT 4
#define EVPN_IP_PREFIX 5


/* BGP Encapsulation Types */
/* https://tools.ietf.org/html/draft-ietf-bess-evpn-overlay-07#section-13 */
#define BGP_ENCAPSULATION_VXLAN      8
#define BGP_ENCAPSULATION_NVGRE      9
#define BGP_ENCAPSULATION_MPLS      10
#define BGP_ENCAPSULATION_MPLSOGRE  11
#define BGP_ENCAPSULATION_VXLANGPE  12

#define IS_EVPN_RT1_PREFIX(p) ((p)->family == AF_L2VPN && \
                               (p)->u.prefix_evpn.route_type == \
                                EVPN_ETHERNET_AUTO_DISCOVERY)
#define IS_EVPN_RT2_PREFIX(p) ((p)->family == AF_L2VPN && \
                               (p)->u.prefix_evpn.route_type == \
                                EVPN_MACIP_ADVERTISEMENT)
#define IS_EVPN_RT3_PREFIX(p) ((p)->family == AF_L2VPN && \
                               (p)->u.prefix_evpn.route_type == \
                                EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
#define EVPN_RT3_STR(p) (((p)->family == AF_L2VPN) ? \
                          (((p)->u.prefix_evpn.route_type == 3) ? \
                           "(Inclusive Multicast Route)" : \
                           (((p)->u.prefix_evpn.route_type == 1) ? \
                            "(Ethernet Auto-discovery Route)" : "")) \
                         : "")

#endif /* _QUAGGA_BGP_EVPN_H */
