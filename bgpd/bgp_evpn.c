/* Ethernet-VPN Packet and vty Processing File
   Copyright (C) 2016 6WIND

This file is part of GNU Quagga

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

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"

#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_mpath.h"

#define AD_STR_MAX_SIZE   120

#define ENTRIES_TO_ADD 2
#define ENTRIES_TO_REMOVE 1

static void bgp_evpn_process_auto_discovery_update_from_vrf (struct bgp_vrf *vrf,
                                                             struct bgp_evpn_ad *ad,
                                                             int action);

static void bgp_evpn_process_auto_discovery_delete_from_vrf (struct bgp_vrf *vrf,
                                                             struct bgp_evpn_ad *ad);

static void
bgp_evpn_process_auto_discovery_propagate (struct bgp_vrf *vrf,
                                           struct bgp_evpn_ad *ad,
                                           int action);

static void bgp_evpn_process_auto_discovery_update_from_vrf (struct bgp_vrf *vrf,
                                                             struct bgp_evpn_ad *ad,
                                                             int action)
{
  struct listnode *node;
  struct bgp_evpn_ad *ad2;
  int found = 0;

  for (ALL_LIST_ELEMENTS_RO(vrf->import_processing_evpn_ad, node, ad2))
    {
      if (0 == bgp_evpn_ad_cmp(ad2, ad->peer, NULL,
                               &ad->eth_s_id, ad->eth_t_id))
        found = 1;
        break;
    }
  /* add */
  if (!found)
    {
      ad2 = bgp_evpn_ad_duplicate_from_ad(ad);
      if (BGP_DEBUG (events, EVENTS))
        {
          char vrf_rd_str[RD_ADDRSTRLEN];
          char buf[AD_STR_MAX_SIZE];
          prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
          bgp_evpn_ad_display (ad2, buf, AD_STR_MAX_SIZE);
          zlog_debug ("vrf[%s]: %s from %s added", vrf_rd_str, buf, ad2->peer->host);
        }
      listnode_add (vrf->import_processing_evpn_ad, ad2);
    }
  else
    {
      /* found - update it */
      if (action == ENTRIES_TO_ADD)
        {
          if(ad2->attr == NULL)
            {
              struct attr new_attr;
              struct attr_extra new_extra;

              memset( &new_attr, 0, sizeof(struct attr));
              memset( &new_extra, 0, sizeof(struct attr_extra));
              bgp_attr_dup (&new_attr, ad->attr);
              ad2->attr = bgp_attr_intern (&new_attr);
            }
          ad2->label = ad->label;
        }
      else if (action == ENTRIES_TO_REMOVE)
        {
          ad2->type = BGP_EVPN_AD_TYPE_MP_UNREACH;
        }
    }
}

static void bgp_evpn_process_auto_discovery_delete_from_vrf (struct bgp_vrf *vrf,
                                                             struct bgp_evpn_ad *ad)
{
  struct listnode *node;
  struct bgp_evpn_ad *ad2;

  for (ALL_LIST_ELEMENTS_RO(vrf->import_processing_evpn_ad, node, ad2))
    {
      if (0 == bgp_evpn_ad_cmp(ad2, ad->peer, NULL,
                               &ad->eth_s_id, ad->eth_t_id))
        break;

    }
  if (!ad2)
    return;
  listnode_delete (vrf->import_processing_evpn_ad, ad2);
  if (BGP_DEBUG (events, EVENTS))
    {
      char vrf_rd_str[RD_ADDRSTRLEN];
      char buf[AD_STR_MAX_SIZE];
      prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
      bgp_evpn_ad_display (ad2, buf, AD_STR_MAX_SIZE);
      zlog_debug ("vrf[%s]: %s from %s deleted", vrf_rd_str, buf, ad2->peer->host);
    }
  bgp_evpn_ad_free (ad2);
}

/*
 * for all entries in VRF, duplicate or remove entries
 * on VRF RIB, and consequently on ADJRIB IN
 */
static void
bgp_evpn_process_auto_discovery_propagate (struct bgp_vrf *vrf,
                                           struct bgp_evpn_ad *ad,
                                           int action)
{
  afi_t afi = AFI_IP;
  struct bgp_info *ri, *ri_next;
  struct bgp_node *rn;
  int entry_found;

  if (!vrf)
    return;

  if (BGP_DEBUG (events, EVENTS))
    {
      char vrf_rd_str[RD_ADDRSTRLEN];
      char nh_str[BUFSIZ] = "<?>";
      char *esi;

      prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));

      esi = esi2str(&(ad->eth_s_id));
      if (ad->attr && ad->attr->extra)
        {
          if (ad->attr->extra->mp_nexthop_len == IPV4_MAX_BYTELEN)
            {
              strcpy (nh_str, inet_ntoa (ad->attr->extra->mp_nexthop_global_in));
              afi = AFI_IP;
            }
          else /* IPv6 nexthop */
            {
              inet_ntop (AF_INET6, &ad->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
              afi = AFI_IP6;
            }
        }
        zlog_debug ("vrf[%s] %s Ethtag %08x/ ESI %s/ Label %u: A/D from %s applied ( nexthop %s)",
                    vrf_rd_str, ad->type == BGP_EVPN_AD_TYPE_MP_UNREACH?"MP_UNREACH":"MP_REACH",
                    ad->eth_t_id, esi, ad->label, ad->peer->host, nh_str);
        free (esi);
    }

  for (rn = bgp_table_top (vrf->rib[afi]); rn; rn = bgp_route_next (rn))
    {
      if(rn->p.family != AF_L2VPN)
        continue;

      entry_found = 0;
      /* check for eth tag if incoming eth tag is not set to 0 */
      if(ad->eth_t_id != MAX_ET && rn->p.u.prefix_evpn.u.prefix_macip.eth_tag_id != ad->eth_t_id)
            continue;

      /* first loop to look for already present entries */
      for (ri = rn->info; ri; ri = ri_next)
        {
          ri_next = ri->next;

          /* static routes can't be impacted by received AD, don't process it */
          if (ri->type == ZEBRA_ROUTE_BGP && ri->sub_type == BGP_ROUTE_STATIC)
            continue;

          if(memcmp(&(ad->eth_s_id), &(ri->attr->extra->evpn_overlay.eth_s_id),
                    sizeof(struct eth_segment_id)))
            continue;
          /* case AD per EVI */
          if (ad->eth_t_id != MAX_ET && ad->label != ri->extra->labels[0])
            continue;
          /* match entry */
          if (ad->peer == ri->peer)
            {
              if (action == ENTRIES_TO_REMOVE)
                {
                  bgp_vrf_process_entry(ri, ROUTE_INFO_TO_REMOVE,
                                        AFI_L2VPN, SAFI_EVPN);
                  bgp_process (ri->peer->bgp, ri->net, afi, SAFI_UNICAST);
                }
              entry_found = 1;
              break;
            }
        }

      /* entry already found */
      if (entry_found == 1)
        continue;

      /* second loop to look for duplicating entry */
      for (ri = rn->info; ri; ri = ri_next)
        {
          ri_next = ri->next;

          /* static routes can't be impacted by received AD, don't process it */
          if (ri->type == ZEBRA_ROUTE_BGP && ri->sub_type == BGP_ROUTE_STATIC)
            continue;

          if(memcmp(&(ad->eth_s_id), &(ri->attr->extra->evpn_overlay.eth_s_id),
                    sizeof(struct eth_segment_id)))
            continue;
          /* case AD per EVI */
          if (ad->eth_t_id != MAX_ET && ad->label != ri->extra->labels[0])
            continue;

          {
            struct bgp_info temp;
            temp.attr = ad->attr;
            if (0 == bgp_info_nexthop_cmp (&temp, ri))
              {
                zlog_err("A-D nexthop already has an entry with same NH");
                continue;
              }
          }
          /* match entry */
          if (ad->peer != ri->peer)
            {
              struct bgp_info *ri_from_ad;
              /* substitute next hop
               * with ad->attr->extra->mp_nexthopglobal_in
               * with ad->attr->nexthop
               */
              /* change peer to our ad->peer */
              ri_from_ad = bgp_evpn_new_bgp_info_from_ad (ri, ad);
              bgp_vrf_process_entry(ri_from_ad, ROUTE_INFO_TO_ADD,
                                    AFI_L2VPN, SAFI_EVPN);
              entry_found = 1;
            }
        }
      if (entry_found)
        bgp_process (vrf->bgp, rn, afi, SAFI_UNICAST);
      /* lookup rt export list from ad->attr */
    }
}

int
bgp_nlri_parse_evpn (struct peer *peer, struct attr *attr,
                     struct bgp_nlri *packet, int withdraw)
{
  u_char *pnt,*pnt2;
  u_char *lim;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp_route_evpn evpn;
  uint8_t route_type, route_length;
  uint32_t labels[BGP_MAX_LABELS];
  size_t nlabels = 0;

  /* Check peer status. */
  if (peer->status != Established)
    return 0;
  
  /* Make prefix_rd */
  prd.family = AF_UNSPEC;
  prd.prefixlen = 64;

  pnt = packet->nlri;
  lim = pnt + packet->length;
  while (pnt < lim)
    {
      /* clear evpn structure */
      memset (&evpn, 0, sizeof (evpn));

      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));
      memset(&evpn.gw_ip, 0, sizeof(union gw_addr));
      evpn.eth_t_id = 0;
      memset(&evpn.eth_s_id, 0, sizeof(struct eth_segment_id));

      /* Fetch Route Type */ 
      route_type = *pnt++;
      route_length = *pnt++;
      pnt2 = pnt; // point to start of route
      /* simply ignore. goto next route type if any */
      if(route_type != EVPN_IP_PREFIX && route_type != EVPN_MACIP_ADVERTISEMENT
         && route_type != EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG
         && route_type != EVPN_ETHERNET_AUTO_DISCOVERY)
	{
	  if (pnt + route_length > lim)
	    {
	      zlog_err ("not enough bytes for New Route Type left in NLRI?");
	      return -1;
	    }
	  pnt += route_length;
	  continue;
	}

      /* Fetch RD */
      if (pnt + 8 > lim)
        {
          zlog_err ("not enough bytes for RD left in NLRI?");
          return -1;
        }

      /* Copy routing distinguisher to rd. */
      memcpy (&prd.val, pnt, 8);
      pnt += 8;

      if (route_type != EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
        {
          /* Fetch ESI */
          if (pnt + 10 > lim)
            {
              zlog_err ("not enough bytes for ESI left in NLRI?");
              return -1;
            }
          memcpy(&evpn.eth_s_id.val, pnt, 10);
          pnt += 10;
        }

      /* Fetch Ethernet Tag */
      if (pnt + 4 > lim)
        {
          zlog_err ("not enough bytes for Eth Tag left in NLRI?");
          return -1;
        }
      p.u.prefix_evpn.route_type = route_type;
      if (route_type == EVPN_MACIP_ADVERTISEMENT ||
          route_type == EVPN_ETHERNET_AUTO_DISCOVERY)
        {
          p.family = AF_L2VPN;
          memcpy(&p.u.prefix_evpn.u.prefix_macip.eth_tag_id, pnt, 4);
          p.u.prefix_evpn.u.prefix_macip.eth_tag_id = ntohl(p.u.prefix_evpn.u.prefix_macip.eth_tag_id);
          pnt += 4;
        }
      if (route_type == EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
        {
          p.family = AF_L2VPN;
          p.prefixlen = L2VPN_MCAST_PREFIX_LEN;
          memcpy(&p.u.prefix_evpn.u.prefix_imethtag.eth_tag_id, pnt, 4);
          p.u.prefix_evpn.u.prefix_imethtag.eth_tag_id =
            ntohl(p.u.prefix_evpn.u.prefix_imethtag.eth_tag_id);
          pnt += 4;
          p.u.prefix_evpn.u.prefix_imethtag.ip_len = *pnt++;
          if (p.u.prefix_evpn.u.prefix_imethtag.ip_len != IPV4_MAX_BITLEN &&
              p.u.prefix_evpn.u.prefix_imethtag.ip_len != IPV6_MAX_BITLEN)
            {
              zlog_err ("invalid ip length %d in RT3 NLRI",
                         p.u.prefix_evpn.u.prefix_imethtag.ip_len);
              return -1;
            }
          else
            {
              int byte_len = 4;

              if (p.u.prefix_evpn.u.prefix_imethtag.ip_len != IPV4_MAX_BITLEN)
                byte_len = 16;
              if (pnt + byte_len > lim)
                {
                  zlog_err ("not enough bytes for Router's IP address in RT3 NLRI?");
                  return -1;
                }
            }
          if (p.u.prefix_evpn.u.prefix_imethtag.ip_len == IPV4_MAX_BITLEN)
            {
              memcpy(&p.u.prefix_evpn.u.prefix_imethtag.ip.in4,
                     pnt, 4);
              pnt += 4;
            }
          else
            {
              memcpy(&p.u.prefix_evpn.u.prefix_imethtag.ip.in6,
                     pnt, 16);
              pnt += 16;
            }
        }
      else if (route_type == EVPN_MACIP_ADVERTISEMENT)
        {
          /* MAC address len in bits */
          p.u.prefix_evpn.u.prefix_macip.mac_len = *pnt++;

          if (p.u.prefix_evpn.u.prefix_macip.mac_len != 8*ETHER_ADDR_LEN)
            {
              zlog_err ("invalid mac length %d in RT2 NLRI, should be 48",
                         p.u.prefix_evpn.u.prefix_macip.mac_len);
              return -1;
            }

          /* MAC address */
          memcpy(&p.u.prefix_evpn.u.prefix_macip.mac, pnt, ETHER_ADDR_LEN);
          pnt += ETHER_ADDR_LEN;

          /* IP Address lenght in bits */
          p.u.prefix_evpn.u.prefix_macip.ip_len = *pnt++;
          if (p.u.prefix_evpn.u.prefix_macip.ip_len == IPV4_MAX_PREFIXLEN)
            {
              memcpy (&p.u.prefix_evpn.u.prefix_macip.ip.in4, pnt, 4);
              pnt += 4;
              p.prefixlen = L2VPN_MAX_PREFIXLEN - IPV6_MAX_PREFIXLEN + IPV4_MAX_PREFIXLEN;
            }
          else if (p.u.prefix_evpn.u.prefix_macip.ip_len == IPV6_MAX_PREFIXLEN)
            {
              memcpy (&p.u.prefix_evpn.u.prefix_macip.ip.in6, pnt, 16);
              pnt += 16;
              p.prefixlen = L2VPN_MAX_PREFIXLEN;
            }
          else if (p.u.prefix_evpn.u.prefix_macip.ip_len == 0)
            p.prefixlen = L2VPN_MAX_PREFIXLEN - IPV6_MAX_PREFIXLEN + IPV4_MAX_PREFIXLEN;
          else
            {
              zlog_err ("invalid IP length %d in RT2 NLRI, should be 0, 32 or 128",
                         p.u.prefix_evpn.u.prefix_macip.ip_len);
              return -1;
            }
	  p.prefixlen += 8; /* adjust prefix length with route type */
        }
      else if (route_type == EVPN_IP_PREFIX)
        {
          memcpy(&evpn.eth_t_id, pnt, 4);
          evpn.eth_t_id = ntohl(evpn.eth_t_id);
          pnt += 4;

           /* Fetch prefix length. */
          p.prefixlen = *pnt++;

          if (p.prefixlen > 128)
            {
              zlog_err ("invalid prefixlen %d in EVPN NLRI?", p.prefixlen);
              return -1;
            }
          /* determine IPv4 or IPv6 prefix */
          if(route_length - 4 - 10 - 8 - 3 /* label to be read */ >= 32)
            {
              p.family = AF_INET6;
              memcpy (&p.u.prefix, pnt, 16);
              pnt += 16;
              memcpy(&evpn.gw_ip.ipv6, pnt, 16);
              pnt += 16;
            }
          else
            {
              p.family = AF_INET;
              memcpy (&p.u.prefix, pnt, 4);
              pnt += 4;
              memcpy(&evpn.gw_ip.ipv4, pnt, 4);
              pnt += 4;
            }
        }

      if (route_type != EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
        {
          /* Fetch Label */
          if (pnt + 3 > lim)
            {
               zlog_err ("not enough bytes for Label left in NLRI?");
               return -1;
            }
          labels[0] = (pnt[0] << 16) + (pnt[1] << 8) + pnt[2];
          nlabels = 1;
          pnt += 3;
        }
      if (route_type == EVPN_MACIP_ADVERTISEMENT)
        {
          if ((pnt - route_length) != pnt2 && 
              (pnt + 3 - route_length) != pnt2)
            {
              zlog_err ("Route Type 2, NLRI length mismatch %d observed %d", route_length, (int)(pnt - pnt2));
              return -1;
            }
          if ( (pnt + 3 - route_length) == pnt2)
            {
              if (pnt + 3 > lim)
                {
                  zlog_err("not enough bytes for Label#2 left in NLRI");
                  return -1;
                }
              labels[1] = (pnt[0] << 16) + (pnt[1] << 8) + pnt[2];
              nlabels = 2;
              pnt+=3;
            }
        }
      else
        {
          if((pnt - route_length != pnt2))
            {
              zlog_err ("Route Type %u, NLRI length mismatch %d observed %ld)",
                        route_type, route_length, pnt - pnt2);
              return -1;
            }
        }
      if (route_type == EVPN_ETHERNET_AUTO_DISCOVERY)
        {
          /* EVPN RT1 encode vni in label. encoding uses full 24 bits */
          if (p.u.prefix_evpn.u.prefix_macip.eth_tag_id == MAX_ET && (labels[0] >> 4) == 0)
            evpn.auto_discovery_type = EVPN_ETHERNET_AD_PER_ESI;
          else if (p.u.prefix_evpn.u.prefix_macip.eth_tag_id == 0)
            evpn.auto_discovery_type = EVPN_ETHERNET_AD_PER_EVI;
          else
            {
              plog_err (peer->log,
                        "%s [Error] Update packet error / EVPN"
                        " (Auto Discovery with eth tag %08x and MPLS label %d not supported)",
                        peer->host, p.u.prefix_evpn.u.prefix_macip.eth_tag_id, labels[0]);
              return -1;
            }
        }

      if (!withdraw)
        {
          bgp_update (peer, &p, attr, AFI_L2VPN, SAFI_EVPN,
                      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd,
                      labels, nlabels, 0, &evpn);
        }
      else
        {
          bgp_withdraw (peer, &p, attr, AFI_L2VPN, SAFI_EVPN,
                        ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
                        &prd, labels, nlabels, &evpn);
        }
    }

  /* Packet length consistency check. */
  if (pnt != lim)
    return -1;

  return 0;
}

#define BGP_SHOW_SCODE_HEADER "Status codes: s suppressed, d damped, "\
			      "h history, * valid, > best, = multipath,%s"\
		"              i internal, r RIB-failure, S Stale, R Removed%s"
#define BGP_SHOW_OCODE_HEADER "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s"
#define BGP_SHOW_HEADER "   Network          Next Hop            Metric LocPrf Weight Path%s"
static int
show_adj_route_evpn (struct vty *vty, struct peer *peer, struct prefix_rd *prd, int in)
{
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  int rd_header;
  int header1 = 1;
  int header2 = 1;
  struct bgp_adj_in *ain;
  struct bgp_adj_out *adj;
  unsigned long output_count;
  char buf[RD_ADDRSTRLEN];
  char *ptr;

  output_count = 0;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (rn = bgp_table_top (bgp->rib[AFI_L2VPN][SAFI_EVPN]); rn;
       rn = bgp_route_next (rn))
    {
      if (prd && memcmp (&(rn->p).u.val, prd->val, 8) != 0)
        continue;

      if ((table = rn->info) != NULL)
        {
          rd_header = 1;

          for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
            if (in)
              {
                for (ain = rm->adj_in; ain; ain = ain->next)
                  if (ain->peer == peer)
                    {
                      if (header1)
                        {
                          vty_out (vty, "BGP table version is 0, local router ID is %s%s", inet_ntoa (bgp->router_id), VTY_NEWLINE);
                          vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                          vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                          header1 = 0;
                        }
                      if (header2)
                        {
                          vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
                          header2 = 0;
                        }
                      if (rd_header)
                        {
                          ptr = prefix_rd2str ((struct prefix_rd *)&(rn->p), buf, RD_ADDRSTRLEN);

                          vty_out (vty, "Route Distinguisher: ");
                          if(ptr)
                            vty_out (vty, "%s", buf);
                          else
                            vty_out (vty, "<unknown>");
                          vty_out (vty, "%s", VTY_NEWLINE);
                          rd_header = 0;
                        }
                      if (ain->attr)
                        {
                          route_vty_out_tmp (vty, &rm->p, ain->attr, SAFI_EVPN);
                          output_count++;
                        }
                    }
              }
            else
              {
                for (adj = rm->adj_out; adj; adj = adj->next)
                  if (adj->peer == peer)
                    {
                      if (header1)
                        {
                          vty_out (vty, "BGP table version is 0, local router ID is %s%s", inet_ntoa (bgp->router_id), VTY_NEWLINE);
                          vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                          vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                          header1 = 0;
                        }
                      if (CHECK_FLAG (rm->flags, BGP_INFO_VPN_HIDEN))
			return CMD_SUCCESS;
                      if (rd_header)
                        {
                          ptr = prefix_rd2str ((struct prefix_rd *)rn->p.u.val, buf, RD_ADDRSTRLEN);

                          vty_out (vty, "Route Distinguisher: ");
                          if(ptr)
                            vty_out (vty, "%s", buf);
                          else
                            vty_out (vty, "<unknown>");
                          vty_out (vty, "%s", VTY_NEWLINE);
                          rd_header = 0;
                        }
                      if (header2)
                        {
                          vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
                          header2 = 0;
                        }
                      if (adj->attr)
                        {
                          route_vty_out_tmp (vty, &rm->p, adj->attr, SAFI_EVPN);
                          output_count++;
                        }
                    }
              }
        }
    }

  if (output_count != 0)
    vty_out (vty, "%sTotal number of prefixes %ld%s",
	     VTY_NEWLINE, output_count, VTY_NEWLINE);

  return CMD_SUCCESS;
}
#undef BGP_SHOW_SCODE_HEADER
#undef BGP_SHOW_OCODE_HEADER
#undef BGP_SHOW_HEADER

enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_neighbor,
  bgp_show_type_cidr_only,
  bgp_show_type_prefix_longer,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact,
  bgp_show_type_hiddentoo
};

#define SHOW_DISPLAY_STANDARD 0
#define SHOW_DISPLAY_TAGS 1
#define SHOW_DISPLAY_OVERLAY 2

static int
bgp_show_ethernet_vpn (struct vty *vty, struct prefix_rd *prd, enum bgp_show_type type,
		   void *output_arg, int option)
{
  afi_t afi = AFI_L2VPN;
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  int rd_header;
  int header = 1;
  char v4_header[] = "   Network          Next Hop            Metric LocPrf Weight Path%s";
  char v4_header_tag[] = "   Network          Next Hop      In tag/Out tag%s";
  char v4_header_overlay[] = "   Network          Next Hop      EthTag    Overlay Index   RouterMac%s";

  unsigned long output_count = 0;
  unsigned long total_count  = 0;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  for (rn = bgp_table_top (bgp->rib[afi][SAFI_EVPN]); rn; rn = bgp_route_next (rn))
    {
      if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
	continue;

      if ((table = rn->info) != NULL)
	{
	  rd_header = 1;

	  for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
	    for (ri = rm->info; ri; ri = ri->next)
	      {
                total_count++;
		if ((type != bgp_show_type_hiddentoo)
                    && CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN))
                  continue;
		if (type == bgp_show_type_neighbor)
		  {
		    union sockunion *su = output_arg;

		    if (ri->peer->su_remote == NULL || ! sockunion_same(ri->peer->su_remote, su))
		      continue;
		  }
		if (header)
		  {
		    if (option == SHOW_DISPLAY_TAGS)
		      vty_out (vty, v4_header_tag, VTY_NEWLINE);
		    else if (option == SHOW_DISPLAY_OVERLAY)
		      vty_out (vty, v4_header_overlay, VTY_NEWLINE);
		    else
		      {
			vty_out (vty, "BGP table version is 0, local router ID is %s%s",
				 inet_ntoa (bgp->router_id), VTY_NEWLINE);
			vty_out (vty, "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal%s",
				 VTY_NEWLINE);
			vty_out (vty, "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s",
				 VTY_NEWLINE, VTY_NEWLINE);
			vty_out (vty, v4_header, VTY_NEWLINE);
		      }
		    header = 0;
		  }

		if (rd_header)
		  {
		    u_int16_t type;
		    struct rd_as rd_as;
		    struct rd_ip rd_ip;
		    u_char *pnt;

		    pnt = rn->p.u.val;

		    /* Decode RD type. */
		    type = decode_rd_type (pnt);
		    /* Decode RD value. */
		    if (type == RD_TYPE_AS)
		      decode_rd_as (pnt + 2, &rd_as);
		    else if (type == RD_TYPE_AS4)
		      decode_rd_as4 (pnt + 2, &rd_as);
		    else if (type == RD_TYPE_IP)
		      decode_rd_ip (pnt + 2, &rd_ip);

		    vty_out (vty, "Route Distinguisher: ");

		    if (type == RD_TYPE_AS)
		      vty_out (vty, "as2 %u:%d", rd_as.as, rd_as.val);
		    else if (type == RD_TYPE_AS4)
		      vty_out (vty, "as4 %u:%d", rd_as.as, rd_as.val);
		    else if (type == RD_TYPE_IP)
		      vty_out (vty, "ip %s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
		    vty_out (vty, "%s", VTY_NEWLINE);
		    rd_header = 0;
		  }
	        if (option == SHOW_DISPLAY_TAGS)
		  route_vty_out_tag (vty, &rm->p, ri, 0, SAFI_EVPN);
	        else if (option == SHOW_DISPLAY_OVERLAY)
		  route_vty_out_overlay (vty, &rm->p, ri, 0);
                else
                  route_vty_out (vty, &rm->p, ri, 0, SAFI_EVPN);
                output_count++;
	      }
        }
    }

  if (output_count == 0)
    {
        vty_out (vty, "No prefixes displayed, %ld exist%s", total_count, VTY_NEWLINE);
    }
  else
    vty_out (vty, "%sDisplayed %ld out of %ld total prefixes%s",
	     VTY_NEWLINE, output_count, total_count, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_l2vpn_evpn_all,
       show_bgp_l2vpn_evpn_all_cmd,
       "show bgp l2vpn evpn all",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all EVPN NLRIs\n")
{
  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_normal, NULL,
                                SHOW_DISPLAY_STANDARD);
}

DEFUN (show_bgp_l2vpn_evpn_all_hidden,
       show_bgp_l2vpn_evpn_all_hidden_cmd,
       "show bgp l2vpn evpn all hidden",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display VPN NLRI specific information\n"
       "Also display entries with non matching VRFs")
{
  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_hiddentoo, NULL, SHOW_DISPLAY_STANDARD);
}

DEFUN (show_bgp_evpn_rd,
       show_bgp_evpn_rd_cmd,
       "show bgp evpn rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       BGP_STR
       "Display EVPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_ethernet_vpn (vty, &prd, bgp_show_type_normal, NULL,
                                SHOW_DISPLAY_STANDARD);
}

ALIAS (show_bgp_evpn_rd,
       show_bgp_l2vpn_evpn_rd_cmd,
       "show bgp l2vpn evpn rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")

DEFUN (show_bgp_l2vpn_evpn_all_tags,
       show_bgp_l2vpn_evpn_all_tags_cmd,
       "show bgp l2vpn evpn all tags",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all EVPN NLRIs\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_normal, NULL,
                                SHOW_DISPLAY_TAGS);
}

DEFUN (show_bgp_l2vpn_evpn_rd_tags,
       show_bgp_l2vpn_evpn_rd_tags_cmd,
       "show bgp l2vpn evpn rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_ethernet_vpn (vty, &prd, bgp_show_type_normal, NULL,
                                SHOW_DISPLAY_TAGS);
}

DEFUN (show_bgp_l2vpn_evpn_all_overlay,
       show_bgp_l2vpn_evpn_all_overlay_cmd,
       "show bgp l2vpn evpn all overlay",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all EVPN NLRIs\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_normal, NULL,
                                SHOW_DISPLAY_OVERLAY);
}

DEFUN (show_bgp_evpn_rd_overlay,
       show_bgp_evpn_rd_overlay_cmd,
       "show bgp evpn rd ASN:nn_or_IP-address:nn overlay",
       SHOW_STR
       BGP_STR
       "Display EVPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Display BGP Overlay information\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_ethernet_vpn (vty, &prd, bgp_show_type_normal, NULL,
                                SHOW_DISPLAY_OVERLAY);
}

ALIAS (show_bgp_evpn_rd_overlay,
       show_bgp_l2vpn_evpn_rd_overlay_cmd,
       "show bgp l2vpn evpn rd ASN:nn_or_IP-address:nn overlay",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "Display BGP Overlay information\n")

DEFUN (show_bgp_l2vpn_evpn_all_neighbor_routes,
       show_bgp_l2vpn_evpn_all_neighbor_routes_cmd,
       "show bgp l2vpn evpn all neighbors A.B.C.D routes",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all EVPN NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  union sockunion su;
  struct peer *peer;
  int ret;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_neighbor, &su,
                                SHOW_DISPLAY_STANDARD);
}

DEFUN (show_bgp_l2vpn_evpn_all_neighbor_received_routes,
       show_bgp_l2vpn_evpn_all_neighbor_received_routes_cmd,
       "show bgp l2vpn evpn all neighbors A.B.C.D received-routes",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all EVPN NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes received from a BGP neighbor\n")
{
  int ret;
  struct peer *peer;
  union sockunion su;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_evpn (vty, peer, NULL, 1);
}


DEFUN (show_bgp_l2vpn_evpn_rd_neighbor_routes,
       show_bgp_l2vpn_evpn_rd_neighbor_routes_cmd,
       "show bgp l2vpn evpn rd ASN:nn_or_IP-address:nn neighbors A.B.C.D routes",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  int ret;
  union sockunion su;
  struct peer *peer;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_ethernet_vpn (vty, &prd, bgp_show_type_neighbor, &su,
                                SHOW_DISPLAY_STANDARD);
}

DEFUN (show_bgp_l2vpn_evpn_all_neighbor_advertised_routes,
       show_bgp_l2vpn_evpn_all_neighbor_advertised_routes_cmd,
       "show bgp l2vpn evpn all neighbors A.B.C.D advertised-routes",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all EVPN NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  int ret;
  struct peer *peer;
  union sockunion su;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_evpn (vty, peer, NULL, 0);
}

DEFUN (show_bgp_l2vpn_evpn_rd_neighbor_advertised_routes,
       show_bgp_l2vpn_evpn_rd_neighbor_advertised_routes_cmd,
       "show bgp l2vpn evpn rd ASN:nn_or_IP-address:nn neighbors A.B.C.D advertised-routes",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  int ret;
  struct peer *peer;
  struct prefix_rd prd;
  union sockunion su;

  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_evpn (vty, peer, &prd, 0);
}

DEFUN (show_bgp_l2vpn_evpn_rd_neighbor_received_routes,
       show_bgp_l2vpn_evpn_rd_neighbor_received_routes_cmd,
       "show bgp l2vpn evpn rd ASN:nn_or_IP-address:nn neighbors A.B.C.D received-routes",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all EVPN NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes received from a BGP neighbor\n")
{
  int ret;
  struct peer *peer;
  struct prefix_rd prd;
  union sockunion su;

  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_evpn (vty, peer, &prd, 1);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (evpnrt5_network,
       evpnrt5_network_cmd,
       "network A.B.C.D/M rd ASN:nn_or_IP-address:nn ethtag WORD label WORD esi WORD gwip A.B.C.D routermac WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "Ethernet Tag\n"
       "Ethernet Tag Value\n"
       "BGP label\n"
       "label value\n"
       "Ethernet Segment Identifier\n"
       "ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
       "Gateway IP\n"
       "Gateway IP ( A.B.C.D )\n"
       "Router Mac Ext Comm\n"
       "Router Mac address Value ( aa:bb:cc:dd:ee:ff format)\n")
{
  return bgp_static_set_safi (SAFI_EVPN, vty, argv[0], argv[1], argv[3], NULL, 
                              argv[4], argv[5], argv[2], argv[6], NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_evpnrt5_network,
       no_evpnrt5_network_cmd,
       "no network A.B.C.D/M rd ASN:nn_or_IP-address:nn ethtag WORD label WORD esi WORD gwip A.B.C.D",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "Ethernet Tag\n"
       "Ethernet Tag Value\n"
       "BGP label\n"
       "label value\n"
       "Ethernet Segment Identifier\n"
       "ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
       "Gateway IP\n"
       "Gateway IP ( A.B.C.D )\n")
{
  return bgp_static_unset_safi (SAFI_EVPN, vty, argv[0], argv[1], 
                                argv[3], argv[4], argv[5], argv[2], NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (evpnrt2_network,
       evpnrt2_network_cmd,
       "network A.B.C.D rd ASN:nn_or_IP-address:nn ethtag WORD mac WORD esi WORD l2label WORD l3label WORD  routermac WORD",
       "Specify a host address to announce via BGP\n"
       "IP host 32 bits, e.g., 10.1.2.32\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "Ethernet Tag\n"
       "Ethernet Tag Value\n"
       "Mac Address Associated\n"
       "Mac address Value ( aa:bb:cc:dd:ee:ff format)\n"
       "Ethernet Segment Identifier\n"
       "ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
       "BGP Layer 2 label\n"
       "label Layer 2 value\n"
       "BGP Layer 3 label\n"
       "label Layer 3 value\n"
       "Router Mac Ext Comm\n"
       "Router Mac address Value ( aa:bb:cc:dd:ee:ff format)\n")
{
  return bgp_static_set_safi (SAFI_EVPN, vty, argv[0], argv[1], argv[6], NULL, 
                              argv[4], NULL, argv[2], argv[7], argv[3], argv[5]);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_evpnrt2_network,
       no_evpnrt2_network_cmd,
       "no network A.B.C.D rd ASN:nn_or_IP-address:nn ethtag WORD mac WORD esi WORD",
       NO_STR
       "Specify a host address to announce via BGP\n"
       "IP host 32 bits, e.g., 10.1.2.32\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "Ethernet Tag\n"
       "Ethernet Tag Value\n"
       "Mac Address Associated\n"
       "Mac address Value ( aa:bb:cc:dd:ee:ff format)\n"
       "Ethernet Segment Identifier\n"
       "ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n")
{
  return bgp_static_unset_safi (SAFI_EVPN, vty, argv[0], argv[1], 
                                NULL, argv[4], NULL, argv[2], argv[3]);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (evpnrt3_network,
       evpnrt3_network_cmd,
       "network rt3 rd ASN:nn_or_IP-address:nn ethtag WORD routerip A.B.C.D",
       "Route type 3 messages\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "Ethernet Tag\n"
       "Ethernet Tag Value\n"
       "Router IP Address\n"
       "Router IP ( A.B.C.D )\n")
{
  return bgp_static_set_evpn_rt3 (vty, argv[0], argv[1], argv[2]);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_evpnrt3_network,
       no_evpnrt3_network_cmd,
       "no network rt3 rd ASN:nn_or_IP-address:nn ethtag WORD routerip A.B.C.D",
       NO_STR
       "Route type 3 messages\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "Ethernet Tag\n"
       "Ethernet Tag Value\n"
       "Router IP Address\n"
       "Router IP ( A.B.C.D )\n")
{
  return bgp_static_unset_evpn_rt3 (vty, argv[0], argv[1], argv[2]);
}

void
bgp_ethernetvpn_init (void)
{
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_hidden_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_rd_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_rd_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_rd_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_overlay_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_rd_overlay_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_rd_overlay_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_rd_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_rd_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_rd_neighbor_received_routes_cmd);
  install_element (BGP_EVPN_NODE, &no_evpnrt5_network_cmd);
  install_element (BGP_EVPN_NODE, &evpnrt5_network_cmd);
  install_element (BGP_EVPN_NODE, &no_evpnrt2_network_cmd);
  install_element (BGP_EVPN_NODE, &evpnrt2_network_cmd);
  install_element (BGP_EVPN_NODE, &no_evpnrt3_network_cmd);
  install_element (BGP_EVPN_NODE, &evpnrt3_network_cmd);
}

int
peer_evpn_auto_discovery_set (struct peer *peer, struct bgp_vrf *vrf, struct attr * attr,
                              struct eth_segment_id *esi, u_int32_t ethtag,
                              struct prefix *nexthop, u_int32_t label)
{
  /* Adress family must be activated.  */
  if (! peer->afc[AFI_L2VPN][SAFI_EVPN])
    return BGP_ERR_PEER_INACTIVE;

  /* https://tools.ietf.org/html/draft-ietf-bess-evpn-overlay-04#5.1.3
   * In EVPN, an MPLS label is distributed by the egress PE via the EVPN control plane
   * MAC Advertisement Ethernet AD per EVI ... is used to carry the VNI.
   * the entire 24-bit field is used to encode the VNI value.
   */
  bgp_auto_discovery_evpn (peer, vrf, attr, esi, ethtag, nexthop, label, 0);

  return 0;
}

int
peer_evpn_auto_discovery_unset (struct peer *peer, struct bgp_vrf *vrf, struct attr * attr,
                                struct eth_segment_id *esi, u_int32_t ethtag,
                                u_int32_t label)
{
  /* Adress family must be activated.  */
  if (! peer->afc[AFI_L2VPN][SAFI_EVPN])
    return BGP_ERR_PEER_INACTIVE;

  bgp_auto_discovery_evpn (peer, vrf, attr, esi, ethtag, NULL, (label << 4) | 1, 1);

  return 0;
}

/* called when receiving BGP A/D from peer or setting locally A/D */
struct bgp_evpn_ad *bgp_evpn_process_auto_discovery(struct peer *peer,
                                     struct prefix_rd *prd,
                                     struct bgp_route_evpn *evpn,
                                     struct prefix *p,
                                     u_int32_t label,
                                     struct attr *attr)
{
  struct bgp_evpn_ad *evpn_ad, *ad;
  struct bgp_vrf *vrf = NULL;
  struct listnode *node;
  /* lookup current AD matching RD and ESI
   * if found, reuse it:
   *      o if previous was withdraw and current is append
   *          -> update && directly call (current)
   *      o if previous was append and current is withdraw
   *          -> update && directly call (current)
   *      o if both withdraw or append, the two rt lists must be investigated
   * if not found, create new entry
   */
  /* check vrf configured */
  for (ALL_LIST_ELEMENTS_RO(peer->bgp->vrfs, node, vrf))
    {
      if (0 == prefix_rd_cmp(prd, &vrf->outbound_rd))
        {
          break;
        }
    }
  if (vrf == NULL) {
    char rd_str[RD_ADDRSTRLEN];
    prefix_rd2str(prd, rd_str, sizeof(rd_str));
    zlog_debug ("RD %s from %s received in AD. Unconfigured. Ignoring", rd_str, peer->host);
    return NULL;
  }
  /* Check if previous AD received */
  for (ALL_LIST_ELEMENTS_RO(vrf->rx_evpn_ad, node, ad))
    {
      if (0 == bgp_evpn_ad_cmp(ad, peer, &vrf->outbound_rd,
                               &evpn->eth_s_id, p->u.prefix_evpn.u.prefix_macip.eth_tag_id))
        break;
    }
  if (ad)
    {
      if ((ad->label != label) &&
          !(evpn->auto_discovery_type | EVPN_ETHERNET_MP_UNREACH))
        ad->label = label;
      /* XXX case list of RT changed */
      if (BGP_DEBUG (events, EVENTS))
        {
          char buf[AD_STR_MAX_SIZE];
          bgp_evpn_ad_display (ad, buf, AD_STR_MAX_SIZE);
          zlog_debug ("%s from %s received", buf, ad->peer->host);
        }
      return ad;
    }
  evpn_ad = bgp_evpn_ad_new_from_update(peer, prd, evpn, p, label, attr);

  if (!evpn_ad)
    {
      zlog_err("Not enough memory to record EVPN Auto-Discovery from peer %s",
               peer->host);
      return NULL;
    }
  if (BGP_DEBUG (events, EVENTS))
    {
      char buf[AD_STR_MAX_SIZE];
      bgp_evpn_ad_display (evpn_ad, buf, AD_STR_MAX_SIZE);
      zlog_debug ("%s from %s received and stored", buf, evpn_ad->peer->host);
    }
  listnode_add (vrf->rx_evpn_ad, evpn_ad);
  return evpn_ad;
}

void bgp_vrf_peer_notification (struct peer *peer, int down)
{
  struct bgp_evpn_ad *ad;
  struct listnode *node, *node2, *nnode2;
  struct bgp_vrf *vrf;

  if (peer->bgp == NULL || peer->bgp->vrfs == NULL)
    return;
  for (ALL_LIST_ELEMENTS_RO(peer->bgp->vrfs, node, vrf))
    {
      for (ALL_LIST_ELEMENTS_RO(vrf->static_evpn_ad, node2, ad))
        {
          if (peer != ad->peer)
            continue;
          if (down)
            {
              ad->status = 1;
              continue;
            }
          if (ad->status != 0)
            {
              struct prefix nexthop;

              ad->status = 0;
              /* force sending XXX */
              if (ad->attr->extra->mp_nexthop_len == IPV4_MAX_BYTELEN)
                {
                  nexthop.family = AF_INET;
                  nexthop.prefixlen = IPV4_MAX_PREFIXLEN;
                  nexthop.u.prefix4 = ad->attr->extra->mp_nexthop_global_in;
                }
              else
                {
                  nexthop.family = AF_INET6;
                  nexthop.prefixlen = IPV6_MAX_PREFIXLEN;
                  memcpy (&nexthop.u.prefix6, &(ad->attr->extra->mp_nexthop_global), sizeof(struct in6_addr));
                }
              peer_evpn_auto_discovery_set (peer, vrf, ad->attr,
                                            &ad->eth_s_id, ad->eth_t_id,
                                            &nexthop,
                                            ad->label);
            }
        }
      /* flush */
      if(!down)
        continue;
      for (ALL_LIST_ELEMENTS(vrf->rx_evpn_ad, node2, nnode2, ad))
        {
          if (peer != ad->peer)
            continue;
          list_delete_node (vrf->rx_evpn_ad, node2);
          bgp_evpn_ad_free (ad);
        }
    }
}

/* propagates a change in the RT configured for each RD
 */
void
bgp_evpn_process_imports (struct bgp *bgp, struct bgp_evpn_ad *old, struct bgp_evpn_ad *new)
{
  struct ecommunity *old_ecom = NULL, *new_ecom = NULL;
  struct bgp_vrf *vrf;
  struct listnode *node;
  size_t i, j;
  struct bgp_evpn_ad *ri = NULL;


  if (old && old->attr && old->attr->extra)
    old_ecom = old->attr->extra->ecommunity;
  if (new && new->attr && new->attr->extra)
    new_ecom = new->attr->extra->ecommunity;

  if(new && !old)
    {
      ri = new;
    }
  else if(!new && old)
    {
      ri = old;
    }

  /*
   * if old present, for each export target
   * get the list of route target subscribers
   * if no new, then withdraw entries in all mentioned export rt
   * if new present, and new contains at least one previous export rt,
   * then export entries in all mentioned export rt
   */
  if (old_ecom)
    {
    for (i = 0; i < (size_t)old_ecom->size; i++)
      {
        struct bgp_rt_sub dummy, *rt_sub;
        uint8_t *val = old_ecom->val + 8 * i;
        uint8_t type = val[1];
        bool withdraw = true;

        if (type != ECOMMUNITY_ROUTE_TARGET)
          continue;

        memcpy(&dummy.rt, val, 8);
        rt_sub = hash_lookup (bgp->rt_subscribers, &dummy);
        if (!rt_sub)
          continue;

        if (new_ecom)
          {
            for (j = 0; j < (size_t)new_ecom->size; j++)
              if (!memcmp(new_ecom->val + j * 8, val, 8))
                {
                  withdraw = false;
                  break;
                }
          }
        for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
          {
            /* case ecom not present in new_ecom : remove associated ri
             * case ecom present in new_ecom : just update
             */
            bgp_evpn_process_auto_discovery_update_from_vrf(vrf, ri,
                                                            withdraw == false?ENTRIES_TO_ADD:ENTRIES_TO_REMOVE);
            bgp_evpn_process_auto_discovery_propagate(vrf, ri, withdraw == false?
                                                      ENTRIES_TO_ADD:ENTRIES_TO_REMOVE);
            if (withdraw != false)
              {
                bgp_evpn_process_auto_discovery_delete_from_vrf (vrf, ri);
              }
          }
      }
    }
  /* for each new export target,
   * get the list of route target subscribers
   * if old export target, and there is at least match
   * between old rt and new rt, then do nothing
   * if there is no match, or if this is a new RT with no old RT,
   * then the route target subscribers are feeded
   */
  if (new_ecom)
    for (i = 0; i < (size_t)new_ecom->size; i++)
      {
        struct bgp_rt_sub dummy, *rt_sub;
        uint8_t *val = new_ecom->val + 8 * i;
        uint8_t type = val[1];
        bool found = false;

        if (type != ECOMMUNITY_ROUTE_TARGET)
          continue;

        memcpy(&dummy.rt, val, 8);
        rt_sub = hash_lookup (bgp->rt_subscribers, &dummy);
        if (!rt_sub)
          continue;

        if (old_ecom)
          for (j = 0; j < (size_t)old_ecom->size; j++)
            if (!memcmp(old_ecom->val + j * 8, val, 8))
              {
                found = true;
                break;
              }

        if (!found)
          for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
            {
              bgp_evpn_process_auto_discovery_update_from_vrf(vrf, ri, ENTRIES_TO_ADD);
              bgp_evpn_process_auto_discovery_propagate(vrf, ri, ENTRIES_TO_ADD);
            }
      }

  return;
}

/*
 * for a new entry in VRF RIB, check for previous A/D received
 * if A/D matches, a new entry will be created for the peer that sent the A/D
 */
void
bgp_evpn_auto_discovery_new_entry (struct bgp_vrf *vrf,
                                   struct bgp_info *ri)
{
  struct listnode *node;
  struct bgp_evpn_ad *ad;
  struct bgp_node *rn;
  struct bgp_info *ri_from_ad;

  rn = ri->net;

  for (ALL_LIST_ELEMENTS_RO(vrf->import_processing_evpn_ad, node, ad))
    {
      if (ri->peer == ad->peer)
        continue;
      if (ad->eth_t_id != MAX_ET &&
         rn->p.u.prefix_evpn.u.prefix_macip.eth_tag_id != ad->eth_t_id)
        continue;
      if (!ri->attr || !ri->attr->extra || !ri->extra)
        continue;
      if (memcmp(&(ad->eth_s_id), &(ri->attr->extra->evpn_overlay.eth_s_id),
                sizeof(struct eth_segment_id)))
        continue;
      /* case AD per EVI */
      if (ad->eth_t_id != MAX_ET && ad->label != ri->extra->labels[0])
        continue;
      /* an a/d matched. duplicate entry for ad->peer 
       * if mp_reach a/d */
      if (!ad->attr)
        continue;
      {
        struct bgp_info temp;
        temp.attr = ad->attr;
        if (0 == bgp_info_nexthop_cmp (&temp, ri))
        {
          zlog_err("A-D nexthop already has an entry with same NH");
          continue;
        }
      }
      if (BGP_DEBUG (events, EVENTS))
        {
          char buf[AD_STR_MAX_SIZE];
          bgp_evpn_ad_display (ad, buf, AD_STR_MAX_SIZE);
          zlog_debug ("%s : duplicating new entry", buf);
        }
      ri_from_ad = bgp_evpn_new_bgp_info_from_ad (ri, ad);
      bgp_vrf_process_entry(ri_from_ad, ROUTE_INFO_TO_ADD,
                            AFI_L2VPN, SAFI_EVPN);
    }
  /* no route processing, since called function will do it */
  /* continue parsing for other ads interested */
}
