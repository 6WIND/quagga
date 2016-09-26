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
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_evpn.h"

int
bgp_nlri_parse_evpn (struct peer *peer, struct attr *attr,
                     struct bgp_nlri *packet)
{
  u_char *pnt,*pnt2;
  u_char *lim;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp_route_evpn evpn;
  uint8_t route_type, route_length;
  uint32_t labels[BGP_MAX_LABELS];
  size_t nlabels;

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
      pnt2 = pnt;
      route_length = *pnt++;
      /* simply ignore. goto next route type if any */
      if(route_type != EVPN_IP_PREFIX && route_type != EVPN_MACIP_ADVERTISEMENT)
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

      /* Fetch ESI */
      if (pnt + 10 > lim)
        {
          zlog_err ("not enough bytes for ESI left in NLRI?");
          return -1;
        }
      memcpy(&evpn.eth_s_id.val, pnt, 10);
      pnt += 10;

      /* Fetch Ethernet Tag */
      if (pnt + 4 > lim)
        {
          zlog_err ("not enough bytes for Eth Tag left in NLRI?");
          return -1;
        }
      if (route_type == EVPN_MACIP_ADVERTISEMENT)
        {
          memcpy(&p.u.prefix_macip.eth_tag_id, pnt, 4);
          p.u.prefix_macip.eth_tag_id = ntohl(p.u.prefix_macip.eth_tag_id);
          pnt += 4;

          /* MAC address len in bits */
          p.family = AF_L2VPN;
          p.u.prefix_macip.mac_len = *pnt++;

          if (p.u.prefix_macip.mac_len != 8*ETHER_ADDR_LEN)
            {
              zlog_err ("invalid mac length %d in RT2 NLRI, should be 48",
                         p.u.prefix_macip.mac_len);
              return -1;
            }

          /* MAC address */
          memcpy(&p.u.prefix_macip.mac, pnt, ETHER_ADDR_LEN);
          pnt += ETHER_ADDR_LEN;

          /* IP Address lenght in bits */
          p.u.prefix_macip.ip_len = *pnt++;
          if (p.u.prefix_macip.ip_len == IPV4_MAX_PREFIXLEN)
            {
              p.prefixlen = L2VPN_IPV4_PREFIX_LEN;
              memcpy (&p.u.prefix_macip.ip.in4, pnt, 4);
              pnt += 4;
              p.prefixlen = L2VPN_MAX_PREFIXLEN - IPV6_MAX_PREFIXLEN + IPV4_MAX_PREFIXLEN;
            }
          else if (p.u.prefix_macip.ip_len == IPV6_MAX_PREFIXLEN)
            {
              p.prefixlen = L2VPN_IPV6_PREFIX_LEN;
              memcpy (&p.u.prefix_macip.ip.in6, pnt, 16);
              pnt += 16;
              p.prefixlen = L2VPN_MAX_PREFIXLEN;
            }
          else if (p.u.prefix_macip.ip_len == 0)
            p.prefixlen = L2VPN_MAX_PREFIXLEN - IPV6_MAX_PREFIXLEN + IPV4_MAX_PREFIXLEN;
          else
            {
              zlog_err ("invalid IP length %d in RT2 NLRI, should be 0, 32 or 128",
                         p.u.prefix_macip.ip_len);
              return -1;
            }
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

      /* Fetch Label */
      if (pnt + 3 > lim)
        {
          zlog_err ("not enough bytes for Label left in NLRI?");
          return -1;
        }
      labels[0] = (pnt[0] << 16) + (pnt[1] << 8) + pnt[2];
      nlabels = 1;

      pnt += 3;

      if (route_type == EVPN_MACIP_ADVERTISEMENT)
        {
          if (pnt + 3 > lim)
            {
              zlog_err ("not enough bytes for Label left in NLRI?");
              return -1;
            }
          labels[1] = (pnt[0] << 16) + (pnt[1] << 8) + pnt[2];
          nlabels = 2;

          pnt += 3;

          if((pnt - route_length != pnt2))
            {
              plog_err (peer->log,
                        "%s [Error] Update packet error / EVPN?"
                        " (NLRI length mismatch %d observed %d)",
                        peer->host, route_length, pnt - pnt2);
              return -1;
            }
        }

      if (attr)
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

static int
show_adj_route_evpn (struct vty *vty, struct peer *peer, struct prefix_rd *prd)
{
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct attr *attr;
  int rd_header;
  int header = 1;
  char v4_header[] = "   Network          Next Hop            Metric LocPrf Weight Path%s";

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (rn = bgp_table_top (bgp->rib[AFI_L2VPN][SAFI_EVPN]); rn;
       rn = bgp_route_next (rn))
    {
      if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
        continue;

      if ((table = rn->info) != NULL)
        {
          rd_header = 1;

          for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
            if ((attr = rm->info) != NULL)
              {
                if (header)
                  {
                    vty_out (vty, "BGP table version is 0, local router ID is %s%s",
                             inet_ntoa (bgp->router_id), VTY_NEWLINE);
                    vty_out (vty, "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal%s",
                             VTY_NEWLINE);
                    vty_out (vty, "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s",
                             VTY_NEWLINE, VTY_NEWLINE);
                    vty_out (vty, v4_header, VTY_NEWLINE);
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
                      vty_out (vty, "%u:%d", rd_as.as, rd_as.val);
                    else if (type == RD_TYPE_AS4)
                      vty_out (vty, "%u:%d", rd_as.as, rd_as.val);
                    else if (type == RD_TYPE_IP)
                      vty_out (vty, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);

                    vty_out (vty, "%s", VTY_NEWLINE);
                    rd_header = 0;
                  }
                route_vty_out_tmp (vty, &rm->p, attr, SAFI_MPLS_VPN);
              }
        }
    }
  return CMD_SUCCESS;
}

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
  bgp_show_type_community_list_exact
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

  return show_adj_route_evpn (vty, peer, NULL);
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

  return show_adj_route_evpn (vty, peer, &prd);
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
                              argv[4], argv[5], argv[2], argv[6]);
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
  return bgp_static_unset_safi (SAFI_EVPN, vty, argv[0], argv[1], argv[3], 
                                argv[4], argv[5], argv[2]);
}


void
bgp_ethernetvpn_init (void)
{
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_cmd);
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
  install_element (BGP_EVPN_NODE, &no_evpnrt5_network_cmd);
  install_element (BGP_EVPN_NODE, &evpnrt5_network_cmd);
}
