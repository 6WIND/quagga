/* MPLS-Labeled Unicast
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

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_lu.h"
#include "bgpd/bgp_packet.h"

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

int
bgp_nlri_parse_lu (struct peer *peer, struct attr *attr, 
                    struct bgp_nlri *packet)
{
  u_char *pnt, *pnt2;
  u_char *lim, *lim2;
  struct prefix p;
  int psize = 0;
  int prefixlen;
  uint32_t labels[BGP_MAX_LABELS];
  size_t nlabels;

  /* Check peer status. */
  if (peer->status != Established)
    return 0;
  
  pnt = packet->nlri;
  lim = pnt + packet->length;
#define VPN_LABEL_SIZE 3
#define VPN_PREFIXLEN_MIN_BYTES (VPN_LABEL_SIZE) /* label + RD */
  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      /* Fetch prefix length. */
      prefixlen = *pnt++;
      p.family = afi2family (packet->afi);
      psize = PSIZE (prefixlen);
      /* sanity check against packet data */
      if (prefixlen < VPN_PREFIXLEN_MIN_BYTES*8)
        {
          plog_err (peer->log, 
                    "%s [Error] Update packet error / LUv4"
                     " (prefix length %d less than LUv4 min length)",
                    peer->host, prefixlen);
          return -1;
        }
      if ((pnt + psize) > lim)
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error / LUv4"
                    " (psize %u exceeds packet size (%u)",
                    peer->host, 
                    prefixlen, (uint)(lim-pnt));
          continue;
        }
      lim2 = pnt + psize;
      nlabels = 0;
      pnt2 = pnt;
      while (1)
        {
          if (pnt2 + VPN_LABEL_SIZE > lim2)
            {
              zlog_err ("label stack running past prefix length");
              return -1;
            }
          uint32_t label = (pnt2[0] << 16) + (pnt2[1] << 8) + pnt2[2];
          pnt2 += VPN_LABEL_SIZE;
          if (nlabels == BGP_MAX_LABELS)
            {
              zlog_err ("label stack too deep");
              return -1;
            }
          labels[nlabels++] = label;
#if 0
          if (label == 0 || label == 0x800000 || label & 0x000001)
              break;
#else
          break; /* ignore if BOT is set or not */
#endif
        }

      if ((psize - VPN_PREFIXLEN_MIN_BYTES - (nlabels - 1)*VPN_LABEL_SIZE) > (ssize_t) sizeof(p.u))
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error / VPNv4"
                    " (psize %u exceeds storage size (%zu)",
                    peer->host,
                    (unsigned int)(prefixlen - VPN_PREFIXLEN_MIN_BYTES*8 -
                                   (nlabels - 1)*VPN_LABEL_SIZE*8),
                    sizeof(p.u));
          continue;
        }
      /* Sanity check against max bitlen of the address family */
      if ((psize - VPN_PREFIXLEN_MIN_BYTES - (nlabels - 1)*VPN_LABEL_SIZE) > (unsigned int)prefix_blen (&p))
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error / VPNv4"
                    " (psize %u exceeds family (%u) max byte len %u)",
                    peer->host,
                    (unsigned int)(prefixlen - VPN_PREFIXLEN_MIN_BYTES*8
                                   - (nlabels - 1)*VPN_LABEL_SIZE*8),
                    p.family, (unsigned int) prefix_blen (&p));
          continue;
        }
      
      p.prefixlen = prefixlen - VPN_PREFIXLEN_MIN_BYTES*8 - (nlabels - 1)*VPN_LABEL_SIZE*8;
      memcpy (&p.u.prefix, pnt + VPN_PREFIXLEN_MIN_BYTES + (nlabels - 1)*VPN_LABEL_SIZE, 
              psize - VPN_PREFIXLEN_MIN_BYTES - (nlabels - 1)*VPN_LABEL_SIZE);

      if (attr)
        bgp_update (peer, &p, attr, packet->afi, SAFI_LABELED_UNICAST,
                    ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, labels, nlabels, 0, NULL);
      else
        bgp_withdraw (peer, &p, attr, packet->afi, SAFI_MPLS_VPN,
                      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, labels, nlabels, NULL);
    }
  /* Packet length consistency check. */
  if (pnt != lim)
    {
      plog_err (peer->log,
                "%s [Error] Update packet error / VPNv4"
                " (%zu data remaining after parsing)",
                peer->host, lim - pnt);
      return -1;
    }
  
  return 0;
#undef VPN_PREFIXLEN_MIN_BYTES
#undef VPN_LABEL_SIZE
}

static int
bgp_show_lu(
    struct vty *vty,
    afi_t afi,
    struct prefix_rd *prd,
    enum bgp_show_type type,
    void *output_arg,
    int tags)
{
  struct bgp *bgp;
  struct bgp_node *rn;
  struct bgp_info *ri;
  int header = 1;
  char v4_header[] = "   Network          Next Hop            Metric LocPrf Weight Path%s";
  char v4_header_tag[] = "   Network          Next Hop      In tag/Out tag%s";

  unsigned long output_count = 0;
  unsigned long total_count  = 0;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  if ((afi != AFI_IP) && (afi != AFI_IP6))
    {
      vty_out (vty, "Afi %d not supported%s", afi, VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (rn = bgp_table_top (bgp->rib[afi][SAFI_LABELED_UNICAST]); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->next)
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
              if (tags)
                vty_out (vty, v4_header_tag, VTY_NEWLINE);
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
          if (tags)
            route_vty_out_tag (vty, &rn->p, ri, 0, SAFI_LABELED_UNICAST);
          else
            route_vty_out (vty, &rn->p, ri, 0, SAFI_LABELED_UNICAST);
          output_count++;
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

void peer_configure_label (struct peer *peer, afi_t afi, safi_t safi, int enable)
{
  struct peer_group *group;
  struct listnode *node, *nnode;
  uint32_t flag;

  if (afi == AFI_IP)
      flag = PEER_CONFIG_SENDLABEL_IPV4;
  else
      flag = PEER_CONFIG_SENDLABEL_IPV6;
  if (enable && (peer->config & flag))
        return;
  if (!enable && ( 0 == (peer->config & flag)))
    return;
  if (enable)
    peer->config |= flag;
  else
    peer->config &= ~flag;

  if (! CHECK_FLAG (peer->sflags, PEER_STATUS_GROUP))
    {
      if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->status))
        {
          peer->last_reset = PEER_DOWN_LOCAL_SEND_LABEL;
          bgp_notify_send (peer, BGP_NOTIFY_CEASE,
                           BGP_NOTIFY_CEASE_CONFIG_CHANGE);
        }
      else
        BGP_EVENT_ADD (peer, BGP_Stop);

      peer_afc_set (peer, afi, safi, enable);
      return ;
    }

  group = peer->group;
  for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
    {
      if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->status))
       {
         peer->last_reset = PEER_DOWN_LOCAL_SEND_LABEL;
         bgp_notify_send (peer, BGP_NOTIFY_CEASE,
                          BGP_NOTIFY_CEASE_CONFIG_CHANGE);
       }
      else
        BGP_EVENT_ADD (peer, BGP_Stop);
      peer_afc_set (peer, afi, safi, enable);
    }
  return;
}

DEFUN (no_neighbor_send_label,
       no_neighbor_send_label_cmd,
       NO_NEIGHBOR_CMD2 "send-label",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable Labeled Unicast for this Neighbor\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;
  peer_configure_label (peer, bgp_node_afi (vty), SAFI_LABELED_UNICAST, 0);
  return CMD_SUCCESS;
}

DEFUN (neighbor_send_label,
       neighbor_send_label_cmd,
       NEIGHBOR_CMD2 "send-label",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable Labeled Unicast for this Neighbor\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;
  peer_configure_label (peer, bgp_node_afi (vty), SAFI_LABELED_UNICAST, 1);
  return CMD_SUCCESS;
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (luv4_network,
       luv4_network_cmd,
       "network A.B.C.D/M tag WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_set_safi (SAFI_MPLS_VPN, vty, argv[0], NULL, argv[1], 
                              NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_luv4_network,
       no_luv4_network_cmd,
       "no network A.B.C.D/M tag WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_unset_safi (SAFI_MPLS_VPN, vty, argv[0], NULL, argv[1], 
                                NULL, NULL, NULL, NULL);
}

DEFUN (luv6_network,
       luv6_network_cmd,
       "network X:X::X:X/M tag WORD",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_set_safi (SAFI_MPLS_VPN, vty, argv[0], NULL, argv[1], 
                              NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_luv6_network,
       no_luv6_network_cmd,
       "no network X:X::X:X/M tag WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_unset_safi (SAFI_MPLS_VPN, vty, argv[0], NULL, argv[1],
                                NULL, NULL, NULL, NULL);
}

DEFUN (show_bgp_ipv4_lu,
       show_bgp_ipv4_lu_cmd,
       "show bgp ipv4 lu",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display Labeled Unicast specific information\n")
{
  return bgp_show_lu (vty, AFI_IP, NULL, bgp_show_type_normal, NULL, 0);
}

DEFUN (show_bgp_ipv6_lu,
       show_bgp_ipv6_lu_cmd,
       "show bgp ipv6 lu",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display Labeled Unicast specific information\n")
{
  return bgp_show_lu (vty, AFI_IP6, NULL, bgp_show_type_normal, NULL, 0);
}

DEFUN (show_bgp_ipv4_lu_tags,
       show_bgp_ipv4_lu_tags_cmd,
       "show bgp ipv4 lu tags",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display Labeled Unicast specific information\n")
{
  return bgp_show_lu (vty, AFI_IP, NULL, bgp_show_type_normal, NULL, 1);
}

DEFUN (show_bgp_ipv6_lu_tags,
       show_bgp_ipv6_lu_tags_cmd,
       "show bgp ipv6 lu tags",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display Labeled Unicast specific information\n")
{
  return bgp_show_lu (vty, AFI_IP6, NULL, bgp_show_type_normal, NULL, 1);
}

void
bgp_lu_init (void)
{
  install_element (BGP_IPV4_NODE, &neighbor_send_label_cmd);
  install_element (BGP_IPV6_NODE, &neighbor_send_label_cmd);
  install_element (BGP_IPV4_NODE, &no_neighbor_send_label_cmd);
  install_element (BGP_IPV6_NODE, &no_neighbor_send_label_cmd);
  install_element (BGP_NODE, &neighbor_send_label_cmd);
  install_element (BGP_NODE, &no_neighbor_send_label_cmd);
  install_element (BGP_IPV4_NODE, &luv4_network_cmd);
  install_element (BGP_IPV4_NODE, &no_luv4_network_cmd);
  install_element (BGP_IPV6_NODE, &luv6_network_cmd);
  install_element (BGP_IPV6_NODE, &no_luv6_network_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_lu_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_lu_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_lu_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_lu_tags_cmd);
}
