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
  u_char *pnt;
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
      route_length = *pnt++;
      /* simply ignore. goto next route type if any */
      if(route_type != EVPN_IP_PREFIX)
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

      if (route_type == EVPN_IP_PREFIX)
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
