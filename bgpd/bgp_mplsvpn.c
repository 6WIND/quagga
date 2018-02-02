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

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_packet.h"

u_int16_t
decode_rd_type (u_char *pnt)
{
  u_int16_t v;
  
  v = ((u_int16_t) *pnt++ << 8);
  v |= (u_int16_t) *pnt;
  return v;
}

/* type == RD_TYPE_AS */
void
decode_rd_as (u_char *pnt, struct rd_as *rd_as)
{
  rd_as->as = (u_int16_t) *pnt++ << 8;
  rd_as->as |= (u_int16_t) *pnt++;
  
  rd_as->val = ((u_int32_t) *pnt++ << 24);
  rd_as->val |= ((u_int32_t) *pnt++ << 16);
  rd_as->val |= ((u_int32_t) *pnt++ << 8);
  rd_as->val |= (u_int32_t) *pnt;
}

/* type == RD_TYPE_AS4 */
void
decode_rd_as4 (u_char *pnt, struct rd_as *rd_as)
{
  rd_as->as  = (u_int32_t) *pnt++ << 24;
  rd_as->as |= (u_int32_t) *pnt++ << 16;
  rd_as->as |= (u_int32_t) *pnt++ << 8;
  rd_as->as |= (u_int32_t) *pnt++;

  rd_as->val  = ((u_int16_t) *pnt++ << 8);
  rd_as->val |= (u_int16_t) *pnt;
}

/* type == RD_TYPE_IP */
void
decode_rd_ip (u_char *pnt, struct rd_ip *rd_ip)
{
  memcpy (&rd_ip->ip, pnt, 4);
  pnt += 4;
  
  rd_ip->val = ((u_int16_t) *pnt++ << 8);
  rd_ip->val |= (u_int16_t) *pnt;
}

char *
labels2str (char *str, size_t size, uint32_t *labels, size_t nlabels)
{
  size_t i;
  if (nlabels == 0)
    {
      snprintf (str, size, ":");
      return str;
    }
  char *pos = str;
  for (i = 0; i < nlabels; i++)
    {
      snprintf (pos, str + size - pos, "%s%d", (i > 0) ? ":" : "", labels[i] >> 4);
      pos += strlen(pos);
    }
  return str;
}

int
bgp_nlri_parse_vpn (struct peer *peer, struct attr *attr, 
                    struct bgp_nlri *packet)
{
  u_char *pnt, *pnt2;
  u_char *lim, *lim2;
  struct prefix p;
  int psize = 0;
  int prefixlen;
  u_int16_t type;
  struct rd_as rd_as;
  struct rd_ip rd_ip;
  struct prefix_rd prd;
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
#define VPN_LABEL_SIZE 3
#define VPN_PREFIXLEN_MIN_BYTES (VPN_LABEL_SIZE + BGP_RD_SIZE) /* label + RD */
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
                    "%s [Error] Update packet error / VPNv4"
                     " (prefix length %d less than VPNv4 min length)",
                    peer->host, prefixlen);
          return -1;
        }
      if ((pnt + psize) > lim)
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error / VPNv4"
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

      /* sanity check against storage for the IP address portion */
      if (pnt + VPN_PREFIXLEN_MIN_BYTES + (nlabels - 1)*VPN_LABEL_SIZE  > lim)
        {
          zlog_err ("not enough bytes for RD left in NLRI?");
          return -1;
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
      
      /* Copy routing distinguisher to rd. */
      memcpy (&prd.val, pnt + VPN_LABEL_SIZE*nlabels, BGP_RD_SIZE);
      /* Decode RD type. */
      type = decode_rd_type (pnt + VPN_LABEL_SIZE*nlabels);

      switch (type)
        {
        case RD_TYPE_AS:
          decode_rd_as (pnt + VPN_LABEL_SIZE*nlabels + 2, &rd_as);
          break;

        case RD_TYPE_AS4:
          decode_rd_as4 (pnt + VPN_LABEL_SIZE*nlabels + 2, &rd_as);
          break;

        case RD_TYPE_IP:
          decode_rd_ip (pnt + VPN_LABEL_SIZE*nlabels + 2, &rd_ip);
          break;

	default:
	  zlog_err ("Unknown RD type %d", type);
          break;  /* just report */
      }

      p.prefixlen = prefixlen - VPN_PREFIXLEN_MIN_BYTES*8 - (nlabels - 1)*VPN_LABEL_SIZE*8;
      memcpy (&p.u.prefix, pnt + VPN_PREFIXLEN_MIN_BYTES + (nlabels - 1)*VPN_LABEL_SIZE, 
              psize - VPN_PREFIXLEN_MIN_BYTES - (nlabels - 1)*VPN_LABEL_SIZE);

      if (attr)
        bgp_update (peer, &p, attr, packet->afi, SAFI_MPLS_VPN,
                    ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, labels, nlabels, 0, NULL);
      else
        bgp_withdraw (peer, &p, attr, packet->afi, SAFI_MPLS_VPN,
                      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, labels, nlabels, NULL);
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

int
str2prefix_rd (const char *str, struct prefix_rd *prd)
{
  int ret; /* ret of called functions */
  int lret; /* local ret, of this func */
  char *p;
  char *p2;
  struct stream *s = NULL;
  char *half = NULL;
  struct in_addr addr;

  s = stream_new (8);

  prd->family = AF_UNSPEC;
  prd->prefixlen = 64;

  lret = 0;
  p = strchr (str, ':');
  if (! p)
    goto out;

  if (! all_digit (p + 1))
    goto out;

  half = XMALLOC (MTYPE_TMP, (p - str) + 1);
  memcpy (half, str, (p - str));
  half[p - str] = '\0';

  p2 = strchr (str, '.');

  if (! p2)
    {
      unsigned long as_val;

      if (! all_digit (half))
        goto out;
      as_val = atol(half);
      if (as_val > 0xffff)
        {
          stream_putw (s, RD_TYPE_AS4);
          stream_putl (s, atol (half));
          stream_putw (s, atol (p + 1));
        }
      else
        {
          stream_putw (s, RD_TYPE_AS);
          stream_putw (s, atol (half));
          stream_putl (s, atol (p + 1));
        }
    }
  else
    {
      ret = inet_aton (half, &addr);
      if (! ret)
        goto out;
      
      stream_putw (s, RD_TYPE_IP);
      stream_put_in_addr (s, &addr);
      stream_putw (s, atol (p + 1));
    }
  memcpy (prd->val, s->data, 8);
  lret = 1;

out:
  if (s)
    stream_free (s);
  if (half)
    XFREE(MTYPE_TMP, half);
  return lret;
}

int
str2labels (const char *str, uint32_t*labels, size_t *nlabels, int type)
{
  unsigned long l;
  char *endptr;

  if (*str == '-')
    return 0;
  
  if (str[0] == ':' && str[1] == '\0')
    return 1;

  *nlabels = 0;
  while (*nlabels < BGP_MAX_LABELS)
    {
      errno = 0;
      l = strtoul (str, &endptr, 0);
      if (type == LABEL_ENCODING_STANDARD && l >= 0x100000)
        return 0;
      if (endptr == str || (*endptr != '\0' && *endptr != ':'))
          return 0;
      if (type == LABEL_ENCODING_STANDARD)
        labels[*nlabels] = l << 4;
      else
        labels[*nlabels] = l;
      (*nlabels)++;
      if ((*endptr == '\0') && (type == LABEL_ENCODING_STANDARD))
        {
          labels[*nlabels - 1] |= 1;
          break;
        }
      if (*endptr == '\0')
        {
          break;
        }
    }
  return *endptr == '\0';
}

int prefix_rd_cmp(struct prefix_rd *p1, struct prefix_rd *p2)
{
  if(p1->family != p2->family)
    return 1;
  if(p1->prefixlen != p2->prefixlen)
    return 1;
  if(memcmp((char *)p1->val, (char *)p2->val, 8))
    return 1;
  return 0;
}

char *
prefix_rd2str (struct prefix_rd *prd, char *buf, size_t size)
{
  u_char *pnt;
  u_int16_t type;
  struct rd_as rd_as;
  struct rd_ip rd_ip;

  if (size < RD_ADDRSTRLEN)
    return NULL;

  pnt = prd->val;

  type = decode_rd_type (pnt);

  if (type == RD_TYPE_AS)
    {
      decode_rd_as (pnt + 2, &rd_as);
      snprintf (buf, size, "%u:%d", rd_as.as, rd_as.val);
      return buf;
    }
  else if (type == RD_TYPE_AS4)
    {
      decode_rd_as4 (pnt + 2, &rd_as);
      snprintf (buf, size, "%u:%d", rd_as.as, rd_as.val);
      return buf;
    }
  else if (type == RD_TYPE_IP)
    {
      decode_rd_ip (pnt + 2, &rd_ip);
      snprintf (buf, size, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
      return buf;
    }
  return NULL;
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (vpnv4_network,
       vpnv4_network_cmd,
       "network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_set_safi (SAFI_MPLS_VPN, vty, argv[0], argv[1], argv[2], 
                              NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

DEFUN (vpnv4_network_route_map,
       vpnv4_network_route_map_cmd,
       "network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD route-map WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n"
       "route map\n"
       "route map name\n")
{
  return bgp_static_set_safi (SAFI_MPLS_VPN, vty, argv[0], argv[1], argv[2], argv[3], 
                              NULL, NULL, NULL, NULL, NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv4_network,
       no_vpnv4_network_cmd,
       "no network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_unset_safi (SAFI_MPLS_VPN, vty, argv[0], argv[1], argv[2], 
                                NULL, NULL, NULL, NULL);
}

DEFUN (vpnv6_network,
       vpnv6_network_cmd,
       "network X:X::X:X/M rd ASN:nn_or_IP-address:nn tag WORD",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_set_safi (SAFI_MPLS_VPN, vty, argv[0], argv[1], argv[2], 
                              NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

DEFUN (vpnv6_network_route_map,
       vpnv6_network_route_map_cmd,
       "network X:X::X:X/M rd ASN:nn_or_IP-address:nn tag WORD route-map WORD",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n"
       "route map\n"
       "route map name\n")
{
  return bgp_static_set_safi (SAFI_MPLS_VPN, vty, argv[0], argv[1], argv[2], argv[3],
                              NULL, NULL, NULL, NULL, NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv6_network,
       no_vpnv6_network_cmd,
       "no network X:X::X:X/M rd ASN:nn_or_IP-address:nn tag WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_unset_safi (SAFI_MPLS_VPN, vty, argv[0], argv[1], argv[2],
                                NULL, NULL, NULL, NULL);
}

static int
show_adj_route_vpn (struct vty *vty, struct peer *peer, struct prefix_rd *prd)
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

  for (rn = bgp_table_top (bgp->rib[AFI_IP][SAFI_MPLS_VPN]); rn;
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
                if (CHECK_FLAG (rm->flags, BGP_INFO_VPN_HIDEN))
                  return CMD_SUCCESS;
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
  bgp_show_type_community_list_exact,
  bgp_show_type_hiddentoo
};

static int
bgp_show_mpls_vpn(
    struct vty *vty,
    afi_t afi,
    struct prefix_rd *prd,
    enum bgp_show_type type,
    void *output_arg,
    int tags)
{
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  int rd_header;
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

  for (rn = bgp_table_top (bgp->rib[afi][SAFI_MPLS_VPN]); rn; rn = bgp_route_next (rn))
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
	        if (tags)
		  route_vty_out_tag (vty, &rm->p, ri, 0, SAFI_MPLS_VPN);
	        else
		  route_vty_out (vty, &rm->p, ri, 0, SAFI_MPLS_VPN);
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

DEFUN (show_bgp_ipv4_vpn,
       show_bgp_ipv4_vpn_cmd,
       "show bgp ipv4 vpn",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n")
{
  return bgp_show_mpls_vpn (vty, AFI_IP, NULL, bgp_show_type_normal, NULL, 0);
}

ALIAS (show_bgp_ipv4_vpn,
       show_ip_bgp_vpnv4_all_cmd,
       "show ip bgp vpnv4 all",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n")

DEFUN (show_bgp_ipv4_vpn_hidden,
       show_bgp_ipv4_vpn_hidden_cmd,
       "show bgp ipv4 vpn all hidden",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Also display entries with non matching VRFs")
{
  return bgp_show_mpls_vpn (vty, AFI_IP, NULL, bgp_show_type_hiddentoo, NULL, 0);
}

DEFUN (show_bgp_ipv6_vpn,
       show_bgp_ipv6_vpn_cmd,
       "show bgp ipv6 vpn",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n")
{
  return bgp_show_mpls_vpn (vty, AFI_IP6, NULL, bgp_show_type_normal, NULL, 0);
}

ALIAS (show_bgp_ipv6_vpn,
       show_ip_bgp_vpnv6_all_cmd,
       "show ip bgp vpnv6 all",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv6 NLRI specific information\n"
       "Display information about all VPNv6 NLRIs\n")

DEFUN (show_bgp_ipv6_vpn_hidden,
       show_bgp_ipv6_vpn_hidden_cmd,
       "show bgp ipv6 vpn all hidden",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Also display entries with non matching VRFs")
{
  return bgp_show_mpls_vpn (vty, AFI_IP6, NULL, bgp_show_type_hiddentoo, NULL, 0);
}

DEFUN (show_bgp_ipv4_vpn_rd,
       show_bgp_ipv4_vpn_rd_cmd,
       "show bgp ipv4 vpn rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
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
  return bgp_show_mpls_vpn (vty, AFI_IP, &prd, bgp_show_type_normal, NULL, 0);
}

DEFUN (show_bgp_ipv6_vpn_rd,
       show_bgp_ipv6_vpn_rd_cmd,
       "show bgp ipv6 vpn rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
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
  return bgp_show_mpls_vpn (vty, AFI_IP6, &prd, bgp_show_type_normal, NULL, 0);
}

ALIAS (show_bgp_ipv4_vpn_rd,
       show_ip_bgp_vpnv4_rd_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")

ALIAS (show_bgp_ipv6_vpn_rd,
       show_ip_bgp_vpnv6_rd_cmd,
       "show ip bgp vpnv6 rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv6 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")

DEFUN (show_bgp_ipv4_vpn_tags,
       show_bgp_ipv4_vpn_tags_cmd,
       "show bgp ipv4 vpn tags",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_mpls_vpn (vty, AFI_IP, NULL, bgp_show_type_normal, NULL,  1);
}

ALIAS (show_bgp_ipv4_vpn_tags,
       show_ip_bgp_vpnv4_all_tags_cmd,
       "show ip bgp vpnv4 all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Display BGP tags for prefixes\n")

DEFUN (show_bgp_ipv6_vpn_tags,
       show_bgp_ipv6_vpn_tags_cmd,
       "show bgp ipv6 vpn tags",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_mpls_vpn (vty, AFI_IP6, NULL, bgp_show_type_normal, NULL,  1);
}

ALIAS (show_bgp_ipv6_vpn_tags,
       show_ip_bgp_vpnv6_all_tags_cmd,
       "show ip bgp vpnv6 all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Display BGP tags for prefixes\n")

DEFUN (show_bgp_ipv4_vpn_rd_tags,
       show_bgp_ipv4_vpn_rd_tags_cmd,
       "show bgp ipv4 vpn rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
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
  return bgp_show_mpls_vpn (vty, AFI_IP, &prd, bgp_show_type_normal, NULL, 1);
}
DEFUN (show_bgp_ipv6_vpn_rd_tags,
       show_bgp_ipv6_vpn_rd_tags_cmd,
       "show bgp ipv6 vpn rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
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
  return bgp_show_mpls_vpn (vty, AFI_IP6, &prd, bgp_show_type_normal, NULL, 1);
}

DEFUN (show_bgp_ipv4_vpn_neighbor_routes,
       show_bgp_ipv4_vpn_neighbor_routes_cmd,
       "show bgp ipv4 vpn neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
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
  if (! peer || ! peer->afc[AFI_IP][SAFI_MPLS_VPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_mpls_vpn (vty, AFI_IP, NULL, bgp_show_type_neighbor, &su, 0);
}

DEFUN (show_bgp_ipv6_vpn_neighbor_routes,
       show_bgp_ipv6_vpn_neighbor_routes_cmd,
       "show bgp ipv6 vpn neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
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
  if (! peer || ! peer->afc[AFI_IP6][SAFI_MPLS_VPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_mpls_vpn (vty, AFI_IP6, NULL, bgp_show_type_neighbor, &su, 0);
}

DEFUN (show_bgp_ipv4_vpn_neighbor_advertised_routes,
       show_bgp_ipv4_vpn_neighbor_advertised_routes_cmd,
       "show bgp ipv4 vpn neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
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
  if (! peer || ! peer->afc[AFI_IP][SAFI_MPLS_VPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_vpn (vty, peer, NULL);
}
DEFUN (show_bgp_ipv6_vpn_neighbor_advertised_routes,
       show_bgp_ipv6_vpn_neighbor_advertised_routes_cmd,
       "show bgp ipv6 vpn neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
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
  if (! peer || ! peer->afc[AFI_IP6][SAFI_MPLS_VPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_vpn (vty, peer, NULL);
}

DEFUN (show_ip_bgp_vpnv4_rd_neighbor_advertised_routes,
       show_bgp_ipv4_vpn_rd_neighbor_advertised_routes_cmd,
       "show bgp ipv4 vpn rd ASN:nn_or_IP-address:nn neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
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
      vty_out (vty, "%% Malformed address: %s%s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_MPLS_VPN])
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

  return show_adj_route_vpn (vty, peer, &prd);
}
DEFUN (show_ip_bgp_vpnv6_rd_neighbor_advertised_routes,
       show_bgp_ipv6_vpn_rd_neighbor_advertised_routes_cmd,
       "show bgp ipv6 vpn rd ASN:nn_or_IP-address:nn neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
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
      vty_out (vty, "%% Malformed address: %s%s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP6][SAFI_MPLS_VPN])
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

  return show_adj_route_vpn (vty, peer, &prd);
}

DEFUN (show_bgp_ipv4_vpn_rd_neighbor_routes,
       show_bgp_ipv4_vpn_rd_neighbor_routes_cmd,
       "show bgp ipv4 vpn rd ASN:nn_or_IP-address:nn neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  int ret;
  union sockunion *su;
  struct peer *peer;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  su = sockunion_str2su (argv[1]);
  if (su == NULL)
    {
      vty_out (vty, "Malformed address: %s%s", argv[1], VTY_NEWLINE);
               return CMD_WARNING;
    }

  peer = peer_lookup (NULL, su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_MPLS_VPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_mpls_vpn (vty, AFI_IP, &prd, bgp_show_type_neighbor, su, 0);
}
DEFUN (show_bgp_ipv6_vpn_rd_neighbor_routes,
       show_bgp_ipv6_vpn_rd_neighbor_routes_cmd,
       "show bgp ipv6 vpn rd ASN:nn_or_IP-address:nn neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  int ret;
  union sockunion *su;
  struct peer *peer;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  su = sockunion_str2su (argv[1]);
  if (su == NULL)
    {
      vty_out (vty, "Malformed address: %s%s", argv[1], VTY_NEWLINE);
               return CMD_WARNING;
    }

  peer = peer_lookup (NULL, su);
  if (! peer || ! peer->afc[AFI_IP6][SAFI_MPLS_VPN])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_mpls_vpn (vty, AFI_IP6, &prd, bgp_show_type_neighbor, su, 0);
}

void
bgp_mplsvpn_init (void)
{
  install_element (BGP_VPNV4_NODE, &vpnv4_network_cmd);
  install_element (BGP_VPNV4_NODE, &vpnv4_network_route_map_cmd);
  install_element (BGP_VPNV4_NODE, &no_vpnv4_network_cmd);

  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_hidden_cmd),
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_rd_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_rd_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_rd_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_rd_neighbor_routes_cmd);

  install_element (BGP_VPNV6_NODE, &vpnv6_network_cmd);
  install_element (BGP_VPNV6_NODE, &vpnv6_network_route_map_cmd);
  install_element (BGP_VPNV6_NODE, &no_vpnv6_network_cmd);

  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv6_all_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_hidden_cmd),
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_rd_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv6_rd_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv6_all_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_rd_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_rd_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_rd_neighbor_routes_cmd);
}
