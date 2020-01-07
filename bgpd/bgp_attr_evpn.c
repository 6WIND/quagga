/* Ethernet-VPN Attribute handling file
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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_encap_tlv.h"
#include "bgpd/bgp_aspath.h"

static uint8_t convertchartohexa (uint8_t *hexa, int *error)
{
  if( (*hexa == '0') || (*hexa == '1') || (*hexa == '2') ||
      (*hexa == '3') || (*hexa == '4') || (*hexa == '5') ||
      (*hexa == '6') || (*hexa == '7') || (*hexa == '8') ||
      (*hexa == '9'))
    return (uint8_t)(*hexa)-'0';
  if((*hexa == 'a') || (*hexa == 'A'))
    return 0xa;
  if((*hexa == 'b') || (*hexa == 'B'))
    return 0xb;
  if((*hexa == 'c') || (*hexa == 'C'))
    return 0xc;
  if((*hexa == 'd') || (*hexa == 'D'))
    return 0xd;
  if((*hexa == 'e') || (*hexa == 'E'))
    return 0xe;
  if((*hexa == 'f') || (*hexa == 'F'))
    return 0xf;
  *error = -1;
  return 0;
}

/* converts to internal representation of mac address
 * returns 1 on success, 0 otherwise 
 * format accepted: AA:BB:CC:DD:EE:FF
 * if mac parameter is null, then check only
 */
int
str2mac (const char *str, char *mac)
{
  unsigned int k=0, i, j;
  uint8_t *ptr, *ptr2;
  size_t len;
  uint8_t car;

  if (!str)
    return 0;

  if (str[0] == ':' && str[1] == '\0')
    return 1;

  i = 0;
  ptr = (uint8_t *)str;
  while (i < 6)
    {
      uint8_t temp[5];
      int error = 0;
      ptr2 = (uint8_t *)strchr((const char *)ptr, ':');
      if (ptr2 == NULL)
	{
	  /* if last occurence return ok */
	  if(i != 5)
            {
              zlog_err("[%s]: format non recognized",mac);
              return 0;
            }
          len = strlen((char *)ptr);
	} 
      else
        {
          len = ptr2 - ptr;
        }
      if(len > 5)
        {
          zlog_err("[%s]: format non recognized",mac);
         return 0;
        }
      memcpy(temp, ptr, len);
      for(j=0;j< len;j++)
	{
	  if (k >= MAC_LEN)
	    return 0;
          if(mac)
            mac[k] = 0;
          car = convertchartohexa (&temp[j], &error);
	  if (error)
	    return 0;
	  if(mac)
            mac[k] = car << 4;
	  j++;
          if(j == len)
            return 0;
          car = convertchartohexa (&temp[j], &error) & 0xf;
	  if (error)
	    return 0;
	  if(mac)
            mac[k] |= car & 0xf;
	  k++;
	  i++;
	}
      ptr = ptr2;
      if(ptr == NULL)
        break;
      ptr++;
    }
  if(mac && 0)
    {
      zlog_err("leave correct : %02x:%02x:%02x:%02x:%02x:%02x",
               mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff,
               mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff);
    }
  return 1;
}

/* converts to an esi
 * returns 1 on success, 0 otherwise
 * format accepted: AA:BB:CC:DD:EE:FF:GG:HH:II:JJ
 * if id is null, check only is done
 */
int
str2esi (const char *str, struct eth_segment_id *id)
{
  unsigned int k=0, i, j;
  uint8_t *ptr, *ptr2;
  size_t len;
  uint8_t car;

  if (!str)
    return 0;
  if (str[0] == ':' && str[1] == '\0')
    return 1;

  i = 0;
  ptr = (uint8_t *)str;
  while (i < 10)
    {
      uint8_t temp[5];
      int error = 0;
      ptr2 = (uint8_t *)strchr((const char *)ptr, ':');
      if (ptr2 == NULL)
	{
	  /* if last occurence return ok */
	  if(i != 9)
            {
              zlog_err("[%s]: format non recognized",str);
              return 0;
            }
          len = strlen((char *)ptr);
	}
      else
        {
          len = ptr2 - ptr;
        }
      memcpy(temp, ptr, len);
      if(len > 5)
        {
          zlog_err("[%s]: format non recognized",str);
         return 0;
        }
      for(j=0;j< len;j++)
	{
	  if (k >= ESI_LEN)
	    return 0;
          if(id)
            id->val[k] = 0;
          car = convertchartohexa (&temp[j], &error);
          if (error)
            return 0;
          if(id)
            id->val[k] = car << 4;
          j++;
          if(j == len)
            return 0;
          car = convertchartohexa (&temp[j], &error) & 0xf;
          if (error)
            return 0;
          if(id)
            id->val[k] |= car & 0xf;
         k++;
         i++;
	}
      ptr = ptr2;
      if(ptr == NULL)
        break;
      ptr++;
    }
  if(id && 0)
    {
      zlog_err("leave correct : %02x:%02x:%02x:%02x:%02x",
               id->val[0], id->val[1], id->val[2], id->val[3], id->val[4]);
      zlog_err("%02x:%02x:%02x:%02x:%02x",
               id->val[5], id->val[6], id->val[7], id->val[8], id->val[9]);
    }
  return 1;
}

char *
esi2str (struct eth_segment_id *id)
{
  char *ptr;
  u_char *val;

  if(!id)
    return NULL;

  val = id->val;
  ptr = (char *) XMALLOC (MTYPE_BGP_ESI, (ESI_LEN*2+ESI_LEN-1+1)*sizeof(char));

  snprintf (ptr, (ESI_LEN*2+ESI_LEN-1+1),
            "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            val[0], val[1], val[2], val[3], val[4],
            val[5], val[6], val[7], val[8], val[9]);

  return ptr;
}

char *
mac2str (char *mac)
{
  char *ptr;

  if(!mac)
    return NULL;

  ptr = (char *) XMALLOC (MTYPE_BGP_MAC, (MAC_LEN*2+MAC_LEN-1+1)*sizeof(char));

  snprintf (ptr, (MAC_LEN*2+MAC_LEN-1+1), "%02x:%02x:%02x:%02x:%02x:%02x",
           (uint8_t) mac[0], (uint8_t)mac[1], (uint8_t)mac[2], (uint8_t)mac[3],
           (uint8_t)mac[4], (uint8_t)mac[5]);

  return ptr;
}

char *ecom_mac2str(char *ecom_mac)
{
  char *en;

  en = ecom_mac;
  en+=2;
  return mac2str(en);
}

/* returns 1 if a change has been observed */
int bgp_evpn_ad_update(struct bgp_evpn_ad *ad, struct in_addr *nexthop, u_int32_t label)
{
  struct attr_extra *extra;
  int ret = 0;
  struct attr new_attr, *attr_new;
  struct attr_extra new_extra;

  memset (&new_attr, 0, sizeof(struct attr));
  memset (&new_extra, 0, sizeof(struct attr_extra));
  new_attr.extra = &new_extra;
  bgp_attr_dup (&new_attr, ad->attr);

  if (ad->label != label)
    ret = 1;

  extra = bgp_attr_extra_get(&new_attr);
  extra->mp_nexthop_global_in = *nexthop;
  if ((nexthop->s_addr != extra->mp_nexthop_global_in.s_addr) ||
      (nexthop->s_addr != ad->attr->nexthop.s_addr))
    ret = 1;

  new_attr.nexthop = *nexthop;
  ad->label = label;

  attr_new = bgp_attr_intern(&new_attr);
  bgp_attr_unintern (&ad->attr);
  ad->attr = attr_new;
  bgp_attr_flush (&new_attr);
  return ret;
}


struct bgp_evpn_ad* bgp_evpn_ad_new(struct peer *peer,
                                    struct bgp_vrf *vrf,
                                    struct eth_segment_id *esi,
                                    u_int32_t ethtag,
                                    struct prefix *nexthop,
                                    u_int32_t label)
{
  struct attr attr;
  struct attr_extra *extra;
  struct bgp_evpn_ad *evpn_ad = XCALLOC(MTYPE_BGP_EVPN_AD, sizeof(struct bgp_evpn_ad));

  if (!evpn_ad)
    return NULL;

  evpn_ad->peer = peer;
  memcpy (&evpn_ad->prd,&vrf->outbound_rd, sizeof(struct prefix_rd));

  evpn_ad->eth_t_id = ethtag;
  evpn_ad->eth_s_id = *esi;
  evpn_ad->label = label;

  memset (&attr, 0, sizeof(struct attr));
  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
  extra = bgp_attr_extra_get(&attr);
  if (!extra)
    return NULL;

  if (vrf->rt_export)
    {
      extra->ecommunity = ecommunity_dup (vrf->rt_export);
      attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
    }

  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);
  if (nexthop->family == AF_INET)
    {
      extra->mp_nexthop_len = IPV4_MAX_BYTELEN;
      extra->mp_nexthop_global_in = nexthop->u.prefix4;
    }
  else
    {
      extra->mp_nexthop_len = IPV6_MAX_BYTELEN;
      memcpy (&extra->mp_nexthop_global, &(nexthop->u.prefix6), sizeof (struct in6_addr));
    }
  /* routermac if present */
  if(vrf->mac_router)
    {
      char routermac_int[MAC_LEN+1];

      str2mac (vrf->mac_router, routermac_int);
      bgp_add_routermac_ecom (&attr, routermac_int);
    }

  /* VXLAN type if present */
  if(ethtag)
    {
      struct bgp_encap_type_vxlan bet;

      memset(&bet, 0, sizeof(struct bgp_encap_type_vxlan));
      bet.vnid = ethtag;
      bgp_encap_type_vxlan_to_tlv(&bet, &attr);
      bgp_attr_extra_get (&attr);
      /* It may be advertised along with BGP Encapsulation Extended Community define
       * in section 4.5 of [RFC5512].
       */
      bgp_add_encapsulation_type (&attr, BGP_ENCAP_TYPE_VXLAN);
    }

  extra->evpn_overlay.eth_s_id = *esi;
  evpn_ad->attr = bgp_attr_intern (&attr);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);

  return evpn_ad;
}

void bgp_evpn_ad_free(struct bgp_evpn_ad* ad)
{
  bgp_attr_unintern (&ad->attr);
  XFREE (MTYPE_BGP_EVPN_AD, ad);
}
int bgp_evpn_ad_cmp(struct bgp_evpn_ad *ad1,
                    struct peer *peer,
                    struct prefix_rd *prd,
                    struct eth_segment_id *esi,
                    u_int32_t ethtag)
{
  if (memcmp(&ad1->eth_s_id, esi, sizeof(struct eth_segment_id)))
    return 1;

  if (prd && prefix_rd_cmp(&ad1->prd, prd))
    return 1;

  if (ad1->eth_t_id != ethtag)
    return 1;

  if (ad1->peer != peer)
    return 1;

  return 0;
}

void bgp_evpn_ad_display (struct bgp_evpn_ad *ad, char *buf, int size)
{
  char vrf_rd_str[RD_ADDRSTRLEN];
  char *esi;

  prefix_rd2str(&ad->prd, vrf_rd_str, sizeof(vrf_rd_str));
  esi = esi2str(&(ad->eth_s_id));
  snprintf(buf, size, "RD[%s] %s Ethtag %08x/ ESI %s/ Label %u: A/D ",
           vrf_rd_str, ad->type == BGP_EVPN_AD_TYPE_MP_UNREACH?"MP_UNREACH":"MP_REACH",
           ad->eth_t_id, esi, ad->label >> 4);
  free (esi);
}


struct bgp_evpn_ad* bgp_evpn_ad_new_from_update(struct peer *peer,
                                                struct prefix_rd *prd,
                                                struct bgp_route_evpn *evpn,
                                                struct prefix *p,
                                                u_int32_t label,
                                                struct attr *attr)
{
  struct attr new_attr;
  struct attr *attr_new;
  struct attr_extra new_extra;
  struct bgp_evpn_ad *evpn_ad = XCALLOC(MTYPE_BGP_EVPN_AD, sizeof(struct bgp_evpn_ad));

  if (!evpn_ad)
    return NULL;
  memset( &new_attr, 0, sizeof(struct attr));
  evpn_ad->peer = peer;
  if (prd)
    evpn_ad->prd = *prd;

  evpn_ad->eth_t_id = p->u.prefix_evpn.u.prefix_macip.eth_tag_id;
  memcpy(&evpn_ad->eth_s_id, &evpn->eth_s_id, sizeof(struct eth_segment_id));

  if (attr)
    {
      new_attr.extra = &new_extra;
      bgp_attr_dup (&new_attr, attr);
      attr_new = bgp_attr_intern (&new_attr);
      evpn_ad->attr = attr_new;
    }
  else
    evpn_ad->attr = NULL;

  evpn_ad->label = label;

  return evpn_ad;
}

/* create a new entry in same rn as iter,but with ad attribute */
struct bgp_info *bgp_evpn_new_bgp_info_from_ad(struct bgp_info *ri, struct bgp_evpn_ad *ad)
{
  struct bgp_node *rn;
  struct bgp_info *iter;
  struct attr attr = { 0 };
  struct attr *attr_new = &attr;

  rn = ri->net;

  /* substitute next hop
   * with ad->attr->extra->mp_nexthopglobal_in
   * with ad->attr->nexthop
   */
  /* change peer to our ad->peer */
  iter = info_make(ri->type, ri->sub_type, ad->peer, NULL, rn);
  bgp_attr_extra_get(&attr);
  bgp_attr_dup (attr_new, ri->attr);

  /* copy ESI */
  if (ri->attr->extra)
    overlay_index_dup(attr_new, &(ri->attr->extra->evpn_overlay));

  /* no duplicate ecom */

  /* duplicate label information */
  if(!iter->extra)
    iter->extra = bgp_info_extra_new();
  iter->extra->vrf_rd = ri->extra->vrf_rd;
  iter->extra->nlabels = 1;
  iter->extra->labels[0] = ri->extra->labels[0];

  /* change nexthop attribute */
  attr_new->nexthop.s_addr = ad->attr->nexthop.s_addr;
  attr_new->extra->mp_nexthop_global_in.s_addr = ad->attr->extra->mp_nexthop_global_in.s_addr;
  attr_new->extra->mp_nexthop_len = 4;

  iter->peer = ad->peer;
  SET_FLAG (iter->flags, BGP_INFO_ORIGIN_EVPN);
  SET_FLAG (iter->flags, BGP_INFO_VALID);

  iter->attr = bgp_attr_intern (&attr);
  bgp_info_add (rn, iter);
  bgp_attr_extra_free (&attr);
  return iter;
}

struct bgp_evpn_ad* bgp_evpn_ad_duplicate_from_ad(struct bgp_evpn_ad *evpn)
{
  struct bgp_evpn_ad *evpn_ad = XCALLOC(MTYPE_BGP_EVPN_AD, sizeof(struct bgp_evpn_ad));
  struct attr *attr_new;

  if (!evpn_ad)
    return NULL;
  evpn_ad->peer = evpn->peer;
  evpn_ad->prd = evpn->prd;

  evpn_ad->eth_t_id = evpn->eth_t_id;
  memcpy(&evpn_ad->eth_s_id, &evpn->eth_s_id, sizeof(struct eth_segment_id));

  if(evpn->attr)
    {
      attr_new = bgp_attr_intern (evpn->attr);
      evpn_ad->attr = attr_new;
    }
  else
    evpn_ad->attr = NULL;

  evpn_ad->label = evpn->label;
  return evpn_ad;
}

/*
 * Fetch and return the sequence number from MAC Mobility extended
 * community, if present, else 0.
 */
int bgp_attr_mac_mobility_seqnum(struct attr *attr)
{
  struct ecommunity *ecom;
  struct attr_extra *extra;
  int i;
  uint8_t flags = 0;

  extra = bgp_attr_extra_get(attr);
  if (!extra)
    return 0;

  ecom = extra->ecommunity;
  if (!ecom || !ecom->size)
    return 0;

  /* If there is a MAC Mobility extended community, return its
   * sequence number.
   * TODO: RFC is silent on handling of multiple MAC mobility extended
   * communities for the same route. We will bail out upon the first
   * one.
   */
  for (i = 0; i < ecom->size; i++)
    {
      uint8_t *pnt;
      uint8_t type, sub_type;
      uint32_t seq_num, tmp;

      pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
      type = *pnt++;
      sub_type = *pnt++;
      if (!(type == ECOMMUNITY_ENCODE_EVPN &&
            sub_type == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY))
        continue;
      flags = *pnt++;

      pnt++;
      memcpy(&tmp, pnt, sizeof(tmp));
      seq_num = ntohl(tmp);
      return seq_num;
    }

  return 0;
}
