/* BGP CapnProto Library
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of GNU Quagga.
 *
 * GNU Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <stdbool.h>
#include "c-capnproto/capn.h"
#include "bgp.bcapnp.h"

#include "zebra.h"
#include "bgpd.h"

static const capn_text capn_val0 = {0, ""};

capn_ptr qcapn_new_BGP(struct capn_segment *s)
{
    return capn_new_struct(s, 32, 3);
}

void qcapn_BGP_write(const struct bgp *s, capn_ptr p)
{
    capn_resolve(&p);
    capn_write32(p, 0, s->as);
    { capn_text tp = { .str = s->name, .len = s->name ? strlen(s->name) : 0 }; capn_set_text(p, 0, tp); }

    {
        capn_ptr tempptr = capn_new_struct(p.seg, 8, 0);
        capn_write32(tempptr, 0, ntohl(s->router_id_static.s_addr));
        capn_setp(p, 1, tempptr);
    }
    capn_write1(p, 32, !!(s->flags & BGP_FLAG_ALWAYS_COMPARE_MED));
    capn_write1(p, 33, !!(s->flags & BGP_FLAG_DETERMINISTIC_MED));
    capn_write1(p, 34, !!(s->flags & BGP_FLAG_MED_MISSING_AS_WORST));
    capn_write1(p, 35, !!(s->flags & BGP_FLAG_MED_CONFED));
    capn_write1(p, 36, !!(s->flags & BGP_FLAG_NO_DEFAULT_IPV4));
    capn_write1(p, 37, !!(s->flags & BGP_FLAG_NO_CLIENT_TO_CLIENT));
    capn_write1(p, 38, !!(s->flags & BGP_FLAG_ENFORCE_FIRST_AS));
    capn_write1(p, 39, !!(s->flags & BGP_FLAG_COMPARE_ROUTER_ID));
    capn_write1(p, 40, !!(s->flags & BGP_FLAG_ASPATH_IGNORE));
    capn_write1(p, 41, !!(s->flags & BGP_FLAG_IMPORT_CHECK));
    capn_write1(p, 42, !!(s->flags & BGP_FLAG_NO_FAST_EXT_FAILOVER));
    capn_write1(p, 43, !!(s->flags & BGP_FLAG_LOG_NEIGHBOR_CHANGES));
    capn_write1(p, 44, !!(s->flags & BGP_FLAG_GRACEFUL_RESTART));
    capn_write1(p, 45, !!(s->flags & BGP_FLAG_ASPATH_CONFED));
    capn_write1(p, 46, !!(s->flags & BGP_FLAG_ASPATH_MULTIPATH_RELAX));
    capn_write1(p, 47, !!(s->flags & BGP_FLAG_GR_PRESERVE_FWD));
    capn_write8(p, 6, s->distance_ebgp);
    capn_write8(p, 7, s->distance_ibgp);
    capn_write8(p, 8, s->distance_local);
    capn_write32(p, 12, s->default_local_pref);
    capn_write32(p, 16, s->default_holdtime);
    capn_write32(p, 20, s->default_keepalive);
    capn_write32(p, 24, s->restart_time);
    capn_write32(p, 28, s->stalepath_time);
    { capn_text tp = { .str = s->notify_zmq_url, .len = s->notify_zmq_url ? strlen(s->notify_zmq_url) : 0 }; capn_set_text(p, 2, tp); }
}

void qcapn_BGPVRF_write(const struct bgp_vrf *s, capn_ptr p)
{
    capn_resolve(&p);
    capn_write64(p, 0, *(uint64_t *)s->outbound_rd.val);
    {
        capn_ptr tempptr = capn_new_struct(p.seg, 0, 1);
        size_t size = s->rt_import ? s->rt_import->size : 0;
        capn_list64 listptr = capn_new_list64(p.seg, size);
        if (size)
            capn_setv64(listptr, 0, (uint64_t *)s->rt_import->val, size);
        capn_setp(tempptr, 0, listptr.p);
        capn_setp(p, 0, tempptr);
    }
    {
        capn_ptr tempptr = capn_new_struct(p.seg, 0, 1);
        size_t size = s->rt_export ? s->rt_export->size : 0;
        capn_list64 listptr = capn_new_list64(p.seg, size);
        if (size)
            capn_setv64(listptr, 0, (uint64_t *)s->rt_export->val, size);
        capn_setp(tempptr, 0, listptr.p);
        capn_setp(p, 1, tempptr);
    }
}

capn_ptr qcapn_new_BGPVRF(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 2);
}

void qcapn_BGPPeer_read(struct peer *s, capn_ptr p)
{
    capn_resolve(&p);
    s->as = capn_read32(p, 0);
    { capn_text tp = capn_get_text(p, 0, capn_val0); free(s->host); s->host = strdup(tp.str); }
    { capn_text tp = capn_get_text(p, 1, capn_val0); free(s->desc); s->desc = strdup(tp.str); }
    s->port = capn_read16(p, 4);
    s->weight = capn_read32(p, 8);
    s->holdtime = capn_read32(p, 12);
    s->keepalive = capn_read32(p, 16);
    { bool tmp;
      tmp = !!(capn_read8(p, 6) & (1 << 0));
      if (tmp) s->flags |=  PEER_FLAG_PASSIVE;
      else     s->flags &= ~PEER_FLAG_PASSIVE;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 6) & (1 << 1));
      if (tmp) s->flags |=  PEER_FLAG_SHUTDOWN;
      else     s->flags &= ~PEER_FLAG_SHUTDOWN;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 6) & (1 << 2));
      if (tmp) s->flags |=  PEER_FLAG_DONT_CAPABILITY;
      else     s->flags &= ~PEER_FLAG_DONT_CAPABILITY;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 6) & (1 << 3));
      if (tmp) s->flags |=  PEER_FLAG_OVERRIDE_CAPABILITY;
      else     s->flags &= ~PEER_FLAG_OVERRIDE_CAPABILITY;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 6) & (1 << 4));
      if (tmp) s->flags |=  PEER_FLAG_STRICT_CAP_MATCH;
      else     s->flags &= ~PEER_FLAG_STRICT_CAP_MATCH;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 6) & (1 << 5));
      if (tmp) s->flags |=  PEER_FLAG_DYNAMIC_CAPABILITY;
      else     s->flags &= ~PEER_FLAG_DYNAMIC_CAPABILITY;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 6) & (1 << 6));
      if (tmp) s->flags |=  PEER_FLAG_DISABLE_CONNECTED_CHECK;
      else     s->flags &= ~PEER_FLAG_DISABLE_CONNECTED_CHECK;
    }
    s->ttl = capn_read32(p, 20);
    {
      const char * update_source = NULL;
      int len;
      capn_text tp = capn_get_text(p, 2, capn_val0);
      update_source = tp.str;
      len = tp.len;
      if (update_source && len != 0)
        {
          union sockunion *su;

          su = sockunion_str2su (update_source);
          if (su)
            s->update_source = su;
          else
            s->update_if = strdup(update_source);
        }
      else
        {
          s->update_source = NULL;
          s->update_if = NULL;
        }
    }
}

void qcapn_BGPPeer_write(const struct peer *s, capn_ptr p)
{
    capn_resolve(&p);
    capn_write32(p, 0, s->as);
    { capn_text tp = { .str = s->host, .len = s->host ? strlen(s->host) : 0 }; capn_set_text(p, 0, tp); }
    { capn_text tp = { .str = s->desc, .len = s->desc ? strlen(s->desc) : 0 }; capn_set_text(p, 1, tp); }
    capn_write16(p, 4, s->port);
    capn_write32(p, 8, s->weight);
    capn_write32(p, 12, s->holdtime);
    capn_write32(p, 16, s->keepalive);
    capn_write1(p, 48, !!(s->flags & PEER_FLAG_PASSIVE));
    capn_write1(p, 49, !!(s->flags & PEER_FLAG_SHUTDOWN));
    capn_write1(p, 50, !!(s->flags & PEER_FLAG_DONT_CAPABILITY));
    capn_write1(p, 51, !!(s->flags & PEER_FLAG_OVERRIDE_CAPABILITY));
    capn_write1(p, 52, !!(s->flags & PEER_FLAG_STRICT_CAP_MATCH));
    capn_write1(p, 53, !!(s->flags & PEER_FLAG_DYNAMIC_CAPABILITY));
    capn_write1(p, 54, !!(s->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK));
    capn_write32(p, 20, s->ttl);
    {
      capn_text tp;
      char *ptr = malloc(65);
      if(s->update_source)
        {
          ptr = (char *)sockunion2str((const union sockunion *)s->update_source, ptr, 64);
          tp.str = ptr;
          tp.len = strlen(ptr);
        } else if (s->update_if)
        {
          tp.str = s->update_if;
          tp.len = strlen(s->update_if);
        } else
        {
          tp.str = NULL;
          tp.len = 0;
        }
      capn_set_text(p, 2, tp);
    }
}

capn_ptr qcapn_new_BGPPeer(struct capn_segment *s)
{
    return capn_new_struct(s, 24, 3);
}

capn_ptr qcapn_new_AfiSafiKey(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 0);
}

capn_ptr qcapn_new_BGPPeerAfiSafi(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 0);
}

void qcapn_BGPPeerAfiSafi_write(const struct peer *s, capn_ptr p, afi_t afi, safi_t safi)
{
    capn_resolve(&p);
    capn_write1(p, 0, s->afc[afi][safi]);
    capn_write1(p, 1, !!(s->af_flags[afi][safi] & PEER_FLAG_SEND_COMMUNITY));
    capn_write1(p, 2, !!(s->af_flags[afi][safi] & PEER_FLAG_SEND_EXT_COMMUNITY));
    capn_write1(p, 3, !!(s->af_flags[afi][safi] & PEER_FLAG_NEXTHOP_SELF));
    capn_write1(p, 4, !!(s->af_flags[afi][safi] & PEER_FLAG_REFLECTOR_CLIENT));
    capn_write1(p, 5, !!(s->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT));
    capn_write1(p, 6, !!(s->af_flags[afi][safi] & PEER_FLAG_SOFT_RECONFIG));
    capn_write1(p, 7, !!(s->af_flags[afi][safi] & PEER_FLAG_AS_PATH_UNCHANGED));
    capn_write1(p, 8, !!(s->af_flags[afi][safi] & PEER_FLAG_NEXTHOP_UNCHANGED));
    capn_write1(p, 9, !!(s->af_flags[afi][safi] & PEER_FLAG_MED_UNCHANGED));
    capn_write1(p, 10, !!(s->af_flags[afi][safi] & PEER_FLAG_DEFAULT_ORIGINATE));
    capn_write1(p, 11, !!(s->af_flags[afi][safi] & PEER_FLAG_REMOVE_PRIVATE_AS));
    capn_write1(p, 12, !!(s->af_flags[afi][safi] & PEER_FLAG_ALLOWAS_IN));
    capn_write1(p, 13, !!(s->af_flags[afi][safi] & PEER_FLAG_ORF_PREFIX_SM));
    capn_write1(p, 14, !!(s->af_flags[afi][safi] & PEER_FLAG_ORF_PREFIX_RM));
    capn_write1(p, 15, !!(s->af_flags[afi][safi] & PEER_FLAG_MAX_PREFIX));
    capn_write1(p, 16, !!(s->af_flags[afi][safi] & PEER_FLAG_MAX_PREFIX_WARNING));
    capn_write1(p, 17, !!(s->af_flags[afi][safi] & PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED));
    capn_write1(p, 18, !!(s->af_flags[afi][safi] & PEER_FLAG_NEXTHOP_SELF_ALL));
    capn_write8(p, 3, s->allowas_in[afi][safi]);
}

void qcapn_BGPPeerAfiSafi_read(struct peer *s, capn_ptr p, afi_t afi, safi_t safi)
{
    capn_resolve(&p);
    s->afc[afi][safi] = !!(capn_read8(p, 0) & (1 << 0));
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 1));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_SEND_COMMUNITY;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_SEND_COMMUNITY;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 2));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_SEND_EXT_COMMUNITY;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_SEND_EXT_COMMUNITY;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 3));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_NEXTHOP_SELF;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_NEXTHOP_SELF;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 4));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_REFLECTOR_CLIENT;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_REFLECTOR_CLIENT;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 5));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_RSERVER_CLIENT;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_RSERVER_CLIENT;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 6));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_SOFT_RECONFIG;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_SOFT_RECONFIG;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 7));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_AS_PATH_UNCHANGED;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_AS_PATH_UNCHANGED;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 1) & (1 << 0));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_NEXTHOP_UNCHANGED;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_NEXTHOP_UNCHANGED;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 1) & (1 << 1));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_MED_UNCHANGED;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_MED_UNCHANGED;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 1) & (1 << 2));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_DEFAULT_ORIGINATE;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_DEFAULT_ORIGINATE;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 1) & (1 << 3));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_REMOVE_PRIVATE_AS;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_REMOVE_PRIVATE_AS;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 1) & (1 << 4));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_ALLOWAS_IN;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_ALLOWAS_IN;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 1) & (1 << 5));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_ORF_PREFIX_SM;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_ORF_PREFIX_SM;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 1) & (1 << 6));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_ORF_PREFIX_RM;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_ORF_PREFIX_RM;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 1) & (1 << 7));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_MAX_PREFIX;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_MAX_PREFIX;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 2) & (1 << 0));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_MAX_PREFIX_WARNING;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_MAX_PREFIX_WARNING;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 2) & (1 << 1));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 2) & (1 << 2));
      if (tmp) s->af_flags[afi][safi] |=  PEER_FLAG_NEXTHOP_SELF_ALL;
      else     s->af_flags[afi][safi] &= ~PEER_FLAG_NEXTHOP_SELF_ALL;
    }
    s->allowas_in[afi][safi] = capn_read8(p, 3);
}

void qcapn_BGPVRFRoute_write(const struct bgp_api_route *s, capn_ptr p)
{
    capn_resolve(&p);
    {
        capn_ptr tempptr = capn_new_struct(p.seg, 8, 0);
        capn_write8(tempptr, 4, s->prefix.prefixlen);
        capn_write32(tempptr, 0, ntohl(s->prefix.prefix.s_addr));
        capn_setp(p, 0, tempptr);
    }
    {
        capn_ptr tempptr = capn_new_struct(p.seg, 8, 0);
        capn_write32(tempptr, 0, ntohl(s->nexthop.s_addr));
        capn_setp(p, 1, tempptr);
    }
    capn_write32(p, 0, s->label);
}

capn_ptr qcapn_new_AfiKey(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 0);
}

capn_ptr qcapn_new_BGPVRFRoute(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 2);
}

void qcapn_BGPVRFRoute_read(struct bgp_api_route *s, capn_ptr p)
{
    capn_resolve(&p);
    
    {
        capn_ptr tmp_p = capn_getp(p, 0, 1);
        s->prefix.family = AF_INET;
        s->prefix.prefixlen = capn_read8(tmp_p, 4);
        s->prefix.prefix.s_addr = htonl(capn_read32(tmp_p, 0));
    }
    
    {
        capn_ptr tmp_p = capn_getp(p, 1, 1);
        s->nexthop.s_addr = htonl(capn_read32(tmp_p, 0));
    }
    s->label = capn_read32(p, 0);
}

void qcapn_VRFTableIter_read(struct tbliter_v4 *s, capn_ptr p)
{
    capn_resolve(&p);
    
    {
        capn_ptr tmp_p = capn_getp(p, 0, 1);
        s->prefix.family = AF_INET;
        s->prefix.prefixlen = capn_read8(tmp_p, 4);
        s->prefix.prefix.s_addr = htonl(capn_read32(tmp_p, 0));
    }
}



void qcapn_VRFTableIter_write(const struct tbliter_v4 *s, capn_ptr p)
{
    capn_resolve(&p);
    
    {
        capn_ptr tempptr = capn_new_struct(p.seg, 8, 0);
        capn_write8(tempptr, 4, s->prefix.prefixlen);
        capn_write32(tempptr, 0, ntohl(s->prefix.prefix.s_addr));
        capn_setp(p, 0, tempptr);
    }
}

capn_ptr qcapn_new_VRFTableIter(struct capn_segment *s)
{
    return capn_new_struct(s, 0, 1);
}

void qcapn_BGPEventVRFRoute_read(struct bgp_event_vrf *s, capn_ptr p)
{
    capn_resolve(&p);
    s->announce = capn_read8(p, 0);
    *(uint64_t *)s->outbound_rd.val = capn_read64(p, 8);
    s->outbound_rd.family = AF_UNSPEC;
    s->outbound_rd.prefixlen = 64;

    {
        capn_ptr tmp_p = capn_getp(p, 0, 1);
        s->prefix.family = AF_INET;
        s->prefix.prefixlen = capn_read8(tmp_p, 4);
        s->prefix.prefix.s_addr = htonl(capn_read32(tmp_p, 0));
    }

    {
        capn_ptr tmp_p = capn_getp(p, 1, 1);
        s->nexthop.s_addr = htonl(capn_read32(tmp_p, 0));
    }
    s->label = capn_read32(p, 4);
}

void qcapn_BGPEventShut_read(struct bgp_event_shut *s, capn_ptr p)
{
    capn_resolve(&p);
    
    {
        capn_ptr tmp_p = capn_getp(p, 0, 1);
        s->peer.s_addr = htonl(capn_read32(tmp_p, 0));
    }
    s->type = capn_read8(p, 0);
    s->subtype = capn_read8(p, 1);
}

/* BGP flag manipulation.  */
int
bgp_flag_set (struct bgp *bgp, int flag)
{
  SET_FLAG (bgp->flags, flag);
  return 0;
}

int
bgp_flag_unset (struct bgp *bgp, int flag)
{
  UNSET_FLAG (bgp->flags, flag);
  return 0;
}

void qcapn_BGP_read(struct bgp *s, capn_ptr p)
{
    capn_resolve(&p);
    s->as = capn_read32(p, 0);
    { capn_text tp = capn_get_text(p, 0, capn_val0); free(s->name); s->name = strdup(tp.str); }

    {
        capn_ptr tmp_p = capn_getp(p, 1, 1);
        s->router_id_static.s_addr = htonl(capn_read32(tmp_p, 0));
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 4) & (1 << 0));
      if (tmp) s->flags |=  BGP_FLAG_ALWAYS_COMPARE_MED;
      else     s->flags &= ~BGP_FLAG_ALWAYS_COMPARE_MED;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 4) & (1 << 1));
      if (tmp) s->flags |=  BGP_FLAG_DETERMINISTIC_MED;
      else     s->flags &= ~BGP_FLAG_DETERMINISTIC_MED;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 4) & (1 << 2));
      if (tmp) s->flags |=  BGP_FLAG_MED_MISSING_AS_WORST;
      else     s->flags &= ~BGP_FLAG_MED_MISSING_AS_WORST;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 4) & (1 << 3));
      if (tmp) s->flags |=  BGP_FLAG_MED_CONFED;
      else     s->flags &= ~BGP_FLAG_MED_CONFED;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 4) & (1 << 4));
      if (tmp) s->flags |=  BGP_FLAG_NO_DEFAULT_IPV4;
      else     s->flags &= ~BGP_FLAG_NO_DEFAULT_IPV4;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 4) & (1 << 5));
      if (tmp) s->flags |=  BGP_FLAG_NO_CLIENT_TO_CLIENT;
      else     s->flags &= ~BGP_FLAG_NO_CLIENT_TO_CLIENT;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 4) & (1 << 6));
      if (tmp) s->flags |=  BGP_FLAG_ENFORCE_FIRST_AS;
      else     s->flags &= ~BGP_FLAG_ENFORCE_FIRST_AS;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 4) & (1 << 7));
      if (tmp) s->flags |=  BGP_FLAG_COMPARE_ROUTER_ID;
      else     s->flags &= ~BGP_FLAG_COMPARE_ROUTER_ID;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 5) & (1 << 0));
      if (tmp) s->flags |=  BGP_FLAG_ASPATH_IGNORE;
      else     s->flags &= ~BGP_FLAG_ASPATH_IGNORE;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 5) & (1 << 1));
      if (tmp) s->flags |=  BGP_FLAG_IMPORT_CHECK;
      else     s->flags &= ~BGP_FLAG_IMPORT_CHECK;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 5) & (1 << 2));
      if (tmp) s->flags |=  BGP_FLAG_NO_FAST_EXT_FAILOVER;
      else     s->flags &= ~BGP_FLAG_NO_FAST_EXT_FAILOVER;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 5) & (1 << 3));
      if (tmp) s->flags |=  BGP_FLAG_LOG_NEIGHBOR_CHANGES;
      else     s->flags &= ~BGP_FLAG_LOG_NEIGHBOR_CHANGES;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 5) & (1 << 4));
      if (tmp) s->flags |=  BGP_FLAG_GRACEFUL_RESTART;
      else     s->flags &= ~BGP_FLAG_GRACEFUL_RESTART;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 5) & (1 << 5));
      if (tmp) s->flags |=  BGP_FLAG_ASPATH_CONFED;
      else     s->flags &= ~BGP_FLAG_ASPATH_CONFED;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 5) & (1 << 6));
      if (tmp) s->flags |=  BGP_FLAG_ASPATH_MULTIPATH_RELAX;
      else     s->flags &= ~BGP_FLAG_ASPATH_MULTIPATH_RELAX;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 5) & (1 << 7));
      if (tmp) s->flags |=  BGP_FLAG_GR_PRESERVE_FWD;
      else    s->flags &= ~BGP_FLAG_GR_PRESERVE_FWD;
    }
    s->distance_ebgp = capn_read8(p, 6);
    s->distance_ibgp = capn_read8(p, 7);
    s->distance_local = capn_read8(p, 8);
    s->default_local_pref = capn_read32(p, 12);
    s->default_holdtime = capn_read32(p, 16);
    s->default_keepalive = capn_read32(p, 20);
    s->restart_time = capn_read32(p, 24);
    s->stalepath_time = capn_read32(p, 28);
    { capn_text tp = capn_get_text(p, 2, capn_val0); free(s->notify_zmq_url); s->notify_zmq_url = strdup(tp.str); }
}

