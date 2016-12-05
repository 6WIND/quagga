/*
 * derived from GPLv2+ sources
 */
#include <stdbool.h>
#include "capnp_c.h"
#include "bgp.bcapnp.h"

static const capn_text capn_val0 = {0, ""};


#include "zebra.h"
#include "bgpd.h"

afi_t qcapn_AfiSafiKey_get_afi(capn_ptr p)
{
    capn_resolve(&p);
    return capn_read8(p, 0);
}


safi_t qcapn_AfiSafiKey_get_safi(capn_ptr p)
{
    capn_resolve(&p);
    return capn_read8(p, 1);
}


capn_ptr qcapn_new_AfiSafiKey(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 0);
}


afi_t qcapn_AfiKey_get_afi(capn_ptr p)
{
    capn_resolve(&p);
    return capn_read8(p, 0);
}


capn_ptr qcapn_new_AfiKey(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 0);
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



void qcapn_VRFTableIter_set(struct tbliter_v4 *s, capn_ptr p)
{
    capn_resolve(&p);
    {
      /* MISSING: prefix */
    }
}


capn_ptr qcapn_new_VRFTableIter(struct capn_segment *s)
{
    return capn_new_struct(s, 0, 1);
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
      else     s->flags &= ~BGP_FLAG_GR_PRESERVE_FWD;
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



void qcapn_BGP_set(struct bgp *s, capn_ptr p)
{
    capn_resolve(&p);
    {
      /* MISSING: as */
    }
    {
      /* MISSING: name */
    }
    {
      struct in_addr router_id_static;
      
    {
        capn_ptr tmp_p = capn_getp(p, 1, 1);
        router_id_static.s_addr = htonl(capn_read32(tmp_p, 0));
    }
      bgp_router_id_static_set(s, router_id_static);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 4) & (1 << 0));
      if (flags) bgp_flag_set(s, BGP_FLAG_ALWAYS_COMPARE_MED);
	else bgp_flag_unset(s, BGP_FLAG_ALWAYS_COMPARE_MED);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 4) & (1 << 1));
      if (flags) bgp_flag_set(s, BGP_FLAG_DETERMINISTIC_MED);
	else bgp_flag_unset(s, BGP_FLAG_DETERMINISTIC_MED);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 4) & (1 << 2));
      if (flags) bgp_flag_set(s, BGP_FLAG_MED_MISSING_AS_WORST);
	else bgp_flag_unset(s, BGP_FLAG_MED_MISSING_AS_WORST);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 4) & (1 << 3));
      if (flags) bgp_flag_set(s, BGP_FLAG_MED_CONFED);
	else bgp_flag_unset(s, BGP_FLAG_MED_CONFED);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 4) & (1 << 4));
      if (flags) bgp_flag_set(s, BGP_FLAG_NO_DEFAULT_IPV4);
	else bgp_flag_unset(s, BGP_FLAG_NO_DEFAULT_IPV4);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 4) & (1 << 5));
      if (flags) bgp_flag_set(s, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	else bgp_flag_unset(s, BGP_FLAG_NO_CLIENT_TO_CLIENT);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 4) & (1 << 6));
      if (flags) bgp_flag_set(s, BGP_FLAG_ENFORCE_FIRST_AS);
	else bgp_flag_unset(s, BGP_FLAG_ENFORCE_FIRST_AS);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 4) & (1 << 7));
      if (flags) bgp_flag_set(s, BGP_FLAG_COMPARE_ROUTER_ID);
	else bgp_flag_unset(s, BGP_FLAG_COMPARE_ROUTER_ID);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 5) & (1 << 0));
      if (flags) bgp_flag_set(s, BGP_FLAG_ASPATH_IGNORE);
	else bgp_flag_unset(s, BGP_FLAG_ASPATH_IGNORE);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 5) & (1 << 1));
      if (flags) bgp_flag_set(s, BGP_FLAG_IMPORT_CHECK);
	else bgp_flag_unset(s, BGP_FLAG_IMPORT_CHECK);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 5) & (1 << 2));
      if (flags) bgp_flag_set(s, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	else bgp_flag_unset(s, BGP_FLAG_NO_FAST_EXT_FAILOVER);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 5) & (1 << 3));
      if (flags) bgp_flag_set(s, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	else bgp_flag_unset(s, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 5) & (1 << 4));
      if (flags) bgp_flag_set(s, BGP_FLAG_GRACEFUL_RESTART);
	else bgp_flag_unset(s, BGP_FLAG_GRACEFUL_RESTART);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 5) & (1 << 5));
      if (flags) bgp_flag_set(s, BGP_FLAG_ASPATH_CONFED);
	else bgp_flag_unset(s, BGP_FLAG_ASPATH_CONFED);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 5) & (1 << 6));
      if (flags) bgp_flag_set(s, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	else bgp_flag_unset(s, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
      
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 5) & (1 << 7));
      if (flags) bgp_flag_set(s, BGP_FLAG_GR_PRESERVE_FWD);
	else bgp_flag_unset(s, BGP_FLAG_GR_PRESERVE_FWD);
    }
    {
      u_int32_t default_local_pref;
      default_local_pref = capn_read32(p, 12);
      if (default_local_pref) { bgp_default_local_preference_set(s, default_local_pref); } else { bgp_default_local_preference_unset(s); }
      
    }
    {
      u_int32_t keepalive;
      u_int32_t holdtime;
      keepalive = capn_read32(p, 20);
      holdtime = capn_read32(p, 16);
      if (keepalive || holdtime) { bgp_timers_set(s, keepalive, holdtime); } else { bgp_timers_unset(s); }
      
      
    }
    {
      s->restart_time = capn_read32(p, 24);
    }
    {
      const char * notify_zmq_url;
      { capn_text tp = capn_get_text(p, 2, capn_val0); notify_zmq_url = tp.str; }
      bgp_notify_zmq_url_set(s, notify_zmq_url);
      
    }
    s->distance_ebgp = capn_read8(p, 6);
    s->distance_ibgp = capn_read8(p, 7);
    s->distance_local = capn_read8(p, 8);
    s->stalepath_time = capn_read32(p, 28);
    s->restart_time = capn_read32(p, 24);
}


as_t qcapn_BGP_get_as(capn_ptr p)
{
    capn_resolve(&p);
    return capn_read32(p, 0);
}


capn_ptr qcapn_new_BGP(struct capn_segment *s)
{
    return capn_new_struct(s, 32, 3);
}



void qcapn_BGPAfiSafi_read(struct bgp *s, capn_ptr p, afi_t afi, safi_t safi)
{
    capn_resolve(&p);
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 0));
      if (tmp) s->af_flags[afi][safi] |=  BGP_CONFIG_DAMPENING;
      else     s->af_flags[afi][safi] &= ~BGP_CONFIG_DAMPENING;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 1));
      if (tmp) s->af_flags[afi][safi] |=  BGP_CONFIG_ASPATH_MULTIPATH_RELAX;
      else     s->af_flags[afi][safi] &= ~BGP_CONFIG_ASPATH_MULTIPATH_RELAX;
    }
    { bool tmp;
      tmp = !!(capn_read8(p, 0) & (1 << 2));
      if (tmp) s->af_flags[afi][safi] |=  BGP_CONFIG_MULTIPATH;
      else     s->af_flags[afi][safi] &= ~BGP_CONFIG_MULTIPATH;
    }
}



void qcapn_BGPAfiSafi_write(const struct bgp *s, capn_ptr p, afi_t afi, safi_t safi)
{
    capn_resolve(&p);
    capn_write1(p, 0, !!(s->af_flags[afi][safi] & BGP_CONFIG_DAMPENING));
    capn_write1(p, 1, !!(s->af_flags[afi][safi] & BGP_CONFIG_ASPATH_MULTIPATH_RELAX));
    capn_write1(p, 2, !!(s->af_flags[afi][safi] & BGP_CONFIG_MULTIPATH));
}



void qcapn_BGPAfiSafi_set(struct bgp *s, capn_ptr p, afi_t afi, safi_t safi)
{
    capn_resolve(&p);
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 0) & (1 << 0));
      if (flags) bgp_af_flag_set(s, BGP_CONFIG_DAMPENING, afi, safi);
        else bgp_af_flag_unset(s, BGP_CONFIG_DAMPENING, afi, safi);
      flags = !!(capn_read8(p, 0) & (1 << 1));
      if (flags)
      {
        bgp_af_flag_set(s, BGP_CONFIG_ASPATH_MULTIPATH_RELAX, afi, safi);
      }
      else
      {
        bgp_af_flag_unset(s, BGP_CONFIG_ASPATH_MULTIPATH_RELAX, afi, safi);
      }
    }
    {
      u_int16_t flags;
      flags = !!(capn_read8(p, 0) & (1 << 2));
      if (flags)
      {
        uint8_t max = capn_read8(p, 3);
        bgp_af_flag_set(s, BGP_CONFIG_MULTIPATH, afi, safi);
        bgp_maximum_paths_set (s, AFI_IP, SAFI_MPLS_VPN,
                               BGP_PEER_EBGP, max);
        bgp_maximum_paths_set (s, AFI_IP, SAFI_MPLS_VPN,
                               BGP_PEER_IBGP, max);
        bgp_maximum_paths_set (s, AFI_IP, SAFI_UNICAST,
                               BGP_PEER_EBGP, max);
        bgp_maximum_paths_set (s, AFI_IP, SAFI_UNICAST,
                               BGP_PEER_IBGP, max);
      }
      else
      {
        bgp_af_flag_unset(s, BGP_CONFIG_MULTIPATH, afi, safi);
        bgp_maximum_paths_unset (s, AFI_IP, SAFI_MPLS_VPN,
                                 BGP_PEER_EBGP);
        bgp_maximum_paths_unset (s, AFI_IP, SAFI_MPLS_VPN,
                                 BGP_PEER_IBGP);
        bgp_maximum_paths_unset (s, AFI_IP, SAFI_UNICAST,
                                 BGP_PEER_EBGP);
        bgp_maximum_paths_unset (s, AFI_IP, SAFI_UNICAST,
                                 BGP_PEER_IBGP);
      }
    }
}


capn_ptr qcapn_new_BGPAfiSafi(struct capn_segment *s)
{
    return capn_new_struct(s, 16, 0);
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
        } else
        {
          tp.str = NULL;
          tp.len = 0;
        }
      capn_set_text(p, 2, tp);
    }
}



void qcapn_BGPPeer_set(struct peer *s, capn_ptr p)
{
    capn_resolve(&p);
    {
      /* MISSING: as */
    }
    {
      /* MISSING: host */
    }
    {
      const char * desc = NULL;
      {
        capn_text tp = capn_get_text(p, 1, capn_val0);
        if (tp.len)
          {
            desc = tp.str;
          }
        if (desc)
          {
            peer_description_set(s, desc);
          }
        else
          {
            peer_description_unset(s);
          }
      }
    }
    {
      unsigned port;
      port = capn_read16(p, 4);
      if (port) { peer_port_set(s, port); } else { peer_port_unset(s); }
      
    }
    {
      u_int32_t weight;
      weight = capn_read32(p, 8);
      if (weight) { peer_weight_set(s, weight); } else { peer_weight_unset(s); }
      
    }
    {
      u_int32_t keepalive;
      u_int32_t holdtime;
      keepalive = capn_read32(p, 16);
      holdtime = capn_read32(p, 12);
      if (keepalive || holdtime) { peer_timers_set(s, keepalive, holdtime); } else { peer_timers_unset(s); }
      
      
    }
    {
      u_int32_t flags;
      flags = !!(capn_read8(p, 6) & (1 << 0));
      if (flags) peer_flag_set(s, PEER_FLAG_PASSIVE);
	else peer_flag_unset(s, PEER_FLAG_PASSIVE);
      
    }
    {
      u_int32_t flags;
      flags = !!(capn_read8(p, 6) & (1 << 1));
      if (flags) peer_flag_set(s, PEER_FLAG_SHUTDOWN);
	else peer_flag_unset(s, PEER_FLAG_SHUTDOWN);
      
    }
    {
      u_int32_t flags;
      flags = !!(capn_read8(p, 6) & (1 << 2));
      if (flags) peer_flag_set(s, PEER_FLAG_DONT_CAPABILITY);
	else peer_flag_unset(s, PEER_FLAG_DONT_CAPABILITY);
      
    }
    {
      u_int32_t flags;
      flags = !!(capn_read8(p, 6) & (1 << 3));
      if (flags) peer_flag_set(s, PEER_FLAG_OVERRIDE_CAPABILITY);
	else peer_flag_unset(s, PEER_FLAG_OVERRIDE_CAPABILITY);
      
    }
    {
      u_int32_t flags;
      flags = !!(capn_read8(p, 6) & (1 << 4));
      if (flags) peer_flag_set(s, PEER_FLAG_STRICT_CAP_MATCH);
	else peer_flag_unset(s, PEER_FLAG_STRICT_CAP_MATCH);
      
    }
    {
      u_int32_t flags;
      flags = !!(capn_read8(p, 6) & (1 << 5));
      if (flags) peer_flag_set(s, PEER_FLAG_DYNAMIC_CAPABILITY);
	else peer_flag_unset(s, PEER_FLAG_DYNAMIC_CAPABILITY);
      
    }
    {
      u_int32_t flags;
      flags = !!(capn_read8(p, 6) & (1 << 6));
      if (flags) peer_flag_set(s, PEER_FLAG_DISABLE_CONNECTED_CHECK);
	else peer_flag_unset(s, PEER_FLAG_DISABLE_CONNECTED_CHECK);
      
    }
    {
      int ttl;
      ttl = capn_read32(p, 20);
      if (ttl) { peer_ebgp_multihop_set(s, ttl); } else { peer_ebgp_multihop_unset(s); }
      
    }
    {
      const char * update_source = NULL;
      int len;
      capn_text tp = capn_get_text(p, 2, capn_val0);
      update_source = tp.str;
      len = tp.len;
      if (update_source && len != 0)
        {
          union sockunion su;
          int ret = str2sockunion (update_source, &su);
          if (ret == 0)
            peer_update_source_addr_set (s, &su);
        }
      else
        {
          peer_update_source_unset (s);
        }
    }
}


as_t qcapn_BGPPeer_get_as(capn_ptr p)
{
    capn_resolve(&p);
    return capn_read32(p, 0);
}


const char * qcapn_BGPPeer_get_host(capn_ptr p)
{
    capn_resolve(&p);
    capn_text tp = capn_get_text(p, 0, capn_val0);; return tp.str;
}


capn_ptr qcapn_new_BGPPeer(struct capn_segment *s)
{
    return capn_new_struct(s, 24, 3);
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



void qcapn_BGPPeerAfiSafi_set(struct peer *s, capn_ptr p, afi_t afi, safi_t safi)
{
    capn_resolve(&p);
    {
      u_char afc;
      afc = !!(capn_read8(p, 0) & (1 << 0));
      peer_afc_set(s, afi, safi, afc);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 0) & (1 << 1));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_SEND_COMMUNITY);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_SEND_COMMUNITY);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 0) & (1 << 2));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_SEND_EXT_COMMUNITY);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_SEND_EXT_COMMUNITY);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 0) & (1 << 3));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_NEXTHOP_SELF);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_NEXTHOP_SELF);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 0) & (1 << 4));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_REFLECTOR_CLIENT);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_REFLECTOR_CLIENT);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 0) & (1 << 5));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_RSERVER_CLIENT);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_RSERVER_CLIENT);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 0) & (1 << 6));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_SOFT_RECONFIG);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_SOFT_RECONFIG);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 0) & (1 << 7));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_AS_PATH_UNCHANGED);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_AS_PATH_UNCHANGED);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 1) & (1 << 0));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_NEXTHOP_UNCHANGED);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_NEXTHOP_UNCHANGED);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 1) & (1 << 1));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_MED_UNCHANGED);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_MED_UNCHANGED);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 1) & (1 << 2));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_DEFAULT_ORIGINATE);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_DEFAULT_ORIGINATE);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 1) & (1 << 3));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 1) & (1 << 4));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_ALLOWAS_IN);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_ALLOWAS_IN);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 1) & (1 << 5));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_ORF_PREFIX_SM);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_ORF_PREFIX_SM);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 1) & (1 << 6));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_ORF_PREFIX_RM);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_ORF_PREFIX_RM);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 1) & (1 << 7));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_MAX_PREFIX);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_MAX_PREFIX);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 2) & (1 << 0));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_MAX_PREFIX_WARNING);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_MAX_PREFIX_WARNING);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 2) & (1 << 1));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
      
    }
    {
      u_int32_t af_flags;
      af_flags = !!(capn_read8(p, 2) & (1 << 2));
      if (af_flags) peer_af_flag_set(s, afi, safi, PEER_FLAG_NEXTHOP_SELF_ALL);
	else peer_af_flag_unset(s, afi, safi, PEER_FLAG_NEXTHOP_SELF_ALL);
      
    }
    {
      char allowas_in;
      allowas_in = capn_read8(p, 3);
      if (allowas_in) { peer_allowas_in_set(s, afi, safi, allowas_in); } else { peer_allowas_in_unset(s, afi, safi); }
      
    }
}


capn_ptr qcapn_new_BGPPeerAfiSafi(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 0);
}



void qcapn_BGPVRF_read(struct bgp_vrf *s, capn_ptr p)
{
    uint64_t tmp;

    capn_resolve(&p);
    tmp = capn_read64(p, 0);
    memcpy(&s->outbound_rd.val, &tmp, 8);
    s->outbound_rd.family = AF_UNSPEC;
    s->outbound_rd.prefixlen = 64;
    s->max_mpath = capn_read32(p, 8);
    {
        capn_ptr tmp_p = capn_getp(p, 0, 1);
        capn_list64 listptr = { .p = capn_getp(tmp_p, 0, 1) };
        size_t listsize = capn_len(listptr);
        uint64_t buf[listsize];
        capn_getv64(listptr, 0, buf, listsize);
        if (s->rt_import)
            ecommunity_unintern(&s->rt_import);
        s->rt_import = ecommunity_parse ((uint8_t *)buf, listsize * 8);
    }
    
    {
        capn_ptr tmp_p = capn_getp(p, 1, 1);
        capn_list64 listptr = { .p = capn_getp(tmp_p, 0, 1) };
        size_t listsize = capn_len(listptr);
        uint64_t buf[listsize];
        capn_getv64(listptr, 0, buf, listsize);
        if (s->rt_export)
            ecommunity_unintern(&s->rt_export);
        s->rt_export = ecommunity_parse ((uint8_t *)buf, listsize * 8);
    }
}



void qcapn_BGPVRF_write(const struct bgp_vrf *s, capn_ptr p)
{
    uint64_t tmp;

    memcpy(&tmp,&(s->outbound_rd.val), 8);
    capn_resolve(&p);
    capn_write64(p, 0, tmp);
    capn_write32(p, 8, s->max_mpath);
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



void qcapn_BGPVRF_set(struct bgp_vrf *s, capn_ptr p)
{
    capn_resolve(&p);
    {
      s->max_mpath = capn_read32(p, 8);
    }
    {
      /* MISSING: outbound_rd */
    }
    {
      struct ecommunity * rt_import;
      
    {
        capn_ptr tmp_p = capn_getp(p, 0, 1);
        capn_list64 listptr = { .p = capn_getp(tmp_p, 0, 1) };
        size_t listsize = capn_len(listptr);
        uint64_t buf[listsize];
        capn_getv64(listptr, 0, buf, listsize);
        rt_import = ecommunity_parse ((uint8_t *)buf, listsize * 8);
    }
      bgp_vrf_rt_import_set(s, rt_import);
      
        ecommunity_unintern(&rt_import);
    }
    {
      struct ecommunity * rt_export;
      
    {
        capn_ptr tmp_p = capn_getp(p, 1, 1);
        capn_list64 listptr = { .p = capn_getp(tmp_p, 0, 1) };
        size_t listsize = capn_len(listptr);
        uint64_t buf[listsize];
        capn_getv64(listptr, 0, buf, listsize);
        rt_export = ecommunity_parse ((uint8_t *)buf, listsize * 8);
    }
      bgp_vrf_rt_export_set(s, rt_export);
      
        ecommunity_unintern(&rt_export);
    }
}


struct prefix_rd qcapn_BGPVRF_get_outbound_rd(capn_ptr p)
{
    capn_resolve(&p);
    uint64_t tmp;
    struct prefix_rd tp;

    tp.family = AF_UNSPEC;
    tp.prefixlen = 64;
    tmp = capn_read64(p, 0);
    memcpy(&tp.val, &tmp, 8);
    return tp;
}


capn_ptr qcapn_new_BGPVRF(struct capn_segment *s)
{
    return capn_new_struct(s, 12, 2);
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



void qcapn_BGPVRFRoute_set(struct bgp_api_route *s, capn_ptr p)
{
    capn_resolve(&p);
    {
      /* MISSING: prefix */
    }
    {
      /* MISSING: nexthop */
    }
    {
      /* MISSING: label */
    }
}


capn_ptr qcapn_new_BGPVRFRoute(struct capn_segment *s, uint8_t extend_by)
{
    return capn_new_struct(s, CAPN_BGPVRF_ROUTE_DEF_SIZE + extend_by, 2);
}

void qcapn_BGPEventVRFRoute_read(struct bgp_event_vrf *s, capn_ptr p)
{
    uint64_t tmp;

    capn_resolve(&p);
    s->announce = capn_read8(p, 0);
    tmp = capn_read64(p, 8);
    memcpy(&s->outbound_rd.val, &tmp, 8);
    s->outbound_rd.family = AF_UNSPEC;
    s->outbound_rd.prefixlen = 64;

    {
       capn_ptr tmp_p = capn_getp(p, 0, 1);
       s->prefix.family = capn_read8(tmp_p, 0);
       s->prefix.prefixlen = capn_read8(tmp_p, 1);
       if (s->prefix.family == AF_INET)
         s->prefix.u.prefix4.s_addr = htonl(capn_read32(tmp_p, 2));
       else if (s->prefix.family == AF_INET6)
         {
           size_t i;
           u_char *in6 = (u_char*) &s->prefix.u.prefix6;

           for(i=0; i < sizeof(struct in6_addr); i++)
             in6[i] = capn_read8(tmp_p, i+2);
         }
       else if (s->prefix.family == AF_L2VPN)
          {
            uint8_t index = 2;

            qcapn_prefix_macip_read (tmp_p, &s->prefix, &index);
          }
    }

    {
        capn_ptr tmp_p = capn_getp(p, 1, 1);
        s->nexthop.s_addr = htonl(capn_read32(tmp_p, 0));
    }
    {
        capn_ptr tmp_p = capn_getp(p, 2, 1);
	s->label = capn_read32(tmp_p, 0);
	s->ethtag = capn_read32(tmp_p, 4);
        s->l2label = capn_read32(tmp_p, 8);
    }
    {
      const char * esi = NULL;
      int len;
      capn_text tp = capn_get_text(p, 3, capn_val0);
      esi = tp.str;
      len = tp.len;
      if (esi && len != 0)
        {
          s->esi = strdup(esi);
        }
      else
        {
          s->esi = NULL;
        }
    }
    {
      const char * mac_router = NULL;
      int len;
      capn_text tp = capn_get_text(p, 4, capn_val0);
      mac_router = tp.str;
      len = tp.len;
      if (mac_router && len != 0)
        {
          s->mac_router  = strdup(mac_router);
        }
      else
        {
          s->mac_router = NULL;
        }
    }
}



void qcapn_BGPEventVRFRoute_write(const struct bgp_event_vrf *s, capn_ptr p)
{
    uint64_t tmp;

    memcpy(&tmp,&(s->outbound_rd.val), 8);
    capn_resolve(&p);
    capn_write8(p, 0, s->announce);
    capn_write64(p, 8, tmp);
    
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
    {
        capn_ptr tempptr = capn_new_struct(p.seg, 12, 0);
	capn_write32(tempptr, 0, s->label);
	capn_write32(tempptr, 4, s->ethtag);
	capn_write32(tempptr, 8, s->l2label);
        capn_setp(p, 2, tempptr);
    }
    { capn_text tp = { .str = s->esi, .len = s->esi ? strlen((const char *)s->esi) : 0 }; capn_set_text(p, 3, tp); }
    { capn_text tp = { .str = s->mac_router, .len = s->mac_router ? strlen((const char *)s->mac_router) : 0 }; capn_set_text(p, 4, tp); }
}



void qcapn_BGPEventVRFRoute_set(struct bgp_event_vrf *s, capn_ptr p)
{
    capn_resolve(&p);
    {
      /* MISSING: announce */
    }
    {
      /* MISSING: outbound_rd */
    }
    {
      /* MISSING: prefix */
    }
    {
      /* MISSING: nexthop */
    }
    {
      /* MISSING: label */
    }
}


capn_ptr qcapn_new_BGPEventVRFRoute(struct capn_segment *s)
{
    return capn_new_struct(s, 16, 5);
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



void qcapn_BGPEventShut_write(const struct bgp_event_shut *s, capn_ptr p)
{
    capn_resolve(&p);
    
    {
        capn_ptr tempptr = capn_new_struct(p.seg, 8, 0);
        capn_write32(tempptr, 0, ntohl(s->peer.s_addr));
        capn_setp(p, 0, tempptr);
    }
    capn_write8(p, 0, s->type);
    capn_write8(p, 1, s->subtype);
}



void qcapn_BGPEventShut_set(struct bgp_event_shut *s, capn_ptr p)
{
    capn_resolve(&p);
    {
      /* MISSING: peer */
    }
    {
      /* MISSING: type */
    }
    {
      /* MISSING: subtype */
    }
}


capn_ptr qcapn_new_BGPEventShut(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 1);
}

capn_ptr qcapn_new_BGPVRFInfoIter(struct capn_segment *s)
{
    return capn_new_struct(s, 8, 0);
}

void qcapn_BGPVRFInfoIter_write(const unsigned long s, capn_ptr p, int offset)
{
    capn_resolve(&p);
    capn_write64(p, offset, s);
}

void qcapn_BGPVRFInfoIter_read(unsigned long *s, capn_ptr p, int offset)
{
    capn_resolve(&p);

    *s = capn_read64(p, offset);
}
