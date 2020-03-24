/* BGP routing information
   Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro

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

#include "prefix.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "str.h"
#include "log.h"
#include "routemap.h"
#include "buffer.h"
#include "sockunion.h"
#include "plist.h"
#include "thread.h"
#include "workqueue.h"
#include "hash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_encap_tlv.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_attr_evpn.h"

/* Extern from bgp_dump.c */
extern const char *bgp_origin_str[];
extern const char *bgp_origin_long_str[];

uint32_t bgp_process_main_lost, bgp_process_vrf_lost;
struct bgp_info *bgp_last_bgp_info_configured[AFI_MAX][SAFI_MAX];

static struct bgp_static * bgp_static_new (void);
static void bgp_static_free (struct bgp_static *bgp_static);
static void
bgp_static_withdraw_safi (struct bgp *bgp, struct prefix *p, afi_t afi,
                          safi_t safi, struct prefix_rd *prd,
                          uint32_t *labels, size_t nlabels);
static void
bgp_static_update_safi (struct bgp *bgp, struct prefix *p,
                        struct bgp_static *bgp_static, afi_t afi, safi_t safi);

static void
bgp_static_free (struct bgp_static *bgp_static);

static void
bgp_vrf_apply_new_imports_internal (struct bgp_vrf *vrf, afi_t afi, safi_t safi);

static void bgp_send_notification_to_sdn (afi_t afi, safi_t safi, struct bgp_node *rn,
                                          struct bgp_info *selected, uint8_t announce);

void
overlay_index_dup(struct attr *attr, struct overlay_index *src)
{
  if(!src)
    return;
  if(!attr->extra)
    bgp_attr_extra_get(attr);
  memcpy(&(attr->extra->evpn_overlay), src, sizeof(struct overlay_index));
  return;
}

static struct bgp_node *
bgp_afi_node_get (struct bgp_table *table, afi_t afi, safi_t safi, struct prefix *p,
		  struct prefix_rd *prd)
{
  struct bgp_node *rn;
  struct bgp_node *prn = NULL;
  
  assert (table);
  if (!table)
    return NULL;
  
  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP) ||
      (safi == SAFI_EVPN))
    {
      prn = bgp_node_get (table, (struct prefix *) prd);

      if (prn->info == NULL)
        {
          struct bgp_table *newtab = bgp_table_init (afi, safi);
          newtab->prd = *prd;
          newtab->type = table->type;
          newtab->owner = table->owner;
          prn->info = newtab;
        }
      else
	bgp_unlock_node (prn);
      table = prn->info;
    }

  rn = bgp_node_get (table, p);

  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP) ||
      (safi == SAFI_EVPN))
    rn->prn = prn;

  return rn;
}

/* Allocate bgp_info_extra */
struct bgp_info_extra *
bgp_info_extra_new (void)
{
  struct bgp_info_extra *new;
  new = XCALLOC (MTYPE_BGP_ROUTE_EXTRA, sizeof (struct bgp_info_extra));
  return new;
}

static void
bgp_info_extra_free (struct bgp_info_extra **extra)
{
  if (extra && *extra)
    {
      if ((*extra)->damp_info)
        bgp_damp_info_free ((*extra)->damp_info, 0);
      
      (*extra)->damp_info = NULL;
      
      XFREE (MTYPE_BGP_ROUTE_EXTRA, *extra);
      
      *extra = NULL;
    }
}

/* Get bgp_info extra information for the given bgp_info, lazy allocated
 * if required.
 */
struct bgp_info_extra *
bgp_info_extra_get (struct bgp_info *ri)
{
  if (!ri->extra)
    ri->extra = bgp_info_extra_new();
  return ri->extra;
}

/* Free bgp route information. */
static void
bgp_info_free (struct bgp_info *binfo)
{
  if (binfo->attr)
    bgp_attr_unintern (&binfo->attr);

  bgp_unlink_nexthop(binfo);
  bgp_info_extra_free (&binfo->extra);
  bgp_info_mpath_free (&binfo->mpath);

  peer_unlock (binfo->peer); /* bgp_info peer reference */

  XFREE (MTYPE_BGP_ROUTE, binfo);
}

struct bgp_info *
bgp_info_lock (struct bgp_info *binfo)
{
  binfo->lock++;
  return binfo;
}

struct bgp_info *
bgp_info_unlock (struct bgp_info *binfo)
{
  assert (binfo && binfo->lock > 0);
  binfo->lock--;
  
  if (binfo->lock == 0)
    {
#if 0
      zlog_debug ("%s: unlocked and freeing", __func__);
      zlog_backtrace (LOG_DEBUG);
#endif
      bgp_info_free (binfo);
      return NULL;
    }

#if 0
  if (binfo->lock == 1)
    {
      zlog_debug ("%s: unlocked to 1", __func__);
      zlog_backtrace (LOG_DEBUG);
    }
#endif
  
  return binfo;
}

void
bgp_info_add (struct bgp_node *rn, struct bgp_info *ri)
{
  struct bgp_info *top;

  top = rn->info;
  
  ri->next = rn->info;
  ri->prev = NULL;
  if (top)
    top->prev = ri;
  rn->info = ri;
  
  bgp_info_lock (ri);
  bgp_lock_node (rn);
  peer_lock (ri->peer); /* bgp_info peer reference */
}

/* Do the actual removal of info from RIB, for use by bgp_process 
   completion callback *only* */
static void
bgp_info_reap (struct bgp_node *rn, struct bgp_info *ri)
{
  if (ri->next)
    ri->next->prev = ri->prev;
  if (ri->prev)
    ri->prev->next = ri->next;
  else
    rn->info = ri->next;
  
  bgp_info_mpath_dequeue (ri);
  bgp_info_unlock (ri);
  bgp_unlock_node (rn);
}

void
bgp_info_delete (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_info_set_flag (rn, ri, BGP_INFO_REMOVED);
  /* set of previous already took care of pcount */
  UNSET_FLAG (ri->flags, BGP_INFO_VALID);
}

/* undo the effects of a previous call to bgp_info_delete; typically
   called when a route is deleted and then quickly re-added before the
   deletion has been processed */
static void
bgp_info_restore (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_info_unset_flag (rn, ri, BGP_INFO_REMOVED);
  /* unset of previous already took care of pcount */
  SET_FLAG (ri->flags, BGP_INFO_VALID);
}

/* Adjust pcount as required */   
static void
bgp_pcount_adjust (struct bgp_node *rn, struct bgp_info *ri)
{
  struct bgp_table *table;

  assert (rn && bgp_node_table (rn));
  assert (ri && ri->peer && ri->peer->bgp);

  table = bgp_node_table (rn);

  /* Ignore 'pcount' for RS-client tables */
  if (table->type != BGP_TABLE_MAIN
      || ri->peer == ri->peer->bgp->peer_self)
    return;
    
  if (!BGP_INFO_COUNTABLE (ri)
      && CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
    {
          
      UNSET_FLAG (ri->flags, BGP_INFO_COUNTED);
      
      /* slight hack, but more robust against errors. */
      if (ri->peer->pcount[table->afi][table->safi])
        ri->peer->pcount[table->afi][table->safi]--;
#if 0
      else
        {
          zlog_warn ("%s: Asked to decrement 0 prefix count for peer %s",
                     __func__, ri->peer->host);
          zlog_backtrace (LOG_WARNING);
          zlog_warn ("%s: Please report to Quagga bugzilla", __func__);
        }      
#endif
    }
  else if (BGP_INFO_COUNTABLE (ri)
           && !CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
    {
      SET_FLAG (ri->flags, BGP_INFO_COUNTED);
      ri->peer->pcount[table->afi][table->safi]++;
    }
}


/* Set/unset bgp_info flags, adjusting any other state as needed.
 * This is here primarily to keep prefix-count in check.
 */
void
bgp_info_set_flag (struct bgp_node *rn, struct bgp_info *ri, u_int32_t flag)
{
  SET_FLAG (ri->flags, flag);
  
  /* early bath if we know it's not a flag that changes countability state */
  if (!CHECK_FLAG (flag, BGP_INFO_VALID|BGP_INFO_HISTORY|BGP_INFO_REMOVED))
    return;
  
  bgp_pcount_adjust (rn, ri);
}

void
bgp_info_unset_flag (struct bgp_node *rn, struct bgp_info *ri, u_int32_t flag)
{
  UNSET_FLAG (ri->flags, flag);
  
  /* early bath if we know it's not a flag that changes countability state */
  if (!CHECK_FLAG (flag, BGP_INFO_VALID|BGP_INFO_HISTORY|BGP_INFO_REMOVED))
    return;
  
  bgp_pcount_adjust (rn, ri);
}

/* Get MED value.  If MED value is missing and "bgp bestpath
   missing-as-worst" is specified, treat it as the worst value. */
static u_int32_t
bgp_med_value (struct attr *attr, struct bgp *bgp)
{
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    return attr->med;
  else
    {
      if (bgp_flag_check (bgp, BGP_FLAG_MED_MISSING_AS_WORST))
	return BGP_MED_MAX;
      else
	return 0;
    }
}

/* Compare two bgp route entity.  Return -1 if new is preferred, 1 if exist
 * is preferred, or 0 if they are the same (usually will only occur if
 * multipath is enabled */
static int
bgp_info_cmp (struct bgp *bgp, struct bgp_info *new, struct bgp_info *exist,
              int *paths_eq, afi_t afi, safi_t safi)
{
  struct attr *newattr, *existattr;
  struct attr_extra *newattre, *existattre;
  bgp_peer_sort_t new_sort;
  bgp_peer_sort_t exist_sort;
  u_int32_t new_pref;
  u_int32_t exist_pref;
  u_int32_t new_med;
  u_int32_t exist_med;
  u_int32_t new_weight;
  u_int32_t exist_weight;
  uint32_t newm, existm;
  struct in_addr new_id;
  struct in_addr exist_id;
  int new_cluster;
  int exist_cluster;
  int internal_as_route;
  int confed_as_route;
  int ret;
  uint32_t new_mm_seqnum = 0, exist_mm_seqnum = 0;
  struct bgp_node *rn;

  *paths_eq = 0;

  /* 0. Null check. */
  if (new == NULL)
    return 1;
  if (exist == NULL)
    return -1;

  newattr = new->attr;
  existattr = exist->attr;
  newattre = newattr->extra;
  existattre = existattr->extra;

  /* For EVPN RT2 routes, we have to compare the MAC mobility
   * sequence number.
   */
  rn = new->net;
  if (rn && rn->p.family == AF_L2VPN &&
      rn->p.u.prefix_evpn.route_type == EVPN_MACIP_ADVERTISEMENT)
    {
      if (newattre)
        new_mm_seqnum = newattre->mm_seqnum;
      if (existattre)
        exist_mm_seqnum = existattre->mm_seqnum;

      if (new_mm_seqnum > exist_mm_seqnum)
        return -1;
      if (new_mm_seqnum < exist_mm_seqnum)
        return 1;

      /* If sequence numbers are the same, prefer the route from
       * the lowest IP.
       */
      if (new->peer == bgp->peer_self)
        {
          if (exist->peer->status == Established)
            ret = sockunion_cmp(exist->peer->su_local, &exist->peer->su);
          else
            ret = -1;
        }
      else if (exist->peer == bgp->peer_self)
        {
          if (new->peer->status == Established)
            ret = sockunion_cmp(&new->peer->su, new->peer->su_local);
          else
            ret = 1;
        }
      else
        {
          ret = sockunion_cmp(&new->peer->su, &exist->peer->su);
        }

      if (ret == 1)
        return 1;
      if (ret == -1)
        return -1;
    }

  /* 1. Weight check. */
  new_weight = exist_weight = 0;

  if (newattre)
    new_weight = newattre->weight;
  if (existattre)
    exist_weight = existattre->weight;

  if (new_weight > exist_weight)
    return -1;
  if (new_weight < exist_weight)
    return 1;

  /* 2. Local preference check. */
  new_pref = exist_pref = bgp->default_local_pref;

  if (newattr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    new_pref = newattr->local_pref;
  if (existattr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    exist_pref = existattr->local_pref;

  if (new_pref > exist_pref)
    return -1;
  if (new_pref < exist_pref)
    return 1;

  /* 3. Local route check. We prefer:
   *  - BGP_ROUTE_STATIC
   *  - BGP_ROUTE_AGGREGATE
   *  - BGP_ROUTE_REDISTRIBUTE
   */
  if (! (new->sub_type == BGP_ROUTE_NORMAL))
     return -1;
  if (! (exist->sub_type == BGP_ROUTE_NORMAL))
     return 1;

  /* 4. AS path length check. */
  if (! bgp_flag_check (bgp, BGP_FLAG_ASPATH_IGNORE))
    {
      int exist_hops = aspath_count_hops (existattr->aspath);
      int exist_confeds = aspath_count_confeds (existattr->aspath);
      
      if (bgp_flag_check (bgp, BGP_FLAG_ASPATH_CONFED))
	{
	  int aspath_hops;
	  
	  aspath_hops = aspath_count_hops (newattr->aspath);
          aspath_hops += aspath_count_confeds (newattr->aspath);
          
	  if ( aspath_hops < (exist_hops + exist_confeds))
	    return -1;
	  if ( aspath_hops > (exist_hops + exist_confeds))
	    return 1;
	}
      else
	{
	  int newhops = aspath_count_hops (newattr->aspath);
	  
	  if (newhops < exist_hops)
	    return -1;
          if (newhops > exist_hops)
	    return 1;
	}
    }

  /* 5. Origin check. */
  if (newattr->origin < existattr->origin)
    return -1;
  if (newattr->origin > existattr->origin)
    return 1;

  /* 6. MED check. */
  internal_as_route = (aspath_count_hops (newattr->aspath) == 0
		      && aspath_count_hops (existattr->aspath) == 0);
  confed_as_route = (aspath_count_confeds (newattr->aspath) > 0
		    && aspath_count_confeds (existattr->aspath) > 0
		    && aspath_count_hops (newattr->aspath) == 0
		    && aspath_count_hops (existattr->aspath) == 0);
  
  if (bgp_flag_check (bgp, BGP_FLAG_ALWAYS_COMPARE_MED)
      || (bgp_flag_check (bgp, BGP_FLAG_MED_CONFED)
	 && confed_as_route)
      || aspath_cmp_left (newattr->aspath, existattr->aspath)
      || aspath_cmp_left_confed (newattr->aspath, existattr->aspath)
      || internal_as_route)
    {
      new_med = bgp_med_value (new->attr, bgp);
      exist_med = bgp_med_value (exist->attr, bgp);

      if (new_med < exist_med)
	return -1;
      if (new_med > exist_med)
	return 1;
    }

  /* 7. Peer type check. */
  new_sort = new->peer->sort;
  exist_sort = exist->peer->sort;

  if (new_sort == BGP_PEER_EBGP
      && (exist_sort == BGP_PEER_IBGP || exist_sort == BGP_PEER_CONFED))
    return -1;
  if (exist_sort == BGP_PEER_EBGP
      && (new_sort == BGP_PEER_IBGP || new_sort == BGP_PEER_CONFED))
    return 1;

  /* 8. IGP metric check. */
  newm = existm = 0;

  if (new->extra)
    newm = new->extra->igpmetric;
  if (exist->extra)
    existm = exist->extra->igpmetric;

  if (newm < existm)
    return -1;
  if (newm > existm)
    return 1;

  /* 9. Maximum path check. */
  if (bgp_mpath_is_configured (bgp, afi, safi, new->net))
    {
      if (bgp_flag_check(bgp, BGP_FLAG_ASPATH_MULTIPATH_RELAX))
        {
          /*
           * For the two paths, all comparison steps till IGP metric
           * have succeeded - including AS_PATH hop count. Since 'bgp
           * bestpath as-path multipath-relax' knob is on, we don't need
           * an exact match of AS_PATH. Thus, mark the paths are equal.
           * That will trigger both these paths to get into the multipath
           * array.
           */
          *paths_eq = 1;
        }
      else if (new->peer->sort == BGP_PEER_IBGP)
        {
          if (aspath_cmp (new->attr->aspath, exist->attr->aspath)) {
            *paths_eq = 1;
          }
        }
      else if (new->peer->as == exist->peer->as) {
        *paths_eq = 1;
      }
    }

  /* 10. If both paths are external, prefer the path that was received
     first (the oldest one).  This step minimizes route-flap, since a
     newer path won't displace an older one, even if it was the
     preferred route based on the additional decision criteria below.  */
  if (! bgp_flag_check (bgp, BGP_FLAG_COMPARE_ROUTER_ID)
      && new_sort == BGP_PEER_EBGP
      && exist_sort == BGP_PEER_EBGP)
    {
      if (CHECK_FLAG (new->flags, BGP_INFO_SELECTED))
	return -1;
      if (CHECK_FLAG (exist->flags, BGP_INFO_SELECTED))
	return 1;
    }

  /* 11. Router-ID comparision. */
  /* If one of the paths is "stale", the corresponding peer router-id will
   * be 0 and would always win over the other path. If originator id is
   * used for the comparision, it will decide which path is better.
   */
  if (newattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
    new_id.s_addr = newattre->originator_id.s_addr;
  else
    new_id.s_addr = new->peer->remote_id.s_addr;
  if (existattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
    exist_id.s_addr = existattre->originator_id.s_addr;
  else
    exist_id.s_addr = exist->peer->remote_id.s_addr;

  if (ntohl (new_id.s_addr) < ntohl (exist_id.s_addr))
    return -1;
  if (ntohl (new_id.s_addr) > ntohl (exist_id.s_addr))
    return 1;

  /* 12. Cluster length comparision. */
  new_cluster = exist_cluster = 0;

  if (newattr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
    new_cluster = newattre->cluster->length;
  if (existattr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
    exist_cluster = existattre->cluster->length;

  if (new_cluster < exist_cluster)
    return -1;
  if (new_cluster > exist_cluster)
    return 1;

  /* 13. Neighbor address comparision. */
  /* Do this only if neither path is "stale" as stale paths do not have
   * valid peer information (as the connection may or may not be up).
   */
  if (CHECK_FLAG (exist->flags, BGP_INFO_STALE|BGP_INFO_STALE_REFRESH))
    return -1;
  if (CHECK_FLAG (new->flags, BGP_INFO_STALE|BGP_INFO_STALE_REFRESH))
    return 1;
  /* locally configured routes to advertise do not have su_remote */
  if (new->peer->su_remote == NULL)
    return 1;
  if (exist->peer->su_remote == NULL)
    return -1;
  
  ret = sockunion_cmp (new->peer->su_remote, exist->peer->su_remote);

  if (ret == 1)
    return 1;
  if (ret == -1)
    return -1;

  return -1;
}

static enum filter_type
bgp_input_filter (struct peer *peer, struct prefix *p, struct attr *attr,
		  afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;

  filter = &peer->filter[afi][safi];

#define FILTER_EXIST_WARN(F,f,filter) \
  if (BGP_DEBUG (update, UPDATE_IN) \
      && !(F ## _IN (filter))) \
    plog_warn (peer->log, "%s: Could not find configured input %s-list %s!", \
               peer->host, #f, F ## _IN_NAME(filter));
  
  if (DISTRIBUTE_IN_NAME (filter)) {
    FILTER_EXIST_WARN(DISTRIBUTE, distribute, filter);
      
    if (access_list_apply (DISTRIBUTE_IN (filter), p) == FILTER_DENY)
      return FILTER_DENY;
  }

  if (PREFIX_LIST_IN_NAME (filter)) {
    FILTER_EXIST_WARN(PREFIX_LIST, prefix, filter);
    
    if (prefix_list_apply (PREFIX_LIST_IN (filter), p) == PREFIX_DENY)
      return FILTER_DENY;
  }
  
  if (FILTER_LIST_IN_NAME (filter)) {
    FILTER_EXIST_WARN(FILTER_LIST, as, filter);
    
    if (as_list_apply (FILTER_LIST_IN (filter), attr->aspath)== AS_FILTER_DENY)
      return FILTER_DENY;
  }
  
  return FILTER_PERMIT;
#undef FILTER_EXIST_WARN
}

static enum filter_type
bgp_output_filter (struct peer *peer, struct prefix *p, struct attr *attr,
		   afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;

  filter = &peer->filter[afi][safi];

#define FILTER_EXIST_WARN(F,f,filter) \
  if (BGP_DEBUG (update, UPDATE_OUT) \
      && !(F ## _OUT (filter))) \
    plog_warn (peer->log, "%s: Could not find configured output %s-list %s!", \
               peer->host, #f, F ## _OUT_NAME(filter));

  if (DISTRIBUTE_OUT_NAME (filter)) {
    FILTER_EXIST_WARN(DISTRIBUTE, distribute, filter);
    
    if (access_list_apply (DISTRIBUTE_OUT (filter), p) == FILTER_DENY)
      return FILTER_DENY;
  }

  if (PREFIX_LIST_OUT_NAME (filter)) {
    FILTER_EXIST_WARN(PREFIX_LIST, prefix, filter);
    
    if (prefix_list_apply (PREFIX_LIST_OUT (filter), p) == PREFIX_DENY)
      return FILTER_DENY;
  }

  if (FILTER_LIST_OUT_NAME (filter)) {
    FILTER_EXIST_WARN(FILTER_LIST, as, filter);
    
    if (as_list_apply (FILTER_LIST_OUT (filter), attr->aspath) == AS_FILTER_DENY)
      return FILTER_DENY;
  }

  return FILTER_PERMIT;
#undef FILTER_EXIST_WARN
}

/* If community attribute includes no_export then return 1. */
static int
bgp_community_filter (struct peer *peer, struct attr *attr)
{
  if (attr->community)
    {
      /* NO_ADVERTISE check. */
      if (community_include (attr->community, COMMUNITY_NO_ADVERTISE))
	return 1;

      /* NO_EXPORT check. */
      if (peer->sort == BGP_PEER_EBGP &&
	  community_include (attr->community, COMMUNITY_NO_EXPORT))
	return 1;

      /* NO_EXPORT_SUBCONFED check. */
      if (peer->sort == BGP_PEER_EBGP
	  || peer->sort == BGP_PEER_CONFED)
	if (community_include (attr->community, COMMUNITY_NO_EXPORT_SUBCONFED))
	  return 1;
    }
  return 0;
}

/* Route reflection loop check.  */
static int
bgp_cluster_filter (struct peer *peer, struct attr *attr)
{
  struct in_addr cluster_id;

  if (attr->extra && attr->extra->cluster)
    {
      if (peer->bgp->config & BGP_CONFIG_CLUSTER_ID)
	cluster_id = peer->bgp->cluster_id;
      else
	cluster_id = peer->bgp->router_id;
      
      if (cluster_loop_check (attr->extra->cluster, cluster_id))
	return 1;
    }
  return 0;
}

static int
bgp_input_modifier (struct peer *peer, struct prefix *p, struct attr *attr,
		    afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;

  filter = &peer->filter[afi][safi];

  /* Apply default weight value. */
  if (peer->weight)
    (bgp_attr_extra_get (attr))->weight = peer->weight;
  /* Route map apply. */
  if (ROUTE_MAP_IN_NAME (filter))
    {
      /* Duplicate current value to new strucutre for modification. */
      info.peer = peer;
      info.attr = attr;

      SET_FLAG (peer->rmap_type, PEER_RMAP_TYPE_IN); 

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (ROUTE_MAP_IN (filter), p, RMAP_BGP, &info);

      peer->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
	/* caller has multiple error paths with bgp_attr_flush() */
	return RMAP_DENY;
    }
  return RMAP_PERMIT;
}

static int
bgp_export_modifier (struct peer *rsclient, struct peer *peer,
        struct prefix *p, struct attr *attr, afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;

  filter = &peer->filter[afi][safi];

  /* Route map apply. */
  if (ROUTE_MAP_EXPORT_NAME (filter))
    {
      /* Duplicate current value to new strucutre for modification. */
      info.peer = rsclient;
      info.attr = attr;

      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_EXPORT);

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (ROUTE_MAP_EXPORT (filter), p, RMAP_BGP, &info);

      rsclient->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
        {
          /* Free newly generated AS path and community by route-map. */
          bgp_attr_flush (attr);
          return RMAP_DENY;
        }
    }
  return RMAP_PERMIT;
}

static int
bgp_import_modifier (struct peer *rsclient, struct peer *peer,
        struct prefix *p, struct attr *attr, afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;

  filter = &rsclient->filter[afi][safi];

  /* Apply default weight value. */
  if (peer->weight)
    (bgp_attr_extra_get (attr))->weight = peer->weight;

  /* Route map apply. */
  if (ROUTE_MAP_IMPORT_NAME (filter))
    {
      /* Duplicate current value to new strucutre for modification. */
      info.peer = peer;
      info.attr = attr;

      SET_FLAG (peer->rmap_type, PEER_RMAP_TYPE_IMPORT);

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (ROUTE_MAP_IMPORT (filter), p, RMAP_BGP, &info);

      peer->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
        {
          /* Free newly generated AS path and community by route-map. */
          bgp_attr_flush (attr);
          return RMAP_DENY;
        }
    }
  return RMAP_PERMIT;
}

static int
bgp_announce_check (struct bgp_info *ri, struct peer *peer, struct prefix *p,
		    struct attr *attr, afi_t afi, safi_t safi)
{
  int ret;
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  struct peer *from;
  struct bgp *bgp;
  int transparent;
  int reflect;
  struct attr *riattr;

  from = ri->peer;
  filter = &peer->filter[afi][safi];
  bgp = peer->bgp;
  riattr = bgp_info_mpath_count (ri) ? bgp_info_mpath_attr (ri) : ri->attr;
  
  if (DISABLE_BGP_ANNOUNCE)
    return 0;

  /* Do not send announces to RS-clients from the 'normal' bgp_table. */
  if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
    return 0;

  /* Do not send back route to sender. */
  if (from == peer)
    return 0;

  /* Aggregate-address suppress check. */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      return 0;

  /* Default route check.  */
  if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE))
    {
      if (p->family == AF_INET && p->u.prefix4.s_addr == INADDR_ANY)
	return 0;
      else if (p->family == AF_INET6 && p->prefixlen == 0)
	return 0;
    }

  /* Transparency check. */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT)
      && CHECK_FLAG (from->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
    transparent = 1;
  else
    transparent = 0;

  /* If community is not disabled check the no-export and local. */
  if (! transparent && riattr && bgp_community_filter (peer, riattr))
    return 0;

  /* If the attribute has originator-id and it is same as remote
     peer's id. */
  if (riattr && riattr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      if (IPV4_ADDR_SAME (&peer->remote_id, &riattr->extra->originator_id))
	{
	  if (BGP_DEBUG (filter, FILTER))  
	    zlog (peer->log, LOG_DEBUG,
		  "%s [Update:SEND] %s/%d originator-id is same as remote router-id",
		  peer->host,
		  inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		  p->prefixlen);
	  return 0;
	}
    }
 
  /* ORF prefix-list filter check */
  if (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
      && (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
	  || CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
    if (peer->orf_plist[afi][safi])
      {
	if (prefix_list_apply (peer->orf_plist[afi][safi], p) == PREFIX_DENY)
          return 0;
      }

  /* Output filter check. */
  if (bgp_output_filter (peer, p, riattr, afi, safi) == FILTER_DENY)
    {
      if (BGP_DEBUG (filter, FILTER))
	zlog (peer->log, LOG_DEBUG,
	      "%s [Update:SEND] %s/%d is filtered",
	      peer->host,
	      inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	      p->prefixlen);
      return 0;
    }

#ifdef BGP_SEND_ASPATH_CHECK
  /* AS path loop check. */
  if (riattr && aspath_loop_check (riattr->aspath, peer->as))
    {
      if (BGP_DEBUG (filter, FILTER))  
        zlog (peer->log, LOG_DEBUG, 
	      "%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
	      peer->host, peer->as);
      return 0;
    }
#endif /* BGP_SEND_ASPATH_CHECK */

  /* If we're a CONFED we need to loop check the CONFED ID too */
  if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
    {
      if (riattr && aspath_loop_check(riattr->aspath, bgp->confed_id))
	{
	  if (BGP_DEBUG (filter, FILTER))  
	    zlog (peer->log, LOG_DEBUG, 
		  "%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
		  peer->host,
		  bgp->confed_id);
	  return 0;
	}      
    }

  /* Route-Reflect check. */
  if (from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP)
    reflect = 1;
  else
    reflect = 0;

  /* IBGP reflection check. */
  if (reflect)
    {
      /* A route from a Client peer. */
      if (CHECK_FLAG (from->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
	{
	  /* Reflect to all the Non-Client peers and also to the
             Client peers other than the originator.  Originator check
             is already done.  So there is noting to do. */
	  /* no bgp client-to-client reflection check. */
	  if (bgp_flag_check (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT))
	    if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
	      return 0;
	}
      else
	{
	  /* A route from a Non-client peer. Reflect to all other
	     clients. */
	  if (! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
	    return 0;
	}
    }
  
  /* For modify attribute, copy it to temporary structure. */
  if (riattr)
    bgp_attr_dup (attr, riattr);
  
  /* If local-preference is not set. */
  if ((peer->sort == BGP_PEER_IBGP
       || peer->sort == BGP_PEER_CONFED)
      && (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))))
    {
      attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
      attr->local_pref = bgp->default_local_pref;
    }

  /* If originator-id is not set and the route is to be reflected,
     set the originator id */
  if (peer && from && peer->sort == BGP_PEER_IBGP &&
      from->sort == BGP_PEER_IBGP &&
      (! (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))))
    {
      attr->extra = bgp_attr_extra_get(attr);
      IPV4_ADDR_COPY(&(attr->extra->originator_id), &(from->remote_id));
      SET_FLAG(attr->flag, BGP_ATTR_ORIGINATOR_ID);
    }

  /* Remove MED if its an EBGP peer - will get overwritten by route-maps */
  if (peer->sort == BGP_PEER_EBGP
      && attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    {
      if (ri->peer != bgp->peer_self && ! transparent
	  && ! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
	attr->flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC));
    }


#define NEXTHOP_IS_V4 (\
    (safi != SAFI_ENCAP && safi != SAFI_MPLS_VPN && p->family == AF_INET) || \
    ((safi == SAFI_ENCAP || safi == SAFI_MPLS_VPN) && attr->extra->mp_nexthop_len == 4))

#define NEXTHOP_IS_V6 (\
    (safi != SAFI_ENCAP && safi != SAFI_MPLS_VPN && p->family == AF_INET6) || \
    ((safi == SAFI_ENCAP || safi == SAFI_MPLS_VPN) && attr->extra->mp_nexthop_len == 16))

  /* next-hop-set */
  if (transparent
      || (reflect && ! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF_ALL))
      || (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_UNCHANGED)
	  && ((NEXTHOP_IS_V4 && attr->nexthop.s_addr)
	      || (NEXTHOP_IS_V6 &&
                  ! IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
	      )))
    {
      /* NEXT-HOP Unchanged. */
    }
  else if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF)
	   || (NEXTHOP_IS_V4 && attr->nexthop.s_addr == 0)
	   || (NEXTHOP_IS_V6 &&
               IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
	   || (peer->sort == BGP_PEER_EBGP
               && (bgp_multiaccess_check_v4 (attr->nexthop, peer) == 0)))
    {
      /* Set IPv4 nexthop. */
      if (NEXTHOP_IS_V4)
	{
	  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
              || (safi == SAFI_EVPN) || (safi == SAFI_LABELED_UNICAST))
	    memcpy (&attr->extra->mp_nexthop_global_in, &peer->nexthop.v4,
	            IPV4_MAX_BYTELEN);
	  else
	    memcpy (&attr->nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);
	}
      /* Set IPv6 nexthop. */
      if (NEXTHOP_IS_V6)
	{
	  /* IPv6 global nexthop must be included. */
	  memcpy (&attr->extra->mp_nexthop_global, &peer->nexthop.v6_global, 
		  IPV6_MAX_BYTELEN);
	  attr->extra->mp_nexthop_len = 16;
	}
    }

  if (p->family == AF_INET6 && safi != SAFI_ENCAP)
    {
      /* Left nexthop_local unchanged if so configured. */ 
      if ( CHECK_FLAG (peer->af_flags[afi][safi], 
           PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED) )
        {
          if ( IN6_IS_ADDR_LINKLOCAL (&attr->extra->mp_nexthop_local) )
            attr->extra->mp_nexthop_len=32;
          else
            attr->extra->mp_nexthop_len=16;
        }

      /* Default nexthop_local treatment for non-RS-Clients */
      else 
        {
      /* Link-local address should not be transit to different peer. */
      attr->extra->mp_nexthop_len = 16;

      /* Set link-local address for shared network peer. */
      if (peer->shared_network 
	  && ! IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
	{
	  memcpy (&attr->extra->mp_nexthop_local, &peer->nexthop.v6_local, 
		  IPV6_MAX_BYTELEN);
	  attr->extra->mp_nexthop_len = 32;
	}

      /* If bgpd act as BGP-4+ route-reflector, do not send link-local
	 address.*/
      if (reflect)
	attr->extra->mp_nexthop_len = 16;

      /* If BGP-4+ link-local nexthop is not link-local nexthop. */
      if (! IN6_IS_ADDR_LINKLOCAL (&peer->nexthop.v6_local))
	attr->extra->mp_nexthop_len = 16;
    }

    }

  /* If this is EBGP peer and remove-private-AS is set.  */
  if (peer->sort == BGP_PEER_EBGP
      && peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS)
      && aspath_private_as_check (attr->aspath))
    attr->aspath = aspath_empty_get ();

  /* Route map & unsuppress-map apply. */
  if (ROUTE_MAP_OUT_NAME (filter)
      || (ri->extra && ri->extra->suppress) )
    {
      struct bgp_info info;
      struct attr dummy_attr;
      struct attr_extra dummy_extra;

      dummy_attr.extra = &dummy_extra;

      info.peer = peer;
      info.attr = attr;

      /* The route reflector is not allowed to modify the attributes
	 of the reflected IBGP routes, unless configured to allow it */
      if ((from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP) &&
	  !bgp_flag_check(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
	{
	  bgp_attr_dup (&dummy_attr, attr);
	  info.attr = &dummy_attr;
	}

      SET_FLAG (peer->rmap_type, PEER_RMAP_TYPE_OUT); 

      if (ri->extra && ri->extra->suppress)
	ret = route_map_apply (UNSUPPRESS_MAP (filter), p, RMAP_BGP, &info);
      else
	ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info);

      peer->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
	{
	  bgp_attr_flush (attr);
	  return 0;
	}
    }
  return 1;
}

static int
bgp_announce_check_rsclient (struct bgp_info *ri, struct peer *rsclient,
        struct prefix *p, struct attr *attr, afi_t afi, safi_t safi)
{
  int ret;
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  struct bgp_info info;
  struct peer *from;
  struct attr *riattr;

  from = ri->peer;
  filter = &rsclient->filter[afi][safi];
  riattr = bgp_info_mpath_count (ri) ? bgp_info_mpath_attr (ri) : ri->attr;

  if (DISABLE_BGP_ANNOUNCE)
    return 0;

  /* Do not send back route to sender. */
  if (from == rsclient)
    return 0;

  /* Aggregate-address suppress check. */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      return 0;

  /* Default route check.  */
  if (CHECK_FLAG (rsclient->af_sflags[afi][safi],
          PEER_STATUS_DEFAULT_ORIGINATE))
    {
      if (p->family == AF_INET && p->u.prefix4.s_addr == INADDR_ANY)
        return 0;
      else if (p->family == AF_INET6 && p->prefixlen == 0)
        return 0;
    }

  /* If the attribute has originator-id and it is same as remote
     peer's id. */
  if (riattr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      if (IPV4_ADDR_SAME (&rsclient->remote_id, 
                          &riattr->extra->originator_id))
        {
         if (BGP_DEBUG (filter, FILTER))
           zlog (rsclient->log, LOG_DEBUG,
                 "%s [Update:SEND] %s/%d originator-id is same as remote router-id",
                 rsclient->host,
                 inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                 p->prefixlen);
         return 0;
       }
    }

  /* ORF prefix-list filter check */
  if (CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
      && (CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
         || CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
    if (rsclient->orf_plist[afi][safi])
      {
       if (prefix_list_apply (rsclient->orf_plist[afi][safi], p) == PREFIX_DENY)
          return 0;
      }

  /* Output filter check. */
  if (bgp_output_filter (rsclient, p, riattr, afi, safi) == FILTER_DENY)
    {
      if (BGP_DEBUG (filter, FILTER))
       zlog (rsclient->log, LOG_DEBUG,
             "%s [Update:SEND] %s/%d is filtered",
             rsclient->host,
             inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
             p->prefixlen);
      return 0;
    }

#ifdef BGP_SEND_ASPATH_CHECK
  /* AS path loop check. */
  if (aspath_loop_check (riattr->aspath, rsclient->as))
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog (rsclient->log, LOG_DEBUG,
             "%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
             rsclient->host, rsclient->as);
      return 0;
    }
#endif /* BGP_SEND_ASPATH_CHECK */

  /* For modify attribute, copy it to temporary structure. */
  bgp_attr_dup (attr, riattr);

  /* next-hop-set */
  if ((p->family == AF_INET && attr->nexthop.s_addr == 0)
          || (p->family == AF_INET6 &&
              IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
     )
  {
    /* Set IPv4 nexthop. */
    if (p->family == AF_INET)
      {
        if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
            || (safi == SAFI_LABELED_UNICAST)
            || (safi == SAFI_EVPN))
          memcpy (&attr->extra->mp_nexthop_global_in, &rsclient->nexthop.v4,
                  IPV4_MAX_BYTELEN);
        else
          memcpy (&attr->nexthop, &rsclient->nexthop.v4, IPV4_MAX_BYTELEN);
      }
    /* Set IPv6 nexthop. */
    if (p->family == AF_INET6)
      {
        /* IPv6 global nexthop must be included. */
        memcpy (&attr->extra->mp_nexthop_global, &rsclient->nexthop.v6_global,
                IPV6_MAX_BYTELEN);
        attr->extra->mp_nexthop_len = 16;
      }
  }

  if (p->family == AF_INET6)
    {
      struct attr_extra *attre = attr->extra;

      /* Left nexthop_local unchanged if so configured. */
      if ( CHECK_FLAG (rsclient->af_flags[afi][safi], 
           PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED) )
        {
          if ( IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local) )
            attre->mp_nexthop_len=32;
          else
            attre->mp_nexthop_len=16;
        }
        
      /* Default nexthop_local treatment for RS-Clients */
      else 
        { 
          /* Announcer and RS-Client are both in the same network */      
          if (rsclient->shared_network && from->shared_network &&
              (rsclient->ifindex == from->ifindex))
            {
              if ( IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local) )
                attre->mp_nexthop_len=32;
              else
                attre->mp_nexthop_len=16;
            }

          /* Set link-local address for shared network peer. */
          else if (rsclient->shared_network
              && IN6_IS_ADDR_LINKLOCAL (&rsclient->nexthop.v6_local))
            {
              memcpy (&attre->mp_nexthop_local, &rsclient->nexthop.v6_local,
                      IPV6_MAX_BYTELEN);
              attre->mp_nexthop_len = 32;
            }

          else
            attre->mp_nexthop_len = 16;
        }

    }

  /* If this is EBGP peer and remove-private-AS is set.  */
  if (rsclient->sort == BGP_PEER_EBGP
      && peer_af_flag_check (rsclient, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS)
      && aspath_private_as_check (attr->aspath))
    attr->aspath = aspath_empty_get ();

  /* Route map & unsuppress-map apply. */
  if (ROUTE_MAP_OUT_NAME (filter) || (ri->extra && ri->extra->suppress) )
    {
      info.peer = rsclient;
      info.attr = attr;

      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_OUT);

      if (ri->extra && ri->extra->suppress)
        ret = route_map_apply (UNSUPPRESS_MAP (filter), p, RMAP_BGP, &info);
      else
        ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info);

      rsclient->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
       {
         bgp_attr_flush (attr);
         return 0;
       }
    }

  return 1;
}

struct bgp_info_pair
{
  struct bgp_info *old;
  struct bgp_info *new;
};

static void
bgp_best_selection (struct bgp *bgp, struct bgp_node *rn,
		    struct bgp_info_pair *result,
		    afi_t afi, safi_t safi)
{
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info *ri;
  struct bgp_info *ri1;
  struct bgp_info *ri2;
  struct bgp_info *nextri = NULL;
  int cmpret, do_mpath;
  struct list mp_list;
  int paths_eq;
    
  result->old = result->new = NULL;
  
  if (rn->info == NULL)
    {
      char buf[PREFIX_STRLEN];
      zlog_warn ("%s: Called for route_node %s with no routing entries!",
                 __func__,
                 prefix2str (&(bgp_node_to_rnode (rn)->p), buf, sizeof(buf)));
      return;
    }
  
  bgp_mp_list_init (&mp_list);
  do_mpath = bgp_mpath_is_configured (bgp, afi, safi, rn);
  /* bgp deterministic-med */
  new_select = NULL;
  if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED))
    for (ri1 = rn->info; ri1; ri1 = ri1->next)
      {
        if (CHECK_FLAG (ri1->flags, BGP_INFO_VPN_HIDEN))
          continue;
	if (CHECK_FLAG (ri1->flags, BGP_INFO_DMED_CHECK))
	  continue;
	if (BGP_INFO_HOLDDOWN (ri1))
	  continue;
        if (ri1->peer && ri1->peer != bgp->peer_self)
          if (ri1->peer->status != Established)
            continue;

	new_select = ri1;
	old_select = CHECK_FLAG (ri1->flags, BGP_INFO_SELECTED) ? ri1 : NULL;
	if (ri1->next)
	  for (ri2 = ri1->next; ri2; ri2 = ri2->next)
	    {
              if (CHECK_FLAG (ri2->flags, BGP_INFO_VPN_HIDEN))
                continue;
	      if (CHECK_FLAG (ri2->flags, BGP_INFO_DMED_CHECK))
		continue;
	      if (BGP_INFO_HOLDDOWN (ri2))
		continue;
              if (ri2->peer &&
                  ri2->peer != bgp->peer_self &&
                  !CHECK_FLAG (ri2->peer->sflags, PEER_STATUS_NSF_WAIT))
                if (ri2->peer->status != Established)
                  continue;

	      if (aspath_cmp_left (ri1->attr->aspath, ri2->attr->aspath)
		  || aspath_cmp_left_confed (ri1->attr->aspath,
					     ri2->attr->aspath))
		{
		  if (CHECK_FLAG (ri2->flags, BGP_INFO_SELECTED))
		    old_select = ri2;
		  if ((cmpret = bgp_info_cmp (bgp, ri2, new_select, &paths_eq, afi, safi))
		       == -1)
		    {
		      bgp_info_unset_flag (rn, new_select, BGP_INFO_DMED_SELECTED);
		      new_select = ri2;
		    }

		  bgp_info_set_flag (rn, ri2, BGP_INFO_DMED_CHECK);
		}
	    }
	bgp_info_set_flag (rn, new_select, BGP_INFO_DMED_CHECK);
	bgp_info_set_flag (rn, new_select, BGP_INFO_DMED_SELECTED);
      }

  /* Check old selected route and new selected route. */
  old_select = NULL;
  new_select = NULL;
  for (ri = rn->info; (ri != NULL) && (nextri = ri->next, 1); ri = nextri)
    {
      if (!CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN) &&
          (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)))
	old_select = ri;

      if (BGP_INFO_HOLDDOWN (ri))
        {
          /* reap REMOVED routes, if needs be 
           * selected route must stay for a while longer though
           */
          if (CHECK_FLAG (ri->flags, BGP_INFO_REMOVED)
              && (ri != old_select))
            {
              struct bgp_vrf *vrf = NULL;
              if(rn)
                vrf = bgp_vrf_lookup_per_rn(bgp, afi, rn);
              if (vrf)
                bgp_vrf_update(vrf, afi, rn, ri, false);
              bgp_info_reap (rn, ri);
            }
          continue;
        }
      if (CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN))
        continue;
      if (ri->peer &&
          ri->peer != bgp->peer_self &&
          !CHECK_FLAG (ri->peer->sflags, PEER_STATUS_NSF_WAIT))
        if (ri->peer->status != Established)
          continue;

      if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED)
          && (! CHECK_FLAG (ri->flags, BGP_INFO_DMED_SELECTED)))
	{
	  bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_CHECK);
	  continue;
        }
      bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_CHECK);
      bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_SELECTED);

      if ((cmpret = bgp_info_cmp (bgp, ri, new_select, &paths_eq, afi, safi)) == -1)
	{
	  new_select = ri;
	}
    }
    
  /* Now that we know which path is the bestpath see if any of the other paths
   * qualify as multipaths
   */
  if (do_mpath && new_select)
    {
      for (ri = rn->info; (ri != NULL) && (nextri = ri->next, 1); ri = nextri)
        {
          if (ri == new_select)
            {
	      bgp_mp_list_add (&mp_list, ri);
              continue;
            }

          if (BGP_INFO_HOLDDOWN (ri))
            continue;

          if (ri->peer &&
              ri->peer != bgp->peer_self &&
              !CHECK_FLAG (ri->peer->sflags, PEER_STATUS_NSF_WAIT))
            if (ri->peer->status != Established)
              continue;

          if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED)
              && (! CHECK_FLAG (ri->flags, BGP_INFO_DMED_SELECTED)))
	      continue;

          bgp_info_cmp (bgp, ri, new_select, &paths_eq, afi, safi);

          if (paths_eq)
            {
	      bgp_mp_list_add (&mp_list, ri);
            }
        }
    }

  if (!bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED))
    bgp_info_mpath_update (rn, new_select, old_select, &mp_list, afi, safi);

  if(!( new_select && !CHECK_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG)))
    bgp_info_mpath_aggregate_update (new_select, old_select);
  bgp_mp_list_clear (&mp_list);

  result->old = old_select;
  result->new = new_select;

  return;
}

static int
bgp_process_announce_selected (struct peer *peer, struct bgp_info *selected,
                               struct bgp_node *rn, afi_t afi, safi_t safi)
{
  struct prefix *p;
  struct attr attr;
  struct attr_extra extra;

  memset (&attr, 0, sizeof(struct attr));
  memset (&extra, 0, sizeof(struct attr_extra));

  p = &rn->p;

  /* Announce route to Established peer. */
  if (peer->status != Established)
    return 0;

  /* Address family configuration check. */
  if (! peer->afc_nego[afi][safi])
    return 0;

  /* First update is deferred until ORF or ROUTE-REFRESH is received */
  if (CHECK_FLAG (peer->af_sflags[afi][safi],
      PEER_STATUS_ORF_WAIT_REFRESH))
    return 0;

  /* It's initialized in bgp_announce_[check|check_rsclient]() */
  attr.extra = &extra;

  switch (bgp_node_table (rn)->type)
    {
      case BGP_TABLE_MAIN:
      /* Announcement to peer->conf.  If the route is filtered,
         withdraw it. */
        if (selected && bgp_announce_check (selected, peer, p, &attr, afi, safi))
          bgp_adj_out_set (rn, peer, p, &attr, afi, safi, selected);
        else
          bgp_adj_out_unset (rn, peer, p, afi, safi);
        break;
      case BGP_TABLE_RSCLIENT:
        /* Announcement to peer->conf.  If the route is filtered, 
           withdraw it. */
        if (selected && 
            bgp_announce_check_rsclient (selected, peer, p, &attr, afi, safi))
          bgp_adj_out_set (rn, peer, p, &attr, afi, safi, selected);
        else
	  bgp_adj_out_unset (rn, peer, p, afi, safi);
        break;
      case BGP_TABLE_VRF:
        /* never called */
        assert (0);
    }

  bgp_attr_flush (&attr);
  return 0;
}

bool bgp_api_route_get_main (struct bgp_api_route *out, struct bgp_node *bn,
                             int iter_on_multipath, void **next)
{
  struct bgp_info *sel, *iter, *sel_start = NULL;

  memset(out, 0, sizeof (*out));
  if (bn->p.family == AF_ETHERNET)
    return false;
  if (!bn->info)
    return false;

  prefix_copy ((struct prefix *)&out->prefix, &bn->p);

  /* prepare sel_start with start of list to look for multipath entries */
  /* Since this function should be first called with iter_on_multipath set to 0 */
  /* sel_start should correspond to the start of the list */
  sel_start = bn->info;
  for (sel = bn->info; sel; sel = sel->next)
    {
      if (sel->type == ZEBRA_ROUTE_BGP
         && sel->sub_type == BGP_ROUTE_STATIC)
        continue;
      if (iter_on_multipath)
        {
          if (CHECK_FLAG (sel->flags, BGP_INFO_MULTIPATH) &&
              ! CHECK_FLAG (sel->flags, BGP_INFO_SELECTED))
            {
              sel_start = sel->next;
              break;
            }
        }
      else
        {
          if (CHECK_FLAG (sel->flags, BGP_INFO_SELECTED))
            break;
          /* continue to loop, as sel_start already inited before */
        }
    }

  if (!sel)
    return false;

  if (sel->attr && sel->attr->extra)
    {
      int af = NEXTHOP_FAMILY(sel->attr->extra->mp_nexthop_len);
      if (af == AF_INET)
      {
        out->nexthop.family = AF_INET;
        out->nexthop.prefixlen = IPV4_MAX_BITLEN;
        out->nexthop.u.prefix4 = sel->attr->nexthop;
      }
    else if (af == AF_INET6)
      {
        out->nexthop.family = AF_INET6;
        out->nexthop.prefixlen = IPV6_MAX_BITLEN;
        memcpy (&out->nexthop.u.prefix6, &sel->attr->extra->mp_nexthop_global, sizeof(struct in6_addr));
      }
    }
  if (sel->extra && sel->extra->nlabels)
    {
      int idx = 0;
      out->label = sel->extra->labels[idx] >> 4;
    }
  /* now that an entry with SELECTED flag was found, check for possibly MULTIPATH entries
     in next items */
  for (iter = sel_start; iter; iter = iter->next)
    if (CHECK_FLAG (iter->flags, BGP_INFO_MULTIPATH) &&
        ! CHECK_FLAG (iter->flags, BGP_INFO_SELECTED))
      {
        *next = iter;
        break;
      }
  return true;
}

bool bgp_api_route_get (struct bgp_vrf *vrf, struct bgp_api_route *out, struct bgp_node *bn,
                        int iter_on_multipath, void **next)
{
  struct bgp_info *sel, *iter, *sel_start = NULL;
  struct prefix *p;

  memset(out, 0, sizeof (*out));
  if (bn->p.family == AF_ETHERNET)
    return false;
  if (!bn->info)
    return false;
  p = &bn->p;
  if (p->family == AF_L2VPN &&
      p->u.prefix_evpn.route_type == EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
    return false;
  prefix_copy ((struct prefix *)&out->prefix, &bn->p);
  /* prepare sel_start with start of list to look for multipath entries */
  /* Since this function should be first called with iter_on_multipath set to 0 */
  /* sel_start should correspond to the start of the list */
  sel_start = bn->info;
  for (sel = bn->info; sel; sel = sel->next)
    {
      if(sel->type == ZEBRA_ROUTE_BGP
         && sel->sub_type == BGP_ROUTE_STATIC)
        continue;
      if (iter_on_multipath)
        {
          if (CHECK_FLAG (sel->flags, BGP_INFO_MULTIPATH) &&
              ! CHECK_FLAG (sel->flags, BGP_INFO_SELECTED))
            {
              sel_start = sel->next;
              break;
            }
        }
      else
        {
          if (CHECK_FLAG (sel->flags, BGP_INFO_SELECTED))
            break;
          /* continue to loop, as sel_start already inited before */
        }
    }

  if (!sel)
    return false;

  if (sel->attr && sel->attr->extra)
    {
      int af = NEXTHOP_FAMILY(sel->attr->extra->mp_nexthop_len);
      if (af == AF_INET)
      {
        out->nexthop.family = AF_INET;
        out->nexthop.prefixlen = IPV4_MAX_BITLEN;
        out->nexthop.u.prefix4 = sel->attr->extra->mp_nexthop_global_in;
      }
    else if (af == AF_INET6)
      {
        out->nexthop.family = AF_INET6;
        out->nexthop.prefixlen = IPV6_MAX_BITLEN;
        memcpy (&out->nexthop.u.prefix6, &sel->attr->extra->mp_nexthop_global, sizeof(struct in6_addr));
      }
    }
  if (sel->extra && sel->extra->nlabels)
    {
      int idx = 0;
      /* VRF RIB have one label only */
      if(CHECK_FLAG (sel->flags, BGP_INFO_ORIGIN_EVPN))
        {
          /* EVPN RT2/RT5 encode vni in label. encoding uses full 24 bits */
          if(vrf->ltype == BGP_LAYER_TYPE_3)
            out->label = sel->extra->labels[idx];
          else
            out->l2label = sel->extra->labels[idx];
        }
      else
        {
          if (sel->extra->nlabels > 1)
            out->l2label = sel->extra->labels[idx++] >> 4;
          out->label = sel->extra->labels[idx] >> 4;
        }
    }
  if(sel->attr && sel->attr->extra && CHECK_FLAG (sel->flags, BGP_INFO_ORIGIN_EVPN))
    {
      out->esi = esi2str(&(sel->attr->extra->evpn_overlay.eth_s_id));
      if (bn->p.family == AF_INET)
        {
          out->gatewayIp.family = AF_INET;
          out->gatewayIp.prefixlen = IPV4_MAX_BITLEN;
          out->gatewayIp.u.prefix4.s_addr = sel->attr->extra->evpn_overlay.gw_ip.ipv4.s_addr;
        }
      else if (bn->p.family == AF_INET6)
        {
          out->gatewayIp.family = AF_INET6;
          out->gatewayIp.prefixlen = IPV6_MAX_BITLEN;
          memcpy ( &(out->gatewayIp.u.prefix6),
                   &(sel->attr->extra->evpn_overlay.gw_ip.ipv6),
                   sizeof(struct in6_addr));
        }
      if (bn->p.family == AF_L2VPN)
        out->ethtag = bn->p.u.prefix_evpn.u.prefix_macip.eth_tag_id;
      else
        out->ethtag = sel->attr->extra->eth_t_id;
      /* only router mac is filled in for VRF RIB layer 3 */
      if(sel->attr->extra->ecommunity)
        {
          struct ecommunity_val *routermac = ecommunity_lookup (sel->attr->extra->ecommunity, 
                                                                ECOMMUNITY_ENCODE_EVPN,
                                                                ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC);

          out->mac_router = NULL;
          /* if routermac not present, try to replace it by def gw, if present */
          if(vrf->ltype == BGP_LAYER_TYPE_3)
            {
              if(routermac)
                  out->mac_router = ecom_mac2str(routermac->val);
              else
                {
                  if(ecommunity_lookup (sel->attr->extra->ecommunity,
                                        ECOMMUNITY_ENCODE_EVPN,
                                        ECOMMUNITY_EVPN_SUBTYPE_DEF_GW))
                    if ((bn->p).u.prefix_evpn.u.prefix_macip.mac_len == 8*ETHER_ADDR_LEN)
                  {
                    out->mac_router = ecom_mac2str((char *)(&(bn->p).u.prefix_evpn.u.prefix_macip.mac));
                  }
                }
            }
        }
    }
  /* now that an entry with SELECTED flag was found, check for possibly MULTIPATH entries
     in next items */
  for (iter = sel_start; iter; iter = iter->next)
    if (CHECK_FLAG (iter->flags, BGP_INFO_MULTIPATH) &&
        ! CHECK_FLAG (iter->flags, BGP_INFO_SELECTED))
      {
        *next = iter;
        break;
      }
  return true;
}

bool bgp_api_static_get (struct bgp_api_route *out, struct bgp_node *bn)
{
  struct bgp_static *bgp_static;

  memset(out, 0, sizeof (*out));
  if (bn->p.family != AF_INET)
    return false;
  if (!bn->info)
    return false;
  bgp_static = bn->info;

  prefix_copy ((struct prefix *)&out->prefix, &bn->p);
  {
    out->nexthop.family = AF_INET;
    out->nexthop.prefixlen = IPV4_MAX_BITLEN;
    out->nexthop.u.prefix4 = bgp_static->igpnexthop;
  }
  out->label = bgp_static->nlabels ? (bgp_static->labels[0] >> 4) : 0;
  return true;
}

static bool rd_same (const struct prefix_rd *a, const struct prefix_rd *b)
{
  return !memcmp(&a->val, &b->val, sizeof(a->val));
}

void bgp_vrf_clean_tables (struct bgp_vrf *vrf)
{
  afi_t afi;

  if (vrf->rib == NULL || vrf->route == NULL)
    return;
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      struct bgp_info *ri, *ri_next;
      struct bgp_node *rn;

      for (rn = bgp_table_top (vrf->rib[afi]); rn; rn = bgp_route_next (rn))
        for (ri = rn->info; ri; ri = ri_next)
          {
            ri_next = ri->next;
            bgp_vrf_update(vrf, afi, rn, ri, false);
            bgp_vrf_delete_vrf_update_global_rib (&(rn->p), ri, vrf, afi);
            bgp_info_reap (rn, ri);
          }
      bgp_table_finish (&vrf->rib[afi]);

      for (rn = bgp_table_top (vrf->route[afi]); rn; rn = bgp_route_next (rn))
        if (rn->info)
          {
            struct bgp_static *bs = rn->info;
            if(afi == AFI_L2VPN)
              bgp_static_withdraw_safi (vrf->bgp, &rn->p, afi, SAFI_EVPN,
                                        &vrf->outbound_rd, NULL, 0);
            else
              bgp_static_withdraw_safi (vrf->bgp, &rn->p, afi, SAFI_MPLS_VPN,
                                        &vrf->outbound_rd, NULL, 0);
            bgp_static_free (bs);
            rn->info = NULL;
            bgp_unlock_node (rn);
          }
      bgp_table_finish (&vrf->route[afi]);
    }
}

void bgp_vrf_enable_perafisafi (struct bgp_vrf *vrf, afi_t afi, safi_t safi)
{
  if (! vrf)
    return;

  if (afi != AFI_IP && afi != AFI_IP6)
    return;

  if (safi != SAFI_MPLS_VPN && safi != SAFI_EVPN)
    return;

  if (safi == SAFI_MPLS_VPN)
      bgp_vrf_update_global_rib_perafisafi(vrf, afi, safi);
  else
      bgp_vrf_update_global_rib_l2vpn(vrf, afi);
}

static void bgp_vrf_disable_perafi (struct bgp_vrf *vrf, afi_t afi)
{
  struct bgp_info *ri, *ri_next;
  struct bgp_node *rn;

  if (! vrf)
    return;

  for (rn = bgp_table_top (vrf->rib[afi]); rn; rn = bgp_route_next (rn))
    for (ri = rn->info; ri; ri = ri_next)
      {
        ri_next = ri->next;
        if (!CHECK_FLAG (ri->flags, BGP_INFO_ORIGIN_EVPN))
          {
            bgp_vrf_update(vrf, afi, rn, ri, false);
            bgp_vrf_delete_vrf_update_global_rib (&(rn->p), ri, vrf, afi);
            bgp_info_reap (rn, ri);
          }
      }
}

static void bgp_vrf_disable_l2vpn (struct bgp_vrf *vrf, afi_t afi)
{
  struct bgp_info *ri, *ri_next;
  struct bgp_node *rn;

  if (! vrf)
    return;

  for (rn = bgp_table_top (vrf->rib[afi]); rn; rn = bgp_route_next (rn))
    for (ri = rn->info; ri; ri = ri_next)
      {
        ri_next = ri->next;
        if (CHECK_FLAG (ri->flags, BGP_INFO_ORIGIN_EVPN))
          {
            bgp_vrf_update(vrf, afi, rn, ri, false);
            bgp_vrf_delete_vrf_update_global_rib (&(rn->p), ri, vrf, AFI_L2VPN);
            bgp_info_reap (rn, ri);
          }
      }
}

void bgp_vrf_disable_perafisafi (struct bgp_vrf *vrf, afi_t afi, safi_t safi)
{
  if (! vrf)
    return;

  if (afi != AFI_IP && afi != AFI_IP6)
    return;

  if (safi != SAFI_MPLS_VPN && safi != SAFI_EVPN)
    return;

  if (safi == SAFI_MPLS_VPN)
      bgp_vrf_disable_perafi (vrf, afi);
  else
      bgp_vrf_disable_l2vpn(vrf, afi);
}

/* Check if VRF route table is enabled for a given prefix */
static int check_vrf_enabled(struct bgp_vrf *vrf, afi_t afi, safi_t safi,
                             struct prefix *p)
{

  if (!vrf || !p)
    return 0;

  if (safi == SAFI_MPLS_VPN)
    return vrf->afc[afi][safi];

  if (safi == SAFI_EVPN)
    {
      afi_t afi_int = AFI_IP;

      if (p->family == AF_INET)
        afi_int = AFI_IP;
      else if (p->family == AF_INET6)
        afi_int = AFI_IP6;
      else if (p->family == AF_L2VPN)
        {
          if (IS_EVPN_RT3_PREFIX(p))
            /* VRF(AFI_IP, SAFI_EVPN) should be enabled for EVPN RT3 */
            afi_int = AFI_IP;
          else if (p->prefixlen == L2VPN_IPV6_PREFIX_LEN)
            afi_int = AFI_IP6;
          else
            afi_int = AFI_IP;
        }

      return vrf->afc[afi_int][safi];
    }

  return 0;
}

/* from draft-ietf-bess-evpn-inter-subnet-forwarding-01,
 * for EVPN, MAC/IP advertisement should be filtered
 * Label-1 = MPLS Label or VNID corresponding to MAC-VRF
 * Label-2 = MPLS Label or VNID corresponding to IP-VRF
 */
static void bgp_vrf_update_labels (struct bgp_vrf *vrf, struct bgp_node *rn, safi_t safi,
                                   struct bgp_info *selected, uint32_t *l3label, uint32_t *l2label)
{
  if (selected->extra->nlabels)
    {
      if (rn->p.family == AF_L2VPN)
        {
          if(vrf->ltype == BGP_LAYER_TYPE_3)
            {
              /* either select belongs to vrf table => only 1 label 
               * or it is part of global rib => 2 labels 
               */
              if(rn->table && bgp_node_table (rn) && bgp_node_table (rn)->type == BGP_TABLE_VRF)
                *l3label = selected->extra->labels[0];
              else
                {
                  if (selected->extra->labels[1])
                    *l3label = selected->extra->labels[1] >> 4;
                  else
                    *l3label = 0;
                }
              *l2label = 0;
            }
          else
            {
              *l2label = selected->extra->labels[0];
              *l3label = 0;
            }
        }
      else
        {
          /* EVPN RT5 encode vni in label. encoding uses full 24 bits */
          if(safi == SAFI_EVPN || CHECK_FLAG (selected->flags, BGP_INFO_ORIGIN_EVPN))
            {
              *l3label = selected->extra->labels[0];
            }
          else
            {
              *l3label = selected->extra->labels[0] >> 4;
            }
          *l2label = 0;
        }
    }
}

static void bgp_send_notification_to_sdn (afi_t afi, safi_t safi, struct bgp_node *rn,
                                          struct bgp_info *selected, uint8_t announce)
{
  struct bgp_event_vrf event;

  if (announce == true)
    {
      if(CHECK_FLAG (selected->flags, BGP_INFO_UPDATE_SENT))
        return;
    }
  else
    {
      /* if not already sent, do nothing */
      if(!CHECK_FLAG (selected->flags, BGP_INFO_UPDATE_SENT))
        return;
      if(CHECK_FLAG (selected->flags, BGP_INFO_WITHDRAW_SENT))
        return;
    }

  memset (&event, 0, sizeof (struct bgp_event_vrf));
  event.announce = announce;
  if (safi == SAFI_LABELED_UNICAST &&
      selected->extra && selected->extra->nlabels)
    event.label = selected->extra->labels[0] >> 4;

  prefix_copy (&event.prefix, &rn->p);

  if (BGP_DEBUG (events, EVENTS))
    {
      char pfx_str[PREFIX_STRLEN];
      char nh_str[BUFSIZ] = "<?>";
      char pre_str[20], post_str[20];

      prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
      if (rn->p.family == AF_INET)
        {
          strcpy (nh_str, inet_ntoa (selected->attr->nexthop));
        }
      else if (rn->p.family == AF_INET6)
        {
          inet_ntop (AF_INET6, &selected->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
        }

      if(selected->type == ZEBRA_ROUTE_BGP
         && selected->sub_type == BGP_ROUTE_STATIC)
        {
          sprintf (post_str, "by config");
          sprintf (pre_str, "mngr->bgp");
        }
      else
        {
          if (announce)
            sprintf (post_str, "to capnp manager");
          else
            sprintf (post_str, "from capnp manager");
          sprintf(pre_str, "bgp->mngr");
        }
      if (announce)
        zlog_info ("%s Route %s : advertised %s ( label %u nh %s)",
                    pre_str, pfx_str, post_str, event.label, nh_str);
      else
        zlog_info ("%s Route %s : withdrawn %s (label %d nh %s)",
                    pre_str, pfx_str, post_str, event.label, nh_str);
    }

  if(selected->type == ZEBRA_ROUTE_BGP
     && selected->sub_type == BGP_ROUTE_STATIC)
    return;
  if (afi == AFI_IP || afi == AFI_IP6)
    {
      if (rn->p.family == AF_INET)
        {
          event.nexthop.family = AF_INET;
          event.nexthop.prefixlen = IPV4_MAX_BITLEN;
          event.nexthop.u.prefix4 = selected->attr->nexthop;
        }
      else if (rn->p.family == AF_INET6)
        {
          event.nexthop.family = AF_INET6;
          event.nexthop.prefixlen = IPV6_MAX_BITLEN;
          memcpy (&event.nexthop.u.prefix6, 
                  &selected->attr->extra->mp_nexthop_global, sizeof(struct in6_addr));
        }
#ifdef HAVE_ZEROMQ
      bgp_notify_route (bgp_get_default (), &event);
#endif /* HAVE_ZEROMQ */
    }

  if (announce == true)
    {
      SET_FLAG (selected->flags, BGP_INFO_UPDATE_SENT);
      UNSET_FLAG (selected->flags, BGP_INFO_WITHDRAW_SENT);
    }
  else
    {
      SET_FLAG (selected->flags, BGP_INFO_WITHDRAW_SENT);
      UNSET_FLAG (selected->flags, BGP_INFO_UPDATE_SENT);
    }
}

/* messages sent to ODL to signify that an entry
 * has been selected, or unselected
 */
void
bgp_vrf_update (struct bgp_vrf *vrf, afi_t afi, struct bgp_node *rn,
                struct bgp_info *selected, uint8_t announce)
{
  char *esi = NULL, *mac_router = NULL;
  uint32_t ethtag = 0, l3label = 0, l2label = 0;
  int is_evpn_rt3 = 0;

  struct bgp_event_vrf event = {
    .announce         = announce,
    .outbound_rd      = vrf->outbound_rd,
    .tunnel_id        = NULL,
  };

  prefix_copy (&event.prefix, &rn->p);

  if(!vrf || (rn && bgp_node_table (rn)->type != BGP_TABLE_VRF))
    return;

  if(selected->type == ZEBRA_ROUTE_BGP
     && selected->sub_type == BGP_ROUTE_STATIC)
    return;

  if (announce == true)
    {
      if(CHECK_FLAG (selected->flags, BGP_INFO_UPDATE_SENT))
        return;
    }
  else
    {
      /* if not already sent, do nothing */
      if(!CHECK_FLAG (selected->flags, BGP_INFO_UPDATE_SENT))
        return;
      if(CHECK_FLAG (selected->flags, BGP_INFO_WITHDRAW_SENT))
        return;
    }

  if (CHECK_FLAG (selected->flags, BGP_INFO_ORIGIN_EVPN))
    {
      if (rn->p.u.prefix_evpn.route_type == EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
        {
          is_evpn_rt3 = 1;

          if (announce)
            event.announce = BGP_EVENT_PUSH_EVPN_RT;
          else
            event.announce = BGP_EVENT_WITHDRAW_EVPN_RT;
	  event.tunnel_type = INGRESS_REPLICATION;
	  event.label = selected->attr->label;
          /* set event.tunnel_id, TODO */
        }

      if (rn->p.family == AF_L2VPN)
        {
          if (is_evpn_rt3)
            ethtag = rn->p.u.prefix_evpn.u.prefix_imethtag.eth_tag_id;
          else
            ethtag = rn->p.u.prefix_evpn.u.prefix_macip.eth_tag_id;
        }
      else
        ethtag = selected->attr->extra->eth_t_id;

    }

  if (selected->extra)
    bgp_vrf_update_labels (vrf, rn, 0, selected, &(event.label), &(event.l2label));

  if (BGP_DEBUG (events, EVENTS))
    {
      char vrf_rd_str[RD_ADDRSTRLEN], rd_str[RD_ADDRSTRLEN], pfx_str[PREFIX_STRLEN];
      char label_str[BUFSIZ] = "<?>", nh_str[BUFSIZ] = "<?>";
      char pre_str[20], post_str[20];

      prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
      prefix_rd2str(&selected->extra->vrf_rd, rd_str, sizeof(rd_str));
      prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
      if (selected->extra->nlabels == 1)
        sprintf (label_str, "%d", event.label);
      else if (selected->extra->nlabels == 2)
        sprintf (label_str, "%d:%d", event.label, event.l2label);

      if (selected->attr && selected->attr->extra)
        {
          int af = NEXTHOP_FAMILY(selected->attr->extra->mp_nexthop_len);
          if (af == AF_INET)
            strcpy (nh_str, inet_ntoa (selected->attr->extra->mp_nexthop_global_in));
          else if (af == AF_INET6)
            inet_ntop (AF_INET6, &selected->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
        }

      if(selected->type == ZEBRA_ROUTE_BGP
         && selected->sub_type == BGP_ROUTE_STATIC)
        {
          sprintf (post_str, "by config");
          sprintf (pre_str, "mngr->bgp");
        }
      else
        {
          if (announce)
            sprintf (post_str, "to capnp manager");
          else
            sprintf (post_str, "from capnp manager");
          sprintf(pre_str, "bgp->mngr");
        }
      if (announce)
        zlog_info ("%s vrf[%s] Route %s%s : advertised %s (RD %s label %s nh %s)",
                    pre_str, vrf_rd_str, pfx_str, EVPN_RT3_STR(&rn->p),
                    post_str, rd_str, label_str, nh_str);
      else
        zlog_info ("%s vrf[%s] Route %s%s : withdrawn %s (RD %s label %d nh %s)",
                    pre_str, vrf_rd_str, pfx_str, EVPN_RT3_STR(&rn->p),
                    post_str, rd_str, event.label, nh_str);

      if(CHECK_FLAG (selected->flags, BGP_INFO_ORIGIN_EVPN))
        {
          esi = esi2str(&(selected->attr->extra->evpn_overlay.eth_s_id));

          if(selected->extra)
            bgp_vrf_update_labels (vrf, rn, 0, selected, &l3label, &l2label);

          if(selected->attr && selected->attr->extra && selected->attr->extra->ecommunity)
            {
              /* only router mac is filled in for VRF RIB layer 3 */
              if(vrf->ltype == BGP_LAYER_TYPE_3)
                {
                  /* import routermac */
                  struct ecommunity_val *routermac = ecommunity_lookup (selected->attr->extra->ecommunity,
                                                                        ECOMMUNITY_ENCODE_EVPN,
                                                                        ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC);
                  if(routermac)
                    mac_router = ecom_mac2str(routermac->val);
                  else
                    {
                      if(ecommunity_lookup (selected->attr->extra->ecommunity,
                                            ECOMMUNITY_ENCODE_EVPN,
                                            ECOMMUNITY_EVPN_SUBTYPE_DEF_GW))
                        if ((rn->p).u.prefix_evpn.u.prefix_macip.mac_len == 8*ETHER_ADDR_LEN)
                          {
                            mac_router = ecom_mac2str((char *)(&(rn->p).u.prefix_evpn.u.prefix_macip.mac));
                          }
                    }
                }
            }
          if(vrf->ltype == BGP_LAYER_TYPE_3)
            zlog_debug ("vrf[layer3] pfx %s%s ethtag %u esi %s  mac_router %s label l3 %u",
                        pfx_str, EVPN_RT3_STR(&rn->p), ethtag,
                        esi == NULL?"<none>":esi,
                        mac_router == NULL?"<none>":mac_router,
                        l3label);
          else
            zlog_debug ("vrf[layer2] pfx %s%s ethtag %u esi %s  label l2 %u",
                        pfx_str, EVPN_RT3_STR(&rn->p), ethtag,
                        esi == NULL?"<none>":esi,
                        l2label);
          if (esi)
            XFREE (MTYPE_BGP_ESI, esi);
          if (mac_router)
            XFREE (MTYPE_BGP_MAC, mac_router);
        }
    }

  if (afi == AFI_IP || afi == AFI_IP6 || afi == AFI_L2VPN)
    {
      if (selected->attr && selected->attr->extra)
        {
          int af = NEXTHOP_FAMILY(selected->attr->extra->mp_nexthop_len);
          if (af == AF_INET)
            {
              event.nexthop.family = AF_INET;
              event.nexthop.prefixlen = IPV4_MAX_BITLEN;
              event.nexthop.u.prefix4 = selected->attr->extra->mp_nexthop_global_in;
            }
          else if (af == AF_INET6)
            {
              event.nexthop.family = AF_INET6;
              event.nexthop.prefixlen = IPV6_MAX_BITLEN;
              memcpy (&event.nexthop.u.prefix6, 
                      &selected->attr->extra->mp_nexthop_global, sizeof(struct in6_addr));
            }
          /* get routermac if origin evpn */
          if(CHECK_FLAG (selected->flags, BGP_INFO_ORIGIN_EVPN))
            {
              char gw_str[BUFSIZ];
              event.esi = esi2str(&(selected->attr->extra->evpn_overlay.eth_s_id));
              event.ethtag = ethtag;

              if ( (rn->p.family == AF_INET) || (rn->p.family == AF_INET6))
                {
                  if (selected->attr->extra->evpn_overlay.gw_ip.ipv4.s_addr != 0)
                    event.gatewayIp = inet_ntop(rn->p.family, &(selected->attr->extra->evpn_overlay.gw_ip.ipv4),
						gw_str, (socklen_t)BUFSIZ);
                  else
                    event.gatewayIp = NULL;
                }
              else
                {
                    event.gatewayIp = NULL;
                }
            }
          else
            {
              event.esi = NULL;
            }
        }
      if (announce)
        {
          if(selected->attr && selected->attr->extra && selected->attr->extra->ecommunity)
            {
              /* only router mac is filled in for VRF RIB layer 3 */
              if(vrf->ltype == BGP_LAYER_TYPE_3)
                {
                  /* import routermac */
                  struct ecommunity_val *routermac = ecommunity_lookup (selected->attr->extra->ecommunity,
                                                                        ECOMMUNITY_ENCODE_EVPN,
                                                                        ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC);
                  if(routermac)
                    event.mac_router = ecom_mac2str(routermac->val);
                  else
                    {
                      event.mac_router = NULL;
                      if(ecommunity_lookup (selected->attr->extra->ecommunity,
                                            ECOMMUNITY_ENCODE_EVPN,
                                            ECOMMUNITY_EVPN_SUBTYPE_DEF_GW))
                        if (                            (rn->p).u.prefix_evpn.u.prefix_macip.mac_len == 8*ETHER_ADDR_LEN)
                          {
                            event.mac_router = ecom_mac2str((char *)(&(rn->p).u.prefix_evpn.u.prefix_macip.mac));
                          }
                    }
                }
              else
                event.mac_router = NULL;
            }
          else
            event.mac_router = NULL;
        }
      else
        {
          event.mac_router = NULL;
          if (rn->p.family == AF_L2VPN)
            {
              event.ethtag = ethtag;
            }
        }
#ifdef HAVE_ZEROMQ
      bgp_notify_route (vrf->bgp, &event);
#endif /* HAVE_ZEROMQ */
    }

  if (announce == true)
    {
      SET_FLAG (selected->flags, BGP_INFO_UPDATE_SENT);
      UNSET_FLAG (selected->flags, BGP_INFO_WITHDRAW_SENT);
    }
  else
    {
      SET_FLAG (selected->flags, BGP_INFO_WITHDRAW_SENT);
      UNSET_FLAG (selected->flags, BGP_INFO_UPDATE_SENT);
    }

  if (event.mac_router)
    XFREE (MTYPE_BGP_MAC, event.mac_router);
  if (event.esi)
    XFREE (MTYPE_BGP_ESI, event.esi);
}

int
bgp_vrf_static_set (struct bgp_vrf *vrf, afi_t afi, const struct bgp_api_route *route)
{
  struct bgp_static *bgp_static;
  struct prefix *p = (struct prefix *)&route->prefix;
  struct bgp_node *rn;
  struct prefix def_route;
  struct prefix def_route_ipv6;
  safi_t safi;

  if ((afi != AFI_IP) && (afi != AFI_IP6) && (afi != AFI_L2VPN))
    return -1;
  if(afi == AFI_L2VPN)
    safi = SAFI_EVPN;
  else
    {
      if (route->l2label == SAFI_LABELED_UNICAST)
        safi = SAFI_LABELED_UNICAST;
      else
        safi = SAFI_MPLS_VPN;
    }
  /* detect Auto Discovery message */
  if ((safi == SAFI_EVPN) && PREFIX_IS_L2VPN_AD(p))
    {
      struct bgp *bgp;
      struct listnode *iter;
      struct listnode *node;
      int ret = -1;
      struct peer *peer;

      bgp = vrf->bgp;

      /* We should find peer list linked to this RD
       * Notify any issue related to peer list before emitting A/D
       */
      for (ALL_LIST_ELEMENTS_RO(bgp->peer, iter, peer))
        {
          if (peer && peer->status != Established && peer->afc_nego[afi][safi])
            {
              zlog_err("Can't send EVPN Auto-Discovery to Idle host %s",
                       peer->host);
              return -1;
            }
        }

      for (ALL_LIST_ELEMENTS_RO(bgp->peer, iter, peer))
        {
          /* Only send UPDATE messages to EVPN peers within same ESI */
          if (peer && peer->status == Established && peer->afc_nego[afi][safi])
            {
              struct bgp_evpn_ad *ad, *ad_found = NULL;
              u_int32_t ethtag = p->u.prefix_evpn.u.prefix_macip.eth_tag_id;
              struct eth_segment_id esi;
              uint32_t ret2 = 1;

              str2esi(route->esi, &esi);
              /* As soon as we enter that loop we consider it's a success unless
               * there is no more memory left for creating new ad */
              ret = 0;

              /* Store A/D message before sending */

              /* lookup for A/D in list matching same parameters */
              /* can't use listnode_lookup since it checks for exact pointer
                 within list which is not possible here */
              for (ALL_LIST_ELEMENTS_RO(vrf->static_evpn_ad, node, ad))
                {
                  if (0 == bgp_evpn_ad_cmp(ad, peer, &vrf->outbound_rd,
                                           &esi, ethtag))
                    {
                      ad_found = ad;
                      ret2 = bgp_evpn_ad_update (ad, (struct in_addr*) &route->nexthop.u.prefix4,
                                                 route->l2label);

                      break;
                    }
                }
              /* update data in recorded ad
               * if no change, then no need to send a/d again.
               * goto next peer
               */
              if (!ret2)
                continue;

              /* the A/D was not found, then record it in list */
              if (!ad_found)
                {
                  ad_found = bgp_evpn_ad_new(peer, vrf,
                                             &esi, ethtag,
                                             (struct prefix *)&route->nexthop,
                                             route->l2label);
                  if (!ad_found)
                    {
                      zlog_err("Not enough memory to store AD message for ESI %s!", route->esi);
                      return -1;
                    }

                  listnode_add(vrf->static_evpn_ad, ad_found);
                }
              peer_evpn_auto_discovery_set (peer, vrf, ad_found->attr,
                                            &esi, ethtag,
                                            route->l2label);
            }
        }
      return ret;
    }

  str2prefix ("0.0.0.0/0", &def_route);
  str2prefix ("::/0", &def_route_ipv6);

  /* if we try to install a default route, set flag accordingly */
  if ( ( (0 == prefix_cmp(&def_route, p)) ||
         (0 == prefix_cmp(&def_route_ipv6, p))) &&
       ( (safi == SAFI_MPLS_VPN) || (safi == SAFI_EVPN)) && !IS_EVPN_RT3_PREFIX(p))
    {
      struct bgp_vrf *v;
      struct bgp *bgp;
      struct listnode *iter;
      int ret = -1;

      /* list all peers that have VPNv4 family enabled */
      bgp = vrf->bgp;

      /* Lookup in list of configured VRF with Route Distinguisher given as parameter */
      v = (struct bgp_vrf*) listnode_lookup(bgp->vrfs, vrf);
      if (v)
        {
          /* We should find peer list linked to this RD */
          for (iter = listhead(bgp->peer); iter; iter = listnextnode(iter))
            {
              struct peer *peer;

              /* Retrieve peer and set DEFAULT_ORIGINATE flag */
              peer = listgetdata(iter);
              /* Only send UPDATE messages to VPNv4 and EVPN and VPNv6 peers */
              if (peer && peer->status == Established && peer->afc_nego[afi][safi])
                {
                  SET_FLAG (peer->af_flags[afi][safi], PEER_FLAG_DEFAULT_ORIGINATE);
                  peer_default_originate_set_rd (peer, &vrf->outbound_rd, afi, safi, route);
                  ret = 0;
                }
            }
        }
      return ret;
    }

  bgp_static = bgp_static_new ();
  bgp_static->bgp_encapsulation_type = BGP_ENCAPSULATION_VXLAN;
  bgp_static->backdoor = 0;
  bgp_static->valid = 1;
  bgp_static->igpmetric = 0;

  if (IS_EVPN_RT3_PREFIX(p))
    {
        bgp_static->pmsi_tunnel_id_ingress_replication = true;
        /* by default: nexthop bgp router id */
        bgp_static->igpnexthop = vrf->bgp->router_id;
        bgp_static->nlabels = 0;
    }
  else
    {
      if (route->nexthop.family == AF_INET)
        bgp_static->igpnexthop = route->nexthop.u.prefix4;
      else if (route->nexthop.family == AF_INET6)
        memcpy (&bgp_static->ipv6nexthop, &route->nexthop.u.prefix6, sizeof(struct in6_addr));

      prefix_copy (&(bgp_static->gatewayIp), &(route->gatewayIp));
      if (route->label != 0xFFFFFFFF)
        {
          if (safi == SAFI_EVPN)
            {
              /* EVPN RT2/RT5 encode vni in label. encoding uses full 24 bits */
              bgp_static->labels[0] = route->label;
            } else {
              bgp_static->labels[0] = (route->label << 4) | 1;
            }
           bgp_static->nlabels = 1;
        }
      else
        bgp_static->nlabels = 0;
    }

  if (vrf)
    {
      bgp_static->prd = vrf->outbound_rd;
      bgp_static->ecomm = vrf->rt_export;
      if (IS_EVPN_RT3_PREFIX(p) && route->rt_export)
        bgp_static->ecomm = route->rt_export;
    }
  if(afi == AFI_L2VPN)
    {
      if(route->esi)
        {
          bgp_static->eth_s_id = XCALLOC (MTYPE_ATTR, sizeof(struct eth_segment_id));
          str2esi (route->esi, bgp_static->eth_s_id);
        }

      if (IS_EVPN_RT3_PREFIX(p))
        bgp_static->eth_t_id = p->u.prefix_evpn.u.prefix_imethtag.eth_tag_id;
      else
        bgp_static->eth_t_id = route->ethtag;

      if(route->mac_router)
        {
          bgp_static->router_mac = XCALLOC (MTYPE_ATTR, MAC_LEN+1);
          str2mac ((const char *)route->mac_router, bgp_static->router_mac);
        }
      if(p->family == AF_L2VPN && !IS_EVPN_RT3_PREFIX(p))
        {
          /* case of RT2 route, l2 label must be considered as mpls label 1 in message */
          if ( (vrf->ltype != BGP_LAYER_TYPE_3) && (route->l2label != 0))
            {
              /* EVPN RT2 encode vni in label. encoding uses full 24 bits */
              bgp_static->labels[0] = route->l2label;
              if (route->label && route->label != 0xffffffff)
                  {
                     bgp_static->labels[1] = (route->label << 4) | 1;
                     bgp_static->nlabels++;
                  }
            }
        }
    }
  if (bgp_static->ecomm)
    {
      assert(bgp_static->ecomm->refcnt > 0);
      bgp_static->ecomm->refcnt++;
    }

  if (vrf)
    {
      if (! check_vrf_enabled(vrf, afi, safi, p))
        return -1;

      rn = bgp_node_get (vrf->route[afi], p);
      if (rn->info)
        {
          struct bgp_static *old = rn->info;
          if (old->ecomm)
            ecommunity_unintern (&old->ecomm);
          bgp_static_free (rn->info);
          /* reference only dropped if we're replacing a route */
          bgp_unlock_node (rn);
        }
      rn->info = bgp_static;
      bgp_static_update_safi (vrf->bgp, p, bgp_static, afi, safi);
    }
  else
    {
      bgp_static_update_safi (bgp_get_default (), p, bgp_static, afi, safi);
    }
  return 0;
}

int
bgp_vrf_static_unset (struct bgp_vrf *vrf, afi_t afi, const struct bgp_api_route *route)
{
  struct prefix *p = (struct prefix *)&route->prefix;
  struct bgp_static *old;
  struct bgp_node *rn;
  struct prefix def_route;
  struct prefix def_route_ipv6;
  safi_t safi;

  if ((afi != AFI_IP) && (afi != AFI_IP6) && (afi != AFI_L2VPN))
    return -1;
  if(afi == AFI_L2VPN)
    safi = SAFI_EVPN;
  else
    {
      if (route->l2label == SAFI_LABELED_UNICAST)
        safi = SAFI_LABELED_UNICAST;
      else
        safi = SAFI_MPLS_VPN;
    }

  /* detect Auto Discovery message */
  if ((safi == SAFI_EVPN) && PREFIX_IS_L2VPN_AD(p))
    {
      struct bgp *bgp;
      struct listnode *iter;
      struct listnode *node;
      int ret = -1;
      struct peer *peer;

      bgp = vrf->bgp;

      /* We should find peer list linked to this RD */
      for (ALL_LIST_ELEMENTS_RO(bgp->peer, iter, peer))
        {
          if (peer && peer->status != Established && peer->afc_nego[afi][safi])
            {
              zlog_err("Can't send EVPN Auto-Discovery to Idle host %s",
                       peer->host);
              return -1;
            }
        }

      for (ALL_LIST_ELEMENTS_RO(bgp->peer, iter, peer))
        {
          if (peer && peer->status == Established && peer->afc_nego[afi][safi])
            {
              struct bgp_evpn_ad *ad, *ad_found = NULL;
              u_int32_t ethtag = p->u.prefix_evpn.u.prefix_macip.eth_tag_id;
              struct eth_segment_id esi;

              str2esi(route->esi, &esi);

              /* Remove A/D message before sending */

              /* lookup for A/D in list matching same parameters */
              /* can't use listnode_lookup since it checks for exact pointer
                 within list which is not possible here */
              for (ALL_LIST_ELEMENTS_RO(vrf->static_evpn_ad, node, ad))
                {
                  if (0 == bgp_evpn_ad_cmp(ad, peer, &vrf->outbound_rd,
                                           &esi, ethtag))
                    {
                      ad_found = ad;
                      break;
                    }
                }

              /* the A/D was not found, then it's an error */
              if (!ad_found)
                {
                  struct eth_segment_id esi;
                  u_int32_t ethtag;

                  ethtag = p->u.prefix_evpn.u.prefix_macip.eth_tag_id;
                  str2esi(route->esi, &esi);
                  zlog_err("No Auto Discovery message for ESI %s ethtag %d. Sending withdraw however !",
                            route->esi, ethtag);
                  ad_found = bgp_evpn_ad_new(peer, vrf,
                                             &esi, ethtag,
                                             (struct prefix *)&route->nexthop,
                                             route->l2label);
                  if (!ad_found)
                    {
                      zlog_err("Not enough memory to store AD message for ESI %s!", route->esi);
                      return -1;
                    }
                  ad_found->type = BGP_EVPN_AD_TYPE_MP_UNREACH;
                }
              else
                listnode_delete (vrf->static_evpn_ad, ad_found);

              peer_evpn_auto_discovery_unset (peer, vrf, ad_found->attr,
                                              &esi, ethtag, ad_found->label);
              bgp_evpn_ad_free (ad_found);
              ret = 0;
            }
        }

      return ret;
    }
  str2prefix ("0.0.0.0/0", &def_route);
  str2prefix ("::/0", &def_route_ipv6);

  /* if we try to withdraw a default route, unset flag accordingly */
  if ( ( (0 == prefix_cmp(&def_route, p)) ||
         (0 == prefix_cmp(&def_route_ipv6, p))) &&
       ( (safi == SAFI_MPLS_VPN) || (safi == SAFI_EVPN)) && !IS_EVPN_RT3_PREFIX(p))
    {
      int ret = -1;
      struct bgp_vrf *v;
      struct bgp *bgp;
      struct listnode *iter;

      /* list all peers that have VPNv4 family enabled */
      bgp = vrf->bgp;

      /* Lookup in list of configured VRF with Route Distinguisher given as parameter */
      v = (struct bgp_vrf*) listnode_lookup(bgp->vrfs, vrf);
      if (v)
        {
          /* We should find peer list linked to this RD */
          for (iter = listhead(bgp->peer); iter; iter = listnextnode(iter))
            {
              struct peer *peer;

              /* Retrieve peer and set DEFAULT_ORIGINATE flag */
              peer = listgetdata(iter);
              /* Only send UPDATE messages to VPNv4 and EVPN peers */
              if (peer && peer->status == Established && peer->afc_nego[afi][safi])
                {
                  peer_default_originate_unset_rd (peer, afi, safi, &vrf->outbound_rd);
                  ret = 0;
                }
            }
        }
      return ret;
    }

  if (vrf)
    {
      if (! check_vrf_enabled(vrf, afi, safi, p))
        return -1;

      rn = bgp_node_lookup (vrf->route[afi], p);
      if (!rn || !rn->info)
        return -1;
      bgp_static_withdraw_safi (vrf->bgp, p, afi, safi,
                            &vrf->outbound_rd, NULL, 0);
      old = rn->info;
      if (old->ecomm)
        ecommunity_unintern (&old->ecomm);
      bgp_static_free (old);
      rn->info = NULL;
      bgp_unlock_node (rn);
    }
  else
    {
      bgp_static_withdraw_safi (bgp_get_default (), p, afi, safi,
                                NULL, NULL, 0);
    }
  return 0;
}

/* when exporting bgp_info structure to out VRF RIB,
 * some information are copied :
 * other info is filtered : labels
 */
static void bgp_vrf_copy_bgp_info(struct bgp_vrf *vrf, struct bgp_node *rn,
                                  safi_t safi, struct bgp_info *select, struct bgp_info *target)
{
  if(!target->extra)
    target->extra = bgp_info_extra_new();
  if(select->attr)
    {
      if(target->attr)
        bgp_attr_unintern(&target->attr);
      target->attr = bgp_attr_intern (select->attr);
      if (select->attr->extra)
        {
          overlay_index_dup (target->attr, &(select->attr->extra->evpn_overlay));
        }
    }
  /* copy label information */
  if(select->extra)
    {
      uint32_t l3label = 0, l2label = 0;
      
      bgp_vrf_update_labels (vrf, rn, safi, select, &l3label, &l2label);
      if(safi == SAFI_EVPN)
        {
          target->extra->nlabels = 1;
          if(vrf->ltype == BGP_LAYER_TYPE_3)
            {
              target->extra->labels[0] = l3label;
            } else {
            target->extra->labels[0] = l2label;
          }
        }
      else
        {
          target->extra->nlabels = select->extra->nlabels;
          memcpy (target->extra->labels, select->extra->labels,
                  select->extra->nlabels * sizeof(select->extra->labels[0]));
        }
    }
}

void bgp_vrf_process_entry (struct bgp_info *iter, 
                            int action, afi_t afi, safi_t safi)
{
  afi_t afi_int = AFI_IP;
  struct bgp_node *vrf_rn = iter->net;
  unsigned int label = 0;

  /* there should always be a label */
  if(iter->extra && iter->extra->nlabels >= 1) {
    if (CHECK_FLAG (iter->flags, BGP_INFO_ORIGIN_EVPN))
      label = iter->extra->labels[0];
    else
      label = iter->extra->labels[0] >> 4;
  }

  if (afi == AFI_L2VPN)
    {
      if (vrf_rn->p.family == AF_INET)
        afi_int = AFI_IP;
      else if (vrf_rn->p.family == AF_INET6)
        afi_int = AFI_IP6;
      else if (vrf_rn->p.family == AF_L2VPN)
        {
          if (IS_EVPN_RT3_PREFIX(&vrf_rn->p))
            afi_int = AFI_IP;
	  else if (vrf_rn->p.prefixlen == L2VPN_IPV6_PREFIX_LEN)
            afi_int = AFI_IP6;
          else
            afi_int = AFI_IP;
        }
    }
  else
    afi_int = afi;
  if(action == ROUTE_INFO_TO_REMOVE)
    {
      if (CHECK_FLAG (iter->peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
          && iter->peer != iter->peer->bgp->peer_self)
        if (!bgp_adj_in_unset (vrf_rn, iter->peer))
          {
            char pfx_str[PREFIX_STRLEN];
            prefix2str(&vrf_rn->p, pfx_str, sizeof(pfx_str));
            zlog (iter->peer->log, LOG_DEBUG, "%s withdrawing route %s%s "
                  "not in adj-in", iter->peer->host, pfx_str,
                  EVPN_RT3_STR(&vrf_rn->p));
          }
      bgp_info_delete(vrf_rn, iter);
      
      if (BGP_DEBUG (events, EVENTS))
        {
          char nh_str[BUFSIZ] = "<?>";
          char pfx_str[PREFIX_STRLEN];
          if(iter->attr && iter->attr->extra)
            {
              if (afi_int == AFI_IP)
                strcpy (nh_str, inet_ntoa (iter->attr->extra->mp_nexthop_global_in));
              else if (afi_int == AFI_IP6)
                inet_ntop (AF_INET6, &iter->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
            }
          else
            {
              inet_ntop (AF_INET, &iter->attr->nexthop,
                         nh_str, sizeof (nh_str));
            }
          prefix2str(&vrf_rn->p, pfx_str, sizeof(pfx_str));
          zlog_debug ("%s%s: processing entry (for removal) from %s [ nh %s label %u]",
                      pfx_str, EVPN_RT3_STR(&vrf_rn->p),
                      iter->peer->host, nh_str, label);
        }
    }
  else
    {
      if (BGP_DEBUG (events, EVENTS))
        {
          char nh_str[BUFSIZ] = "<?>";
          char pfx_str[PREFIX_STRLEN];

          if(iter->attr && iter->attr->extra)
            {
              if (afi_int == AFI_IP)
                strcpy (nh_str, inet_ntoa (iter->attr->extra->mp_nexthop_global_in));
              else if (afi_int == AFI_IP6)
                inet_ntop (AF_INET6, &iter->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
            }
          else
            {
              inet_ntop (AF_INET, &iter->attr->nexthop,
                         nh_str, sizeof (nh_str));
            }
          prefix2str(&vrf_rn->p, pfx_str, sizeof(pfx_str));
          zlog_debug ("%s%s: processing entry (for %s) from %s [ nh %s label %u]",
                      pfx_str, EVPN_RT3_STR(&vrf_rn->p),
                      action == ROUTE_INFO_TO_UPDATE?"upgrading":"adding",
                      iter->peer->host, nh_str, label);
        }
      /* When peer's soft reconfiguration enabled.  Record input packet in
         Adj-RIBs-In.  */
      if( ( action == ROUTE_INFO_TO_UPDATE) || (action == ROUTE_INFO_TO_ADD ))
        {
          /* soft_reconfig is set to 0 so, it should work XXX */
          if ( CHECK_FLAG (iter->peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
               && iter->peer != iter->peer->bgp->peer_self)
            bgp_adj_in_set (vrf_rn, iter->peer, iter->attr);
        }
    }
}

/*
 * Add MAC mobility extended community to attribute.
 */
static void
bgp_add_mac_mobility_to_attr(uint32_t seq_num, struct attr *attr)
{
  struct ecommunity ecom_tmp;
  struct ecommunity_val eval;
  uint8_t *ecom_val_ptr = NULL;
  int i;
  uint8_t *pnt;
  int type = 0;
  int sub_type = 0;
  struct attr_extra *ae;

  if (!seq_num)
    return;

  ae = attr->extra;
  if (!ae)
    return;

  memset(&eval, 0, sizeof(eval));
  eval.val[0] = ECOMMUNITY_ENCODE_EVPN;
  eval.val[1] = ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY;
  eval.val[4] = (seq_num >> 24) & 0xff;
  eval.val[5] = (seq_num >> 16) & 0xff;
  eval.val[6] = (seq_num >> 8) & 0xff;
  eval.val[7] = seq_num & 0xff;

  /* Find current MM ecommunity */
  if (ae->ecommunity)
    {
      for (i = 0; i < ae->ecommunity->size; i++)
        {
          pnt = ae->ecommunity->val + (i * 8);
          type = *pnt++;
          sub_type = *pnt++;

          if (type == ECOMMUNITY_ENCODE_EVPN &&
              sub_type == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY)
            {
              ecom_val_ptr = (uint8_t *)(ae->ecommunity->val + (i * 8));
              break;
            }
        }
    }

  /* Update the existing MM ecommunity */
  if (ecom_val_ptr)
    memcpy(ecom_val_ptr, eval.val, sizeof(char) * ECOMMUNITY_SIZE);
  else /* Add MM to existing */
    {
      memset(&ecom_tmp, 0, sizeof(ecom_tmp));
      ecom_tmp.size = 1;
      ecom_tmp.val = (uint8_t *)eval.val;

      if (ae->ecommunity)
        ae->ecommunity = ecommunity_merge(ae->ecommunity, &ecom_tmp);
      else
        ae->ecommunity = ecommunity_dup(&ecom_tmp);
    }
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
}

static void
bgp_update_mac_mobility_seqnum(struct bgp *bgp, struct bgp_node *rn,
                               struct attr *attr)
{
  struct bgp_info *iter;
  struct bgp_node *vrf_rn = NULL;
  struct ecommunity *new_ecom = NULL;
  afi_t afi_int;
  size_t i;
  struct listnode *node;
  uint32_t hi_mm_seqnum;
  int has_remote_entry = 0;

  if (!rn || !attr || !attr->extra || !attr->extra->ecommunity)
    return;

  if (rn->p.family != AF_L2VPN)
    return;

  if (rn->p.u.prefix_evpn.route_type != EVPN_MACIP_ADVERTISEMENT)
    return;

  new_ecom = attr->extra->ecommunity;
  if (!new_ecom)
    return;

  if (rn->p.prefixlen == L2VPN_IPV6_PREFIX_LEN)
    afi_int = AFI_IP6;
  else
    afi_int = AFI_IP;

  for (i = 0; i < (size_t)new_ecom->size; i++)
    {
      struct bgp_rt_sub dummy, *rt_sub;
      uint8_t *val = new_ecom->val + 8 * i;
      uint8_t type = val[1];
      struct bgp_vrf *vrf;

      if (type != ECOMMUNITY_ROUTE_TARGET)
        continue;

      memcpy(&dummy.rt, val, 8);
      rt_sub = hash_lookup (bgp->rt_subscribers, &dummy);
      if (!rt_sub)
        continue;

      for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
        {
          vrf_rn = bgp_node_get (vrf->rib[afi_int], &rn->p);
          if (!vrf_rn)
            continue;
          break;
        }
    }

  if (!vrf_rn)
    return;

  hi_mm_seqnum = 0;
  /* look for the highest MAC sequence number from peer */
  for (iter = vrf_rn->info; iter; iter = iter->next)
    {
      if (iter->peer == bgp->peer_self)
        continue;
      if (iter->attr->extra->mm_seqnum > hi_mm_seqnum)
        hi_mm_seqnum = iter->attr->extra->mm_seqnum;
      if (!has_remote_entry)
        has_remote_entry = 1;
    }

  if (has_remote_entry)
    {
      attr->extra->mm_seqnum = hi_mm_seqnum + 1;
      bgp_add_mac_mobility_to_attr(attr->extra->mm_seqnum, attr);
    }
}

/* updates selected bgp_info structure to bgp vrf rib table
 * most of the cases, processing consists in adding or removing entries in RIB tables
 * on some cases, there is an update request. then it is necessary to have both old and new ri
 */
static void
bgp_vrf_process_one (struct bgp_vrf *vrf, afi_t afi, safi_t safi, struct bgp_node *rn,
                     struct bgp_info *select, int action)
{
  struct bgp_node *vrf_rn;
  struct bgp_info *iter = NULL;
  struct prefix_rd *prd;
  char pfx_str[PREFIX_STRLEN];
  afi_t afi_int = AFI_IP;
  char vrf_rd_str[RD_ADDRSTRLEN];

  prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
  if (afi == AFI_L2VPN)
    {
      if (rn->p.family == AF_INET)
        afi_int = AFI_IP;
      else if (rn->p.family == AF_INET6)
        afi_int = AFI_IP6;
      else if (rn->p.family == AF_L2VPN)
        {
          if (IS_EVPN_RT3_PREFIX(&rn->p))
            /* VRF(AFI_IP, SAFI_EVPN) should be enabled for EVPN RT3 */
            afi_int = AFI_IP;
	  else if (rn->p.prefixlen == L2VPN_IPV6_PREFIX_LEN)
            afi_int = AFI_IP6;
          else
            afi_int = AFI_IP;
        }
    }
  else
    afi_int = afi;
  prd = &bgp_node_table (rn)->prd;
  if (BGP_DEBUG (events, EVENTS))
    {
      char rd_str[RD_ADDRSTRLEN];
      char nh_str[BUFSIZ] = "<?>";
      char mm_seq_str[128];

      prefix_rd2str(prd, rd_str, sizeof(rd_str));
      prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
      if(select && select->attr && select->attr->extra)
        {
          if (afi_int == AFI_IP)
            strcpy (nh_str, inet_ntoa (select->attr->extra->mp_nexthop_global_in));
          else if (afi_int == AFI_IP6)
            inet_ntop (AF_INET6, &select->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
        }
      else if(select)
        {
          inet_ntop (AF_INET, &select->attr->nexthop,
                     nh_str, sizeof (nh_str));
        }
      if (IS_EVPN_RT2_PREFIX(&rn->p) && select &&
          select->attr && select->attr->extra &&
          select->attr->extra->mm_seqnum)
        snprintf(mm_seq_str, sizeof(mm_seq_str), " MAC seq %u",
                 select->attr->extra->mm_seqnum);
      else
        mm_seq_str[0] = '\0';
      zlog_debug ("vrf[%s] %s%s: [%s] [nh %s%s] %s ", vrf_rd_str, pfx_str,
                  EVPN_RT3_STR(&rn->p), rd_str, nh_str, mm_seq_str,
                  action == ROUTE_INFO_TO_REMOVE? "withdrawing" : "updating");
    }  

  if (!vrf->afc[afi_int][safi])
    {
      zlog_info ("ignore vrf processing because VRF %s table is disabled (afi %d safi %d)",
                 vrf_rd_str, afi_int, safi);
      if (select)
	SET_FLAG (select->flags, BGP_INFO_VPN_EXPORT_TODO);
      return;
    }

  /* add a new entry if necessary
   * if already present, do nothing. 
   * use the loop to parse old entry also */

  /* check if global RIB plans for destroying initial entry
   * if yes, then suppress it
   */

  if (IS_EVPN_RT3_PREFIX(&rn->p))
    afi_int = AFI_L2VPN; /* store EVPN RT3 prefix in vrf->rib[AFI_L2VPN] */

  if(!vrf || !vrf->rib[afi_int] || !select)
    {
      return;
    }
  vrf_rn = bgp_node_get (vrf->rib[afi_int], &rn->p);
  if(!vrf_rn)
    {
      return;
    }
  if ( (action == ROUTE_INFO_TO_REMOVE) &&
       (CHECK_FLAG (select->flags, BGP_INFO_REMOVED)))
    {
      /* check entry not already present */
      for (iter = vrf_rn->info; iter; iter = iter->next)
        {
          if (iter->extra == NULL)
            continue;
          /* coming from same peer */
          if(iter->peer->remote_id.s_addr != select->peer->remote_id.s_addr)
            continue;
          if (!rd_same (&iter->extra->vrf_rd, &select->extra->vrf_rd))
            continue;
          if (0 == bgp_info_nexthop_cmp (iter, select))
            {
              if (!CHECK_FLAG (iter->flags, BGP_INFO_HISTORY))
                bgp_info_delete (iter->net, iter);
              bgp_vrf_process_entry(iter, action, afi,safi);
              bgp_process (iter->peer->bgp, iter->net, afi_int, SAFI_UNICAST);
              break;
            }
        }
    }
  if(action == ROUTE_INFO_TO_ADD || action == ROUTE_INFO_TO_UPDATE)
    {
      /* check entry not already present */
      for (iter = vrf_rn->info; iter; iter = iter->next)
        {
          if (!rd_same (&iter->extra->vrf_rd, &select->extra->vrf_rd))
            continue;
          /* search associated old entry.
           * assume with same peer */
          if(iter->peer->remote_id.s_addr != select->peer->remote_id.s_addr)
            continue;

          if(action == ROUTE_INFO_TO_UPDATE)
            {
              /* because there is an update, signify a withdraw */
              bgp_vrf_update (vrf, afi_int, vrf_rn, iter, false);
              /* update labels labels */
              /* update attr part / containing next hop */
              bgp_vrf_copy_bgp_info (vrf, rn, safi, select, iter);
              bgp_info_set_flag (rn, iter, BGP_INFO_ATTR_CHANGED);
              UNSET_FLAG (iter->flags, BGP_INFO_UPDATE_SENT);
            }
          break;
        }
      /* silently add new entry to rn */
      if(!iter)
        {
          iter = info_make (select->type, select->sub_type, select->peer, 
                            select->attr?bgp_attr_intern (select->attr):NULL,
                            vrf_rn);
          if (select->extra)
            {
              iter->extra = bgp_info_extra_new();
              memcpy(&iter->extra->vrf_rd,&select->extra->vrf_rd,sizeof(struct prefix_rd));
            }
          if(safi == SAFI_EVPN)
            SET_FLAG (iter->flags, BGP_INFO_ORIGIN_EVPN);
          bgp_vrf_copy_bgp_info(vrf, rn, safi, select, iter);
	  if (select->attr->extra)
	    overlay_index_dup(iter->attr, &(select->attr->extra->evpn_overlay));
          SET_FLAG (iter->flags, BGP_INFO_VALID);
          bgp_info_add (vrf_rn, iter);

          if (iter->sub_type != BGP_ROUTE_STATIC || iter->type != ZEBRA_ROUTE_BGP)
            bgp_evpn_auto_discovery_new_entry (vrf, iter);
        }
      else
        {
          if (CHECK_FLAG(iter->flags, BGP_INFO_REMOVED))
            {
              if (BGP_DEBUG (events, EVENTS))
                {
                  char vrf_rd_str[RD_ADDRSTRLEN], pfx_str[PREFIX_STRLEN];

                  prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
                  prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
                  zlog_debug ("vrf[%s]: %s rcvd %s%s, flapped quicker than processing",
                              vrf_rd_str, iter->peer->host, pfx_str,
                              EVPN_RT3_STR(&rn->p));
                }

              bgp_info_restore (vrf_rn, iter);
              if (action == ROUTE_INFO_TO_ADD)
                {
                  /* because onUpdateWithdraw is not sent yet, signify a withdraw */
                  bgp_vrf_update (vrf, afi_int, vrf_rn, iter, false);
                  /* update labels labels */
                  /* update attr part / containing next hop */
                  bgp_vrf_copy_bgp_info (vrf, rn, safi, select, iter);
                  bgp_info_set_flag (rn, iter, BGP_INFO_ATTR_CHANGED);
                  UNSET_FLAG (iter->flags, BGP_INFO_UPDATE_SENT);
                }
            }
        }
      bgp_vrf_process_entry(iter, action, afi, safi);
      bgp_process (iter->peer->bgp, iter->net, afi_int, SAFI_UNICAST);
    }
  bgp_unlock_node (vrf_rn);
}

/* propagates a change in the BGP per VRF tables,
 * according to import export rules contained:
 * - in bgp vrf configuration
 * - in Route Target extended communities
 * result stands for a new ri to add, an old ri to suppress,
 * or an change in the ri itself. for latter case, old ri is
 * not attached
 */
static void
bgp_vrf_process_imports (struct bgp *bgp, afi_t afi, safi_t safi,
                         struct bgp_node *rn,
                         struct bgp_info *old_select,
                         struct bgp_info *new_select)
{
  struct ecommunity *old_ecom = NULL, *new_ecom = NULL;
  struct bgp_vrf *vrf;
  struct listnode *node;
  size_t i, j;
  struct prefix_rd *prd;
  int action;
  struct bgp_info *ri;
  int action_add_done = 0, vrf_enabled = 0;
  int count_missing_export = 0;

  if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_EVPN))
    return;

  prd = &bgp_node_table (rn)->prd;
  if(new_select && !old_select)
    {
      ri = new_select;
      action = ROUTE_INFO_TO_ADD;
    }
  else if(!new_select && old_select)
    {
      ri = old_select;
      action = ROUTE_INFO_TO_REMOVE;
    }
  else
    {
      /* old_select set to null */
      old_select = NULL;
      ri = new_select;
      action = ROUTE_INFO_TO_UPDATE;
    }

  if (old_select && old_select->attr && old_select->attr->extra)
    old_ecom = old_select->attr->extra->ecommunity;
  if (new_select && new_select->attr && new_select->attr->extra)
    new_ecom = new_select->attr->extra->ecommunity;
  /* remove the flag vpn_export todo
   * this flag will be set again,
   * if an exportation fails to happen,
   * in bgp_vrf_process_one()
   */
  if (ri)
    UNSET_FLAG (ri->flags, BGP_INFO_VPN_EXPORT_TODO);
  if (old_select
      && old_select->type == ZEBRA_ROUTE_BGP
      && old_select->sub_type == BGP_ROUTE_STATIC
      && (!new_select
          || !new_select->type == ZEBRA_ROUTE_BGP
          || !new_select->sub_type == BGP_ROUTE_STATIC))
    for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
      if (!prefix_cmp((struct prefix*)&vrf->outbound_rd,
                      (struct prefix*)prd))
        {

          bgp_vrf_process_one(vrf, afi, safi, rn, ri, action);
          vrf_enabled = check_vrf_enabled(vrf, afi, safi, &rn->p);
          if (!vrf_enabled)
            count_missing_export++;
          if (action == ROUTE_INFO_TO_ADD && vrf_enabled)
            action_add_done = 1;
        }
  if (old_ecom)
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
          for (j = 0; j < (size_t)new_ecom->size; j++)
            if (!memcmp(new_ecom->val + j * 8, val, 8))
              {
                withdraw = false;
                break;
              }

        for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
          {
            bgp_vrf_process_one (vrf, afi, safi, rn, ri, withdraw == false?
                                 ROUTE_INFO_TO_UPDATE:ROUTE_INFO_TO_REMOVE);
            if (withdraw == false)
              action_add_done = 1;
          }
      }

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
              bgp_vrf_process_one (vrf, afi, safi, rn, ri, action);
              vrf_enabled = check_vrf_enabled(vrf, afi, safi, &rn->p);
              if ((action == ROUTE_INFO_TO_ADD ||
                   action == ROUTE_INFO_TO_UPDATE) && vrf_enabled)
                action_add_done = 1;
            }
      }

  if (new_select
      && new_select->type == ZEBRA_ROUTE_BGP
      && new_select->sub_type == BGP_ROUTE_STATIC)
    for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
      if (!prefix_cmp((struct prefix*)&vrf->outbound_rd,
                      (struct prefix*)prd))
        {
          bgp_vrf_process_one(vrf, afi, safi, rn, ri, action);
          vrf_enabled = check_vrf_enabled(vrf, afi, safi, &rn->p);
          if ((action == ROUTE_INFO_TO_ADD ||
               action == ROUTE_INFO_TO_UPDATE) && vrf_enabled)
            action_add_done = 1;
        }
  if (ri && (ri->sub_type != BGP_ROUTE_STATIC) &&
      (action_add_done == 0) &&
      (action == ROUTE_INFO_TO_ADD || action == ROUTE_INFO_TO_UPDATE) &&
      !CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN))
    {
      SET_FLAG (ri->flags, BGP_INFO_VPN_HIDEN);
    }
  else if (ri && CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN) && action_add_done == 1)
    {
      UNSET_FLAG (ri->flags, BGP_INFO_VPN_HIDEN);
    }
  if (ri && ri->extra)
    ri->extra->vrf_exportation_fail = count_missing_export;
}

static void bgp_vrf_remove_bgp_info (struct bgp_vrf *vrf, afi_t afi, safi_t safi,
                                     struct bgp_node *rn, struct bgp_info *select)
{
  struct bgp_node *vrf_rn;
  struct bgp_info *iter = NULL;
  struct prefix_rd *prd;
  char pfx_str[PREFIX_STRLEN];
  afi_t afi_int = AFI_IP;

  if (afi == AFI_L2VPN)
    {
      if (rn->p.family == AF_INET)
        afi_int = AFI_IP;
      else if (rn->p.family == AF_INET6)
        afi_int = AFI_IP6;
      else if (rn->p.family == AF_L2VPN)
        {
          if (IS_EVPN_RT3_PREFIX(&rn->p))
            afi_int = AFI_IP;
	  else if (rn->p.prefixlen == L2VPN_IPV6_PREFIX_LEN)
            afi_int = AFI_IP6;
          else
            afi_int = AFI_IP;
        }
    }
  else
    afi_int = afi;
  prd = &bgp_node_table (rn)->prd;
  if (BGP_DEBUG (events, EVENTS))
    {
      char vrf_rd_str[RD_ADDRSTRLEN], rd_str[RD_ADDRSTRLEN];
      char nh_str[BUFSIZ] = "<?>";

      prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
      prefix_rd2str(prd, rd_str, sizeof(rd_str));
      prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
      if(select && select->attr && select->attr->extra)
        {
          if (afi_int == AFI_IP)
            strcpy (nh_str, inet_ntoa (select->attr->extra->mp_nexthop_global_in));
          else if (afi_int == AFI_IP6)
            inet_ntop (AF_INET6, &select->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
        }
      else if(select)
        {
          inet_ntop (AF_INET, &select->attr->nexthop,
                     nh_str, sizeof (nh_str));
        }
      zlog_debug ("vrf[%s] %s: [%s] [nh %s] removing", vrf_rd_str, pfx_str,
                  rd_str, nh_str);
    }

  if (!vrf->afc[afi_int][safi])
    {
      zlog_info ("ignore vrf processing because VRF table is disabled (afi %d safi %d)",
                  afi_int, safi);
      return;
    }

  if (IS_EVPN_RT3_PREFIX(&rn->p))
    afi_int = AFI_L2VPN; /* store EVPN RT3 prefix in vrf->rib[AFI_L2VPN] */

  if(!vrf || !vrf->rib[afi_int] || !select)
    {
      return;
    }
  vrf_rn = bgp_node_get (vrf->rib[afi_int], &rn->p);
  if(!vrf_rn)
    {
      return;
    }

  /* check entry not already present */
  for (iter = vrf_rn->info; iter; iter = iter->next)
    {
      if (iter->extra == NULL)
        continue;
      /* coming from same peer */
      if(iter->peer->remote_id.s_addr != select->peer->remote_id.s_addr)
        continue;
      if (!rd_same (&iter->extra->vrf_rd, &select->extra->vrf_rd))
        continue;
      bgp_vrf_process_entry(iter, ROUTE_INFO_TO_REMOVE, afi, safi);
      bgp_process (iter->peer->bgp, iter->net, afi_int, SAFI_UNICAST);
      break;
    }
  bgp_unlock_node (vrf_rn);
}

/* Process the change of ecommunity.
 * If an old ecommunity is not present in new ecommunity, the entry in
 * the vrf who subscribed this old ecommunity should be removed.
 */
static void
bgp_vrf_process_ecom_change (struct bgp *bgp, afi_t afi, safi_t safi,
                             struct bgp_node *rn,
                             struct bgp_info *ri,
                             struct attr *new_attr)

{
  struct ecommunity *old_ecom = NULL, *new_ecom = NULL;
  struct attr *old_attr = ri->attr;

  if (safi != SAFI_MPLS_VPN && safi != SAFI_EVPN)
    return;

  if (old_attr && old_attr->extra)
    old_ecom = old_attr->extra->ecommunity;
  if (new_attr && new_attr->extra)
    new_ecom = new_attr->extra->ecommunity;

  /*
   * if old present, for each export target
   * get the list of route target subscribers
   * if no new, then withdraw entries in all mentioned export rt
   */
  if (old_ecom)
    {
      size_t i, j;

      for (i = 0; i < (size_t)old_ecom->size; i++)
        {
          struct bgp_rt_sub dummy, *rt_sub;
          uint8_t *val = old_ecom->val + 8 * i;
          uint8_t type = val[1];
          bool found = false;
          struct bgp_vrf *vrf;
          struct listnode *node;

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
                    found = true;
                    break;
                  }
            }
          if (!found)
            for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
              {
                /* case ecom not present in new_ecom : remove associated ri
                 */
                bgp_vrf_remove_bgp_info(vrf, afi, safi, rn, ri);
              }
        }
    }
}

void
bgp_vrf_update_global_rib_perafisafi (struct bgp_vrf *vrf, afi_t afi, safi_t safi)
{
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    return ;

  for (rn = bgp_table_top (bgp->rib[afi][safi]); rn; rn = bgp_route_next (rn))
    {
      if ((table = rn->info) != NULL)
	{
	  for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
	    for (ri = rm->info; ri; ri = ri->next)
	      {
                bool vpn_hidden_presence = false;
                bool vpn_export_todo_presence = false;
                int cnt_fail = 0;

                if (ri->extra)
                  cnt_fail = ri->extra->vrf_exportation_fail;

                if (CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN))
                  vpn_hidden_presence = true;
                if (CHECK_FLAG (ri->flags, BGP_INFO_VPN_EXPORT_TODO))
                  vpn_export_todo_presence = true;
                /* a new vrf just has been added. check hidden vpn information */
                if (vpn_hidden_presence || vpn_export_todo_presence)
                  {
                    bgp_vrf_process_imports(bgp, afi, safi, rm, NULL, ri);
                    if ( (!CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN) && vpn_hidden_presence)
                         || (vpn_export_todo_presence && cnt_fail != ri->extra->vrf_exportation_fail))
                      bgp_process (bgp, rm, afi, safi);
                  }
              }
        }
    }
}

void bgp_vrf_added_vrf_update_global_rib (struct bgp_vrf *vrf)
{
  bgp_vrf_update_global_rib_perafisafi (vrf, AFI_IP, SAFI_MPLS_VPN);
  bgp_vrf_update_global_rib_perafisafi (vrf, AFI_IP6, SAFI_MPLS_VPN);
  bgp_vrf_update_global_rib_perafisafi (vrf, AFI_L2VPN, SAFI_EVPN);
}

void
bgp_vrf_update_global_rib_l2vpn (struct bgp_vrf *vrf, afi_t afi)
{
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    return ;

  for (rn = bgp_table_top (bgp->rib[AFI_L2VPN][SAFI_EVPN]); rn; rn = bgp_route_next (rn))
    {
      if ((table = rn->info) != NULL)
	{
	  for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
            {
              afi_t afi_int = AFI_IP;
              struct prefix *p = &rm->p;

              if (p->family == AF_INET)
                afi_int = AFI_IP;
              else if (p->family == AF_INET6)
                afi_int = AFI_IP6;
              else if (p->family == AF_L2VPN)
                {
                  if (IS_EVPN_RT3_PREFIX(p))
                    afi_int = AFI_IP;
                  else if (p->prefixlen == L2VPN_IPV6_PREFIX_LEN)
                    afi_int = AFI_IP6;
                  else
                    afi_int = AFI_IP;
                }
              if (afi_int != afi)
                continue;

              for (ri = rm->info; ri; ri = ri->next)
                {
                  /* a new vrf just has been added. check hidden vpn information */
                  if (CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN))
                    {
                      bgp_vrf_process_imports(bgp, AFI_L2VPN, SAFI_EVPN, rm, NULL, ri);
                      if (!CHECK_FLAG (ri->flags, BGP_INFO_VPN_HIDEN))
                        bgp_process (bgp, rm, AFI_L2VPN, SAFI_EVPN);
                    }
                }
            }
        }
    }
}

/* set to hidden entry from global RIB */
void
bgp_vrf_delete_vrf_update_global_rib (struct prefix *p, struct bgp_info *vrf_ri,
                                      struct bgp_vrf *in_vrf, afi_t afi)
{
  struct bgp_node *rn = NULL;
  struct bgp_info *ri;
  struct bgp *bgp;
  struct ecommunity *ecom = NULL;
  struct listnode *node;
  safi_t safi_int = SAFI_MPLS_VPN;
  size_t i;
  int vrf_ignore = 1;
  struct attr *attr;
  struct prefix_rd *prd = &(vrf_ri->extra->vrf_rd);

  bgp = bgp_get_default ();
  if (bgp == NULL)
    return ;
  if (afi == AFI_IP || afi == AFI_IP6)
    safi_int = SAFI_MPLS_VPN;
  else if (afi == AFI_L2VPN)
    safi_int = SAFI_EVPN;
  rn = bgp_afi_node_get (bgp->rib[afi][safi_int], afi, safi_int, p, prd);
  /* Check previously received route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == vrf_ri->peer)
      break;
  if (!ri)
    return;
  attr = ri->attr;
  if (attr && attr->extra)
    ecom = attr->extra->ecommunity;
  else
    return;
  if (ecom)
    for (i = 0; i < (size_t)ecom->size; i++)
      {
        struct bgp_rt_sub dummy, *rt_sub;
        uint8_t *val = ecom->val + 8 * i;
        uint8_t type = val[1];
        struct bgp_vrf *vrf;

        if (type != ECOMMUNITY_ROUTE_TARGET)
          continue;

        memcpy(&dummy.rt, val, 8);
        rt_sub = hash_lookup (bgp->rt_subscribers, &dummy);
        if (!rt_sub)
          continue;
        for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
          {
            if (in_vrf && vrf == in_vrf)
              continue;
            vrf_ignore = 0;
          }
      }
  /* if vrf ignore, then hide it */
  if (vrf_ignore)
    {
      SET_FLAG (ri->flags, BGP_INFO_VPN_HIDEN);
      UNSET_FLAG (ri->flags, BGP_INFO_SELECTED);
      bgp_process (bgp, rn, afi, safi_int);
    }
}

void
bgp_vrf_apply_new_imports (struct bgp_vrf *vrf, afi_t afi)
{
  if (!vrf->rt_import || vrf->rt_import->size == 0)
    return;
if (afi == AFI_L2VPN)
  return bgp_vrf_apply_new_imports_internal (vrf, afi, SAFI_EVPN);
  bgp_vrf_apply_new_imports_internal (vrf, afi, SAFI_MPLS_VPN);
  bgp_vrf_apply_new_imports_internal (vrf, afi, SAFI_ENCAP);
  return;
}

static void
bgp_vrf_apply_new_imports_internal (struct bgp_vrf *vrf, afi_t afi, safi_t safi)
{
  struct bgp_node *rd_rn, *rn;
  struct bgp_info *sel, *mp;
  struct bgp_table *table;
  struct ecommunity *ecom;
  size_t i, j;
  bool found;

  for (rd_rn = bgp_table_top (vrf->bgp->rib[afi][safi]); rd_rn;
                  rd_rn = bgp_route_next (rd_rn))
    if (rd_rn->info != NULL)
      {
        table = rd_rn->info;

        for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
          {
            for (sel = rn->info; sel; sel = sel->next)
              {
                if (!sel->attr || !sel->attr->extra)
                  continue;
                ecom = sel->attr->extra->ecommunity;
                if (!ecom)
                  continue;

                found = false;
                for (i = 0; i < (size_t)ecom->size && !found; i++)
                  for (j = 0; j < (size_t)vrf->rt_import->size && !found; j++)
                    if (!memcmp(ecom->val + i * 8, vrf->rt_import->val + j * 8, 8))
                      found = true;
                if (!found)
                  continue;
                bgp_vrf_process_one(vrf, afi, safi, rn, sel, 0);
              }
          }
      }
}

/* Called in bgp_process_vrf_main in order to withdraw local EVPN
 * RT2 route.
 */
static void
bgp_local_evpn_rt2_entry_delete(struct bgp *bgp, struct bgp_vrf *vrf,
                                struct bgp_node *rn,
                                struct bgp_info *new_select,
                                struct bgp_info *old_select)
{
  if (!vrf || !bgp || !rn)
    return;
  if (rn->p.family != AF_L2VPN)
    return;
  if (rn->p.u.prefix_evpn.route_type != EVPN_MACIP_ADVERTISEMENT)
    return;

  if (new_select && old_select && (new_select != old_select))
    {
      char vrf_rd_str[RD_ADDRSTRLEN];
      char old_loc_rem[128], new_loc_rem[128];
      char *mac = NULL;

      prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));

      memset(old_loc_rem, '\0', sizeof(old_loc_rem));
      memset(new_loc_rem, '\0', sizeof(new_loc_rem));

      if (old_select->sub_type == BGP_ROUTE_STATIC)
        snprintf(old_loc_rem, sizeof(old_loc_rem), " local");
      else if (old_select->sub_type == BGP_ROUTE_NORMAL)
        snprintf(old_loc_rem, sizeof(old_loc_rem), " remote(%s)",
                 old_select->peer->host);

      if (new_select->sub_type == BGP_ROUTE_STATIC)
        snprintf(new_loc_rem, sizeof(new_loc_rem), " local");
      else if (new_select->sub_type == BGP_ROUTE_NORMAL)
        snprintf(new_loc_rem, sizeof(new_loc_rem), " remote(%s)",
                 new_select->peer->host);

      mac = mac2str((char *)&rn->p.u.prefix_evpn.u.prefix_macip.mac);
      zlog_info("vrf[%s]: this old%s entry MAC %s (seq %u) conflicts "
                "with new%s MAC (seq %u)",
                vrf_rd_str,  old_loc_rem, mac,
                old_select->attr->extra->mm_seqnum,
                new_loc_rem, new_select->attr->extra->mm_seqnum);
      if (mac)
        XFREE (MTYPE_BGP_MAC, mac);

      /* Withdraw local static route */
      if (old_select && old_select->peer == bgp->peer_self &&
          old_select->type == ZEBRA_ROUTE_BGP &&
          old_select->sub_type == BGP_ROUTE_STATIC)
        {
          struct bgp_node *global_rn = NULL;
          struct bgp_info *ri = NULL;
          struct prefix_rd *prd = &(old_select->extra->vrf_rd);

          global_rn =  bgp_afi_node_get (bgp->rib[AFI_L2VPN][SAFI_EVPN],
                                         AFI_L2VPN, SAFI_EVPN,
                                         &rn->p, prd);
          if (global_rn)
            {
              /* search local route entry in global rib, mark deletion
	       * and schedule for processing.
	       */
              for (ri = global_rn->info; ri; ri = ri->next)
                {
                  if (ri->peer == bgp->peer_self &&
                      ri->type == ZEBRA_ROUTE_BGP &&
                      ri->sub_type == BGP_ROUTE_STATIC)
                    break;
                }
              if (ri)
                {
                  bgp_info_delete(global_rn, ri);
                  bgp_process(bgp, global_rn, AFI_L2VPN, SAFI_EVPN);
                }

              bgp_unlock_node(global_rn);
            }

          /* Also mark deletion for old_select which must be in vrf rib,
           * old_select will be removed in bgp_process_vrf_main().
           */
          bgp_info_delete(rn, old_select);
        }
    }
}

struct bgp_process_queue 
{
  struct bgp *bgp;
  struct bgp_node *rn;
  afi_t afi;
  safi_t safi;
};

static wq_item_status
bgp_process_rsclient (struct work_queue *wq, void *data)
{
  struct bgp_process_queue *pq = data;
  struct bgp *bgp = pq->bgp;
  struct bgp_node *rn = pq->rn;
  afi_t afi = pq->afi;
  safi_t safi = pq->safi;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info_pair old_and_new;
  struct listnode *node, *nnode;
  struct peer *rsclient = bgp_node_table (rn)->owner;
  
  /* Best path selection. */
  bgp_best_selection (bgp, rn, &old_and_new, afi, safi);
  new_select = old_and_new.new;
  old_select = old_and_new.old;

  if (CHECK_FLAG (rsclient->sflags, PEER_STATUS_GROUP))
    {
      if (rsclient->group)
        for (ALL_LIST_ELEMENTS (rsclient->group->peer, node, nnode, rsclient))
          {
            /* Nothing to do. */
            if (old_select && old_select == new_select)
              if (!CHECK_FLAG (old_select->flags, BGP_INFO_ATTR_CHANGED))
                continue;

            if (old_select)
              bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
            if (new_select)
              {
                bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
                bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
		UNSET_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG);
             }

            bgp_process_announce_selected (rsclient, new_select, rn,
                                           afi, safi);
          }
    }
  else
    {
      if (old_select)
	bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
      if (new_select)
	{
	  bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
	  bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
	  UNSET_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG);
	}
      bgp_process_announce_selected (rsclient, new_select, rn, afi, safi);
    }

  if (old_select && CHECK_FLAG (old_select->flags, BGP_INFO_REMOVED))
    bgp_info_reap (rn, old_select);
  
  UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
  return WQ_SUCCESS;
}

/* send an informational message to upper layer */
static void 
bgp_process_notification_to_sdn (struct bgp_node *rn, afi_t afi, safi_t safi,
                         struct bgp_info *old_select, struct bgp_info *new_select)
{
  struct bgp_info *ri;

  if (safi == SAFI_MPLS_VPN || safi == SAFI_EVPN || safi == SAFI_ENCAP)
    return;

  if (old_select && new_select)
    {
      if(!CHECK_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG) &&
         !CHECK_FLAG (new_select->flags, BGP_INFO_ATTR_CHANGED))
        {
          return;
        }
    }
  if (old_select)
    {
      if( CHECK_FLAG (old_select->flags, BGP_INFO_SELECTED))
        {
          if(!bgp_is_mpath_entry(old_select, new_select))
            {
              bgp_send_notification_to_sdn (afi, safi, rn, old_select, false);
            }
        }
      /* withdraw mp entries which could have been removed
       * and that a update has previously been sent
       */
      for(ri = rn->info; ri; ri = ri->next)
        {
          if(ri == old_select || (ri == new_select) )
            continue;
          if(!bgp_is_mpath_entry(ri, new_select))
            {
              bgp_send_notification_to_sdn (afi, safi, rn, ri, false);
            }
        }
    }
  if (new_select)
    {
      if(!CHECK_FLAG (new_select->flags, BGP_INFO_SELECTED) ||
         CHECK_FLAG (new_select->flags, BGP_INFO_MULTIPATH) ||
         CHECK_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG))
        {
          bgp_send_notification_to_sdn (afi, safi, rn, new_select, true);
        }
      /* append mp entries which could have been added 
       * and that a update has not been sent
       */
      for(ri = rn->info; ri; ri = ri->next)
        {
          if( (ri == new_select) || ( ri == old_select))
            continue;
          if(bgp_is_mpath_entry(ri, new_select))
            {
              bgp_send_notification_to_sdn (afi, safi, rn, ri, true);
            }
        }
    }
  return;
}

static wq_item_status
bgp_process_main (struct work_queue *wq, void *data)
{
  struct bgp_process_queue *pq = data;
  struct bgp *bgp = pq->bgp;
  struct bgp_node *rn = pq->rn;
  afi_t afi = pq->afi;
  safi_t safi = pq->safi;
  struct prefix *p = &rn->p;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info_pair old_and_new;
  struct listnode *node, *nnode;
  struct peer *peer;
  
  /* Best path selection. */
  bgp_best_selection (bgp, rn, &old_and_new, afi, safi);
  old_select = old_and_new.old;
  new_select = old_and_new.new;

  /* Nothing to do. */
  if (old_select && old_select == new_select 
      && !CHECK_FLAG(rn->flags, BGP_NODE_USER_CLEAR))
    {
      if (! CHECK_FLAG (old_select->flags, BGP_INFO_ATTR_CHANGED))
        {
          if (CHECK_FLAG (old_select->flags, BGP_INFO_IGP_CHANGED) ||
	      CHECK_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG))
            bgp_zebra_announce (p, old_select, bgp, safi);
          
	  UNSET_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG);
          UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
          return WQ_SUCCESS;
        }
    }

  /* If the user did "clear ip bgp prefix x.x.x.x" this flag will be set */
  UNSET_FLAG(rn->flags, BGP_NODE_USER_CLEAR);
  bgp_process_notification_to_sdn (rn, afi, safi, old_select, new_select);
  if (old_select)
      bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
  if (new_select)
    {
      bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
      bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
      UNSET_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG);
    }

  /* Check each BGP peer. */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      bgp_process_announce_selected (peer, new_select, rn, afi, safi);
    }

  /* FIB update. */
  if ((safi == SAFI_UNICAST || safi == SAFI_MULTICAST) && (! bgp->name &&
      ! bgp_option_check (BGP_OPT_NO_FIB)))
    {
      if (new_select 
	  && new_select->type == ZEBRA_ROUTE_BGP 
	  && new_select->sub_type == BGP_ROUTE_NORMAL)
	bgp_zebra_announce (p, new_select, bgp, safi);
      else
	{
	  /* Withdraw the route from the kernel. */
	  if (old_select 
	      && old_select->type == ZEBRA_ROUTE_BGP
	      && old_select->sub_type == BGP_ROUTE_NORMAL)
	    bgp_zebra_withdraw (p, old_select, safi);
	}
    }
    
  /* Reap old select bgp_info, if it has been removed */
  if (old_select && CHECK_FLAG (old_select->flags, BGP_INFO_REMOVED))
    bgp_info_reap (rn, old_select);
  
  UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
  return WQ_SUCCESS;
}

/* processing done for BGP VRF tables */
static wq_item_status
bgp_process_vrf_main (struct work_queue *wq, void *data)
{
  struct bgp_process_queue *pq = data;
  struct bgp *bgp = pq->bgp;
  struct bgp_node *rn = pq->rn;
  afi_t afi = pq->afi;
  safi_t safi = pq->safi;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info *ri, *ri_next = NULL;
  struct bgp_info_pair old_and_new;
  struct bgp_vrf *vrf = NULL;

  if(rn)
    vrf = bgp_vrf_lookup_per_rn(bgp, afi, rn);

  /* Best path selection. */
  bgp_best_selection (bgp, rn, &old_and_new, afi, safi);
  old_select = old_and_new.old;
  new_select = old_and_new.new;

  /* Nothing to do. */
  if (old_select && old_select == new_select)
    {
      if (! CHECK_FLAG (old_select->flags, BGP_INFO_ATTR_CHANGED))
        {
          /* case mpath number of entries changed */
          if (CHECK_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG))
            {
              UNSET_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG);
              SET_FLAG (old_select->flags, BGP_INFO_MULTIPATH);
            }
          for (ri = rn->info; ri; ri = ri->next)
            {
              if (ri == old_select)
                continue;
              if (!bgp_is_mpath_entry(ri, new_select))
                bgp_vrf_update (vrf, afi, rn, ri, false);
              else
                bgp_vrf_update (vrf, afi, rn, ri, true);
            }
          /* no zebra announce */
	  UNSET_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG);
          UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
          return WQ_SUCCESS;
        }
    }
  if (old_select)
    {
      if( CHECK_FLAG (old_select->flags, BGP_INFO_SELECTED))
        {
          if (CHECK_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG) ||
              old_select != new_select)
            {
              if (old_select == new_select &&
                  CHECK_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG))
                ;
              else if(!bgp_is_mpath_entry(old_select, new_select))
                {
                  bgp_vrf_update(vrf, afi, rn, old_select, false);
                }
            }
        }
      /* withdraw mp entries which could have been removed
       * and that a update has previously been sent
       */
      for(ri = rn->info; ri; ri = ri_next)
        {
          ri_next = ri->next;
          if(ri == old_select || (ri == new_select) )
            continue;
          if(!bgp_is_mpath_entry(ri, new_select))
            {
              bgp_vrf_update(vrf, afi, rn, ri, false);
            }
          else if (ri->flags & BGP_INFO_REMOVED)
            {
              bgp_vrf_update(vrf, afi, rn, ri, false);
              bgp_info_reap (rn, ri);
            }
        }
      bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
    }
  if (new_select)
    {
      if(!CHECK_FLAG (new_select->flags, BGP_INFO_SELECTED) ||
         CHECK_FLAG (new_select->flags, BGP_INFO_MULTIPATH) ||
         CHECK_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG))
        {
          bgp_vrf_update(vrf, afi, rn, new_select, true);
        }
      bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
      bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
      UNSET_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG);
      /* append mp entries which could have been added 
       * and that a update has not been sent
       */
      for(ri = rn->info; ri; ri = ri->next)
        {
          if (ri == new_select)
            continue;
          if(bgp_is_mpath_entry(ri, new_select))
            {
              bgp_vrf_update(vrf, afi, rn, ri, true);
            }
        }
    }

  bgp_local_evpn_rt2_entry_delete(bgp, vrf, rn, new_select, old_select);

  /* Reap old select bgp_info, if it has been removed */
  if (old_select && CHECK_FLAG (old_select->flags, BGP_INFO_REMOVED))
    bgp_info_reap (rn, old_select);

  UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
  return WQ_SUCCESS;
  /* no announce */
}

static void
bgp_processq_del (struct work_queue *wq, void *data)
{
  struct bgp_process_queue *pq = data;
  struct bgp_table *table = bgp_node_table (pq->rn);
  
  bgp_unlock (pq->bgp);
  bgp_unlock_node (pq->rn);
  bgp_table_unlock (table);
  XFREE (MTYPE_BGP_PROCESS_QUEUE, pq);
}

static void
bgp_process_queue_init (void)
{
  bm->process_main_queue
    = work_queue_new (bm->master, "process_main_queue");
  bm->process_rsclient_queue
    = work_queue_new (bm->master, "process_rsclient_queue");
  bm->process_vrf_queue
    = work_queue_new (bm->master, "process_vrf_queue");
  
  if ( !(bm->process_main_queue && bm->process_rsclient_queue && bm->process_vrf_queue) )
    {
      zlog_err ("%s: Failed to allocate work queue", __func__);
      exit (1);
    }
  
  bm->process_main_queue->spec.workfunc = &bgp_process_main;
  bm->process_main_queue->spec.del_item_data = &bgp_processq_del;
  bm->process_main_queue->spec.max_retries = 0;
  bm->process_main_queue->spec.hold = 50;
  
  bm->process_rsclient_queue->spec.workfunc = &bgp_process_rsclient;
  bm->process_rsclient_queue->spec.del_item_data = &bgp_processq_del;
  bm->process_rsclient_queue->spec.max_retries = 0;
  bm->process_rsclient_queue->spec.hold = 50;

  bm->process_vrf_queue->spec.workfunc = &bgp_process_vrf_main;
  bm->process_vrf_queue->spec.del_item_data = &bgp_processq_del;
  bm->process_vrf_queue->spec.max_retries = 0;
  bm->process_vrf_queue->spec.hold = 50;

}

/*
 *  Check if a route entry is EVPN.
 */
static bool
is_origin_evpn (struct bgp_node *rn)
{
  struct bgp_info *ri;
  bool ret = false;

  assert (rn);

  for (ri = rn->info; ri; ri = ri->next)
    {
      if (CHECK_FLAG (ri->flags, BGP_INFO_ORIGIN_EVPN))
        {
          ret = true;
	  break;
        }
    }

  return ret;
}

/*
 *  Check if bgp bestpath selection should be triggered for afi/safi family.
 *  If yes, return 1, else return 0;
 */
static bool
bgp_trigger_bgp_selection_check (struct bgp *bgp, afi_t afi, safi_t safi)
{
  struct peer *peer;
  struct listnode *node, *next;
  bool all_peers_eor_received = true;

  assert (bgp);

  for (ALL_LIST_ELEMENTS (bgp->peer, node, next, peer))
    {
      if (peer->status != Established)
        continue;

      if (!CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_EOR_RECEIVED) &&
          !CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_SELECTION_DEFERRAL_EXPIRED) &&
          !CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_FIRST_KEEPALIVE_RECEIVED))
        {
          all_peers_eor_received = false;
          break;
        }
    }

  return all_peers_eor_received;
}

void
bgp_trigger_bgp_selection (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_vrf *vrf;
  struct listnode *node;
  uint32_t nb_prefixes = 0;

  zlog_debug ("%s: %s, running bgp best selection for %d, %d", __func__,
              peer->host, afi, safi);

  if (!bgp_trigger_bgp_selection_check (peer->bgp, afi, safi))
    goto end_running;

  if (safi == SAFI_MPLS_VPN || safi == SAFI_EVPN)
    {
      for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn; rn = bgp_route_next (rn))
        {
          struct bgp_node *rm;
	  struct bgp_table *table;

          /* look for neighbor in tables */
          if ((table = rn->info) != NULL)
            {
              for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
                {
                  if (CHECK_FLAG (rm->flags, BGP_NODE_PROCESS_TO_SCHEDULE))
                    {
                      UNSET_FLAG (rm->flags, BGP_NODE_PROCESS_TO_SCHEDULE);
                      bgp_process(peer->bgp, rm, afi, safi);
                      nb_prefixes++;
                    }
                }
            }
        }
    }
  else
    {
      for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn; rn = bgp_route_next (rn))
        {
          if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE))
            {
              UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE);
              bgp_process(peer->bgp, rn, afi, safi);
              nb_prefixes++;
            }
        }
    }

  if (safi != SAFI_MPLS_VPN && safi != SAFI_EVPN)
    goto end_running;

  if (safi == SAFI_MPLS_VPN)
    {
      for (ALL_LIST_ELEMENTS_RO(peer->bgp->vrfs, node, vrf)) {
        for (rn = bgp_table_top (vrf->rib[afi]); rn; rn = bgp_route_next (rn))
          {
            if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE) && !is_origin_evpn(rn))
              {
                UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE);
                bgp_process(peer->bgp, rn, afi, SAFI_UNICAST);
                nb_prefixes++;
              }
          }
      }
    }
  else
    {
      for (ALL_LIST_ELEMENTS_RO(peer->bgp->vrfs, node, vrf)) {
        for (rn = bgp_table_top (vrf->rib[AFI_L2VPN]); rn; rn = bgp_route_next (rn))
          {
            if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE) && is_origin_evpn(rn))
              {
                UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE);
                bgp_process(peer->bgp, rn, AFI_L2VPN, SAFI_UNICAST);
                nb_prefixes++;
              }
          }
        for (rn = bgp_table_top (vrf->rib[AFI_IP]); rn; rn = bgp_route_next (rn))
          {
            if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE) && is_origin_evpn(rn))
              {
                UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE);
                bgp_process(peer->bgp, rn, AFI_IP, SAFI_UNICAST);
                nb_prefixes++;
              }
          }
	for (rn = bgp_table_top (vrf->rib[AFI_IP6]); rn; rn = bgp_route_next (rn))
          {
            if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE) && is_origin_evpn(rn))
              {
                UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE);
                bgp_process(peer->bgp, rn, AFI_IP6, SAFI_UNICAST);
                nb_prefixes++;
              }
          }
      }
    }

 end_running:
  zlog_debug ("%s: %s, enqueued %u prefixes for bgp best selection for %d, %d", __func__,
              peer->host, nb_prefixes, afi, safi);
  return;
}

void
bgp_trigger_bgp_selection_peer (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  /* check established */
  if (peer->status != Established)
    return;

  /* check afc selected */
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      if (peer->afc[afi][safi])
        {
          /* End-of-RIB received */
          if (CHECK_FLAG (peer->af_sflags[afi][safi],
                          PEER_STATUS_EOR_RECEIVED) ||
              CHECK_FLAG (peer->af_sflags[afi][safi],
                          PEER_STATUS_SELECTION_DEFERRAL_EXPIRED) ||
              CHECK_FLAG (peer->af_sflags[afi][safi],
                          PEER_STATUS_FIRST_KEEPALIVE_RECEIVED))
            continue;

          /* If BGP UPDATE messages have been received, trigger
           * bgp best selection.
           */
          if (peer->pcount[afi][safi])
            {
              if (BGP_DEBUG (normal, NORMAL))
                zlog (peer->log, LOG_DEBUG,
                      "KEEPALIVE rcvd %s, trigger bgp best selection for %s",
                      peer->host, afi_safi_print (afi, safi));

              SET_FLAG (peer->af_sflags[afi][safi],
                        PEER_STATUS_FIRST_KEEPALIVE_RECEIVED);
              bgp_trigger_bgp_selection (peer, afi, safi);
              /* Stop bgp selection deferral timer */
              if (bgp_selection_deferral_timer_active (peer, afi, safi))
                bgp_selection_deferral_timer_end (peer, afi, safi);
            }
        }
}

static void
bgp_process_send (struct bgp *bgp, struct bgp_node *rn, afi_t afi, safi_t safi)
{
  struct bgp_process_queue *pqnode;

  if ( (bm->process_main_queue == NULL) ||
       (bm->process_rsclient_queue == NULL) ||
       (bm->process_vrf_queue == NULL) )
    bgp_process_queue_init ();
  
  pqnode = XCALLOC (MTYPE_BGP_PROCESS_QUEUE, 
                    sizeof (struct bgp_process_queue));
  if (!pqnode)
    return;

  /* all unlocked in bgp_processq_del */
  bgp_table_lock (bgp_node_table (rn));
  pqnode->rn = bgp_lock_node (rn);
  pqnode->bgp = bgp;
  bgp_lock (bgp);
  pqnode->afi = afi;
  pqnode->safi = safi;
  
  switch (bgp_node_table (rn)->type)
    {
      case BGP_TABLE_MAIN:
        work_queue_add (bm->process_main_queue, pqnode);
        break;
      case BGP_TABLE_RSCLIENT:
        work_queue_add (bm->process_rsclient_queue, pqnode);
        break;
      case BGP_TABLE_VRF:
        work_queue_add (bm->process_vrf_queue, pqnode);
        break;
    }
  SET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
  return;
}

void
bgp_process (struct bgp *bgp, struct bgp_node *rn, afi_t afi, safi_t safi)
{
  struct bgp_info *ri;
  afi_t orig_afi = afi;
  safi_t orig_safi = safi;

  /* already scheduled for processing? */
  if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED))
    {
      return;
    }

  if (rn->info == NULL)
    {
      /* XXX: Perhaps remove before next release, after we've flushed out
       * any obvious cases
       */
      assert (rn->info != NULL);
      char buf[PREFIX_STRLEN];
      zlog_warn ("%s: Called for route_node %s with no routing entries!",
                 __func__,
                 prefix2str (&(bgp_node_to_rnode (rn)->p), buf, sizeof(buf)));
      return;
    }

  /* if deferral timer is disabled, then
   * go back to old behaviour, ie: process incoming entries
   * as soon as possible
   */
  if (!bgp->v_selection_deferral) {
    if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE))
      UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE);
    bgp_process_send(bgp, rn, afi, safi);
    return;
  }

  if (rn->table && bgp_node_table (rn) &&
      bgp_node_table (rn)->type == BGP_TABLE_VRF)
    {
      int is_origin_evpn = 0;

      for (ri = rn->info; ri; ri = ri->next)
        if (CHECK_FLAG (ri->flags, BGP_INFO_ORIGIN_EVPN))
          {
            is_origin_evpn = 1;
            break;
          }

      if (is_origin_evpn)
        {
          orig_afi = AFI_L2VPN;
          orig_safi = SAFI_EVPN;
        }
      else
        {
          orig_safi = SAFI_MPLS_VPN;
        }
    }

  /* do not enqueue for BGP, wait reception of EOR marker */
  if (!bgp_trigger_bgp_selection_check (bgp, orig_afi, orig_safi))
    {
      SET_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE);
      return;
    }

  if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE))
    UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_TO_SCHEDULE);

  bgp_process_send(bgp, rn, afi, safi);
  return;
}

static int
bgp_maximum_prefix_restart_timer (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_pmax_restart = NULL;

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("%s Maximum-prefix restart timer expired, restore peering",
		peer->host);

  peer_clear (peer);

  return 0;
}

int
bgp_maximum_prefix_overflow (struct peer *peer, afi_t afi, 
                             safi_t safi, int always)
{
  if (!CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX))
    return 0;

  if (peer->pcount[afi][safi] > peer->pmax[afi][safi])
    {
      if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT)
         && ! always)
       return 0;

      zlog (peer->log, LOG_INFO,
	    "%%MAXPFXEXCEED: No. of %s prefix received from %s %ld exceed, "
	    "limit %ld", afi_safi_print (afi, safi), peer->host,
	    peer->pcount[afi][safi], peer->pmax[afi][safi]);
      SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT);

      if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_WARNING))
       return 0;

      {
       u_int8_t ndata[7];

       if (safi == SAFI_MPLS_VPN)
         ndata[2]  = SAFI_MPLS_LABELED_VPN;
       else if (safi == SAFI_EVPN)
         ndata[2] = SAFI_IANA_EVPN;
       else if (safi == SAFI_LABELED_UNICAST)
         ndata[2] = SAFI_IANA_LABELED_UNICAST;
       else
         ndata[2] = safi;
       if (afi == AFI_L2VPN)
         ndata[1] = AFI_IANA_L2VPN;
       else
         ndata[1] = afi;
       ndata[0] = (afi >>  8);
       ndata[1] = afi;
       ndata[2] = safi;
       ndata[3] = (peer->pmax[afi][safi] >> 24);
       ndata[4] = (peer->pmax[afi][safi] >> 16);
       ndata[5] = (peer->pmax[afi][safi] >> 8);
       ndata[6] = (peer->pmax[afi][safi]);

       SET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
       bgp_notify_send_with_data (peer, BGP_NOTIFY_CEASE,
                                  BGP_NOTIFY_CEASE_MAX_PREFIX, ndata, 7);
      }

      /* restart timer start */
      if (peer->pmax_restart[afi][safi])
	{
	  peer->v_pmax_restart = peer->pmax_restart[afi][safi] * 60;

	  if (BGP_DEBUG (events, EVENTS))
	    zlog_debug ("%s Maximum-prefix restart timer started for %d secs",
			peer->host, peer->v_pmax_restart);

	  BGP_TIMER_ON (peer->t_pmax_restart, bgp_maximum_prefix_restart_timer,
			peer->v_pmax_restart);
	}

      return 1;
    }
  else
    UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT);

  if (peer->pcount[afi][safi] > (peer->pmax[afi][safi] * peer->pmax_threshold[afi][safi] / 100))
    {
      if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD)
         && ! always)
       return 0;

      zlog (peer->log, LOG_INFO,
	    "%%MAXPFX: No. of %s prefix received from %s reaches %ld, max %ld",
	    afi_safi_print (afi, safi), peer->host, peer->pcount[afi][safi],
	    peer->pmax[afi][safi]);
      SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD);
    }
  else
    UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD);
  return 0;
}

/* Unconditionally remove the route from the RIB, without taking
 * damping into consideration (eg, because the session went down)
 */
static void
bgp_rib_remove (struct bgp_node *rn, struct bgp_info *ri, struct peer *peer,
		afi_t afi, safi_t safi)
{
  bgp_aggregate_decrement (peer->bgp, &rn->p, ri, afi, safi);
  
  if (!CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    bgp_info_delete (rn, ri); /* keep historical info */

  if (!CHECK_FLAG(peer->bgp->flags, BGP_FLAG_DELETING) &&
      !IS_EVPN_RT1_PREFIX(&rn->p))
    bgp_vrf_process_imports (peer->bgp, afi, safi, rn, ri, NULL);
  bgp_process (peer->bgp, rn, afi, safi);
}


static void
bgp_rib_withdraw (struct bgp_node *rn, struct bgp_info *ri, struct peer *peer,
		  afi_t afi, safi_t safi, struct prefix_rd *prd)
{
  int status = BGP_DAMP_NONE;

  /* apply dampening, if result is suppressed, we'll be retaining 
   * the bgp_info in the RIB for historical reference.
   */
  if (CHECK_FLAG (peer->bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
      && peer->sort == BGP_PEER_EBGP)
    if ( (status = bgp_damp_withdraw (ri, rn, afi, safi, 0)) 
         == BGP_DAMP_SUPPRESSED)
      {
        bgp_aggregate_decrement (peer->bgp, &rn->p, ri, afi, safi);
        return;
      }
    
  bgp_rib_remove (rn, ri, peer, afi, safi);
}

struct bgp_info *
info_make (int type, int sub_type, struct peer *peer, struct attr *attr,
	   struct bgp_node *rn)
{
  struct bgp_info *new;

  /* Make new BGP info. */
  new = XCALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_info));
  new->type = type;
  new->sub_type = sub_type;
  new->peer = peer;
  new->attr = attr;
  new->uptime = bgp_clock ();
  new->net = rn;
  return new;
}

static void
overlay_index_update(struct attr *attr, struct eth_segment_id *eth_s_id, union gw_addr *gw_ip)
{
  struct attr_extra *extra;

  if(!attr)
    return;
  extra = bgp_attr_extra_get(attr);

  if(eth_s_id == NULL)
    {
      memset(&(extra->evpn_overlay.eth_s_id),0, sizeof(struct eth_segment_id));
    }
  else
    {
      memcpy(&(extra->evpn_overlay.eth_s_id), eth_s_id, sizeof(struct eth_segment_id));
    }
  if(gw_ip == NULL)
    {
      memset(&(extra->evpn_overlay.gw_ip), 0, sizeof(union gw_addr));
    }
  else
    {
      memcpy(&(extra->evpn_overlay.gw_ip),gw_ip, sizeof(union gw_addr));
    }
}

static bool
eth_tag_id_equal(afi_t afi, struct bgp_info *info, uint32_t *eth_t_id)
{
  uint32_t local_eth_t_id;

  if(afi != AFI_L2VPN)
    return true;
  if (!info->attr || !info->attr->extra) {
    local_eth_t_id = 0;
    if(eth_t_id == NULL)
      return true;
  } else {
    local_eth_t_id = info->attr->extra->eth_t_id;
  }
  if(eth_t_id && (local_eth_t_id == *eth_t_id))
    return true;
  if (local_eth_t_id == 0)
    return true;
  return false;
}

static bool
overlay_index_equal(afi_t afi, struct bgp_info *info, struct eth_segment_id *eth_s_id, union gw_addr *gw_ip)
{
  struct eth_segment_id *info_eth_s_id, *info_eth_s_id_remote;
  union gw_addr *info_gw_ip, *info_gw_ip_remote;
  char temp[16];

  if(afi != AFI_L2VPN)
    return true;
  if (!info->attr || !info->attr->extra) {
    memset(&temp, 0, 16);
    info_eth_s_id = (struct eth_segment_id *)&temp;
    info_gw_ip = (union gw_addr *)&temp;
    if(eth_s_id == NULL && gw_ip == NULL)
      return true;
  } else {
    info_eth_s_id = &(info->attr->extra->evpn_overlay.eth_s_id);
    info_gw_ip = &(info->attr->extra->evpn_overlay.gw_ip);
  }
  if(gw_ip == NULL)
    info_gw_ip_remote = (union gw_addr *)&temp;
  else
    info_gw_ip_remote = gw_ip;
  if(eth_s_id == NULL)
    info_eth_s_id_remote =  (struct eth_segment_id *)&temp;
  else
    info_eth_s_id_remote =  eth_s_id;
  if (memcmp(info_gw_ip, info_gw_ip_remote, sizeof(union gw_addr)))
    return false;
  return !memcmp(info_eth_s_id, info_eth_s_id_remote, sizeof(struct eth_segment_id));
}

static bool
labels_equal(struct bgp_info *info, uint32_t *labels, size_t nlabels)
{
	uint32_t *info_labels;
	size_t info_nlabels;

	if (!info->extra) {
		info_labels = NULL;
		info_nlabels = 0;
	} else {
		info_labels = info->extra->labels;
		info_nlabels = info->extra->nlabels;
	}

	if (info_nlabels != nlabels)
		return false;

	if (!nlabels)
		return true;

	return !memcmp(labels, info_labels, nlabels * sizeof(labels[0]));
}

static void
bgp_update_rsclient (struct peer *rsclient, afi_t afi, safi_t safi,
      struct attr *attr, struct peer *peer, struct prefix *p, int type,
      int sub_type, struct prefix_rd *prd, uint32_t *labels, size_t nlabels,
      struct bgp_route_evpn* evpn)
{
  struct bgp_node *rn;
  struct bgp *bgp;
  struct attr new_attr;
  struct attr_extra new_extra;
  struct attr *attr_new;
  struct attr *attr_new2;
  struct bgp_info *ri;
  struct bgp_info *new;
  const char *reason;
  char buf[SU_ADDRSTRLEN];

  /* Do not insert announces from a rsclient into its own 'bgp_table'. */
  if (peer == rsclient)
    return;

  bgp = peer->bgp;
  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, prd);

  /* Check previously received route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type)
      break;

  /* AS path loop check. */
  if (aspath_loop_check (attr->aspath, rsclient->as) > rsclient->allowas_in[afi][safi])
    {
      reason = "as-path contains our own AS;";
      goto filtered;
    }

  /* Route reflector originator ID check.  */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID)
      && IPV4_ADDR_SAME (&rsclient->remote_id, &attr->extra->originator_id))
    {
      reason = "originator is us;";
      goto filtered;
    }
  
  new_attr.extra = &new_extra;
  bgp_attr_dup (&new_attr, attr);

  /* Apply export policy. */
  if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT) &&
        bgp_export_modifier (rsclient, peer, p, &new_attr, afi, safi) == RMAP_DENY)
    {
      reason = "export-policy;";
      goto filtered;
    }

  attr_new2 = bgp_attr_intern (&new_attr);
  
  /* Apply import policy. */
  if (bgp_import_modifier (rsclient, peer, p, &new_attr, afi, safi) == RMAP_DENY)
    {
      bgp_attr_unintern (&attr_new2);

      reason = "import-policy;";
      goto filtered;
    }

  attr_new = bgp_attr_intern (&new_attr);
  bgp_attr_unintern (&attr_new2);

  /* IPv4 unicast next hop check.  */
  if ((afi == AFI_IP) && ((safi == SAFI_UNICAST) || safi == SAFI_MULTICAST))
    {
     /* Next hop must not be 0.0.0.0 nor Class D/E address. */
      if (new_attr.nexthop.s_addr == 0
         || IPV4_CLASS_DE (ntohl (new_attr.nexthop.s_addr)))
       {
         bgp_attr_unintern (&attr_new);

         reason = "martian next-hop;";
         goto filtered;
       }
    }

  /* If the update is implicit withdraw. */
  if (ri)
    {
      ri->uptime = bgp_clock ();

      /* Same attribute comes in. */
      if (!CHECK_FLAG(ri->flags, BGP_INFO_REMOVED)
          && attrhash_cmp (ri->attr, attr_new)
          && labels_equal (ri, labels, nlabels)
          && eth_tag_id_equal(afi, ri, evpn==NULL?NULL:&evpn->eth_t_id)
          && (overlay_index_equal(afi, ri, 
                                  evpn==NULL?NULL:&evpn->eth_s_id, 
                                  evpn==NULL?NULL:&evpn->gw_ip)))
        {


          if (BGP_DEBUG (update, UPDATE_IN))
            zlog (peer->log, LOG_DEBUG,
                    "%s rcvd %s/%d for RS-client %s...duplicate ignored",
                    peer->host,
                    inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                    p->prefixlen, rsclient->host);

          bgp_unlock_node (rn);
          bgp_attr_unintern (&attr_new);
          bgp_attr_flush(&new_attr);
          return;
        }

      /* Withdraw/Announce before we fully processed the withdraw */
      if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
        bgp_info_restore (rn, ri);
      
      /* Received Logging. */
      if (BGP_DEBUG (update, UPDATE_IN))
        zlog (peer->log, LOG_DEBUG, "%s rcvd %s/%d for RS-client %s",
                peer->host,
                inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                p->prefixlen, rsclient->host);

      /* The attribute is changed. */
      bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

      /* Update to new attribute.  */
      bgp_attr_unintern (&ri->attr);
      ri->attr = attr_new;

      /* Update MPLS tag. */
      if (nlabels)
        {
          bgp_info_extra_get (ri)->nlabels = nlabels;
          memcpy (ri->extra->labels, labels, sizeof(*labels) * nlabels);
        }
      else if (ri->extra)
        ri->extra->nlabels = 0;

      /* Update Overlay Index */
      if(afi == AFI_L2VPN)
        {
          overlay_index_update(ri->attr, evpn==NULL?NULL:&evpn->eth_s_id, 
                               evpn==NULL?NULL:&evpn->gw_ip);
          if(ri->attr && ri->attr->extra)
            {
              if(evpn && evpn->eth_t_id)
                ri->attr->extra->eth_t_id = evpn->eth_t_id;
              else
                ri->attr->extra->eth_t_id = 0;
            }
        }
      bgp_info_set_flag (rn, ri, BGP_INFO_VALID);

      /* Process change. */
      bgp_process (bgp, rn, afi, safi);
      bgp_unlock_node (rn);

      return;
    }

  /* Received Logging. */
  if (BGP_DEBUG (update, UPDATE_IN))
    {
      zlog (peer->log, LOG_DEBUG, "%s rcvd %s/%d for RS-client %s",
              peer->host,
              inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
              p->prefixlen, rsclient->host);
    }

  new = info_make(type, sub_type, peer, attr_new, rn);

  /* Update MPLS tag. */
  if (nlabels)
    {
      bgp_info_extra_get (new)->nlabels = nlabels;
      memcpy (new->extra->labels, labels, sizeof(*labels) * nlabels);
    }

  /* Update Overlay Index */
  if(afi == AFI_L2VPN)
    {
      overlay_index_update(new->attr, evpn==NULL?NULL:&evpn->eth_s_id,
                           evpn==NULL?NULL:&evpn->gw_ip);
      if(new->attr && new->attr->extra)
        {
          if(evpn && evpn->eth_t_id)
            new->attr->extra->eth_t_id = evpn->eth_t_id;
          else
            new->attr->extra->eth_t_id = 0;
        }
    }
  bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);
  
  /* Process change. */
  bgp_process (bgp, rn, afi, safi);

  return;

 filtered: 

  /* This BGP update is filtered.  Log the reason then update BGP entry.  */
  if (BGP_DEBUG (update, UPDATE_IN))
        zlog (peer->log, LOG_DEBUG,
        "%s rcvd UPDATE about %s/%d -- DENIED for RS-client %s due to: %s",
        peer->host,
        inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
        p->prefixlen, rsclient->host, reason);

  if (ri)
    bgp_rib_remove (rn, ri, peer, afi, safi);

  bgp_unlock_node (rn);

  return;
}

static void
bgp_withdraw_rsclient (struct peer *rsclient, afi_t afi, safi_t safi,
      struct peer *peer, struct prefix *p, int type, int sub_type,
      struct prefix_rd *prd)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  char buf[SU_ADDRSTRLEN];

  if (rsclient == peer)
    return;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, prd);

  /* Lookup withdrawn route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type)
      break;
  /* Withdraw specified route from routing table. */
  if (ri && ! CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    bgp_rib_withdraw (rn, ri, peer, afi, safi, prd);
  else if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG,
          "%s Can't find the route %s/%d", peer->host,
          inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
          p->prefixlen);

  /* Unlock bgp_node_get() lock. */
  bgp_unlock_node (rn);
}

static void
bgp_vrf_restore_one (struct bgp_vrf *vrf, afi_t afi, safi_t safi, struct bgp_node *rn,
                     struct bgp_info *select)
{
  struct bgp_node *vrf_rn;
  struct bgp_info *iter = NULL;
  struct prefix_rd *prd;
  char pfx_str[PREFIX_STRLEN];
  afi_t afi_int = AFI_IP;

  if (afi == AFI_L2VPN)
    {
      if (rn->p.family == AF_INET)
        afi_int = AFI_IP;
      else if (rn->p.family == AF_INET6)
        afi_int = AFI_IP6;
      else if (rn->p.family == AF_L2VPN)
        {
          if (IS_EVPN_RT3_PREFIX(&rn->p))
            afi_int = AFI_IP;
          else if (rn->p.prefixlen == L2VPN_IPV6_PREFIX_LEN)
            afi_int = AFI_IP6;
          else
            afi_int = AFI_IP;
        }
    }
  else
    afi_int = afi;

  prd = &bgp_node_table (rn)->prd;
  if (BGP_DEBUG (events, EVENTS))
    {
      char vrf_rd_str[RD_ADDRSTRLEN], rd_str[RD_ADDRSTRLEN];
      char nh_str[BUFSIZ] = "<?>";

      prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
      prefix_rd2str(prd, rd_str, sizeof(rd_str));
      prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
      if(select && select->attr && select->attr->extra)
        {
          if (afi_int == AFI_IP)
            strcpy (nh_str, inet_ntoa (select->attr->extra->mp_nexthop_global_in));
          else if (afi_int == AFI_IP6)
            inet_ntop (AF_INET6, &select->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
        }
      else if(select)
        {
          inet_ntop (AF_INET, &select->attr->nexthop,
                     nh_str, sizeof (nh_str));
        }
      zlog_debug ("vrf[%s] %s: [%s] [nh %s] %s ", vrf_rd_str, pfx_str, rd_str, nh_str,
                "restoring");
    }

  /* EVPN RT3 prefix is stored in vrf->rib[AFI_L2VPN] */
  if (IS_EVPN_RT3_PREFIX(&rn->p))
    afi_int = AF_L2VPN;

  if(!vrf || !vrf->rib[afi_int] || !select)
    {
      return;
    }

  vrf_rn = bgp_node_get (vrf->rib[afi_int], &rn->p);
  if(!vrf_rn)
    {
      return;
    }

  /* check entry not already present */
  for (iter = vrf_rn->info; iter; iter = iter->next)
    {
      if (!rd_same (&iter->extra->vrf_rd, prd))
        continue;
      /* search associated old entry.
       * assume with same nexthop and same peer */
      if(iter->peer->remote_id.s_addr == select->peer->remote_id.s_addr)
        {
          /* match */
          if (CHECK_FLAG(iter->flags, BGP_INFO_REMOVED))
            {
              bgp_info_restore (vrf_rn, iter);
            }
          break;
        }
    }
  bgp_unlock_node (vrf_rn);
}

/* Undo the effects of a previous call to bgp_info_delete for vrf node. */
static void
bgp_vrf_info_restore (struct bgp *bgp, afi_t afi, safi_t safi,
                      struct bgp_node *rn,
                      struct bgp_info *ri)
{
  struct ecommunity *ecom = NULL;
  struct bgp_vrf *vrf;
  struct listnode *node;
  size_t i;

  if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_EVPN))
    return;

  if (ri && ri->attr && ri->attr->extra)
    ecom = ri->attr->extra->ecommunity;

  if (ecom)
    for (i = 0; i < (size_t)ecom->size; i++)
      {
        struct bgp_rt_sub dummy, *rt_sub;
        uint8_t *val = ecom->val + 8 * i;
        uint8_t type = val[1];

        if (type != ECOMMUNITY_ROUTE_TARGET)
          continue;

        memcpy(&dummy.rt, val, 8);
        rt_sub = hash_lookup (bgp->rt_subscribers, &dummy);
        if (!rt_sub)
          continue;
        for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
          {
            bgp_vrf_restore_one (vrf, afi, safi, rn, ri);
          }
      }
}

/*
 * Check if target subscriber's multipath has been changed.
 * Return true if at least one subscriber's multipath has been changed,
 * else return false.
 */
static bool bgp_target_subscribers_mpath_check(struct bgp *bgp, struct attr *attr)
{
  struct ecommunity *ecom = NULL;

  if (!attr || !attr->extra)
    return false;

  ecom = attr->extra->ecommunity;
  if (ecom)
    {
      for (size_t i = 0; i < (size_t)ecom->size; i++)
        {
          struct bgp_rt_sub dummy, *rt_sub;
          uint8_t *val = ecom->val + 8 * i;
          uint8_t type = val[1];
          struct bgp_vrf *vrf;
          struct listnode *node;

          if (type != ECOMMUNITY_ROUTE_TARGET)
            continue;

          memcpy(&dummy.rt, val, 8);
          rt_sub = hash_lookup (bgp->rt_subscribers, &dummy);
          if (!rt_sub)
            continue;

          for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
            {
              if (vrf->flag & BGP_VRF_MPATH_CHANGE)
                return true;
            }
        }
    }

  return false;
}

static int
bgp_update_main (struct peer *peer, struct prefix *p, struct attr *attr,
	    afi_t afi, safi_t safi, int type, int sub_type,
	    struct prefix_rd *prd, uint32_t *labels, size_t nlabels,
            int soft_reconfig, struct bgp_route_evpn* evpn)
{
  int ret;
  int aspath_loop_count = 0;
  struct bgp_node *rn = NULL;
  struct bgp *bgp;
  struct attr new_attr;
  struct attr_extra new_extra;
  struct attr *attr_new;
  struct bgp_info *ri = NULL;
  struct bgp_info *new;
  const char *reason;
  char buf[SU_ADDRSTRLEN];
  int connected = 0;

  memset (&new_attr, 0, sizeof(struct attr));
  memset (&new_extra, 0, sizeof(struct attr_extra));

  bgp = peer->bgp;

  /* Update Overlay Index */
  if(afi == AFI_L2VPN)
    {
      overlay_index_update(attr, evpn==NULL?NULL:&evpn->eth_s_id,
                           evpn==NULL?NULL:&evpn->gw_ip);
      if(attr && attr->extra)
        {
          if(evpn && evpn->eth_t_id)
            attr->extra->eth_t_id = evpn->eth_t_id;
          else
            attr->extra->eth_t_id = 0;
        }
    }

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);
  
  /* When peer's soft reconfiguration enabled.  Record input packet in
     Adj-RIBs-In.  */
  if (! soft_reconfig && CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
      && peer != bgp->peer_self)
    bgp_adj_in_set (rn, peer, attr);

  /* Check previously received route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type)
      break;

  /* AS path local-as loop check. */
  if (peer->change_local_as)
    {
      if (! CHECK_FLAG (peer->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND))
	aspath_loop_count = 1;

      if (aspath_loop_check (attr->aspath, peer->change_local_as) > aspath_loop_count) 
	{
	  reason = "as-path contains our own AS;";
	  goto filtered;
	}
    }

  /* AS path loop check. */
  if (aspath_loop_check (attr->aspath, bgp->as) > peer->allowas_in[afi][safi]
      || (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
	  && aspath_loop_check(attr->aspath, bgp->confed_id)
	  > peer->allowas_in[afi][safi]))
    {
      reason = "as-path contains our own AS;";
      goto filtered;
    }

  /* Route reflector originator ID check.  */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID)
      && IPV4_ADDR_SAME (&bgp->router_id, &attr->extra->originator_id))
    {
      reason = "originator is us;";
      goto filtered;
    }

  /* Route reflector cluster ID check.  */
  if (bgp_cluster_filter (peer, attr))
    {
      reason = "reflected from the same cluster;";
      goto  filtered;
    }

  /* Apply incoming filter.  */
  if (bgp_input_filter (peer, p, attr, afi, safi) == FILTER_DENY)
    {
      reason = "filter;";
      goto filtered;
    }

  new_attr.extra = &new_extra;
  bgp_attr_dup (&new_attr, attr);

  /* Apply incoming route-map.
   * NB: new_attr may now contain newly allocated values from route-map "set"
   * commands, so we need bgp_attr_flush in the error paths, until we intern
   * the attr (which takes over the memory references) */
  if (bgp_input_modifier (peer, p, &new_attr, afi, safi) == RMAP_DENY)
    {
      reason = "route-map;";
      bgp_attr_flush (&new_attr);
      goto filtered;
    }

  /* IPv4 unicast next hop check.  */
  if (afi == AFI_IP && safi == SAFI_UNICAST)
    {
      /* Next hop must not be 0.0.0.0 nor Class D/E address. Next hop
	 must not be my own address.  */
      if (new_attr.nexthop.s_addr == 0
	  || IPV4_CLASS_DE (ntohl (new_attr.nexthop.s_addr))
	  || bgp_nexthop_self (&new_attr))
	{
	  reason = "martian next-hop;";
	  bgp_attr_flush (&new_attr);
	  goto filtered;
	}
    }

  attr_new = bgp_attr_intern (&new_attr);

  /* If the update is implicit withdraw. */
  if (ri)
    {
      char pstr[PREFIX_STRLEN];

      if (BGP_DEBUG (update, UPDATE_IN))
        prefix2str(p, pstr, PREFIX_STRLEN);

      ri->uptime = bgp_clock ();

      /* Same attribute comes in. */
      if (!CHECK_FLAG (ri->flags, BGP_INFO_REMOVED) 
          && attrhash_cmp (ri->attr, attr_new)
          && labels_equal (ri, labels, nlabels)
          && eth_tag_id_equal(afi, ri, evpn==NULL?0:&evpn->eth_t_id)
          && (overlay_index_equal(afi, ri, evpn==NULL?NULL:&evpn->eth_s_id,
                                  evpn==NULL?NULL:&evpn->gw_ip)))
	{
	  if (CHECK_FLAG (bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
	      && peer->sort == BGP_PEER_EBGP
	      && CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
	    {
              size_t i;

	      if (BGP_DEBUG (update, UPDATE_IN))
	        {
                  zlog (peer->log, LOG_DEBUG, "%s rcvd %s%s",
                        peer->host,
                        pstr,
                        EVPN_RT3_STR(p));
                  for (i = 0; i < nlabels; i++)
                    zlog (peer->log, LOG_DEBUG, "    : label[%lu]=%x", i, labels[i]);
                }

	      if (bgp_damp_update (ri, rn, afi, safi) != BGP_DAMP_SUPPRESSED)
	        {
                  bgp_aggregate_increment (bgp, p, ri, afi, safi);
                  bgp_process (bgp, rn, afi, safi);
                }
	    }
          else /* Duplicate - odd */
	    {
              if (BGP_DEBUG (update, UPDATE_IN))
                {
                  size_t i;
                  zlog (peer->log, LOG_DEBUG,
                        "%s rcvd %s%s...duplicate ignored",
                        peer->host,
                        pstr,
                        EVPN_RT3_STR(p));
                  for (i = 0; i < nlabels; i++)
                    zlog (peer->log, LOG_DEBUG, "    : label[%lu]=%x", i, labels[i]);
                }
	      /* graceful restart STALE flag unset. */
	      if (CHECK_FLAG (ri->flags, BGP_INFO_STALE) ||
                  CHECK_FLAG (ri->flags, BGP_INFO_STALE_REFRESH) ||
                  soft_reconfig)
		{
                  if (CHECK_FLAG (ri->flags, BGP_INFO_STALE))
                      bgp_info_unset_flag (rn, ri, BGP_INFO_STALE);
                  else if (CHECK_FLAG (ri->flags, BGP_INFO_STALE_REFRESH))
                    bgp_info_unset_flag (rn, ri, BGP_INFO_STALE_REFRESH);

		  bgp_process (bgp, rn, afi, safi);
		  if (evpn && ((evpn->auto_discovery_type & EVPN_ETHERNET_AD_PER_ESI)
                               ||(evpn->auto_discovery_type & EVPN_ETHERNET_AD_PER_EVI)))
                    {
                      struct bgp_evpn_ad *ad;
                      ad = bgp_evpn_process_auto_discovery(peer, prd, evpn, p, labels[0], attr);
                      bgp_evpn_process_imports(bgp, NULL, ad);
                    }
                  else
                    {
		      if (soft_reconfig)
			{
			  if (bgp_target_subscribers_mpath_check(bgp, ri->attr))
			    bgp_vrf_process_imports(bgp, afi, safi, rn, (struct bgp_info *)0xffffffff, ri);
			}
		      else
			bgp_vrf_process_imports(bgp, afi, safi, rn, (struct bgp_info *)0xffffffff, ri);
                    }
		}
	    }

	  bgp_unlock_node (rn);
	  bgp_attr_unintern (&attr_new);
          bgp_attr_flush (&new_attr);

	  return 0;
	}

      /* Withdraw/Announce before we fully processed the withdraw */
      if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
        {
          if (BGP_DEBUG (update, UPDATE_IN))
            zlog (peer->log, LOG_DEBUG, "%s rcvd %s%s, flapped quicker than processing",
            peer->host,
            pstr, EVPN_RT3_STR(p));
          bgp_info_restore (rn, ri);
          bgp_vrf_info_restore (bgp, afi, safi, rn, ri);
        }

      /* Received Logging. */
      if (BGP_DEBUG (update, UPDATE_IN))
        zlog (peer->log, LOG_DEBUG, "%s rcvd %s%s",
              peer->host,
              pstr,
              EVPN_RT3_STR(p));

      /* graceful restart STALE flag unset. */
      if (CHECK_FLAG (ri->flags, BGP_INFO_STALE))
	bgp_info_unset_flag (rn, ri, BGP_INFO_STALE);

      /* BGP route refresh  STALE_REFRESH flag unset. */
      if (CHECK_FLAG (ri->flags, BGP_INFO_STALE_REFRESH))
	bgp_info_unset_flag (rn, ri, BGP_INFO_STALE_REFRESH);

      /* The attribute is changed. */
      bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
      
      /* implicit withdraw, decrement aggregate and pcount here.
       * only if update is accepted, they'll increment below.
       */
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      
      /* Update bgp route dampening information.  */
      if (CHECK_FLAG (bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
	  && peer->sort == BGP_PEER_EBGP)
	{
	  /* This is implicit withdraw so we should update dampening
	     information.  */
	  if (! CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
	    bgp_damp_withdraw (ri, rn, afi, safi, 1);  
	}


      /* Maybe there is the case that ecommunities changed */
      bgp_vrf_process_ecom_change (bgp, afi, safi, rn, ri, attr_new);

      /* Update to new attribute.  */
      bgp_attr_unintern (&ri->attr);
      ri->attr = attr_new;

      /* Update MPLS tag. */
      if (nlabels)
        {
          bgp_info_extra_get (ri)->nlabels = nlabels;
          memcpy (ri->extra->labels, labels, sizeof(*labels) * nlabels);
        }
      else if (ri->extra)
        ri->extra->nlabels = 0;

      bgp_attr_flush (&new_attr);

      /* Update bgp route dampening information.  */
      if (CHECK_FLAG (bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
	  && peer->sort == BGP_PEER_EBGP)
	{
	  /* Now we do normal update dampening.  */
	  ret = bgp_damp_update (ri, rn, afi, safi);
	  if (ret == BGP_DAMP_SUPPRESSED)
	    {
	      bgp_unlock_node (rn);
	      return 0;
	    }
	}

      /* Nexthop reachability check. */
      if ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST)
	{
	  if (peer->sort == BGP_PEER_EBGP && peer->ttl == 1 &&
	      ! CHECK_FLAG (peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK))
	    connected = 1;
	  else
	    connected = 0;

	  if (bgp_find_or_add_nexthop (afi, ri, NULL, connected))
	    bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
	  else
	    {
	      if (BGP_DEBUG(nht, NHT))
		{
		  char buf1[INET6_ADDRSTRLEN];
		  inet_ntop(AF_INET, (const void *)&attr_new->nexthop, buf1, INET6_ADDRSTRLEN);
		  zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
		}
	      bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
	    }
	}
      else
	bgp_info_set_flag (rn, ri, BGP_INFO_VALID);

      bgp_attr_flush (&new_attr);

      /* Process change. */
      bgp_aggregate_increment (bgp, p, ri, afi, safi);

      bgp_process (bgp, rn, afi, safi);
      if (evpn && ((evpn->auto_discovery_type & EVPN_ETHERNET_AD_PER_ESI)
               ||(evpn->auto_discovery_type & EVPN_ETHERNET_AD_PER_EVI)))
        {
          struct bgp_evpn_ad *ad;
          ad = bgp_evpn_process_auto_discovery(peer, prd, evpn, p, labels[0], attr);
          bgp_evpn_process_imports(bgp, NULL, ad);
        }
      else
        {
          bgp_vrf_process_imports(bgp, afi, safi, rn, (struct bgp_info *)0xffffffff, ri);
        }

      /* non null value for old_select to inform update */
      bgp_unlock_node (rn);

      return 0;
    }

  /* Received Logging. */
  if (BGP_DEBUG (update, UPDATE_IN))  
    {
      char pstr[PREFIX_STRLEN];

      prefix2str(p, pstr, PREFIX_STRLEN);
      zlog (peer->log, LOG_DEBUG, "%s rcvd %s%s",
	    peer->host,
	    pstr,
	    EVPN_RT3_STR(p));
    }

  /* Make new BGP info. */
  new = info_make(type, sub_type, peer, attr_new, rn);

  /* Update MPLS tag. */
  if (nlabels)
    {
      bgp_info_extra_get (new)->nlabels = nlabels;
      memcpy (new->extra->labels, labels, sizeof(*labels) * nlabels);
    }

  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP) || (safi == SAFI_EVPN))
    memcpy (&(bgp_info_extra_get (new)->vrf_rd), prd,sizeof(struct prefix_rd));
  /* Nexthop reachability check. */
  if ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST)
    {
      if (peer->sort == BGP_PEER_EBGP && peer->ttl == 1 &&
	  ! CHECK_FLAG (peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK))
	connected = 1;
      else
	connected = 0;

      if (bgp_find_or_add_nexthop (afi, new, NULL, connected))
	bgp_info_set_flag (rn, new, BGP_INFO_VALID);
      else
	{
	  if (BGP_DEBUG(nht, NHT))
	    {
	      char buf1[INET6_ADDRSTRLEN];
	      inet_ntop(AF_INET, (const void *)&attr_new->nexthop, buf1, INET6_ADDRSTRLEN);
	      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
	    }
	  bgp_info_unset_flag (rn, new, BGP_INFO_VALID);
	}
    }
  else
    bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Increment prefix */
  bgp_aggregate_increment (bgp, p, new, afi, safi);
  
  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);

  bgp_attr_flush (&new_attr);

  /* If maximum prefix count is configured and current prefix
     count exeed it. */
  if (bgp_maximum_prefix_overflow (peer, afi, safi, 0))
    return -1;

  /* Process change. */
  bgp_process (bgp, rn, afi, safi);
  if (evpn && ((evpn->auto_discovery_type & EVPN_ETHERNET_AD_PER_ESI)
               ||(evpn->auto_discovery_type & EVPN_ETHERNET_AD_PER_EVI)))
    {
      struct bgp_evpn_ad *ad;
      ad = bgp_evpn_process_auto_discovery(peer, prd, evpn, p, labels[0], attr);
      bgp_evpn_process_imports(bgp, NULL, ad);
    }
  else
    {
      bgp_vrf_process_imports(peer->bgp, afi, safi, rn, NULL, new);
    }

  return 0;

  /* This BGP update is filtered.  Log the reason then update BGP
     entry.  */
 filtered:
  if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG,
	  "%s rcvd UPDATE about %s/%d -- DENIED due to: %s",
	  peer->host,
	  inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	  p->prefixlen, reason);

  if (ri)
    bgp_rib_remove (rn, ri, peer, afi, safi);

  if (rn)
    {
      bgp_unlock_node (rn);
      bgp_attr_flush (&new_attr);
    }
  return 0;
}

int
bgp_update (struct peer *peer, struct prefix *p, struct attr *attr,
            afi_t afi, safi_t safi, int type, int sub_type,
            struct prefix_rd *prd, uint32_t *labels, size_t nlabels,
            int soft_reconfig, struct bgp_route_evpn* evpn)
{
  struct peer *rsclient;
  struct listnode *node, *nnode;
  struct bgp *bgp;
  int ret;

  ret = bgp_update_main (peer, p, attr, afi, safi, type, sub_type, prd,
                         labels, nlabels, soft_reconfig,
                         evpn);

  bgp = peer->bgp;

  /* Process the update for each RS-client. */
  for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
    {
      if (CHECK_FLAG (rsclient->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        bgp_update_rsclient (rsclient, afi, safi, attr, peer, p, type,
                             sub_type, prd, labels, nlabels, evpn);
    }

  return ret;
}

int
bgp_withdraw (struct peer *peer, struct prefix *p, struct attr *attr, 
	     afi_t afi, safi_t safi, int type, int sub_type, 
             struct prefix_rd *prd, uint32_t *labels, size_t nlabels,
             struct bgp_route_evpn* evpn)
{
  struct bgp *bgp;
  char buf[SU_ADDRSTRLEN];
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct peer *rsclient;
  struct listnode *node, *nnode;

  bgp = peer->bgp;

  /* Lookup node. */
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* Cisco IOS 12.4(24)T4 on session establishment sends withdraws for all
   * routes that are filtered.  This tanks out Quagga RS pretty badly due to
   * the iteration over all RS clients.
   * Since we need to remove the entry from adj_in anyway, do that first and
   * if there was no entry, we don't need to do anything more. */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
      && peer != bgp->peer_self)
    if (!bgp_adj_in_unset (rn, peer))
      {
        if (BGP_DEBUG (update, UPDATE_IN))
          zlog (peer->log, LOG_DEBUG, "%s withdrawing route %s "
                "not in adj-in", peer->host,
                EVPN_RT3_STR(p));
        bgp_unlock_node (rn);
        return 0;
      }

  /* Process the withdraw for each RS-client. */
  for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
    {
      if (CHECK_FLAG (rsclient->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        bgp_withdraw_rsclient (rsclient, afi, safi, peer, p, type, sub_type, prd);
    }

  /* Logging. */
  if (BGP_DEBUG (update, UPDATE_IN))  
    zlog (peer->log, LOG_DEBUG, "%s rcvd UPDATE about %s -- withdrawn",
	  peer->host,
	  EVPN_RT3_STR(p));

  /* Lookup withdrawn route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type)
      break;

  if (evpn && evpn->auto_discovery_type & (EVPN_ETHERNET_AD_PER_ESI|EVPN_ETHERNET_AD_PER_EVI))
    {
      struct bgp_evpn_ad *ad;
      ad = bgp_evpn_process_auto_discovery(peer, prd, evpn, p, labels[0], attr);
      ad->type = BGP_EVPN_AD_TYPE_MP_UNREACH;
      bgp_evpn_process_imports(bgp, ad, NULL);
      bgp_evpn_process_remove_auto_discovery(bgp, peer, prd, ad);
    }

  /* Withdraw specified route from routing table. */
  if (ri && ! CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    bgp_rib_withdraw (rn, ri, peer, afi, safi, prd);
  else if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG, 
	  "%s Can't find the route %s", peer->host,
	  EVPN_RT3_STR(p));

  /* Unlock bgp_node_get() lock. */
  bgp_unlock_node (rn);

  return 0;
}

void
bgp_default_originate (struct peer *peer, afi_t afi, safi_t safi, int withdraw)
{
  struct bgp *bgp;
  struct attr attr;
  struct aspath *aspath;
  struct prefix p;
  struct peer *from;
  struct bgp_node *rn;
  struct bgp_info *ri;
  int ret = RMAP_DENYMATCH;
  
  if (!(afi == AFI_IP || afi == AFI_IP6))
    return;
  
  bgp = peer->bgp;
  from = bgp->peer_self;
  
  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
  aspath = attr.aspath;
  attr.local_pref = bgp->default_local_pref;
  memcpy (&attr.nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);

  if (afi == AFI_IP)
    str2prefix ("0.0.0.0/0", &p);
  else if (afi == AFI_IP6)
    {
      struct attr_extra *ae = attr.extra;

      str2prefix ("::/0", &p);

      /* IPv6 global nexthop must be included. */
      memcpy (&ae->mp_nexthop_global, &peer->nexthop.v6_global, 
	      IPV6_MAX_BYTELEN);
	      ae->mp_nexthop_len = 16;
 
      /* If the peer is on shared nextwork and we have link-local
	 nexthop set it. */
      if (peer->shared_network 
	  && !IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
	{
	  memcpy (&ae->mp_nexthop_local, &peer->nexthop.v6_local, 
		  IPV6_MAX_BYTELEN);
	  ae->mp_nexthop_len = 32;
	}
    }

  if (peer->default_rmap[afi][safi].name)
    {
      SET_FLAG (bgp->peer_self->rmap_type, PEER_RMAP_TYPE_DEFAULT);
      for (rn = bgp_table_top(bgp->rib[afi][safi]); rn; rn = bgp_route_next(rn))
        {
          for (ri = rn->info; ri; ri = ri->next)
            {
              struct attr dummy_attr;
              struct attr_extra dummy_extra;
              struct bgp_info info;

              /* Provide dummy so the route-map can't modify the attributes */
              dummy_attr.extra = &dummy_extra;
              bgp_attr_dup(&dummy_attr, ri->attr);
              info.peer = ri->peer;
              info.attr = &dummy_attr;

              ret = route_map_apply(peer->default_rmap[afi][safi].map, &rn->p,
                                    RMAP_BGP, &info);

              /* The route map might have set attributes. If we don't flush them
               * here, they will be leaked. */
              bgp_attr_flush(&dummy_attr);
              if (ret != RMAP_DENYMATCH)
                break;
            }
          if (ret != RMAP_DENYMATCH)
            break;
        }
      bgp->peer_self->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
        withdraw = 1;
    }

  if (withdraw)
    {
      if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE))
	bgp_default_withdraw_send (peer, afi, safi);
      UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE);
    }
  else
    {
      if (! CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE))
        {
          SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE);
          bgp_default_update_send (peer, &attr, afi, safi, from);
        }
    }
  
  bgp_attr_extra_free (&attr);
  aspath_unintern (&aspath);
}

void bgp_add_encapsulation_type (struct attr *attr, int bgp_encapsulation_type)
{
  struct ecommunity_val bgp_encaps_ecom;
  if(attr->extra)
    {
      attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
      memset(&bgp_encaps_ecom, 0, sizeof(struct ecommunity_val));
      bgp_encaps_ecom.val[0] = ECOMMUNITY_ENCODE_OPAQUE;
      bgp_encaps_ecom.val[1] = ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP;
      bgp_encaps_ecom.val[7] = bgp_encapsulation_type;
      if(!attr->extra->ecommunity)
        attr->extra->ecommunity = ecommunity_new ();
      ecommunity_add_val(attr->extra->ecommunity, &bgp_encaps_ecom);
    }
}

void bgp_add_routermac_ecom (struct attr* attr, char * routermac)
{
  struct ecommunity_val routermac_ecom;

  if(attr->extra)
    {
      attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
      memset(&routermac_ecom, 0, sizeof(struct ecommunity_val));
      routermac_ecom.val[0] = ECOMMUNITY_ENCODE_EVPN;
      routermac_ecom.val[1] = ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC;
      memcpy(&routermac_ecom.val[2], routermac, MAC_LEN);
      if(!attr->extra->ecommunity)
        attr->extra->ecommunity = ecommunity_new ();
      ecommunity_add_val(attr->extra->ecommunity, &routermac_ecom);
    }
}

void
bgp_default_originate_rd (struct peer *peer, afi_t afi, safi_t safi, struct prefix_rd *rd,
                          struct bgp_vrf *vrf, int withdraw)
{
  if (withdraw)
    {
      int empty = 0;

      if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE))
        {
          if (safi == SAFI_MPLS_VPN)
            {
              bgp_default_withdraw_vpn_send (peer, afi, rd);
              if (afi == AFI_IP6)
                empty = (NULL == listnode_head(peer->def_route_rd_vpnv6));
              else
                empty = (NULL == listnode_head(peer->def_route_rd_vpnv4));
            }
          else if (safi == SAFI_EVPN)
            {
              /* XXX IPv4 */
              bgp_default_withdraw_evpn_send (peer, AFI_IP, rd);
              empty = (NULL == listnode_head(peer->def_route_rd_evpn));
            }
        }
      if (empty)
        UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE);
    }
  else
    {
      struct attr attr;
      struct aspath *aspath;
      struct attr_extra *ae;
      struct bgp *bgp = peer->bgp;

      bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
      aspath = attr.aspath;
      attr.local_pref = bgp->default_local_pref;
      ae = attr.extra;

      if (vrf->nh.v4.s_addr)
        {
          memcpy (&attr.nexthop, &(vrf->nh.v4), 4);
          bgp_attr_extra_get (&attr)->mp_nexthop_global_in.s_addr = vrf->nh.v4.s_addr;
          bgp_attr_extra_get (&attr)->mp_nexthop_len = IPV4_MAX_BYTELEN;
        }
      else
        {
          const char *ip6str = "::0";
          struct in6_addr result;
          if (1 != inet_pton(AF_INET6, ip6str, &result) ||
              0 == memcmp (&result, &vrf->nh.v6_global, sizeof (struct in6_addr)))
            {
              /* IPv6 global nexthop must be included. */
              memcpy (&ae->mp_nexthop_global,
                      &peer->nexthop.v6_global, sizeof (struct in6_addr));
              ae->mp_nexthop_len = IPV6_MAX_BYTELEN;
            }
          else
            {
              memcpy (&ae->mp_nexthop_global,
                      &vrf->nh.v6_global, sizeof (struct in6_addr));
              ae->mp_nexthop_len = IPV6_MAX_BYTELEN;
            }
        }

      if (vrf->rt_export)
        {
          ae->ecommunity = ecommunity_dup(vrf->rt_export);
          attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
        }

      if (safi == SAFI_EVPN)
        {
          struct eth_segment_id esi;
          union gw_addr add;

          ae->eth_t_id = vrf->ethtag;
          /* overlay index */
          if(vrf->esi)
            str2esi (vrf->esi, &esi);/* esi2str */
          else
            memset(&esi, 0, sizeof(struct eth_segment_id));
          memset(&add, 0, sizeof(union gw_addr));
          if (vrf->ipv4_gatewayIp.s_addr)
            add.ipv4.s_addr = vrf->ipv4_gatewayIp.s_addr;
          else
            add.ipv4 = bgp->router_id;
          overlay_index_update(&attr, &esi, &add);
          /* router mac */
          if(vrf->mac_router)
            {
              char routermac_int[MAC_LEN+1];

              str2mac (vrf->mac_router, routermac_int);
              bgp_add_routermac_ecom (&attr, routermac_int);
            }
        }
      if (! CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE))
        {
          SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE);
        }
      if (safi == SAFI_MPLS_VPN)
        bgp_default_update_vpn_send(peer, rd, &attr, afi, vrf->nlabels, vrf->labels);
      else if (safi == SAFI_EVPN)
        {
          if (ae->mp_nexthop_len == IPV6_MAX_BYTELEN)
            bgp_default_update_evpn_send(peer, rd, &attr, AFI_IP6, vrf->nlabels, vrf->labels);
          else
            bgp_default_update_evpn_send(peer, rd, &attr, AFI_IP, vrf->nlabels, vrf->labels);
        }

      if (ae->ecommunity)
        ecommunity_free (&ae->ecommunity);
      bgp_attr_extra_free (&attr);
      aspath_unintern (&aspath);
    }
}

void
bgp_auto_discovery_evpn (struct peer *peer, struct bgp_vrf *vrf, struct attr * attr,
                         struct eth_segment_id *esi, u_int32_t ethtag,
                         u_int32_t label, int withdraw)
{
  if (withdraw)
    {
      /* all extented communities are already set by a previous push */
      bgp_auto_discovery_withdraw_send (peer, &vrf->outbound_rd, attr, ethtag, label);
    }
  else
    {
      bgp_auto_discovery_update_send(peer, &vrf->outbound_rd, attr, ethtag, label);
    }
}

static void
bgp_announce_table (struct peer *peer, afi_t afi, safi_t safi,
                   struct bgp_table *table, int rsclient)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct attr attr;
  struct attr_extra extra;

  memset(&extra, 0, sizeof(extra));
  if (! table)
    table = (rsclient) ? peer->rib[afi][safi] : peer->bgp->rib[afi][safi];

  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_DEFAULT_ORIGINATE))
    {
      if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP) && (safi != SAFI_EVPN))
      bgp_default_originate (peer, afi, safi, 0);
    else
      {
        /* Create as many UPDATE message needed for each Route Distinguisher */
        for (rn = rsclient ?
               bgp_table_top(peer->rib[afi][safi]):bgp_table_top(peer->bgp->rib[afi][safi]);
             rn; rn = bgp_route_next (rn))
          {
            struct bgp_node *rm;
            struct bgp_info *ri;

            /* look for neighbor in tables */
            if ((table = rn->info) != NULL)
              {
                 int rd_header = 1;

                 for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
                    for (ri = rm->info; ri; ri = ri->next)
                     {
                       if (rd_header)
                         {
                           struct listnode *node;
                           struct bgp_vrf *vrf;

                           /* use vrf labels */

                           rd_header = 0;

                           /* find nh in VRF list */
                           for (ALL_LIST_ELEMENTS_RO(peer->bgp->vrfs, node, vrf))
                             {
                               if (!prefix_rd_cmp((struct prefix_rd*)&rn->p,
                                                   &vrf->outbound_rd))
                                 {
                                   bgp_default_originate_rd (peer, afi, safi,
                                                             (struct prefix_rd*)&rn->p,
                                                             vrf, 0);
                                   break;
                                 }
                             }
                         }
                      }
              }
          }
      }
    }
  /* It's initialized in bgp_announce_[check|check_rsclient]() */
  attr.extra = &extra;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next(rn))
    for (ri = rn->info; ri; ri = ri->next)
      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED) && ri->peer != peer)
	{
         if ( (rsclient) ?
              (bgp_announce_check_rsclient (ri, peer, &rn->p, &attr, afi, safi))
              : (bgp_announce_check (ri, peer, &rn->p, &attr, afi, safi)))
	    bgp_adj_out_set (rn, peer, &rn->p, &attr, afi, safi, ri);
	  else
	    bgp_adj_out_unset (rn, peer, &rn->p, afi, safi);
	}

  bgp_attr_flush_encap(&attr);
}

void
bgp_announce_route (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_table *table;

  if (peer->status != Established)
    return;

  if (! peer->afc_nego[afi][safi])
    return;

  /* First update is deferred until ORF or ROUTE-REFRESH is received */
  if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_ORF_WAIT_REFRESH))
    return;

  if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP) && ( safi != SAFI_EVPN))
    bgp_announce_table (peer, afi, safi, NULL, 0);
  else
    for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
	 rn = bgp_route_next(rn))
      if ((table = (rn->info)) != NULL)
       bgp_announce_table (peer, afi, safi, table, 0);

  if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
    {
      if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP))
        bgp_announce_table (peer, afi, safi, NULL, 1);
      else
        for (rn = bgp_table_top (peer->rib[afi][safi]); rn;
             rn = bgp_route_next(rn))
          if ((table = (rn->info)) != NULL)
            bgp_announce_table (peer, afi, safi, table, 1);
    }
}

void
bgp_announce_route_all (struct peer *peer)
{
  afi_t afi;
  safi_t safi;
  
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_announce_route (peer, afi, safi);
}

static void
bgp_soft_reconfig_table_rsclient (struct peer *rsclient, afi_t afi,
        safi_t safi, struct bgp_table *table, struct prefix_rd *prd)
{
  struct bgp_node *rn;
  struct bgp_adj_in *ain;

  if (! table)
    table = rsclient->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain; ain = ain->next)
      {
        struct bgp_info *ri = rn->info;
        uint32_t *labels = (ri && ri->extra) ? ri->extra->labels : NULL;
        size_t nlabels = (ri && ri->extra) ? ri->extra->nlabels : 0;

        bgp_update_rsclient (rsclient, afi, safi, ain->attr, ain->peer,
                             &rn->p, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, prd,
                             labels, nlabels, NULL);
      }
}

void
bgp_soft_reconfig_rsclient (struct peer *rsclient, afi_t afi, safi_t safi)
{
  struct bgp_table *table;
  struct bgp_node *rn;
  
  if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP) && (safi != SAFI_EVPN))
    bgp_soft_reconfig_table_rsclient (rsclient, afi, safi, NULL, NULL);

  else
    for (rn = bgp_table_top (rsclient->bgp->rib[afi][safi]); rn;
            rn = bgp_route_next (rn))
      if ((table = rn->info) != NULL)
        {
          struct prefix_rd prd;
          prd.family = AF_UNSPEC;
          prd.prefixlen = 64;
          memcpy(&prd.val, rn->p.u.val, 8);

          bgp_soft_reconfig_table_rsclient (rsclient, afi, safi, table, &prd);
        }
}

static void
bgp_soft_reconfig_table (struct peer *peer, afi_t afi, safi_t safi,
			 struct bgp_table *table, struct prefix_rd *prd)
{
  int ret;
  struct bgp_node *rn;
  struct bgp_adj_in *ain;

  if (! table)
    table = peer->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain; ain = ain->next)
      {
	if (ain->peer == peer)
	  {
            struct bgp_info *ri = NULL;
            uint32_t labels[BGP_MAX_LABELS];
            size_t nlabels = 0;
            struct bgp_route_evpn evpn_copy;
            struct bgp_route_evpn *evpn_ptr = NULL;

            /* Check previously received route. */
            for (ri = rn->info; ri; ri = ri->next)
              if (ri->peer == peer)
                break;
            if (ri == NULL)
              continue;

            nlabels = (ri->extra) ? ri->extra->nlabels : 0;
            if (nlabels)
              memcpy (labels, ri->extra->labels, sizeof(ri->extra->labels[0]) * nlabels);

            if (safi == SAFI_EVPN && ri && ri->attr && ri->attr->extra) {
              evpn_ptr = &evpn_copy;
              evpn_ptr->eth_t_id = ri->attr->extra->eth_t_id;
              memcpy(&evpn_ptr->eth_s_id, &ri->attr->extra->evpn_overlay.eth_s_id, sizeof(struct eth_segment_id));
              memcpy(&evpn_ptr->gw_ip, &ri->attr->extra->evpn_overlay.gw_ip, sizeof(union gw_addr));
              evpn_ptr->auto_discovery_type = 0;
            }
	    ret = bgp_update (peer, &rn->p, ain->attr, afi, safi,
			      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
			      prd, labels, nlabels, 1, evpn_ptr);

	    if (ret < 0)
	      {
		bgp_unlock_node (rn);
		return;
	      }
	    continue;
	  }
      }
}

void
bgp_soft_reconfig_in (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_table *table;

  if (peer->status != Established)
    return;

  if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP) && (safi != SAFI_EVPN))
    bgp_soft_reconfig_table (peer, afi, safi, NULL, NULL);
  else
    for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
	 rn = bgp_route_next (rn))
      if ((table = rn->info) != NULL)
        {
          struct prefix_rd prd;
          prd.family = AF_UNSPEC;
          prd.prefixlen = 64;
          memcpy(&prd.val, rn->p.u.val, 8);

          bgp_soft_reconfig_table (peer, afi, safi, table, &prd);
        }
}


struct bgp_clear_node_queue
{
  struct bgp_node *rn;
  enum bgp_clear_route_type purpose;
};

static wq_item_status
bgp_clear_route_node (struct work_queue *wq, void *data)
{
  struct bgp_clear_node_queue *cnq = data;
  struct bgp_node *rn = cnq->rn;
  struct peer *peer = wq->spec.data;
  struct bgp_info *ri;
  afi_t afi = bgp_node_table (rn)->afi;
  safi_t safi = bgp_node_table (rn)->safi;
  
  assert (rn && peer);
  
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer || cnq->purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
      {
        /* graceful restart STALE flag set. */
        if ((CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT)
             && peer->nsf[afi][safi]
             && ! CHECK_FLAG (ri->flags, BGP_INFO_STALE)
             && ! CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))) {
          bgp_info_set_flag (rn, ri, BGP_INFO_STALE);
        } else if (cnq->purpose == BGP_CLEAR_ROUTE_REFRESH) {
          bgp_info_set_flag (rn, ri, BGP_INFO_STALE_REFRESH);
        } else
          bgp_rib_remove (rn, ri, peer, afi, safi);
        break;
      }
  return WQ_SUCCESS;
}

static void
bgp_clear_node_queue_del (struct work_queue *wq, void *data)
{
  struct bgp_clear_node_queue *cnq = data;
  struct bgp_node *rn = cnq->rn;
  struct bgp_table *table = bgp_node_table (rn);
  
  bgp_unlock_node (rn); 
  bgp_table_unlock (table);
  XFREE (MTYPE_BGP_CLEAR_NODE_QUEUE, cnq);
}

static void
bgp_clear_node_complete (struct work_queue *wq)
{
  struct peer *peer = wq->spec.data;
  struct listnode *pn;
  
  if (peer->clear_purpose != BGP_CLEAR_ROUTE_REFRESH)
    {
      /* Tickle FSM to start moving again */
      BGP_EVENT_ADD (peer, Clearing_Completed);
    }

  /* Delete from bgp dying peer list. */
  if ((pn = listnode_lookup (peer->bgp->dying_peer, peer)))
    {
      zlog_debug ("%s removed from BGP dying list", peer->host);
      peer = peer_unlock (peer); /* bgp peer list reference */
      list_delete_node (peer->bgp->dying_peer, pn);
    }

  peer_unlock (peer); /* bgp_clear_route */
}

static void
bgp_clear_node_queue_init (struct peer *peer)
{
  char wname[sizeof("clear xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx")];
  
  snprintf (wname, sizeof(wname), "clear %s", peer->host);
#undef CLEAR_QUEUE_NAME_LEN

  if ( (peer->clear_node_queue = work_queue_new (bm->master, wname)) == NULL)
    {
      zlog_err ("%s: Failed to allocate work queue", __func__);
      exit (1);
    }
  peer->clear_node_queue->spec.hold = 10;
  peer->clear_node_queue->spec.workfunc = &bgp_clear_route_node;
  peer->clear_node_queue->spec.del_item_data = &bgp_clear_node_queue_del;
  peer->clear_node_queue->spec.completion_func = &bgp_clear_node_complete;
  peer->clear_node_queue->spec.max_retries = 0;
  
  /* we only 'lock' this peer reference when the queue is actually active */
  peer->clear_node_queue->spec.data = peer;
}

static void
bgp_clear_route_table (struct peer *peer, afi_t afi, safi_t safi,
                       struct bgp_table *table, struct peer *rsclient,
                       enum bgp_clear_route_type purpose)
{
  struct bgp_node *rn;
  
  
  if (! table)
    table = (rsclient) ? rsclient->rib[afi][safi] : peer->bgp->rib[afi][safi];
  
  /* If still no table => afi/safi isn't configured at all or smth. */
  if (! table)
    return;
  
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      struct bgp_info *ri;
      struct bgp_adj_in *ain;
      struct bgp_adj_out *aout;

      /* XXX:TODO: This is suboptimal, every non-empty route_node is
       * queued for every clearing peer, regardless of whether it is
       * relevant to the peer at hand.
       *
       * Overview: There are 3 different indices which need to be
       * scrubbed, potentially, when a peer is removed:
       *
       * 1 peer's routes visible via the RIB (ie accepted routes)
       * 2 peer's routes visible by the (optional) peer's adj-in index
       * 3 other routes visible by the peer's adj-out index
       *
       * 3 there is no hurry in scrubbing, once the struct peer is
       * removed from bgp->peer, we could just GC such deleted peer's
       * adj-outs at our leisure.
       *
       * 1 and 2 must be 'scrubbed' in some way, at least made
       * invisible via RIB index before peer session is allowed to be
       * brought back up. So one needs to know when such a 'search' is
       * complete.
       *
       * Ideally:
       *
       * - there'd be a single global queue or a single RIB walker
       * - rather than tracking which route_nodes still need to be
       *   examined on a peer basis, we'd track which peers still
       *   aren't cleared
       *
       * Given that our per-peer prefix-counts now should be reliable,
       * this may actually be achievable. It doesn't seem to be a huge
       * problem at this time,
       */
      for (ain = rn->adj_in; ain; ain = ain->next)
        if (ain->peer == peer || purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
          {
            bgp_adj_in_remove (rn, ain);
            bgp_unlock_node (rn);
            break;
          }
      for (aout = rn->adj_out; aout; aout = aout->next)
        if (aout->peer == peer || purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
          {
            bgp_adj_out_remove (rn, aout, peer, afi, safi);
            bgp_unlock_node (rn);
            break;
          }

      for (ri = rn->info; ri; ri = ri->next)
        if (ri->peer == peer || purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
          {
            struct bgp_clear_node_queue *cnq;

            /* both unlocked in bgp_clear_node_queue_del */
            bgp_table_lock (bgp_node_table (rn));
            bgp_lock_node (rn);
            cnq = XCALLOC (MTYPE_BGP_CLEAR_NODE_QUEUE,
                           sizeof (struct bgp_clear_node_queue));
            cnq->rn = rn;
            cnq->purpose = purpose;
            work_queue_add (peer->clear_node_queue, cnq);
            break;
          }
    }
  return;
}

void
bgp_clear_route (struct peer *peer, afi_t afi, safi_t safi,
                 enum bgp_clear_route_type purpose)
{
  struct bgp_node *rn;
  struct bgp_table *table;
  struct peer *rsclient;
  struct listnode *node, *nnode;
  peer->clear_purpose = purpose;
  if (peer->clear_node_queue == NULL)
    bgp_clear_node_queue_init (peer);
  
  /* bgp_fsm.c keeps sessions in state Clearing, not transitioning to
   * Idle until it receives a Clearing_Completed event. This protects
   * against peers which flap faster than we can we clear, which could
   * lead to:
   *
   * a) race with routes from the new session being installed before
   *    clear_route_node visits the node (to delete the route of that
   *    peer)
   * b) resource exhaustion, clear_route_node likely leads to an entry
   *    on the process_main queue. Fast-flapping could cause that queue
   *    to grow and grow.
   */

  /* lock peer in assumption that clear-node-queue will get nodes; if so,
   * the unlock will happen upon work-queue completion; other wise, the
   * unlock happens at the end of this function.
   */
  if (!peer->clear_node_queue->thread)
    peer_lock (peer); /* bgp_clear_node_complete */
  switch (purpose)
    {
    case BGP_CLEAR_ROUTE_REFRESH:
    case BGP_CLEAR_ROUTE_NORMAL:
      if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP) &&
          (safi != SAFI_EVPN))
        bgp_clear_route_table (peer, afi, safi, NULL, NULL, purpose);
      else
        for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
             rn = bgp_route_next (rn))
          if ((table = rn->info) != NULL)
            bgp_clear_route_table (peer, afi, safi, table, NULL, purpose);
      for (ALL_LIST_ELEMENTS (peer->bgp->rsclient, node, nnode, rsclient))
        if (CHECK_FLAG(rsclient->af_flags[afi][safi],
                       PEER_FLAG_RSERVER_CLIENT))
          {
            if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP))
              bgp_clear_route_table (peer, afi, safi, NULL, rsclient, purpose);
            else
              for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
                   rn = bgp_route_next (rn))
                if ((table = rn->info) != NULL)
                  bgp_clear_route_table (peer, afi, safi, table, rsclient, purpose);
          }
      break;

    case BGP_CLEAR_ROUTE_MY_RSCLIENT:
      if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP))
        bgp_clear_route_table (peer, afi, safi, NULL, peer, purpose);
      else
        for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
             rn = bgp_route_next (rn))
          if ((table = rn->info) != NULL)
            bgp_clear_route_table (peer, afi, safi, table, peer, purpose);
      break;

    default:
      assert (0);
      break;
    }

  /* unlock if no nodes got added to the clear-node-queue. */
  if (!peer->clear_node_queue->thread)
    peer_unlock (peer);

}
  
void
bgp_clear_route_all (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_clear_route (peer, afi, safi, BGP_CLEAR_ROUTE_NORMAL);
}

/*
 * Finish freeing things when exiting
 */
static void
bgp_drain_workqueue_immediate (struct work_queue *wq)
{
  if (!wq)
    return;

  if (!wq->thread)
    {
      /*
       * no thread implies no queued items
       */
      assert(!wq->items->count);
      return;
    }

   while (wq->items->count)
     {
       if (wq->thread)
         thread_cancel(wq->thread);
       work_queue_run(wq->thread);
     }
}

/*
 * Special function to process clear node queue when bgpd is exiting
 * and the thread scheduler is no longer running.
 */
void
bgp_peer_clear_node_queue_drain_immediate(struct peer *peer)
{
  if (!peer)
    return;

  bgp_drain_workqueue_immediate(peer->clear_node_queue);
}

/*
 * The work queues are not specific to a BGP instance, but the
 * items in them refer to BGP instances, so this should be called
 * before each BGP instance is deleted.
 */
void
bgp_process_queues_drain_immediate(void)
{
  bgp_drain_workqueue_immediate(bm->process_main_queue);
  bgp_drain_workqueue_immediate(bm->process_rsclient_queue);
  bgp_drain_workqueue_immediate(bm->process_vrf_queue);
}

void
bgp_clear_adj_in (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_adj_in *ain;

  table = peer->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain ; ain = ain->next)
      if (ain->peer == peer)
	{
          bgp_adj_in_remove (rn, ain);
          bgp_unlock_node (rn);
          break;
	}
}

void
bgp_vrf_clear_adj_in (struct peer *peer, struct bgp_vrf *vrf, afi_t afi)
{
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_adj_in *ain;

  table = vrf->rib[afi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain ; ain = ain->next)
      if (ain->peer == peer)
	{
          bgp_adj_in_remove (rn, ain);
          bgp_unlock_node (rn);
          break;
	}
}

void
bgp_clear_stale_route (struct peer *peer, afi_t afi, safi_t safi, int status)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_table *table;

  if ( safi == SAFI_MPLS_VPN || safi == SAFI_EVPN)
    {
      for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn; rn = bgp_route_next (rn))
        {
          struct bgp_node *rm;
          struct bgp_info *ri;

          /* look for neighbor in tables */
          if ((table = rn->info) != NULL)
            {
              for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
                for (ri = rm->info; ri; ri = ri->next)
                  if (ri->peer == peer)
                    {
                      if (CHECK_FLAG (ri->flags, status))
                        bgp_rib_remove (rm, ri, peer, afi, safi);
                      break;
                    }
            }
        }
    }
  else
    {
      for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn; rn = bgp_route_next (rn))
        for (ri = rn->info; ri; ri = ri->next)
          if (ri->peer == peer)
            {
              if (CHECK_FLAG (ri->flags, status))
                bgp_rib_remove (rn, ri, peer, afi, safi);
              break;
            }
    }
}

static void
bgp_cleanup_table(struct bgp_table *table, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_info *next;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ri = rn->info; ri; ri = next)
      {
        next = ri->next;
        if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
            && ri->type == ZEBRA_ROUTE_BGP
            && ri->sub_type == BGP_ROUTE_NORMAL)
          bgp_zebra_withdraw (&rn->p, ri, safi);
      }
}

/* Delete all kernel routes. */
void
bgp_cleanup_routes (void)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  afi_t afi;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      struct bgp_node *rn;
      for (afi = AFI_IP; afi < AFI_MAX; ++afi)
	{
          if(afi == AFI_L2VPN)
            continue;
	  bgp_cleanup_table(bgp->rib[afi][SAFI_UNICAST], SAFI_UNICAST);
	  bgp_cleanup_table(bgp->rib[afi][SAFI_LABELED_UNICAST], SAFI_LABELED_UNICAST);

	  /*
	   * VPN and ENCAP tables are two-level (RD is top level)
	   */
	  for (rn = bgp_table_top(bgp->rib[afi][SAFI_MPLS_VPN]); rn;
               rn = bgp_route_next (rn))
	    {
	      if (rn->info)
                {
		  bgp_cleanup_table((struct bgp_table *)(rn->info), SAFI_MPLS_VPN);
		  bgp_table_finish ((struct bgp_table **)&(rn->info));
		  rn->info = NULL;
		  bgp_unlock_node(rn);
                }
	    }

	  for (rn = bgp_table_top(bgp->rib[afi][SAFI_ENCAP]); rn;
               rn = bgp_route_next (rn))
	    {
	      if (rn->info)
		{
		  bgp_cleanup_table((struct bgp_table *)(rn->info), SAFI_ENCAP);
		  bgp_table_finish ((struct bgp_table **)&(rn->info));
		  rn->info = NULL;
		  bgp_unlock_node(rn);
		}
	    }
	}
      for (rn = bgp_table_top(bgp->rib[AFI_L2VPN][SAFI_EVPN]); rn;
           rn = bgp_route_next (rn))
        {
          if (rn->info)
            {
              bgp_cleanup_table((struct bgp_table *)(rn->info), SAFI_EVPN);
              bgp_table_finish ((struct bgp_table **)&(rn->info));
              rn->info = NULL;
              bgp_unlock_node(rn);
            }
        }
    }
}

void
bgp_reset (void)
{
  vty_reset ();
  bgp_zclient_reset ();
  access_list_reset ();
  prefix_list_reset ();
}

/* Parse NLRI stream.  Withdraw NLRI is recognized by NULL attr
   value. */
int
bgp_nlri_parse_ip (struct peer *peer, struct attr *attr,
                   struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  struct prefix p;
  int psize;
  int ret;

  /* Check peer status. */
  if (peer->status != Established)
    return 0;
  
  pnt = packet->nlri;
  lim = pnt + packet->length;

  /* RFC4771 6.3 The NLRI field in the UPDATE message is checked for
     syntactic validity.  If the field is syntactically incorrect,
     then the Error Subcode is set to Invalid Network Field. */
  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      /* Fetch prefix length. */
      p.prefixlen = *pnt++;
      /* afi/safi validity already verified by caller, bgp_update_receive */
      p.family = afi2family (packet->afi);
      
      /* Prefix length check. */
      if (p.prefixlen > prefix_blen (&p) * 8)
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error"
                    " (wrong prefix length %u for afi %u)",
                    peer->host, p.prefixlen, packet->afi);
          return -1;
        }
      
      /* Packet size overflow check. */
      psize = PSIZE (p.prefixlen);

      /* When packet overflow occur return immediately. */
      if (pnt + psize > lim)
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error"
                    " (prefix length %u overflows packet)",
                    peer->host, p.prefixlen);
          return -1;
        }
      
      /* Defensive coding, double-check the psize fits in a struct prefix */  
      if (psize > (ssize_t) sizeof(p.u))
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error"
                    " (prefix length %u too large for prefix storage %zu!?!!",
                    peer->host, p.prefixlen, sizeof(p.u));
          return -1;
        }

      /* Fetch prefix from NLRI packet. */
      memcpy (&p.u.prefix, pnt, psize);

      /* Check address. */
      if (packet->afi == AFI_IP && packet->safi == SAFI_UNICAST)
	{
	  if (IN_CLASSD (ntohl (p.u.prefix4.s_addr)))
	    {
	     /* 
 	      * From RFC4271 Section 6.3: 
	      * 
	      * If a prefix in the NLRI field is semantically incorrect
	      * (e.g., an unexpected multicast IP address), an error SHOULD
	      * be logged locally, and the prefix SHOULD be ignored.
	      */
	      zlog (peer->log, LOG_ERR, 
		    "%s: IPv4 unicast NLRI is multicast address %s, ignoring",
		    peer->host, inet_ntoa (p.u.prefix4));
	      continue;
	    }
	}

      /* Check address. */
      if (packet->afi == AFI_IP6 && packet->safi == SAFI_UNICAST)
	{
	  if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
	    {
	      char buf[BUFSIZ];

	      zlog (peer->log, LOG_ERR, 
		    "%s: IPv6 unicast NLRI is link-local address %s, ignoring",
		    peer->host,
		    inet_ntop (AF_INET6, &p.u.prefix6, buf, BUFSIZ));
	      continue;
	    }
	  if (IN6_IS_ADDR_MULTICAST (&p.u.prefix6))
	    {
	      char buf[BUFSIZ];

	      zlog (peer->log, LOG_ERR, 
		    "%s: IPv6 unicast NLRI is multicast address %s, ignoring",
		    peer->host,
		    inet_ntop (AF_INET6, &p.u.prefix6, buf, BUFSIZ));
	      continue;
	    }
        }

      /* Normal process. */
      if (attr)
	ret = bgp_update (peer, &p, attr, packet->afi, packet->safi, 
			  ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL, 0, 0,
                          NULL);
      else
	ret = bgp_withdraw (peer, &p, attr, packet->afi, packet->safi, 
			    ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL, 0,
                            NULL);

      /* Address family configuration mismatch or maximum-prefix count
         overflow. */
      if (ret < 0)
	return -1;
    }

  /* Packet length consistency check. */
  if (pnt != lim)
    {
      plog_err (peer->log,
                "%s [Error] Update packet error"
                " (prefix length mismatch with total length)",
                peer->host);
      return -1;
    }
  
  return 0;
}

static struct bgp_static *
bgp_static_new (void)
{
  return XCALLOC (MTYPE_BGP_STATIC, sizeof (struct bgp_static));
}

static void
bgp_static_free (struct bgp_static *bgp_static)
{
  if (bgp_static->rmap.name)
    free (bgp_static->rmap.name);
  if(bgp_static->eth_s_id)
    XFREE(MTYPE_ATTR, bgp_static->eth_s_id);
  if(bgp_static->router_mac)
    XFREE(MTYPE_ATTR, bgp_static->router_mac);
  XFREE (MTYPE_BGP_STATIC, bgp_static);
}

static void
bgp_static_withdraw_rsclient (struct bgp *bgp, struct peer *rsclient,
        struct prefix *p, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, NULL);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
       && ri->type == ZEBRA_ROUTE_BGP
       && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

static void
bgp_static_update_rsclient (struct peer *rsclient, struct prefix *p,
                            struct bgp_static *bgp_static,
                            afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_info *new;
  struct bgp_info info;
  struct attr *attr_new;
  struct attr attr;
  struct attr new_attr;
  struct attr_extra new_extra;
  struct bgp *bgp;
  int ret;
  char buf[SU_ADDRSTRLEN];

  bgp = rsclient->bgp;

  assert (bgp_static);
  if (!bgp_static)
    return;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, NULL);

  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);

  attr.nexthop = bgp_static->igpnexthop;
  attr.med = bgp_static->igpmetric;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
  
  if (bgp_static->atomic)
    attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);
  
  /* Apply network route-map for export to this rsclient. */
  if (bgp_static->rmap.name)
    {
      struct attr attr_tmp = attr;
      info.peer = rsclient;
      info.attr = &attr_tmp;
      
      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_EXPORT);
      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_NETWORK);

      ret = route_map_apply (bgp_static->rmap.map, p, RMAP_BGP, &info);

      rsclient->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
        {
          /* Free uninterned attribute. */
          bgp_attr_flush (&attr_tmp);

          /* Unintern original. */
          aspath_unintern (&attr.aspath);
          bgp_static_withdraw_rsclient (bgp, rsclient, p, afi, safi);
          bgp_attr_extra_free (&attr);
          
          return;
        }
      attr_new = bgp_attr_intern (&attr_tmp);
    }
  else
    attr_new = bgp_attr_intern (&attr);

  new_attr.extra = &new_extra;
  bgp_attr_dup(&new_attr, attr_new);
  
  SET_FLAG (bgp->peer_self->rmap_type, PEER_RMAP_TYPE_NETWORK);

  if (bgp_import_modifier (rsclient, bgp->peer_self, p, &new_attr, afi, safi) 
        == RMAP_DENY)
    {
      /* This BGP update is filtered.  Log the reason then update BGP entry.  */
      if (BGP_DEBUG (update, UPDATE_IN))
              zlog (rsclient->log, LOG_DEBUG,
              "Static UPDATE about %s/%d -- DENIED for RS-client %s due to: import-policy",
              inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
              p->prefixlen, rsclient->host);

      bgp->peer_self->rmap_type = 0;

      bgp_attr_unintern (&attr_new);
      aspath_unintern (&attr.aspath);
      bgp_attr_extra_free (&attr);

      bgp_static_withdraw_rsclient (bgp, rsclient, p, afi, safi);
      
      return;
    }

  bgp->peer_self->rmap_type = 0;

  bgp_attr_unintern (&attr_new);
  attr_new = bgp_attr_intern (&new_attr);

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self && ri->type == ZEBRA_ROUTE_BGP
            && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  if (ri)
       {
      if (attrhash_cmp (ri->attr, attr_new) &&
	  !CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
        {
          bgp_unlock_node (rn);
          bgp_attr_unintern (&attr_new);
          aspath_unintern (&attr.aspath);
          bgp_attr_extra_free (&attr);
          return;
       }
      else
        {
          /* The attribute is changed. */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* update label information - add or remove*/
          if(bgp_static->nlabels)
            {
              bgp_info_extra_get (ri)->nlabels = bgp_static->nlabels;
              memcpy (ri->extra->labels, bgp_static->labels, sizeof(*bgp_static->labels) * bgp_static->nlabels);
            }

          /* Rewrite BGP route information. */
	  if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
	    bgp_info_restore(rn, ri);
          bgp_attr_unintern (&ri->attr);
          ri->attr = attr_new;
          ri->uptime = bgp_clock ();

	  /* Nexthop reachability check. */
	  if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
	    {
	      if (bgp_find_or_add_nexthop (afi, ri, NULL, 0))
		bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
	      else
		{
		  if (BGP_DEBUG(nht, NHT))
		    {
		      char buf1[INET6_ADDRSTRLEN];
		      inet_ntop(AF_INET, (const void *)&attr_new->nexthop,
				buf1, INET6_ADDRSTRLEN);
		      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
		    }
		  bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
		}
	    }
          /* Process change. */
          bgp_process (bgp, rn, afi, safi);
          bgp_unlock_node (rn);
          aspath_unintern (&attr.aspath);
          bgp_attr_extra_free (&attr);
          return;
        }
    }

  /* Make new BGP info. */
  new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, bgp->peer_self,
		  attr_new, rn);
  /* Nexthop reachability check. */
  if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
    {
      if (bgp_find_or_add_nexthop (afi, new, NULL, 0))
	bgp_info_set_flag (rn, new, BGP_INFO_VALID);
      else
	{
	  if (BGP_DEBUG(nht, NHT))
	    {
	      char buf1[INET6_ADDRSTRLEN];
	      inet_ntop(AF_INET, (const void *)&attr_new->nexthop,
			buf1, INET6_ADDRSTRLEN);
	      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
	    }
	  bgp_info_unset_flag (rn, new, BGP_INFO_VALID);
	}
    }
  else
    bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);
  
  /* Process change. */
  bgp_process (bgp, rn, afi, safi);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

static void
bgp_static_update_main (struct bgp *bgp, struct prefix *p,
			struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_info *new;
  struct bgp_info info;
  struct attr attr;
  struct attr *attr_new;
  int ret;

  assert (bgp_static);
  if (!bgp_static)
    return;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, NULL);

  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
  
  attr.nexthop = bgp_static->igpnexthop;
  attr.med = bgp_static->igpmetric;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  if (bgp_static->atomic)
    attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  /* Apply route-map. */
  if (bgp_static->rmap.name)
    {
      struct attr attr_tmp = attr;
      info.peer = bgp->peer_self;
      info.attr = &attr_tmp;

      SET_FLAG (bgp->peer_self->rmap_type, PEER_RMAP_TYPE_NETWORK);

      ret = route_map_apply (bgp_static->rmap.map, p, RMAP_BGP, &info);

      bgp->peer_self->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
	{    
	  /* Free uninterned attribute. */
	  bgp_attr_flush (&attr_tmp);

	  /* Unintern original. */
	  aspath_unintern (&attr.aspath);
	  bgp_attr_extra_free (&attr);
	  bgp_static_withdraw (bgp, p, afi, safi);
	  return;
	}
      attr_new = bgp_attr_intern (&attr_tmp);
    }
  else
    attr_new = bgp_attr_intern (&attr);

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self && ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_STATIC)
      break;

  if (ri)
    {
      if (attrhash_cmp (ri->attr, attr_new) &&
	  !CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
	{
	  bgp_unlock_node (rn);
	  bgp_attr_unintern (&attr_new);
	  aspath_unintern (&attr.aspath);
	  bgp_attr_extra_free (&attr);
	  return;
	}
      else
	{
	  /* The attribute is changed. */
	  bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

	  /* Rewrite BGP route information. */
	  if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
	    bgp_info_restore(rn, ri);
	  else
	    bgp_aggregate_decrement (bgp, p, ri, afi, safi);
	  bgp_attr_unintern (&ri->attr);
	  ri->attr = attr_new;
	  ri->uptime = bgp_clock ();

	  /* Nexthop reachability check. */
	  if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
	    {
	      if (bgp_find_or_add_nexthop (afi, ri, NULL, 0))
		bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
	      else
		{
		  if (BGP_DEBUG(nht, NHT))
		    {
		      char buf1[INET6_ADDRSTRLEN];
		      inet_ntop(AF_INET, (const void *)&attr_new->nexthop,
				buf1, INET6_ADDRSTRLEN);
		      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
		    }
		  bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
		}
	    }
	  /* Process change. */
	  bgp_aggregate_increment (bgp, p, ri, afi, safi);
	  bgp_process (bgp, rn, afi, safi);
	  bgp_vrf_process_imports(bgp, afi, safi, rn, (struct bgp_info *)0xffffffff, ri);
          bgp_unlock_node (rn);
	  aspath_unintern (&attr.aspath);
	  bgp_attr_extra_free (&attr);
	  return;
	}
    }

  /* Make new BGP info. */
  new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, bgp->peer_self, attr_new,
		  rn);
  /* Nexthop reachability check. */
  if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
    {
      if (bgp_find_or_add_nexthop (afi, new, NULL, 0))
	bgp_info_set_flag (rn, new, BGP_INFO_VALID);
      else
	{
	  if (BGP_DEBUG(nht, NHT))
	    {
	      char buf1[INET6_ADDRSTRLEN];
	      inet_ntop(AF_INET, (const void *)&attr_new->nexthop, buf1,
			INET6_ADDRSTRLEN);
	      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
	    }
	  bgp_info_unset_flag (rn, new, BGP_INFO_VALID);
	}
    }
  else
    bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Aggregate address increment. */
  bgp_aggregate_increment (bgp, p, new, afi, safi);
  
  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);
  
  /* Process change. */
  bgp_process (bgp, rn, afi, safi);
  bgp_vrf_process_imports(bgp, afi, safi, rn, NULL, new);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

void
bgp_static_update (struct bgp *bgp, struct prefix *p,
                  struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
  struct peer *rsclient;
  struct listnode *node, *nnode;

  bgp_static_update_main (bgp, p, bgp_static, afi, safi);

  for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
    {
      if (CHECK_FLAG (rsclient->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        bgp_static_update_rsclient (rsclient, p, bgp_static, afi, safi);
    }
}

void
bgp_static_withdraw (struct bgp *bgp, struct prefix *p, afi_t afi,
		     safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  /* Make new BGP info. */
  rn = bgp_node_get (bgp->rib[afi][safi], p);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_unlink_nexthop(ri);
      bgp_info_delete (rn, ri);
      bgp_vrf_process_imports(bgp, afi, safi, rn, ri, NULL);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

void
bgp_check_local_routes_rsclient (struct peer *rsclient, afi_t afi, safi_t safi)
{
  struct bgp_static *bgp_static;
  struct bgp *bgp;
  struct bgp_node *rn;
  struct prefix *p;

  bgp = rsclient->bgp;

  for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn))
    if ((bgp_static = rn->info) != NULL)
      {
        p = &rn->p;

        bgp_static_update_rsclient (rsclient, p, bgp_static,
                afi, safi);
      }
}

/*
 * Used for SAFI_MPLS_VPN and SAFI_ENCAP
 */
static void
bgp_static_withdraw_safi (struct bgp *bgp, struct prefix *p, afi_t afi,
                          safi_t safi, struct prefix_rd *prd,
                          uint32_t *labels, size_t nlabels)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      if (bgp_last_bgp_info_configured[afi][safi] == ri)
        bgp_last_bgp_info_configured[afi][safi] = NULL;
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_info_delete (rn, ri);
      bgp_vrf_process_imports(bgp, afi, safi, rn, ri, NULL);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

static void
bgp_static_update_safi (struct bgp *bgp, struct prefix *p,
                        struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *new;
  struct attr *attr_new;
  struct attr attr = { 0 };
  struct bgp_info *ri;
  union gw_addr add;

  assert (bgp_static);
  if (safi != SAFI_LABELED_UNICAST)
    rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, &bgp_static->prd);
  else
    rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, NULL);
  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);

  if (bgp_static->pmsi_tunnel_id_ingress_replication)
    attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_PMSI_TUNNEL);

  attr.nexthop = bgp_static->igpnexthop;
  attr.med = bgp_static->igpmetric;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  if (bgp_static->ecomm)
    {
      if (bgp_attr_extra_get (&attr)->ecommunity)
        ecommunity_free (&bgp_attr_extra_get (&attr)->ecommunity);
      bgp_attr_extra_get (&attr)->ecommunity = ecommunity_dup (bgp_static->ecomm);
      attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);
    }
  memset(&add, 0, sizeof(union gw_addr));
  if (bgp_static->gatewayIp.family == AF_INET)
    add.ipv4.s_addr = bgp_static->gatewayIp.u.prefix4.s_addr;
  else if (bgp_static->gatewayIp.family == AF_INET6)
    memcpy( &(add.ipv6), &(bgp_static->gatewayIp.u.prefix6), sizeof (struct in6_addr));
  if((safi == SAFI_EVPN) &&
     p->u.prefix_evpn.route_type != EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
    {
      struct bgp_encap_type_vxlan bet;

      memset(&bet, 0, sizeof(struct bgp_encap_type_vxlan));
      if ((PREFIX_FAMILY(p) == AF_INET) || (PREFIX_FAMILY(p) == AF_INET6)) {
        /* as per https://tools.ietf.org/html/draft-ietf-bess-evpn-prefix-advertisement-05
         * BGP Encapsulation Extended Community ( as per RFC5512) identifies tunnel type
         * containing VNI from Label field
         */
        if (bgp_static->nlabels > 0)
          bet.vnid = bgp_static->labels[0];
      } else {
        if(bgp_static->eth_t_id)
          bet.vnid = bgp_static->eth_t_id;
        else if (PREFIX_FAMILY(p) == AF_L2VPN)
          if (bgp_static->nlabels > 0)
            bet.vnid = bgp_static->labels[0];
      }
      bgp_encap_type_vxlan_to_tlv(&bet, &attr);
      bgp_attr_extra_get (&attr);
      /* It may be advertised along with BGP Encapsulation Extended Community define
       * in section 4.5 of [RFC5512].
       */
      bgp_add_encapsulation_type (&attr, bgp_static->bgp_encapsulation_type);

      if(bgp_static->router_mac)
        {
          bgp_add_routermac_ecom (&attr, bgp_static->router_mac);
        }

      bgp_update_mac_mobility_seqnum(bgp, rn, &attr);

      if (bgp_static->igpnexthop.s_addr)
        {
          overlay_index_update(&attr, bgp_static->eth_s_id, &add);
        }
      else
        {
          overlay_index_update(&attr, bgp_static->eth_s_id, &add);
        }
      if((&attr)->extra)
        (&attr)->extra->eth_t_id = bgp_static->eth_t_id;
    }

  if (bgp_static->igpnexthop.s_addr)
    {
      bgp_attr_extra_get (&attr)->mp_nexthop_global_in = bgp_static->igpnexthop;
      bgp_attr_extra_get (&attr)->mp_nexthop_len = IPV4_MAX_BYTELEN;
    }
  else
    {
      const char *ip6str = "::0";
      struct in6_addr result;
      if (1 == inet_pton(AF_INET6, ip6str, &result))
        {
          if (memcmp (&result, &bgp_static->ipv6nexthop, sizeof (struct in6_addr)))
          {
            memcpy (&bgp_attr_extra_get (&attr)->mp_nexthop_global,
                    &bgp_static->ipv6nexthop, sizeof (struct in6_addr));
            bgp_attr_extra_get (&attr)->mp_nexthop_len = IPV6_MAX_BYTELEN;
          }
        }
    }
  /* Apply route-map. */
  if (bgp_static->rmap.name)
    {
      struct attr attr_tmp = attr;
      struct bgp_info info;
      int ret;

      info.peer = bgp->peer_self;
      info.attr = &attr_tmp;

      SET_FLAG (bgp->peer_self->rmap_type, PEER_RMAP_TYPE_NETWORK);

      ret = route_map_apply (bgp_static->rmap.map, p, RMAP_BGP, &info);

      bgp->peer_self->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
        {
          /* Free uninterned attribute. */
          bgp_attr_flush (&attr_tmp);

          /* Unintern original. */
          aspath_unintern (&attr.aspath);
          bgp_attr_extra_free (&attr);
          if (safi != SAFI_LABELED_UNICAST)
            bgp_static_withdraw_safi (bgp, p, afi, safi, &bgp_static->prd,
                                      bgp_static->labels, bgp_static->nlabels);
          else
            bgp_static_withdraw_safi (bgp, p, afi, safi, NULL,
                                      bgp_static->labels, bgp_static->nlabels);
          return;
        }

      attr_new = bgp_attr_intern (&attr_tmp);
    }
  else
    {
      attr_new = bgp_attr_intern (&attr);
    }

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self && ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  if (ri)
    {
      if (attrhash_cmp (ri->attr, attr_new) &&
          labels_equal (ri, bgp_static->labels, bgp_static->nlabels) &&
          eth_tag_id_equal(afi, ri, &bgp_static->eth_t_id) &&
          overlay_index_equal(afi, ri, bgp_static->eth_s_id, &add) &&
          !CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
        {
          bgp_unlock_node (rn);
          bgp_attr_unintern (&attr_new);
          aspath_unintern (&attr.aspath);
          bgp_attr_extra_free (&attr);
          return;
        }
      else
        {
          /* The attribute is changed. */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* Rewrite BGP route information. */
          if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
            bgp_info_restore(rn, ri);
          else
            bgp_aggregate_decrement (bgp, p, ri, afi, safi);
          bgp_attr_unintern (&ri->attr);
          ri->attr = attr_new;
          ri->uptime = bgp_clock ();
          /* update label */
          if(bgp_static->nlabels)
            {
              bgp_info_extra_get (ri)->nlabels = bgp_static->nlabels;
              memcpy (ri->extra->labels, bgp_static->labels, sizeof(*bgp_static->labels) * bgp_static->nlabels);
            }
          /* Process change. */
          bgp_aggregate_increment (bgp, p, ri, afi, safi);
          bgp_process (bgp, rn, afi, safi);
          bgp_unlock_node (rn);
          aspath_unintern (&attr.aspath);
          bgp_attr_extra_free (&attr);
          if (bgp_order_send_eor == 0)
            {
              bgp_last_bgp_info_configured[afi][safi] = ri;
              bgp_packet_bgp_info_sent[afi][safi] = 0;
            }
          return;
        }
    }


  /* Make new BGP info. */
  new = info_make (ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, bgp->peer_self,
		   attr_new, rn);
  SET_FLAG (new->flags, BGP_INFO_VALID);
  new->extra = bgp_info_extra_new();
  new->extra->nlabels = bgp_static->nlabels;
  memcpy (&(bgp_info_extra_get (new)->vrf_rd), &(bgp_static->prd),sizeof(struct prefix_rd));
  memcpy (new->extra->labels, bgp_static->labels,
                  sizeof(*bgp_static->labels) * bgp_static->nlabels);

  /* Aggregate address increment. */
  bgp_aggregate_increment (bgp, p, new, afi, safi);

  /* Register new BGP information. */
  bgp_info_add (rn, new);
  if (bgp_order_send_eor == 0)
    {
      bgp_last_bgp_info_configured[afi][safi] = new;
      bgp_packet_bgp_info_sent[afi][safi] = 0;
    }
  /* route_node_get lock */
  bgp_unlock_node (rn);

  /* Process change. */
  bgp_process (bgp, rn, afi, safi);
  
  bgp_vrf_process_imports(bgp, afi, safi, rn, NULL, new);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

/* Configure static BGP network.  When user don't run zebra, static
   route should be installed as valid.  */
static int
bgp_static_set (struct vty *vty, struct bgp *bgp, const char *ip_str, 
                afi_t afi, safi_t safi, const char *rmap, int backdoor)
{
  int ret;
  struct prefix p;
  struct bgp_static *bgp_static;
  struct bgp_node *rn;
  u_char need_update = 0;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
    {
      vty_out (vty, "%% Malformed prefix (link-local address)%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask (&p);

  /* Set BGP static route configuration. */
  rn = bgp_node_get (bgp->route[afi][safi], &p);

  if (rn->info)
    {
      /* Configuration change. */
      bgp_static = rn->info;

      /* Check previous routes are installed into BGP.  */
      if (bgp_static->valid && bgp_static->backdoor != backdoor)
        need_update = 1;
      
      bgp_static->backdoor = backdoor;
      
      if (rmap)
	{
	  if (bgp_static->rmap.name)
	    free (bgp_static->rmap.name);
	  bgp_static->rmap.name = strdup (rmap);
	  bgp_static->rmap.map = route_map_lookup_by_name (rmap);
	}
      else
	{
	  if (bgp_static->rmap.name)
	    free (bgp_static->rmap.name);
	  bgp_static->rmap.name = NULL;
	  bgp_static->rmap.map = NULL;
	  bgp_static->valid = 0;
	}
      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration. */
      bgp_static = bgp_static_new ();
      bgp_static->bgp_encapsulation_type = BGP_ENCAPSULATION_VXLAN;
      bgp_static->backdoor = backdoor;
      bgp_static->valid = 0;
      bgp_static->igpmetric = 0;
      bgp_static->igpnexthop.s_addr = 0;
      
      if (rmap)
	{
	  if (bgp_static->rmap.name)
	    free (bgp_static->rmap.name);
	  bgp_static->rmap.name = strdup (rmap);
	  bgp_static->rmap.map = route_map_lookup_by_name (rmap);
	}
      rn->info = bgp_static;
    }

  bgp_static->valid = 1;
  if (need_update)
    bgp_static_withdraw (bgp, &p, afi, safi);

  if (! bgp_static->backdoor)
    bgp_static_update (bgp, &p, bgp_static, afi, safi);

  return CMD_SUCCESS;
}

/* Configure static BGP network. */
static int
bgp_static_unset (struct vty *vty, struct bgp *bgp, const char *ip_str,
		  afi_t afi, safi_t safi)
{
  int ret;
  struct prefix p;
  struct bgp_static *bgp_static;
  struct bgp_node *rn;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
    {
      vty_out (vty, "%% Malformed prefix (link-local address)%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask (&p);

  rn = bgp_node_lookup (bgp->route[afi][safi], &p);
  if (! rn)
    {
      vty_out (vty, "%% Can't find specified static route configuration.%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_static = rn->info;
  
  /* Update BGP RIB. */
  if (! bgp_static->backdoor)
    bgp_static_withdraw (bgp, &p, afi, safi);

  /* Clear configuration. */
  bgp_static_free (bgp_static);
  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

/* Called from bgp_delete().  Delete all static routes from the BGP
   instance. */
void
bgp_static_delete (struct bgp *bgp)
{
  afi_t afi;
  safi_t safi;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_table *table;
  struct bgp_static *bgp_static;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn))
	if (rn->info != NULL)
	  {      
	    if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP) || (safi == SAFI_EVPN))
	      {
		table = rn->info;

		for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
		  {
		    bgp_static = rm->info;
		    if (!bgp_static)
		      continue;
		    bgp_static_withdraw_safi (bgp, &rm->p,
					       AFI_IP, safi,
					       (struct prefix_rd *)&rn->p,
					       bgp_static->labels,
                                               bgp_static->nlabels);
		    bgp_static_free (bgp_static);
		    rm->info = NULL;
		    bgp_unlock_node (rm);
		  }
		rn->info = NULL;
		bgp_unlock_node (rn);
	      }
	    else
	      {
		bgp_static = rn->info;
		bgp_static_withdraw (bgp, &rn->p, afi, safi);
		bgp_static_free (bgp_static);
		rn->info = NULL;
		bgp_unlock_node (rn);
	      }
	  }
}

int
bgp_static_unset_evpn_rt3 (struct vty *vty, const char *rd_str,
                         const char *eth_tag, const char *routerip)
{
  int ret;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp *bgp;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  afi_t afi;
  safi_t safi;
  struct in_addr router_ip_addr;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;

  bgp = vty->index;

  memset (&p, 0, sizeof (struct prefix));
  p.family = AF_L2VPN;
  p.prefixlen = L2VPN_MCAST_PREFIX_LEN;
  p.u.prefix_evpn.route_type = EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG;
  p.u.prefix_evpn.u.prefix_imethtag.eth_tag_id = atol(eth_tag);
  p.u.prefix_evpn.u.prefix_imethtag.ip_len = IPV4_MAX_BITLEN;

  if (1 != inet_pton(AF_INET, routerip, &router_ip_addr))
    {
      vty_out (vty, "%% Malformed router IP%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  p.u.prefix_evpn.u.prefix_imethtag.ip.in4.s_addr = router_ip_addr.s_addr;

  ret = str2prefix_rd (rd_str, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed rd%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  prn = bgp_node_get (bgp->route[afi][safi],
                      (struct prefix *)&prd);
  if (prn->info == NULL)
    prn->info = bgp_table_init (afi, safi);
  else
    bgp_unlock_node (prn);
  table = prn->info;

  rn = bgp_node_lookup (table, &p);
  if (!rn || !rn->info)
    {
      vty_out (vty, "%% Can't find the route%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  bgp_static = rn->info;

  /* Update BGP RIB. */
  bgp_static_withdraw_safi (bgp, &p, afi, safi, &prd, NULL, 0);

  /* Clear configuration. */
  bgp_static_free (bgp_static);
  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);
  return CMD_SUCCESS;
}

int
bgp_static_set_evpn_rt3 (struct vty *vty, const char *rd_str,
                         const char *eth_tag, const char *routerip)
{
  int ret;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp *bgp;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  struct bgp_vrf *vrf;
  afi_t afi;
  safi_t safi;
  struct in_addr router_ip_addr;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;

  bgp = vty->index;

  memset (&p, 0, sizeof (struct prefix));
  p.family = AF_L2VPN;
  p.prefixlen = L2VPN_MCAST_PREFIX_LEN;
  p.u.prefix_evpn.route_type = EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG;
  p.u.prefix_evpn.u.prefix_imethtag.eth_tag_id = atol(eth_tag);
  p.u.prefix_evpn.u.prefix_imethtag.ip_len = IPV4_MAX_BITLEN;

  if (1 != inet_pton(AF_INET, routerip, &router_ip_addr))
    {
      vty_out (vty, "%% Malformed router IP%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  p.u.prefix_evpn.u.prefix_imethtag.ip.in4.s_addr = router_ip_addr.s_addr;

  ret = str2prefix_rd (rd_str, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed rd%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  prn = bgp_node_get (bgp->route[afi][safi],
                      (struct prefix *)&prd);
  if (prn->info == NULL)
    prn->info = bgp_table_init (afi, safi);
  else
    bgp_unlock_node (prn);
  table = prn->info;
  rn = bgp_node_get (table, &p);

  if (rn->info)
    {
      vty_out (vty, "%% Same network configuration exists%s", VTY_NEWLINE);
      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration. */
      bgp_static = bgp_static_new ();
      bgp_static->backdoor = 0;
      bgp_static->valid = 0;
      bgp_static->igpmetric = 0;
      /* by default: nexthop bgp router id */
      bgp_static->igpnexthop = bgp->router_id;
      if (rd_str)
        {
          vrf = bgp_vrf_lookup(bgp, &prd);
          if (vrf)
            {
              bgp_static->ecomm = vrf->rt_export;
            }
          bgp_static->prd = prd;
        }

      bgp_static->eth_t_id = atol(eth_tag);
      bgp_static->pmsi_tunnel_id_ingress_replication = true;
      rn->info = bgp_static;

      bgp_static->valid = 1;
      bgp_static_update_safi (bgp, &p, bgp_static, afi, safi);
    }

  return CMD_SUCCESS;
}

/*
 * gpz 110624
 * Currently this is used to set static routes for VPN and ENCAP.
 * I think it can probably be factored with bgp_static_set.
 */
int
bgp_static_set_safi (safi_t safi, struct vty *vty, const char *ip_str,
                     const char *rd_str, const char *tag_str,
                     const char *rmap_str, const char *esi, const char *gwip, 
                     const char *ethtag, const char *routermac,
                     const char *macaddress, const char *l2label)
{
  int ret;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp *bgp;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  struct bgp_vrf *vrf;
  uint32_t labels[BGP_MAX_LABELS];
  size_t nlabels;
  afi_t afi;

  if(safi == SAFI_EVPN)
    afi = AFI_L2VPN;
  else
    afi = AFI_IP;
  if (!rd_str)
    {
      safi = SAFI_LABELED_UNICAST;
    }
  bgp = vty->index;

  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  if (rd_str)
    {
      ret = str2prefix_rd (rd_str, &prd);
      if (! ret)
        {
          vty_out (vty, "%% Malformed rd%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  int label_encoding_method = LABEL_ENCODING_STANDARD;

  if( safi == SAFI_EVPN)
    {
      /* EVPN RT2/RT5 encode vni in label. encoding uses full 24 bits */
      label_encoding_method = LABEL_ENCODING_FULL;
    }
  if (! str2labels (tag_str, labels, &nlabels, label_encoding_method))
    {
      vty_out (vty, "%% Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (safi == SAFI_EVPN)
    {
      if( macaddress && str2mac (macaddress, NULL) != 0)
        {
          struct macipaddr *m = &p.u.prefix_evpn.u.prefix_macip;
          struct prefix_ipv4 dummy;

          p.family = AF_L2VPN;
          p.prefixlen = L2VPN_IPV4_PREFIX_LEN;
          p.u.prefix_evpn.route_type = EVPN_MACIP_ADVERTISEMENT;

          str2mac(macaddress, (char*) &m->mac);
          if (strncmp(ip_str, "0.0.0.0", 8))
            {
              str2prefix_ipv4(ip_str,&dummy);

              if (dummy.prefixlen != 0 && dummy.prefixlen != 32)
                {
                  vty_out (vty, "%% Malformed Network%s", VTY_NEWLINE);
                  return CMD_WARNING;
                }
              memcpy(&m->ip.in4, &dummy.prefix, sizeof(struct in_addr));
              m->eth_tag_id = atol(ethtag);
              m->ip_len = 32;
            }
          else
            m->ip_len = 0;
          m->mac_len = ETHER_ADDR_LEN * 8;
        }
      if( esi && str2esi (esi, NULL) == 0)
        {
          vty_out (vty, "%% Malformed ESI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      if( routermac && str2mac (routermac, NULL) == 0)
        {
          vty_out (vty, "%% Malformed Router MAC%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      if(!ethtag)
        {
          vty_out (vty, "%% Eth Tag Compulsory%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      if(nlabels != 1)
        {
          vty_out (vty, "%% L3 Label Format not valid%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      if(l2label)
        {
          /* EVPN RT2/RT5 encode vni in label. encoding uses full 24 bits */
          if (safi != SAFI_EVPN)
            labels[nlabels - 1] &= ~1;
         labels[nlabels] = atol(l2label) << 4;
         labels[nlabels] |= 1;
         nlabels++;
        }
      else
        {
          if(macaddress) /* not required to have a second label */
            {
              labels[nlabels] &= ~1;
              labels[nlabels] = 0;
            }
        }
    }
  else
    afi = (p.family == AF_INET) ? AFI_IP : AFI_IP6;
  if (rd_str)
    {
      prn = bgp_node_get (bgp->route[afi][safi],
                          (struct prefix *)&prd);
      if (prn->info == NULL)
        prn->info = bgp_table_init (afi, safi);
      else
        bgp_unlock_node (prn);
      table = prn->info;
    }
  else
    table = bgp->route[afi][safi];
  rn = bgp_node_get (table, &p);

  if (rn->info)
    {
      vty_out (vty, "%% Same network configuration exists%s", VTY_NEWLINE);
      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration. */
      bgp_static = bgp_static_new ();
      bgp_static->backdoor = 0;
      bgp_static->valid = 0;
      bgp_static->igpmetric = 0;
      /* by default: nexthop bgp router id */
      bgp_static->igpnexthop = bgp->router_id;
      memcpy(bgp_static->labels, labels, sizeof(labels[0]) * nlabels);
      bgp_static->nlabels = nlabels;
      bgp_static->bgp_encapsulation_type = BGP_ENCAPSULATION_VXLAN;
      if (rd_str)
        {
          vrf = bgp_vrf_lookup(bgp, &prd);
          if (vrf)
            {
              bgp_static->ecomm = vrf->rt_export;
            }
          bgp_static->prd = prd;
        }
      if (rmap_str)
	{
	  if (bgp_static->rmap.name)
	    free (bgp_static->rmap.name);
	  bgp_static->rmap.name = strdup (rmap_str);
	  bgp_static->rmap.map = route_map_lookup_by_name (rmap_str);
	}

      if (safi == SAFI_EVPN)
        {
          if(esi)
            {
              bgp_static->eth_s_id = XCALLOC (MTYPE_ATTR, sizeof(struct eth_segment_id));
              str2esi (esi, bgp_static->eth_s_id);
            }
          if( routermac)
            {
              bgp_static->router_mac = XCALLOC (MTYPE_ATTR, MAC_LEN+1);
              str2mac (routermac, bgp_static->router_mac);
            }
          bgp_static->eth_t_id = atol(ethtag);
          if (gwip)
            inet_aton (gwip, &bgp_static->igpnexthop);
        }
      rn->info = bgp_static;

      bgp_static->valid = 1;
      bgp_static_update_safi (bgp, &p, bgp_static, afi, safi);
    }

  return CMD_SUCCESS;
}

/* Configure static BGP network. */
int
bgp_static_unset_safi(safi_t safi, struct vty *vty, const char *ip_str,
                      const char *rd_str, const char *tag_str,
                      const char *esi, const char *gwip, const char *ethtag,
                      const char *mac)
{
  int ret;
  struct bgp *bgp;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  uint32_t labels[BGP_MAX_LABELS];
  size_t nlabels;
  afi_t afi;

  if (!rd_str)
    {
      safi = SAFI_LABELED_UNICAST;
    }
  bgp = vty->index;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  if (rd_str)
    {
      ret = str2prefix_rd (rd_str, &prd);
      if (! ret)
        {
          vty_out (vty, "%% Malformed rd%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  int label_encoding_method = LABEL_ENCODING_STANDARD;
  if( safi == SAFI_EVPN)
    {
      /* EVPN RT2/RT5 encode vni in label. encoding uses full 24 bits */
      label_encoding_method = LABEL_ENCODING_FULL;
    }
  if (! str2labels (tag_str, labels, &nlabels, label_encoding_method))
    {
      vty_out (vty, "%% Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  afi = (p.family == AF_INET) ? AFI_IP : AFI_IP6;
  if (rd_str)
    {
      prn = bgp_node_get (bgp->route[afi][safi],
                          (struct prefix *)&prd);
      if (prn->info == NULL)
        prn->info = bgp_table_init (afi, safi);
      else
        bgp_unlock_node (prn);
      table = prn->info;
    }
  else
    table = bgp->route[afi][safi];
  rn = bgp_node_lookup (table, &p);

  if (rn)
    {
      if(safi == SAFI_EVPN)
        bgp_static_withdraw_safi (bgp, &p, AFI_L2VPN, safi, &prd, labels, nlabels);
      else
        bgp_static_withdraw_safi (bgp, &p, afi, safi, rd_str==NULL?NULL:&prd, labels, nlabels);

      bgp_static = rn->info;
      bgp_static_free (bgp_static);
      rn->info = NULL;
      bgp_unlock_node (rn);
      bgp_unlock_node (rn);
    }
  else
    vty_out (vty, "%% Can't find the route%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (bgp_network,
       bgp_network_cmd,
       "network A.B.C.D/M",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
			 AFI_IP, bgp_node_safi (vty), NULL, 0);
}

DEFUN (bgp_network_route_map,
       bgp_network_route_map_cmd,
       "network A.B.C.D/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
			 AFI_IP, bgp_node_safi (vty), argv[1], 0);
}

DEFUN (bgp_network_backdoor,
       bgp_network_backdoor_cmd,
       "network A.B.C.D/M backdoor",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (bgp_network_mask,
       bgp_network_mask_cmd,
       "network A.B.C.D mask A.B.C.D",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
			 AFI_IP, bgp_node_safi (vty), NULL, 0);
}

DEFUN (bgp_network_mask_route_map,
       bgp_network_mask_route_map_cmd,
       "network A.B.C.D mask A.B.C.D route-map WORD",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
			 AFI_IP, bgp_node_safi (vty), argv[2], 0);
}

DEFUN (bgp_network_mask_backdoor,
       bgp_network_mask_backdoor_cmd,
       "network A.B.C.D mask A.B.C.D backdoor",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n")
{
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str, AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (bgp_network_mask_natural,
       bgp_network_mask_natural_cmd,
       "network A.B.C.D",
       "Specify a network to announce via BGP\n"
       "Network number\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
			 AFI_IP, bgp_node_safi (vty), NULL, 0);
}

DEFUN (bgp_network_mask_natural_route_map,
       bgp_network_mask_natural_route_map_cmd,
       "network A.B.C.D route-map WORD",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
			 AFI_IP, bgp_node_safi (vty), argv[1], 0);
}

DEFUN (bgp_network_mask_natural_backdoor,
       bgp_network_mask_natural_backdoor_cmd,
       "network A.B.C.D backdoor",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str, AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network A.B.C.D/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP, 
			   bgp_node_safi (vty));
}

ALIAS (no_bgp_network,
       no_bgp_network_route_map_cmd,
       "no network A.B.C.D/M route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network,
       no_bgp_network_backdoor_cmd,
       "no network A.B.C.D/M backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")

DEFUN (no_bgp_network_mask,
       no_bgp_network_mask_cmd,
       "no network A.B.C.D mask A.B.C.D",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_unset (vty, vty->index, prefix_str, AFI_IP, 
			   bgp_node_safi (vty));
}

ALIAS (no_bgp_network_mask,
       no_bgp_network_mask_route_map_cmd,
       "no network A.B.C.D mask A.B.C.D route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network_mask,
       no_bgp_network_mask_backdoor_cmd,
       "no network A.B.C.D mask A.B.C.D backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n")

DEFUN (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_cmd,
       "no network A.B.C.D",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_unset (vty, vty->index, prefix_str, AFI_IP, 
			   bgp_node_safi (vty));
}

ALIAS (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_route_map_cmd,
       "no network A.B.C.D route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_backdoor_cmd,
       "no network A.B.C.D backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n")

DEFUN (ipv6_bgp_network,
       ipv6_bgp_network_cmd,
       "network X:X::X:X/M",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6, bgp_node_safi(vty),
                         NULL, 0);
}

DEFUN (ipv6_bgp_network_route_map,
       ipv6_bgp_network_route_map_cmd,
       "network X:X::X:X/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6,
			 bgp_node_safi (vty), argv[1], 0);
}

DEFUN (no_ipv6_bgp_network,
       no_ipv6_bgp_network_cmd,
       "no network X:X::X:X/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP6, bgp_node_safi(vty));
}

ALIAS (no_ipv6_bgp_network,
       no_ipv6_bgp_network_route_map_cmd,
       "no network X:X::X:X/M route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (ipv6_bgp_network,
       old_ipv6_bgp_network_cmd,
       "ipv6 bgp network X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

ALIAS (no_ipv6_bgp_network,
       old_no_ipv6_bgp_network_cmd,
       "no ipv6 bgp network X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

/* stubs for removed AS-Pathlimit commands, kept for config compatibility */
ALIAS_DEPRECATED (bgp_network,
       bgp_network_ttl_cmd,
       "network A.B.C.D/M pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_backdoor,
       bgp_network_backdoor_ttl_cmd,
       "network A.B.C.D/M backdoor pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_mask,
       bgp_network_mask_ttl_cmd,
       "network A.B.C.D mask A.B.C.D pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_mask_backdoor,
       bgp_network_mask_backdoor_ttl_cmd,
       "network A.B.C.D mask A.B.C.D backdoor pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_mask_natural,
       bgp_network_mask_natural_ttl_cmd,
       "network A.B.C.D pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_mask_natural_backdoor,
       bgp_network_mask_natural_backdoor_ttl_cmd,
       "network A.B.C.D backdoor pathlimit <1-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_ttl_cmd,
       "no network A.B.C.D/M pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_backdoor_ttl_cmd,
       "no network A.B.C.D/M backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_mask_ttl_cmd,
       "no network A.B.C.D mask A.B.C.D pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network_mask,
       no_bgp_network_mask_backdoor_ttl_cmd,
       "no network A.B.C.D mask A.B.C.D  backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_ttl_cmd,
       "no network A.B.C.D pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_backdoor_ttl_cmd,
       "no network A.B.C.D backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (ipv6_bgp_network,
       ipv6_bgp_network_ttl_cmd,
       "network X:X::X:X/M pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_ipv6_bgp_network,
       no_ipv6_bgp_network_ttl_cmd,
       "no network X:X::X:X/M pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

/* Aggreagete address:

  advertise-map  Set condition to advertise attribute
  as-set         Generate AS set path information
  attribute-map  Set attributes of aggregate
  route-map      Set parameters of aggregate
  summary-only   Filter more specific routes from updates
  suppress-map   Conditionally filter more specific routes from updates
  <cr>
 */
struct bgp_aggregate
{
  /* Summary-only flag. */
  u_char summary_only;

  /* AS set generation. */
  u_char as_set;

  /* Route-map for aggregated route. */
  struct route_map *map;

  /* Suppress-count. */
  unsigned long count;

  /* SAFI configuration. */
  safi_t safi;
};

static struct bgp_aggregate *
bgp_aggregate_new (void)
{
  return XCALLOC (MTYPE_BGP_AGGREGATE, sizeof (struct bgp_aggregate));
}

static void
bgp_aggregate_free (struct bgp_aggregate *aggregate)
{
  XFREE (MTYPE_BGP_AGGREGATE, aggregate);
}     

/* Update an aggregate as routes are added/removed from the BGP table */
static void
bgp_aggregate_route (struct bgp *bgp, struct prefix *p, struct bgp_info *rinew,
		     afi_t afi, safi_t safi, struct bgp_info *del, 
		     struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  u_char origin;
  struct aspath *aspath = NULL;
  struct aspath *asmerge = NULL;
  struct community *community = NULL;
  struct community *commerge = NULL;
  struct bgp_info *ri;
  struct bgp_info *new;
  int first = 1;
  unsigned long match = 0;
  u_char atomic_aggregate = 0;

  /* ORIGIN attribute: If at least one route among routes that are
     aggregated has ORIGIN with the value INCOMPLETE, then the
     aggregated route must have the ORIGIN attribute with the value
     INCOMPLETE. Otherwise, if at least one route among routes that
     are aggregated has ORIGIN with the value EGP, then the aggregated
     route must have the origin attribute with the value EGP. In all
     other case the value of the ORIGIN attribute of the aggregated
     route is INTERNAL. */
  origin = BGP_ORIGIN_IGP;

  table = bgp->rib[afi][safi];

  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
	match = 0;

	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (BGP_INFO_HOLDDOWN (ri))
	      continue;

	    if (del && ri == del)
	      continue;

	    if (! rinew && first)
              first = 0;

#ifdef AGGREGATE_NEXTHOP_CHECK
	    if (! IPV4_ADDR_SAME (&ri->attr->nexthop, &nexthop)
		|| ri->attr->med != med)
	      {
		if (aspath)
		  aspath_free (aspath);
		if (community)
		  community_free (community);
		bgp_unlock_node (rn);
		bgp_unlock_node (top);
		return;
	      }
#endif /* AGGREGATE_NEXTHOP_CHECK */

            if (ri->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
              atomic_aggregate = 1;

	    if (ri->sub_type != BGP_ROUTE_AGGREGATE)
	      {
		if (aggregate->summary_only)
		  {
		    (bgp_info_extra_get (ri))->suppress++;
		    bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
		    match++;
		  }

		aggregate->count++;

		if (origin < ri->attr->origin)
		  origin = ri->attr->origin;

		if (aggregate->as_set)
		  {
		    if (aspath)
		      {
			asmerge = aspath_aggregate (aspath, ri->attr->aspath);
			aspath_free (aspath);
			aspath = asmerge;
		      }
		    else
		      aspath = aspath_dup (ri->attr->aspath);

		    if (ri->attr->community)
		      {
			if (community)
			  {
			    commerge = community_merge (community,
							ri->attr->community);
			    community = community_uniq_sort (commerge);
			    community_free (commerge);
			  }
			else
			  community = community_dup (ri->attr->community);
		      }
		  }
	      }
	  }
	if (match)
	  bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  if (rinew)
    {
      aggregate->count++;
      
      if (aggregate->summary_only)
        (bgp_info_extra_get (rinew))->suppress++;

      if (origin < rinew->attr->origin)
        origin = rinew->attr->origin;

      if (aggregate->as_set)
	{
	  if (aspath)
	    {
	      asmerge = aspath_aggregate (aspath, rinew->attr->aspath);
	      aspath_free (aspath);
	      aspath = asmerge;
	    }
	  else
	    aspath = aspath_dup (rinew->attr->aspath);

	  if (rinew->attr->community)
	    {
	      if (community)
		{
		  commerge = community_merge (community,
					      rinew->attr->community);
		  community = community_uniq_sort (commerge);
		  community_free (commerge);
		}
	      else
		community = community_dup (rinew->attr->community);
	    }
	}
    }

  if (aggregate->count > 0)
    {
      rn = bgp_node_get (table, p);
      new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_AGGREGATE, bgp->peer_self,
		      bgp_attr_aggregate_intern(bgp, origin, aspath, community,
						aggregate->as_set,
                                                atomic_aggregate), rn);
      SET_FLAG (new->flags, BGP_INFO_VALID);

      bgp_info_add (rn, new);
      bgp_unlock_node (rn);
      bgp_process (bgp, rn, afi, safi);
    }
  else
    {
      if (aspath)
	aspath_free (aspath);
      if (community)
	community_free (community);
    }
}

void bgp_aggregate_delete (struct bgp *, struct prefix *, afi_t, safi_t,
			   struct bgp_aggregate *);

void
bgp_aggregate_increment (struct bgp *bgp, struct prefix *p,
			 struct bgp_info *ri, afi_t afi, safi_t safi)
{
  struct bgp_node *child;
  struct bgp_node *rn;
  struct bgp_aggregate *aggregate;
  struct bgp_table *table;

  /* MPLS-VPN aggregation is not yet supported. */
  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP) || (safi == SAFI_EVPN)
      || (safi == SAFI_LABELED_UNICAST))
    return;

  table = bgp->aggregate[afi][safi];

  /* No aggregates configured. */
  if (bgp_table_top_nolock (table) == NULL)
    return;

  if (p->prefixlen == 0)
    return;

  if (BGP_INFO_HOLDDOWN (ri))
    return;

  child = bgp_node_get (table, p);

  /* Aggregate address configuration check. */
  for (rn = child; rn; rn = bgp_node_parent_nolock (rn))
    if ((aggregate = rn->info) != NULL && rn->p.prefixlen < p->prefixlen)
      {
	bgp_aggregate_delete (bgp, &rn->p, afi, safi, aggregate);
	bgp_aggregate_route (bgp, &rn->p, ri, afi, safi, NULL, aggregate);
      }
  bgp_unlock_node (child);
}

void
bgp_aggregate_decrement (struct bgp *bgp, struct prefix *p, 
			 struct bgp_info *del, afi_t afi, safi_t safi)
{
  struct bgp_node *child;
  struct bgp_node *rn;
  struct bgp_aggregate *aggregate;
  struct bgp_table *table;

  /* MPLS-VPN aggregation is not yet supported. */
  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP) || (safi == SAFI_EVPN)
      || (safi == SAFI_LABELED_UNICAST))
    return;

  table = bgp->aggregate[afi][safi];

  /* No aggregates configured. */
  if (bgp_table_top_nolock (table) == NULL)
    return;

  if (p->prefixlen == 0)
    return;

  child = bgp_node_get (table, p);

  /* Aggregate address configuration check. */
  for (rn = child; rn; rn = bgp_node_parent_nolock (rn))
    if ((aggregate = rn->info) != NULL && rn->p.prefixlen < p->prefixlen)
      {
	bgp_aggregate_delete (bgp, &rn->p, afi, safi, aggregate);
	bgp_aggregate_route (bgp, &rn->p, NULL, afi, safi, del, aggregate);
      }
  bgp_unlock_node (child);
}

/* Called via bgp_aggregate_set when the user configures aggregate-address */
static void
bgp_aggregate_add (struct bgp *bgp, struct prefix *p, afi_t afi, safi_t safi,
		   struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  struct bgp_info *new;
  struct bgp_info *ri;
  unsigned long match;
  u_char origin = BGP_ORIGIN_IGP;
  struct aspath *aspath = NULL;
  struct aspath *asmerge = NULL;
  struct community *community = NULL;
  struct community *commerge = NULL;
  u_char atomic_aggregate = 0;

  table = bgp->rib[afi][safi];

  /* Sanity check. */
  if (afi == AFI_IP && p->prefixlen == IPV4_MAX_BITLEN)
    return;
  if (afi == AFI_IP6 && p->prefixlen == IPV6_MAX_BITLEN)
    return;
    
  /* If routes exists below this node, generate aggregate routes. */
  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
	match = 0;

	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (BGP_INFO_HOLDDOWN (ri))
	      continue;

            if (ri->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
              atomic_aggregate = 1;

	    if (ri->sub_type != BGP_ROUTE_AGGREGATE)
	      {
		/* summary-only aggregate route suppress aggregated
		   route announcement.  */
		if (aggregate->summary_only)
		  {
		    (bgp_info_extra_get (ri))->suppress++;
		    bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
		    match++;
		  }

                /* If at least one route among routes that are aggregated has
                 * ORIGIN with the value INCOMPLETE, then the aggregated route
                 * MUST have the ORIGIN attribute with the value INCOMPLETE.
                 * Otherwise, if at least one route among routes that are
                 * aggregated has ORIGIN with the value EGP, then the aggregated
                 * route MUST have the ORIGIN attribute with the value EGP.
                 */
                if (origin < ri->attr->origin)
                    origin = ri->attr->origin;

		/* as-set aggregate route generate origin, as path,
		   community aggregation.  */
		if (aggregate->as_set)
		  {
		    if (aspath)
		      {
			asmerge = aspath_aggregate (aspath, ri->attr->aspath);
			aspath_free (aspath);
			aspath = asmerge;
		      }
		    else
		      aspath = aspath_dup (ri->attr->aspath);

		    if (ri->attr->community)
		      {
			if (community)
			  {
			    commerge = community_merge (community,
							ri->attr->community);
			    community = community_uniq_sort (commerge);
			    community_free (commerge);
			  }
			else
			  community = community_dup (ri->attr->community);
		      }
		  }
		aggregate->count++;
	      }
	  }
	
	/* If this node is suppressed, process the change. */
	if (match)
	  bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  /* Add aggregate route to BGP table. */
  if (aggregate->count)
    {
      rn = bgp_node_get (table, p);
      new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_AGGREGATE, bgp->peer_self,
		      bgp_attr_aggregate_intern(bgp, origin, aspath, community,
						aggregate->as_set,
                                                atomic_aggregate), rn);
      SET_FLAG (new->flags, BGP_INFO_VALID);

      bgp_info_add (rn, new);
      bgp_unlock_node (rn);
      
      /* Process change. */
      bgp_process (bgp, rn, afi, safi);
    }
  else
    {
      if (aspath)
	aspath_free (aspath);
      if (community)
	community_free (community);
    }
}

void
bgp_aggregate_delete (struct bgp *bgp, struct prefix *p, afi_t afi, 
		      safi_t safi, struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  struct bgp_info *ri;
  unsigned long match;

  table = bgp->rib[afi][safi];

  if (afi == AFI_IP && p->prefixlen == IPV4_MAX_BITLEN)
    return;
  if (afi == AFI_IP6 && p->prefixlen == IPV6_MAX_BITLEN)
    return;

  /* If routes exists below this node, generate aggregate routes. */
  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
	match = 0;

	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (BGP_INFO_HOLDDOWN (ri))
	      continue;

	    if (ri->sub_type != BGP_ROUTE_AGGREGATE)
	      {
		if (aggregate->summary_only && ri->extra)
		  {
		    ri->extra->suppress--;

		    if (ri->extra->suppress == 0)
		      {
			bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
			match++;
		      }
		  }
		aggregate->count--;
	      }
	  }

	/* If this node was suppressed, process the change. */
	if (match)
	  bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  /* Delete aggregate route from BGP table. */
  rn = bgp_node_get (table, p);

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_AGGREGATE)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

/* Aggregate route attribute. */
#define AGGREGATE_SUMMARY_ONLY 1
#define AGGREGATE_AS_SET       1

static int
bgp_aggregate_unset (struct vty *vty, const char *prefix_str,
                     afi_t afi, safi_t safi)
{
  int ret;
  struct prefix p;
  struct bgp_node *rn;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  /* Get BGP structure. */
  bgp = vty->index;

  /* Old configuration check. */
  rn = bgp_node_lookup (bgp->aggregate[afi][safi], &p);
  if (! rn)
    {
      vty_out (vty, "%% There is no aggregate-address configuration.%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  aggregate = rn->info;
  if (aggregate->safi & SAFI_UNICAST)
    bgp_aggregate_delete (bgp, &p, afi, SAFI_UNICAST, aggregate);
  if (aggregate->safi & SAFI_MULTICAST)
    bgp_aggregate_delete (bgp, &p, afi, SAFI_MULTICAST, aggregate);

  /* Unlock aggregate address configuration. */
  rn->info = NULL;
  bgp_aggregate_free (aggregate);
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

static int
bgp_aggregate_set (struct vty *vty, const char *prefix_str,
                   afi_t afi, safi_t safi,
		   u_char summary_only, u_char as_set)
{
  int ret;
  struct prefix p;
  struct bgp_node *rn;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  /* Get BGP structure. */
  bgp = vty->index;

  /* Old configuration check. */
  rn = bgp_node_get (bgp->aggregate[afi][safi], &p);

  if (rn->info)
    {
      vty_out (vty, "There is already same aggregate network.%s", VTY_NEWLINE);
      /* try to remove the old entry */
      ret = bgp_aggregate_unset (vty, prefix_str, afi, safi);
      if (ret)
        {
          vty_out (vty, "Error deleting aggregate.%s", VTY_NEWLINE);
	  bgp_unlock_node (rn);
	  return CMD_WARNING;
        }
    }

  /* Make aggregate address structure. */
  aggregate = bgp_aggregate_new ();
  aggregate->summary_only = summary_only;
  aggregate->as_set = as_set;
  aggregate->safi = safi;
  rn->info = aggregate;

  /* Aggregate address insert into BGP routing table. */
  if (safi & SAFI_UNICAST)
    bgp_aggregate_add (bgp, &p, afi, SAFI_UNICAST, aggregate);
  if (safi & SAFI_MULTICAST)
    bgp_aggregate_add (bgp, &p, afi, SAFI_MULTICAST, aggregate);

  return CMD_SUCCESS;
}

DEFUN (aggregate_address,
       aggregate_address_cmd,
       "aggregate-address A.B.C.D/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty), 0, 0);
}

DEFUN (aggregate_address_mask,
       aggregate_address_mask_cmd,
       "aggregate-address A.B.C.D A.B.C.D",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
			    0, 0);
}

DEFUN (aggregate_address_summary_only,
       aggregate_address_summary_only_cmd,
       "aggregate-address A.B.C.D/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
			    AGGREGATE_SUMMARY_ONLY, 0);
}

DEFUN (aggregate_address_mask_summary_only,
       aggregate_address_mask_summary_only_cmd,
       "aggregate-address A.B.C.D A.B.C.D summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
			    AGGREGATE_SUMMARY_ONLY, 0);
}

DEFUN (aggregate_address_as_set,
       aggregate_address_as_set_cmd,
       "aggregate-address A.B.C.D/M as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
			    0, AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_mask_as_set,
       aggregate_address_mask_as_set_cmd,
       "aggregate-address A.B.C.D A.B.C.D as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
			    0, AGGREGATE_AS_SET);
}


DEFUN (aggregate_address_as_set_summary,
       aggregate_address_as_set_summary_cmd,
       "aggregate-address A.B.C.D/M as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
			    AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

ALIAS (aggregate_address_as_set_summary,
       aggregate_address_summary_as_set_cmd,
       "aggregate-address A.B.C.D/M summary-only as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (aggregate_address_mask_as_set_summary,
       aggregate_address_mask_as_set_summary_cmd,
       "aggregate-address A.B.C.D A.B.C.D as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
			    AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

ALIAS (aggregate_address_mask_as_set_summary,
       aggregate_address_mask_summary_as_set_cmd,
       "aggregate-address A.B.C.D A.B.C.D summary-only as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (no_aggregate_address,
       no_aggregate_address_cmd,
       "no aggregate-address A.B.C.D/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP, bgp_node_safi (vty));
}

ALIAS (no_aggregate_address,
       no_aggregate_address_summary_only_cmd,
       "no aggregate-address A.B.C.D/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_as_set_cmd,
       "no aggregate-address A.B.C.D/M as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_as_set_summary_cmd,
       "no aggregate-address A.B.C.D/M as-set summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_summary_as_set_cmd,
       "no aggregate-address A.B.C.D/M summary-only as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (no_aggregate_address_mask,
       no_aggregate_address_mask_cmd,
       "no aggregate-address A.B.C.D A.B.C.D",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_unset (vty, prefix_str, AFI_IP, bgp_node_safi (vty));
}

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_summary_only_cmd,
       "no aggregate-address A.B.C.D A.B.C.D summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_as_set_cmd,
       "no aggregate-address A.B.C.D A.B.C.D as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_as_set_summary_cmd,
       "no aggregate-address A.B.C.D A.B.C.D as-set summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_summary_as_set_cmd,
       "no aggregate-address A.B.C.D A.B.C.D summary-only as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (ipv6_aggregate_address,
       ipv6_aggregate_address_cmd,
       "aggregate-address X:X::X:X/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP6, SAFI_UNICAST, 0, 0);
}

DEFUN (ipv6_aggregate_address_summary_only,
       ipv6_aggregate_address_summary_only_cmd,
       "aggregate-address X:X::X:X/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP6, SAFI_UNICAST, 
			    AGGREGATE_SUMMARY_ONLY, 0);
}

DEFUN (no_ipv6_aggregate_address,
       no_ipv6_aggregate_address_cmd,
       "no aggregate-address X:X::X:X/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP6, SAFI_UNICAST);
}

DEFUN (no_ipv6_aggregate_address_summary_only,
       no_ipv6_aggregate_address_summary_only_cmd,
       "no aggregate-address X:X::X:X/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP6, SAFI_UNICAST);
}

ALIAS (ipv6_aggregate_address,
       old_ipv6_aggregate_address_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

ALIAS (ipv6_aggregate_address_summary_only,
       old_ipv6_aggregate_address_summary_only_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

ALIAS (no_ipv6_aggregate_address,
       old_no_ipv6_aggregate_address_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

ALIAS (no_ipv6_aggregate_address_summary_only,
       old_no_ipv6_aggregate_address_summary_only_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

/* Redistribute route treatment. */
void
bgp_redistribute_add (struct prefix *p, const struct in_addr *nexthop,
		      const struct in6_addr *nexthop6,
		      u_int32_t metric, u_char type, route_tag_t tag)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  struct bgp_info *new;
  struct bgp_info *bi;
  struct bgp_info info;
  struct bgp_node *bn;
  struct attr attr;
  struct attr *new_attr;
  afi_t afi;
  int ret;

  /* Make default attribute. */
  bgp_attr_default_set (&attr, BGP_ORIGIN_INCOMPLETE);
  if (nexthop)
    attr.nexthop = *nexthop;

  if (nexthop6)
    {
      struct attr_extra *extra = bgp_attr_extra_get(&attr);
      extra->mp_nexthop_global = *nexthop6;
      extra->mp_nexthop_len = 16;
    }

  attr.med = metric;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
  attr.extra->tag = tag;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      afi = family2afi (p->family);

      if (bgp->redist[afi][type])
	{
	  struct attr attr_new;
	  struct attr_extra extra_new;

	  /* Copy attribute for modification. */
	  attr_new.extra = &extra_new;
	  bgp_attr_dup (&attr_new, &attr);

	  if (bgp->redist_metric_flag[afi][type])
	    attr_new.med = bgp->redist_metric[afi][type];

	  /* Apply route-map. */
	  if (bgp->rmap[afi][type].name)
	    {
	      info.peer = bgp->peer_self;
	      info.attr = &attr_new;

              SET_FLAG (bgp->peer_self->rmap_type, PEER_RMAP_TYPE_REDISTRIBUTE);

	      ret = route_map_apply (bgp->rmap[afi][type].map, p, RMAP_BGP,
				     &info);

              bgp->peer_self->rmap_type = 0;

	      if (ret == RMAP_DENYMATCH)
		{
		  /* Free uninterned attribute. */
		  bgp_attr_flush (&attr_new);

		  /* Unintern original. */
		  aspath_unintern (&attr.aspath);
		  bgp_attr_extra_free (&attr);
		  bgp_redistribute_delete (p, type);
		  return;
		}
	    }

          bn = bgp_afi_node_get (bgp->rib[afi][SAFI_UNICAST], 
                                 afi, SAFI_UNICAST, p, NULL);
          
	  new_attr = bgp_attr_intern (&attr_new);

 	  for (bi = bn->info; bi; bi = bi->next)
 	    if (bi->peer == bgp->peer_self
 		&& bi->sub_type == BGP_ROUTE_REDISTRIBUTE)
 	      break;
 
 	  if (bi)
 	    {
 	      if (attrhash_cmp (bi->attr, new_attr) &&
		  !CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
 		{
 		  bgp_attr_unintern (&new_attr);
 		  aspath_unintern (&attr.aspath);
 		  bgp_attr_extra_free (&attr);
 		  bgp_unlock_node (bn);
 		  return;
 		}
 	      else
 		{
 		  /* The attribute is changed. */
 		  bgp_info_set_flag (bn, bi, BGP_INFO_ATTR_CHANGED);
 
 		  /* Rewrite BGP route information. */
		  if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
		    bgp_info_restore(bn, bi);
		  else
		    bgp_aggregate_decrement (bgp, p, bi, afi, SAFI_UNICAST);
 		  bgp_attr_unintern (&bi->attr);
 		  bi->attr = new_attr;
 		  bi->uptime = bgp_clock ();
 
 		  /* Process change. */
 		  bgp_aggregate_increment (bgp, p, bi, afi, SAFI_UNICAST);
 		  bgp_process (bgp, bn, afi, SAFI_UNICAST);
 		  bgp_unlock_node (bn);
 		  aspath_unintern (&attr.aspath);
 		  bgp_attr_extra_free (&attr);
 		  return;
		}
 	    }

	  new = info_make(type, BGP_ROUTE_REDISTRIBUTE, bgp->peer_self,
			  new_attr, bn);
	  SET_FLAG (new->flags, BGP_INFO_VALID);

	  bgp_aggregate_increment (bgp, p, new, afi, SAFI_UNICAST);
	  bgp_info_add (bn, new);
	  bgp_unlock_node (bn);
	  bgp_process (bgp, bn, afi, SAFI_UNICAST);
	}
    }

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

void
bgp_redistribute_delete (struct prefix *p, u_char type)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  afi_t afi;
  struct bgp_node *rn;
  struct bgp_info *ri;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      afi = family2afi (p->family);

      if (bgp->redist[afi][type])
	{
         rn = bgp_afi_node_get (bgp->rib[afi][SAFI_UNICAST], afi, SAFI_UNICAST, p, NULL);

	  for (ri = rn->info; ri; ri = ri->next)
	    if (ri->peer == bgp->peer_self
		&& ri->type == type)
	      break;

	  if (ri)
	    {
	      bgp_aggregate_decrement (bgp, p, ri, afi, SAFI_UNICAST);
	      bgp_info_delete (rn, ri);
	      bgp_process (bgp, rn, afi, SAFI_UNICAST);
	    }
	  bgp_unlock_node (rn);
	}
    }
}

/* Withdraw specified route type's route. */
void
bgp_redistribute_withdraw (struct bgp *bgp, afi_t afi, int type)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_table *table;

  table = bgp->rib[afi][SAFI_UNICAST];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->next)
	if (ri->peer == bgp->peer_self
	    && ri->type == type)
	  break;

      if (ri)
	{
	  bgp_aggregate_decrement (bgp, &rn->p, ri, afi, SAFI_UNICAST);
	  bgp_info_delete (rn, ri);
	  bgp_process (bgp, rn, afi, SAFI_UNICAST);
	}
    }
}

/* Static function to display route. */
static void
route_vty_out_route (struct prefix *p, struct vty *vty)
{
  int len;
  char buf[BUFSIZ];

  if (p->family == AF_L2VPN)
    {
      prefix2str(p, buf, PREFIX_STRLEN);
      len = vty_out (vty, "%s", buf);
    }
  else
    len = vty_out (vty, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		   p->prefixlen);

  len = 17 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 20, " ");
  else
    vty_out (vty, "%*s", len, " ");
}

enum bgp_display_type
{
  normal_list,
};

/* Print the short form route status for a bgp_info */
static void
route_vty_short_status_out (struct vty *vty, struct bgp_info *binfo)
{
 /* Route status display. */
  if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
    vty_out (vty, "R");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE|BGP_INFO_STALE_REFRESH))
    vty_out (vty, "S");
  else if (binfo->extra && binfo->extra->suppress)
    vty_out (vty, "s");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_VALID) &&
           ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "*");
  else
    vty_out (vty, " ");

  /* Selected */
  if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "h");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
    vty_out (vty, "d");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
    vty_out (vty, ">");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_MULTIPATH))
    vty_out (vty, "=");
  else
    vty_out (vty, " ");

  /* Internal route. */
    if ((binfo->peer->as) && (binfo->peer->as == binfo->peer->local_as))
      vty_out (vty, "i");
    else
      vty_out (vty, " "); 
}

/* called from terminal list command */
void
route_vty_out(
    struct vty *vty,
    struct prefix *p,
    struct bgp_info *binfo,
    int display,
    safi_t safi)
{
  struct attr *attr;
  
  /* short status lead text */ 
  route_vty_short_status_out (vty, binfo);
  
  /* print prefix and mask */
  if (!display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {

      /*
       * NEXTHOP start
       */

      /*
       * For ENCAP routes, nexthop address family is not
       * neccessarily the same as the prefix address family.
       * Both SAFI_MPLS_VPN and SAFI_ENCAP use the MP nexthop field
       */
      if ((safi == SAFI_ENCAP) || (safi == SAFI_MPLS_VPN) || (safi == SAFI_EVPN)
          || (safi == SAFI_LABELED_UNICAST)) {
	if (attr->extra) {
	    char	buf[BUFSIZ];
	    int		af = NEXTHOP_FAMILY(attr->extra->mp_nexthop_len);

	    switch (af) {
		case AF_INET:
		    vty_out (vty, "%s", inet_ntop(af,
			&attr->extra->mp_nexthop_global_in, buf, BUFSIZ));
		    break;
		case AF_INET6:
		    vty_out (vty, "%s", inet_ntop(af,
			&attr->extra->mp_nexthop_global, buf, BUFSIZ));
		    break;
		default:
		    vty_out(vty, "?");
	    }
	} else {
	    vty_out(vty, "?");
	}
      } else {

	  if (p->family == AF_INET)
	    {
		vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
	    }
	  else if (p->family == AF_INET6)
	    {
	      int len;
	      char buf[BUFSIZ];

	      len = vty_out (vty, "%s",
			     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
			     buf, BUFSIZ));
	      len = 16 - len;
	      if (len < 1)
		vty_out (vty, "%s%*s", VTY_NEWLINE, 36, " ");
	      else
		vty_out (vty, "%*s", len, " ");
	    }
         else
	   {
	     vty_out(vty, "?");
	   }
      }

      /*
       * NEXTHOP end
       */


      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
	vty_out (vty, "%10u ", attr->med);
      else
	  vty_out (vty, "          ");

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
	vty_out (vty, "%7u ", attr->local_pref);
      else
	  vty_out (vty, "       ");

      vty_out (vty, "%7u ", (attr->extra ? attr->extra->weight : 0));
    
      /* Print aspath */
      if (attr->aspath)
        aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}  

/* called from terminal list command */
void
route_vty_out_tmp (struct vty *vty, struct prefix *p,
		   struct attr *attr, safi_t safi)
{
  afi_t family;

  /* Route status display. */
  vty_out (vty, "*");
  vty_out (vty, ">");
  vty_out (vty, " ");

  /* print prefix and mask */
  route_vty_out_route (p, vty);
  family = p->family;

  /* Print attribute */
  if (attr) 
    {
      if (p->family == AF_L2VPN) /* MAC/IP prefix */
        {
          family = AF_INET;
        }
      if (family == AF_INET)
	{
	  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP) || (safi == SAFI_EVPN)
              || (safi == SAFI_LABELED_UNICAST))
	    vty_out (vty, "%-16s",
                     inet_ntoa (attr->extra->mp_nexthop_global_in));
	  else
	    vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
	}
      else if (family == AF_INET6)
        {
          int len;
          char buf[BUFSIZ];
          
          assert (attr->extra);

          len = vty_out (vty, "%s",
                         inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                         buf, BUFSIZ));
          len = 16 - len;
          if (len < 1)
            vty_out (vty, "%s%*s", VTY_NEWLINE, 36, " ");
          else
            vty_out (vty, "%*s", len, " ");
        }

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
	vty_out (vty, "%10u ", attr->med);
      else
	vty_out (vty, "          ");

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
	vty_out (vty, "%7u ", attr->local_pref);
      else
	vty_out (vty, "       ");
      
      vty_out (vty, "%7u ", (attr->extra ? attr->extra->weight : 0));
      
      /* Print aspath */
      if (attr->aspath)
        aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}  

void
route_vty_out_tag (struct vty *vty, struct prefix *p,
		   struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  
  if (!binfo->extra)
    return;
  /* short status lead text */ 
  route_vty_short_status_out (vty, binfo);
    
  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {
      if (p->family == AF_INET)
	{
	  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
              || (safi == SAFI_LABELED_UNICAST))
	    vty_out (vty, "%-16s",
                     inet_ntoa (attr->extra->mp_nexthop_global_in));
	  else
	    vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
	}
      else if (p->family == AF_INET6)
	{
	  assert (attr->extra);
	  char buf[BUFSIZ];
	  char buf1[BUFSIZ];
	  if (attr->extra->mp_nexthop_len == 16)
	    vty_out (vty, "%s", 
		     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                     buf, BUFSIZ));
	  else if (attr->extra->mp_nexthop_len == 32)
	    vty_out (vty, "%s(%s)",
		     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
		                buf, BUFSIZ),
		     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
		                buf1, BUFSIZ));
	  
	}
    }

  char buf[BUFSIZ];
  /* EVPN RT2/RT5 encode vni in label. encoding uses full 24 bits */
  if (safi == SAFI_EVPN)
    {
      if (p->u.prefix_evpn.route_type != EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG)
        {
      if(binfo->extra->nlabels == 1)
        sprintf(buf,"%u", binfo->extra->labels[0]);
      else if (binfo->extra->nlabels == 2)
        sprintf(buf,"%u:%u", binfo->extra->labels[0], binfo->extra->labels[1] >> 4);
        }
      else
        {
          sprintf(buf, "%u", attr->label);
        }
    }
  else
    {
      labels2str (buf, sizeof(buf),
                  binfo->extra->labels, binfo->extra->nlabels);
    }
  vty_out (vty, ":/%s",buf); 
  vty_out (vty, "%s", VTY_NEWLINE);
}  

void
route_vty_out_overlay (struct vty *vty, struct prefix *p,
                       struct bgp_info *binfo, int display)
{
  struct attr *attr;
  char buf[BUFSIZ];

  if (!binfo->extra)
    return;

  /* short status lead text */
  route_vty_short_status_out (vty, binfo);

  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      if (attr->extra) {
        char	buf1[BUFSIZ];
        int af = NEXTHOP_FAMILY(attr->extra->mp_nexthop_len);

        switch (af) {
        case AF_INET:
          vty_out (vty, "%-16s", inet_ntop(af,
                                        &attr->extra->mp_nexthop_global_in, buf, BUFSIZ));
          break;
        case AF_INET6:
          vty_out (vty, "%s(%s)",
                   inet_ntop (af,
                             &attr->extra->mp_nexthop_global, buf, BUFSIZ),
                   inet_ntop (af,
                              &attr->extra->mp_nexthop_local, buf1, BUFSIZ));
          break;
        default:
          vty_out(vty, "?");
        }
      } else {
        vty_out(vty, "?");
      }
    }

  if (p->family != AF_L2VPN)
    vty_out (vty, "%u/", attr->extra->eth_t_id);

  if(attr->extra)
    {
      struct eth_segment_id *id = &(attr->extra->evpn_overlay.eth_s_id);
      char *str = esi2str(id);
      vty_out (vty, "%s", str);
      free(str);
      if (p->family == AF_INET)
	{
          vty_out (vty, "/%s", inet_ntoa (attr->extra->evpn_overlay.gw_ip.ipv4));
	}
      else if (p->family == AF_INET6)
	{
          vty_out (vty, "/%s",
                   inet_ntop (AF_INET6, &(attr->extra->evpn_overlay.gw_ip.ipv6),
                              buf, BUFSIZ));
	}
      if(attr->extra->ecommunity)
        {
          char *mac = NULL;
          struct ecommunity_val *routermac = ecommunity_lookup (attr->extra->ecommunity, 
                                                                ECOMMUNITY_ENCODE_EVPN,
                                                                ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC);
          if(routermac)
            mac = ecom_mac2str((char *)routermac->val);
          else
            {
              if(ecommunity_lookup (attr->extra->ecommunity, 
                                    ECOMMUNITY_ENCODE_EVPN,
                                    ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC))
                if ((p->u).prefix_evpn.u.prefix_macip.mac_len == 8*ETHER_ADDR_LEN)
                  mac = ecom_mac2str((char *)&(p->u).prefix_evpn.u.prefix_macip.mac);
            }
          if(mac)
            {
              vty_out (vty, "/%s",(char *)mac);
              XFREE(MTYPE_BGP_MAC, mac);
            }
        }
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

/* dampening route */
static void
damp_route_vty_out (struct vty *vty, struct prefix *p,
		    struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  int len;
  char timebuf[BGP_UPTIME_LEN];

  /* short status lead text */ 
  route_vty_short_status_out (vty, binfo);
  
  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", binfo->peer->host);
  len = 17 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 34, " ");
  else
    vty_out (vty, "%*s", len, " ");

  vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN));

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      /* Print aspath */
      if (attr->aspath)
	aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

/* flap route */
static void
flap_route_vty_out (struct vty *vty, struct prefix *p,
		    struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  struct bgp_damp_info *bdi;
  char timebuf[BGP_UPTIME_LEN];
  int len;
  
  if (!binfo->extra)
    return;
  
  bdi = binfo->extra->damp_info;

  /* short status lead text */
  route_vty_short_status_out (vty, binfo);
  
  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", binfo->peer->host);
  len = 16 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 33, " ");
  else
    vty_out (vty, "%*s", len, " ");

  len = vty_out (vty, "%d", bdi->flap);
  len = 5 - len;
  if (len < 1)
    vty_out (vty, " ");
  else
    vty_out (vty, "%*s ", len, " ");
    
  vty_out (vty, "%s ", peer_uptime (bdi->start_time,
	   timebuf, BGP_UPTIME_LEN));

  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED)
      && ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN));
  else
    vty_out (vty, "%*s ", 8, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      /* Print aspath */
      if (attr->aspath)
	aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

static void
route_vty_out_detail (struct vty *vty, struct bgp *bgp, struct prefix *p, 
		      struct bgp_info *binfo, afi_t afi, safi_t safi)
{
  char buf[INET6_ADDRSTRLEN];
  char buf1[BUFSIZ];
  struct attr *attr;
  int sockunion_vty_out (struct vty *, union sockunion *);
#ifdef HAVE_CLOCK_MONOTONIC
  time_t tbuf;
#endif
	
  attr = binfo->attr;

  if (safi == SAFI_MPLS_LABELED_VPN)
    safi = SAFI_MPLS_VPN;
  if (safi == SAFI_IANA_LABELED_UNICAST)
    safi = SAFI_LABELED_UNICAST;
  if (attr)
    {
      /* Line1 display AS-path, Aggregator */
      if (attr->aspath)
	{
	  vty_out (vty, "  ");
	  if (aspath_count_hops (attr->aspath) == 0)
	    vty_out (vty, "Local");
	  else
	    aspath_print_vty (vty, "%s", attr->aspath, "");
	}

      if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
        vty_out (vty, ", (removed)");
      if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE|BGP_INFO_STALE_REFRESH))
	vty_out (vty, ", (stale)");
      if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)))
	vty_out (vty, ", (aggregated by %u %s)", 
	         attr->extra->aggregator_as,
		 inet_ntoa (attr->extra->aggregator_addr));
      if (CHECK_FLAG (binfo->peer->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
	vty_out (vty, ", (Received from a RR-client)");
      if (CHECK_FLAG (binfo->peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
	vty_out (vty, ", (Received from a RS-client)");
      if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
	vty_out (vty, ", (history entry)");
      else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
	vty_out (vty, ", (suppressed due to dampening)");
      vty_out (vty, "%s", VTY_NEWLINE);
	  
      /* Line2 display Next-hop, Neighbor, Router-id */
      if (p->family == AF_INET)
	{
	  vty_out (vty, "    %s", ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)
                                   || (safi == SAFI_LABELED_UNICAST)) ?
		   inet_ntoa (attr->extra->mp_nexthop_global_in) :
		   inet_ntoa (attr->nexthop));
	}
      else
	{
	  assert (attr->extra);
	  vty_out (vty, "    %s",
		   inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
			      buf, INET6_ADDRSTRLEN));
	}

      if (binfo->peer == bgp->peer_self)
	{
	  vty_out (vty, " from %s ", 
		   p->family == AF_INET ? "0.0.0.0" : "::");
	  vty_out (vty, "(%s)", inet_ntoa(bgp->router_id));
	}
      else
	{
	  if (! CHECK_FLAG (binfo->flags, BGP_INFO_VALID))
	    vty_out (vty, " (inaccessible)"); 
	  else if (binfo->extra && binfo->extra->igpmetric)
	    vty_out (vty, " (metric %u)", binfo->extra->igpmetric);
	  if (!sockunion2str (&binfo->peer->su, buf, sizeof(buf))) {
	    buf[0] = '?';
	    buf[1] = 0;
	  }
	  vty_out (vty, " from %s", buf);
	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
	    vty_out (vty, " (%s)", inet_ntoa (attr->extra->originator_id));
	  else
	    vty_out (vty, " (%s)", inet_ntop (AF_INET, &binfo->peer->remote_id, buf1, BUFSIZ));
	}
      vty_out (vty, "%s", VTY_NEWLINE);

      /* display nexthop local */
      if (attr->extra && attr->extra->mp_nexthop_len == 32)
	{
	  vty_out (vty, "    (%s)%s",
		   inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
			      buf, INET6_ADDRSTRLEN),
		   VTY_NEWLINE);
	}

      /* Line 3 display Origin, Med, Locpref, Weight, Tag, valid, Int/Ext/Local, Atomic, best */
      vty_out (vty, "      Origin %s", bgp_origin_long_str[attr->origin]);
	  
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
	vty_out (vty, ", metric %u", attr->med);
	  
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
	vty_out (vty, ", localpref %u", attr->local_pref);
      else
	vty_out (vty, ", localpref %u", bgp->default_local_pref);

      if (attr->extra && attr->extra->weight != 0)
	vty_out (vty, ", weight %u", attr->extra->weight);

      if (attr->extra && attr->extra->tag != 0)
        vty_out (vty, ", tag %d", attr->extra->tag);
	
      if (! CHECK_FLAG (binfo->flags, BGP_INFO_VALID))
	vty_out (vty, ", invalid");
      else if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
	vty_out (vty, ", valid");

      if (binfo->peer != bgp->peer_self)
	{
	  if (binfo->peer->as == binfo->peer->local_as)
	    vty_out (vty, ", internal");
	  else 
	    vty_out (vty, ", %s", 
		     (bgp_confederation_peers_check(bgp, binfo->peer->as) ? "confed-external" : "external"));
	}
      else if (binfo->sub_type == BGP_ROUTE_AGGREGATE)
	vty_out (vty, ", aggregated, local");
      else if (binfo->type != ZEBRA_ROUTE_BGP)
	vty_out (vty, ", sourced");
      else
	vty_out (vty, ", sourced, local");

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
	vty_out (vty, ", atomic-aggregate");
	  
      if (CHECK_FLAG (binfo->flags, BGP_INFO_MULTIPATH) ||
	  (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED) &&
	   bgp_info_mpath_count (binfo)))
	vty_out (vty, ", multipath");

      if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
	vty_out (vty, ", best");

      vty_out (vty, "%s", VTY_NEWLINE);
	  
      /* Line 4 display Community */
      if (attr->community)
	vty_out (vty, "      Community: %s%s", attr->community->str,
		 VTY_NEWLINE);
	  
      /* Line 5 display Extended-community */
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))
	vty_out (vty, "      Extended Community: %s%s", 
	         attr->extra->ecommunity->str, VTY_NEWLINE);
	  
      /* Line 6 display Originator, Cluster-id */
      if ((attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)) ||
	  (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST)))
	{
	  assert (attr->extra);
	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
	    vty_out (vty, "      Originator: %s", 
	             inet_ntoa (attr->extra->originator_id));

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
	    {
	      int i;
	      vty_out (vty, ", Cluster list: ");
	      for (i = 0; i < attr->extra->cluster->length / 4; i++)
		vty_out (vty, "%s ", 
		         inet_ntoa (attr->extra->cluster->list[i]));
	    }
	  vty_out (vty, "%s", VTY_NEWLINE);
	}
      
      if (binfo->extra && binfo->extra->damp_info)
	bgp_damp_info_vty (vty, binfo);

      /* Line 7 display Uptime */
#ifdef HAVE_CLOCK_MONOTONIC
      tbuf = time(NULL) - (bgp_clock() - binfo->uptime);
      vty_out (vty, "      Last update: %s", ctime(&tbuf));
#else
      vty_out (vty, "      Last update: %s", ctime(&binfo->uptime));
#endif /* HAVE_CLOCK_MONOTONIC */
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

#define BGP_SHOW_SCODE_HEADER "Status codes: s suppressed, d damped, "\
			      "h history, * valid, > best, = multipath,%s"\
		"              i internal, r RIB-failure, S Stale, R Removed%s"
#define BGP_SHOW_OCODE_HEADER "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s"
#define BGP_SHOW_HEADER "   Network          Next Hop            Metric LocPrf Weight Path%s"
#define BGP_SHOW_DAMP_HEADER "   Network          From             Reuse    Path%s"
#define BGP_SHOW_FLAP_HEADER "   Network          From            Flaps Duration Reuse    Path%s"
#define BGP_SHOW_TAG_HEADER  "   Network          Next Hop      In tag/Out tag%s"

enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_route_map,
  bgp_show_type_neighbor,
  bgp_show_type_cidr_only,
  bgp_show_type_prefix_longer,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact,
  bgp_show_type_flap_statistics,
  bgp_show_type_flap_address,
  bgp_show_type_flap_prefix,
  bgp_show_type_flap_cidr_only,
  bgp_show_type_flap_regexp,
  bgp_show_type_flap_filter_list,
  bgp_show_type_flap_prefix_list,
  bgp_show_type_flap_prefix_longer,
  bgp_show_type_flap_route_map,
  bgp_show_type_flap_neighbor,
  bgp_show_type_dampend_paths,
  bgp_show_type_damp_neighbor,
  bgp_show_type_tags
};

static int
bgp_show_table (struct vty *vty, struct bgp_table *table, struct in_addr *router_id,
                enum bgp_show_type type, void *output_arg, int display_all)
{
  struct bgp_info *ri;
  struct bgp_node *rn;
  int header = 1;
  int display;
  unsigned long output_count;
  unsigned long total_count;
  safi_t safi = table->type == BGP_TABLE_VRF ? SAFI_MPLS_VPN : SAFI_UNICAST;

  /* This is first entry point, so reset total line. */
  output_count = 0;
  total_count  = 0;

  /* Start processing of routes. */
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn)) 
    if (rn->info != NULL)
      {
	display = 0;

	for (ri = rn->info; ri; ri = ri->next)
	  {
            total_count++;
	    if (type == bgp_show_type_flap_statistics
		|| type == bgp_show_type_flap_address
		|| type == bgp_show_type_flap_prefix
		|| type == bgp_show_type_flap_cidr_only
		|| type == bgp_show_type_flap_regexp
		|| type == bgp_show_type_flap_filter_list
		|| type == bgp_show_type_flap_prefix_list
		|| type == bgp_show_type_flap_prefix_longer
		|| type == bgp_show_type_flap_route_map
		|| type == bgp_show_type_flap_neighbor
		|| type == bgp_show_type_dampend_paths
		|| type == bgp_show_type_damp_neighbor)
	      {
		if (!(ri->extra && ri->extra->damp_info))
		  continue;
	      }
	    if (type == bgp_show_type_regexp
		|| type == bgp_show_type_flap_regexp)
	      {
		regex_t *regex = output_arg;
		    
		if (bgp_regexec (regex, ri->attr->aspath) == REG_NOMATCH)
		  continue;
	      }
	    if (type == bgp_show_type_prefix_list
		|| type == bgp_show_type_flap_prefix_list)
	      {
		struct prefix_list *plist = output_arg;
		    
		if (prefix_list_apply (plist, &rn->p) != PREFIX_PERMIT)
		  continue;
	      }
	    if (type == bgp_show_type_filter_list
		|| type == bgp_show_type_flap_filter_list)
	      {
		struct as_list *as_list = output_arg;

		if (as_list_apply (as_list, ri->attr->aspath) != AS_FILTER_PERMIT)
		  continue;
	      }
	    if (type == bgp_show_type_route_map
		|| type == bgp_show_type_flap_route_map)
	      {
		struct route_map *rmap = output_arg;
		struct bgp_info binfo;
		struct attr dummy_attr;
		struct attr_extra dummy_extra;
		int ret;

		dummy_attr.extra = &dummy_extra;
		bgp_attr_dup (&dummy_attr, ri->attr);

		binfo.peer = ri->peer;
		binfo.attr = &dummy_attr;

		ret = route_map_apply (rmap, &rn->p, RMAP_BGP, &binfo);
		if (ret == RMAP_DENYMATCH)
		  continue;
	      }
	    if (type == bgp_show_type_neighbor
		|| type == bgp_show_type_flap_neighbor
		|| type == bgp_show_type_damp_neighbor)
	      {
		union sockunion *su = output_arg;

		if (ri->peer->su_remote == NULL || ! sockunion_same(ri->peer->su_remote, su))
		  continue;
	      }
	    if (type == bgp_show_type_cidr_only
		|| type == bgp_show_type_flap_cidr_only)
	      {
		u_int32_t destination;

		destination = ntohl (rn->p.u.prefix4.s_addr);
		if (IN_CLASSC (destination) && rn->p.prefixlen == 24)
		  continue;
		if (IN_CLASSB (destination) && rn->p.prefixlen == 16)
		  continue;
		if (IN_CLASSA (destination) && rn->p.prefixlen == 8)
		  continue;
	      }
	    if (type == bgp_show_type_prefix_longer
		|| type == bgp_show_type_flap_prefix_longer)
	      {
		struct prefix *p = output_arg;

		if (! prefix_match (p, &rn->p))
		  continue;
	      }
	    if (type == bgp_show_type_community_all)
	      {
		if (! ri->attr->community)
		  continue;
	      }
	    if (type == bgp_show_type_community)
	      {
		struct community *com = output_arg;

		if (! ri->attr->community ||
		    ! community_match (ri->attr->community, com))
		  continue;
	      }
	    if (type == bgp_show_type_community_exact)
	      {
		struct community *com = output_arg;

		if (! ri->attr->community ||
		    ! community_cmp (ri->attr->community, com))
		  continue;
	      }
	    if (type == bgp_show_type_community_list)
	      {
		struct community_list *list = output_arg;

		if (! community_list_match (ri->attr->community, list))
		  continue;
	      }
	    if (type == bgp_show_type_community_list_exact)
	      {
		struct community_list *list = output_arg;

		if (! community_list_exact_match (ri->attr->community, list))
		  continue;
	      }
	    if (type == bgp_show_type_flap_address
		|| type == bgp_show_type_flap_prefix)
	      {
		struct prefix *p = output_arg;

		if (! prefix_match (&rn->p, p))
		  continue;

		if (type == bgp_show_type_flap_prefix)
		  if (p->prefixlen != rn->p.prefixlen)
		    continue;
	      }
	    if (type == bgp_show_type_dampend_paths
		|| type == bgp_show_type_damp_neighbor)
	      {
		if (! CHECK_FLAG (ri->flags, BGP_INFO_DAMPED)
		    || CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
		  continue;
	      }

	    if (header)
	      {
		vty_out (vty, "BGP table version is 0, local router ID is %s%s", inet_ntoa (*router_id), VTY_NEWLINE);
		vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
		vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
		if (type == bgp_show_type_dampend_paths
		    || type == bgp_show_type_damp_neighbor)
		  vty_out (vty, BGP_SHOW_DAMP_HEADER, VTY_NEWLINE);
		else if (type == bgp_show_type_flap_statistics
			 || type == bgp_show_type_flap_address
			 || type == bgp_show_type_flap_prefix
			 || type == bgp_show_type_flap_cidr_only
			 || type == bgp_show_type_flap_regexp
			 || type == bgp_show_type_flap_filter_list
			 || type == bgp_show_type_flap_prefix_list
			 || type == bgp_show_type_flap_prefix_longer
			 || type == bgp_show_type_flap_route_map
			 || type == bgp_show_type_flap_neighbor)
		  vty_out (vty, BGP_SHOW_FLAP_HEADER, VTY_NEWLINE);
		else if (type == bgp_show_type_tags)
                  vty_out (vty, BGP_SHOW_TAG_HEADER, VTY_NEWLINE);
                else
		  vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
		header = 0;
	      }

	    if (type == bgp_show_type_dampend_paths
		|| type == bgp_show_type_damp_neighbor)
	      damp_route_vty_out (vty, &rn->p, ri, display, safi);
	    else if (type == bgp_show_type_flap_statistics
		     || type == bgp_show_type_flap_address
		     || type == bgp_show_type_flap_prefix
		     || type == bgp_show_type_flap_cidr_only
		     || type == bgp_show_type_flap_regexp
		     || type == bgp_show_type_flap_filter_list
		     || type == bgp_show_type_flap_prefix_list
		     || type == bgp_show_type_flap_prefix_longer
		     || type == bgp_show_type_flap_route_map
		     || type == bgp_show_type_flap_neighbor)
	      flap_route_vty_out (vty, &rn->p, ri, display, safi);
	    else if (type == bgp_show_type_tags)
              route_vty_out_tag (vty, &rn->p, ri, 0, safi);
            else
              if(display_all)
                route_vty_out (vty, &rn->p, ri, 0, safi);
              else
                route_vty_out (vty, &rn->p, ri, display, safi);
	    display++;
	  }
	if (display)
	  output_count++;
      }

  /* No route is displayed */
  if (output_count == 0)
    {
      if (type == bgp_show_type_normal)
        vty_out (vty, "No BGP prefixes displayed, %ld exist%s", total_count, VTY_NEWLINE);
    }
  else
    vty_out (vty, "%sDisplayed  %ld out of %ld total prefixes%s",
	     VTY_NEWLINE, output_count, total_count, VTY_NEWLINE);

  return CMD_SUCCESS;
}

#define BGP_SHOW_SCODE_HEADER "Status codes: s suppressed, d damped, "\
			      "h history, * valid, > best, = multipath,%s"\
		"              i internal, r RIB-failure, S Stale, R Removed%s"
#define BGP_SHOW_OCODE_HEADER "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s"
#define BGP_SHOW_HEADER "   Network          Next Hop            Metric LocPrf Weight Path%s"
int
show_adj_route_vrf (struct vty *vty, struct peer *peer, struct bgp_vrf *vrf, int in)
{
  struct bgp_table *table;
  struct bgp *bgp;
  char buf[RD_ADDRSTRLEN];
  char *ptr;
  struct bgp_node *rn;
  unsigned long output_count;
  safi_t safi;
  int rd_header = 1;
  int header1 = 1;
  int header2 = 1;
  struct bgp_adj_in *ain;
  struct bgp_adj_out *adj;

  /* This is first entry point, so reset total line. */
  output_count = 0;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  table = vrf->rib[AFI_IP];

  safi = table->type == BGP_TABLE_VRF ? SAFI_EVPN : SAFI_UNICAST;
  /* Start processing of routes. */
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if (rn->info != NULL)
      {
        if (in)
          {
            for (ain = rn->adj_in; ain; ain = ain->next)
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
                      ptr = prefix_rd2str (&(vrf->outbound_rd), buf, RD_ADDRSTRLEN);
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
                      route_vty_out_tmp (vty, &rn->p, ain->attr, safi);
                      output_count++;
                    }
                }
          }
        else
          {
            for (adj = rn->adj_out; adj; adj = adj->next)
              if (adj->peer == peer)
                {
                  if (header1)
                    {
                      vty_out (vty, "BGP table version is 0, local router ID is %s%s", inet_ntoa (bgp->router_id), VTY_NEWLINE);
                      vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                      vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                      header1 = 0;
                    }
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
                      route_vty_out_tmp (vty, &rn->p, adj->attr, safi);
                      output_count++;
                    }
                }
          }
      }
  if (output_count != 0)
    vty_out (vty, "%sTotal number of prefixes %ld%s",
	     VTY_NEWLINE, output_count, VTY_NEWLINE);

  return CMD_SUCCESS;
}

static int
bgp_show (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
         enum bgp_show_type type, void *output_arg)
{
  struct bgp_table *table;

  if (bgp == NULL) {
    bgp = bgp_get_default ();
  }

  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }


  table = bgp->rib[afi][safi];

  return bgp_show_table (vty, table, &bgp->router_id, type, output_arg, 0);
}

static int
bgp_show_vrf_neigh (struct vty *vty, const char *vrf_name, afi_t afi,
                    const char *peername, int type)
{
  struct bgp *bgp = bgp_get_default();
  struct bgp_vrf *vrf;
  struct prefix_rd prd;
  struct peer *peer;
  union sockunion su;
  int ret;

  if (! bgp)
    {
      vty_out (vty, "%% No default BGP instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (! str2prefix_rd (vrf_name, &prd))
    {
      vty_out (vty, "%% Invalid RD '%s'%s", vrf_name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  vrf = bgp_vrf_lookup (bgp, &prd);
  if (! vrf)
    {
      vty_out (vty, "%% No VRF with RD '%s'%s", vrf_name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2sockunion (peername, &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", peername, VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer)
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return show_adj_route_vrf (vty, peer, vrf, 1);
}

static int
bgp_show_vrf (struct vty *vty, const char *vrf_name, afi_t afi,
         enum bgp_show_type type, void *output_arg)
{
  struct bgp *bgp = bgp_get_default();
  struct bgp_vrf *vrf = NULL;
  struct prefix_rd prd;
  struct listnode *node;
  char buf[RD_ADDRSTRLEN];

  if (! bgp)
    {
      vty_out (vty, "%% No default BGP instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (!vrf_name)
    {
      for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
        {
          prefix_rd2str (&(vrf->outbound_rd), buf, RD_ADDRSTRLEN);
          vty_out (vty, "Route Distinguisher: %s%s", buf, VTY_NEWLINE);
          bgp_show_table (vty, vrf->rib[afi],
                          &bgp->router_id, type, output_arg, 1);
        }
        return CMD_SUCCESS;
    }
  if (! str2prefix_rd (vrf_name, &prd))
    {
      vty_out (vty, "%% Invalid RD '%s'%s", vrf_name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  vrf = bgp_vrf_lookup (bgp, &prd);
  if (! vrf)
    {
      vty_out (vty, "%% No VRF with RD '%s'%s", vrf_name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_table (vty, vrf->rib[afi], &bgp->router_id, type, output_arg, 1);
}

/* Header of detailed BGP route information */
static void
route_vty_out_detail_header (struct vty *vty, struct bgp *bgp,
			     struct bgp_node *rn,
                             struct prefix_rd *prd, afi_t afi, safi_t safi)
{
  struct bgp_info *ri;
  struct prefix *p;
  struct peer *peer;
  struct listnode *node, *nnode;
  char buf1[INET6_ADDRSTRLEN];
  char buf2[INET6_ADDRSTRLEN];
  int count = 0;
  int best = 0;
  int suppress = 0;
  int no_export = 0;
  int no_advertise = 0;
  int local_as = 0;
  int first = 0;
  int printrd = ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP));

  p = &rn->p;
  if (p->family == AF_L2VPN)
    prefix2str(p, buf2, INET6_ADDRSTRLEN);
  else
    inet_ntop (p->family, &p->u.prefix, buf2, INET6_ADDRSTRLEN);
  vty_out (vty, "BGP routing table entry for %s%s%s/%d%s",
	   (printrd ?  prefix_rd2str (prd, buf1, RD_ADDRSTRLEN) : ""),
	   printrd ?  ":" : "",
	   buf2,
	   p->prefixlen, VTY_NEWLINE);

  for (ri = rn->info; ri; ri = ri->next)
    {
      count++;
      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
	{
	  best = count;
	  if (ri->extra && ri->extra->suppress)
	    suppress = 1;
	  if (ri->attr->community != NULL)
	    {
	      if (community_include (ri->attr->community, COMMUNITY_NO_ADVERTISE))
		no_advertise = 1;
	      if (community_include (ri->attr->community, COMMUNITY_NO_EXPORT))
		no_export = 1;
	      if (community_include (ri->attr->community, COMMUNITY_LOCAL_AS))
		local_as = 1;
	    }
	}
    }

  vty_out (vty, "Paths: (%d available", count);
  if (best)
    {
      vty_out (vty, ", best #%d", best);
      if (safi == SAFI_UNICAST)
	vty_out (vty, ", table Default-IP-Routing-Table");
    }
  else
    vty_out (vty, ", no best path");
  if (no_advertise)
    vty_out (vty, ", not advertised to any peer");
  else if (no_export)
    vty_out (vty, ", not advertised to EBGP peer");
  else if (local_as)
    vty_out (vty, ", not advertised outside local AS");
  if (suppress)
    vty_out (vty, ", Advertisements suppressed by an aggregate.");
  vty_out (vty, ")%s", VTY_NEWLINE);

  if (safi == SAFI_MPLS_LABELED_VPN)
    {
      vty_out (vty, "%s", VTY_NEWLINE);
      return;
    }

  /* advertised peer */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (bgp_adj_out_lookup (peer, p, afi, safi, rn))
	{
	  if (! first)
	    vty_out (vty, "  Advertised to non peer-group peers:%s ", VTY_NEWLINE);
	  vty_out (vty, " %s", sockunion2str (&peer->su, buf1, SU_ADDRSTRLEN));
	  first = 1;
	}
    }
  if (! first)
    vty_out (vty, "  Not advertised to any peer");
  vty_out (vty, "%s", VTY_NEWLINE);
}

/* Display specified route of BGP table. */
static int
bgp_show_route_in_table (struct vty *vty, struct bgp *bgp, 
                         struct bgp_table *rib, const char *ip_str,
                         afi_t afi, safi_t safi, struct prefix_rd *prd,
                         int prefix_check, enum bgp_path_type pathtype)
{
  int ret;
  int header;
  int display = 0;
  struct prefix match;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_table *table;

  memset (&match, 0, sizeof (struct prefix)); /* keep valgrind happy */
  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = afi2family (afi);

  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP) || (safi == SAFI_EVPN))
    {
      for (rn = bgp_table_top (rib); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

          if ((table = rn->info) != NULL)
            {
              header = 1;

              if ((rm = bgp_node_match (table, &match)) != NULL)
                {
                  if (prefix_check && rm->p.prefixlen != match.prefixlen)
                    {
                      bgp_unlock_node (rm);
                      continue;
                    }

                  for (ri = rm->info; ri; ri = ri->next)
                    {
                      if (header)
                        {
                          route_vty_out_detail_header (vty, bgp, rm, (struct prefix_rd *)&rn->p,
                                                       AFI_IP, safi);

                          header = 0;
                        }
                      display++;

                      if (pathtype == BGP_PATH_ALL ||
                          (pathtype == BGP_PATH_BESTPATH && CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)) ||
                          (pathtype == BGP_PATH_MULTIPATH &&
                           (CHECK_FLAG (ri->flags, BGP_INFO_MULTIPATH) || CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))))
                        route_vty_out_detail (vty, bgp, &rm->p, ri, AFI_IP, safi);
                    }

                  bgp_unlock_node (rm);
                }
            }
        }
    }
  else
    {
      header = 1;

      if ((rn = bgp_node_match (rib, &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              for (ri = rn->info; ri; ri = ri->next)
                {
                  if (header)
                    {
                      route_vty_out_detail_header (vty, bgp, rn, NULL, afi, safi);
                      header = 0;
                    }
                  display++;

                  if (pathtype == BGP_PATH_ALL ||
                      (pathtype == BGP_PATH_BESTPATH && CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)) ||
                      (pathtype == BGP_PATH_MULTIPATH &&
                       (CHECK_FLAG (ri->flags, BGP_INFO_MULTIPATH) || CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))))
                    route_vty_out_detail (vty, bgp, &rn->p, ri, afi, safi);
                }
            }

          bgp_unlock_node (rn);
        }
    }

  if (! display)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

static int
bgp_show_vrf_route (struct vty *vty, const char *vrf_name, const char *ip_str,
		afi_t afi, int prefix_check)
{
  struct bgp *bgp = bgp_get_default();
  struct bgp_vrf *vrf;
  struct prefix_rd prd;

  if (! bgp)
    {
      vty_out (vty, "%% No default BGP instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (! str2prefix_rd (vrf_name, &prd))
    {
      vty_out (vty, "%% Invalid RD '%s'%s", vrf_name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  vrf = bgp_vrf_lookup (bgp, &prd);
  if (! vrf)
    {
      vty_out (vty, "%% No VRF with RD '%s'%s", vrf_name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, vrf->rib[afi], ip_str,
                                  afi, SAFI_MPLS_LABELED_VPN, NULL, prefix_check, BGP_PATH_ALL);
}

/* Display specified route of Main RIB */
static int
bgp_show_route (struct vty *vty, const char *view_name, const char *ip_str,
		afi_t afi, safi_t safi, struct prefix_rd *prd,
		int prefix_check, enum bgp_path_type pathtype)
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
 
  return bgp_show_route_in_table (vty, bgp, bgp->rib[afi][safi], ip_str, 
                                  afi, safi, prd, prefix_check, pathtype);
}

/* BGP route print out function. */
DEFUN (show_ip_bgp,
       show_ip_bgp_cmd,
       "show ip bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

DEFUN (show_ip_bgp_vrf,
       show_ip_bgp_vrf_cmd,
       "show ip bgp vrf WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n")
{
  return bgp_show_vrf (vty, argv[0], AFI_IP, bgp_show_type_normal, NULL);
}

DEFUN (show_ip_bgp_vrf_all,
       show_ip_bgp_vrf_all_cmd,
       "show ip bgp vrf-all",
       SHOW_STR
       IP_STR
       BGP_STR
       "All VRFs\n")
{
  return bgp_show_vrf (vty, NULL, AFI_IP, bgp_show_type_normal, NULL);
}

DEFUN (show_ip_bgp_vrf_all_tags,
       show_ip_bgp_vrf_all_tags_cmd,
       "show ip bgp vrf-all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "All VRFs\n"
       "Tags\n")
{
  return bgp_show_vrf (vty, NULL, AFI_IP, bgp_show_type_tags, NULL);
}

DEFUN (show_ip_bgp_vrf_tags,
       show_ip_bgp_vrf_tags_cmd,
       "show ip bgp vrf WORD tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n"
       "Tags\n")
{
  return bgp_show_vrf (vty, argv[0], AFI_IP, bgp_show_type_tags, NULL);
}

DEFUN (show_ip_bgp_vrf_neighbor_received,
       show_ip_bgp_vrf_neighbor_received_cmd,
       "show ip bgp vrf WORD neighbor A.B.C.D received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes received from a BGP neighbor\n")
{
  return bgp_show_vrf_neigh (vty, argv[0], AFI_IP, argv[1], 1);
}

DEFUN (show_ipv6_bgp_vrf,
       show_ipv6_bgp_vrf_cmd,
       "show ipv6 bgp vrf WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n")
{
  return bgp_show_vrf (vty, argv[0], AFI_IP6, bgp_show_type_normal, NULL);
}

DEFUN (show_ipv6_bgp_vrf_all,
       show_ipv6_bgp_vrf_all_cmd,
       "show ipv6 bgp vrf-all",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "All VRFs\n")
{
  return bgp_show_vrf (vty, NULL, AFI_IP6, bgp_show_type_normal, NULL);
}

DEFUN (show_ipv6_bgp_vrf_all_tags,
       show_ipv6_bgp_vrf_all_tags_cmd,
       "show ipv6 bgp vrf-all tags",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "All VRFs\n"
       "Tags\n")
{
  return bgp_show_vrf (vty, NULL, AFI_IP6, bgp_show_type_tags, NULL);
}

DEFUN (show_ipv6_bgp_vrf_tags,
       show_ipv6_bgp_vrf_tags_cmd,
       "show ipv6 bgp vrf WORD tags",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n"
       "Tags\n")
{
  return bgp_show_vrf (vty, argv[0], AFI_IP6, bgp_show_type_tags, NULL);
}

DEFUN (show_l2vpn_bgp_vrf,
       show_l2vpn_bgp_vrf_cmd,
       "show l2vpn bgp vrf WORD",
       SHOW_STR
       "Display L2VPN AFI information\n"
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n")
{
  return bgp_show_vrf (vty, argv[0], AFI_L2VPN, bgp_show_type_normal, NULL);
}

DEFUN (show_l2vpn_bgp_vrf_all,
       show_l2vpn_bgp_vrf_all_cmd,
       "show l2vpn bgp vrf-all",
       SHOW_STR
       "Display L2VPN AFI information\n"
       BGP_STR
       "All VRFs\n")
{
  return bgp_show_vrf (vty, NULL, AFI_L2VPN, bgp_show_type_normal, NULL);
}

DEFUN (show_l2vpn_bgp_vrf_all_tags,
       show_l2vpn_bgp_vrf_all_tags_cmd,
       "show l2vpn bgp vrf-all tags",
       SHOW_STR
       "Display L2VPN AFI information\n"
       BGP_STR
       "All VRFs\n"
       "Tags\n")
{
  return bgp_show_vrf (vty, NULL, AFI_L2VPN, bgp_show_type_tags, NULL);
}

DEFUN (show_l2vpn_bgp_vrf_tags,
       show_l2vpn_bgp_vrf_tags_cmd,
       "show l2vpn bgp vrf WORD tags",
       SHOW_STR
       "Display L2VPN AFI information\n"
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n"
       "Tags\n")
{
  return bgp_show_vrf (vty, argv[0], AFI_L2VPN, bgp_show_type_tags, NULL);
}

DEFUN (show_ip_bgp_ipv4,
       show_ip_bgp_ipv4_cmd,
       "show ip bgp ipv4 (unicast|multicast)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST, bgp_show_type_normal,
                     NULL);
 
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show ip bgp A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_route_pathtype,
       show_ip_bgp_route_pathtype_cmd,
       "show ip bgp A.B.C.D (bestpath|multipath)",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")
{
  if (strncmp (argv[1], "b", 1) == 0)
    return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_BESTPATH);
  else
    return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_MULTIPATH);
}

DEFUN (show_bgp_ipv4_safi_route_pathtype,
       show_bgp_ipv4_safi_route_pathtype_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D (bestpath|multipath)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 0, BGP_PATH_BESTPATH);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 0, BGP_PATH_MULTIPATH);
  else
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_BESTPATH);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_MULTIPATH);
}

DEFUN (show_ip_bgp_vrf_route,
       show_ip_bgp_vrf_route_cmd,
       "show ip bgp vrf WORD A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n"
       "IPv4 Address\n")
{
  return bgp_show_vrf_route (vty, argv[0], argv[1], AFI_IP, 0);
}

DEFUN (show_ipv6_bgp_vrf_route,
       show_ipv6_bgp_vrf_route_cmd,
       "show ipv6 bgp vrf WORD X:X::X:X",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "VRF\n"
       "Route Distinguisher\n"
       "IPv6 address")
{
  afi_t afi = AFI_IP6;
  return bgp_show_vrf_route (vty, argv[0], argv[1], afi, 0);
}

DEFUN (show_ip_bgp_ipv4_route,
       show_ip_bgp_ipv4_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 0, BGP_PATH_ALL);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_vpnv4_all_route,
       show_ip_bgp_vpnv4_all_route_cmd,
       "show ip bgp vpnv4 all A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_MPLS_VPN, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_l2vpn_evpn_all_route,
       show_bgp_l2vpn_evpn_all_route_cmd,
       "show bgp l2vpn all A.B.C.D",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_L2VPN, SAFI_EVPN, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_vpnv4_rd_route,
       show_ip_bgp_vpnv4_rd_route_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MPLS_VPN, &prd, 0, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_prefix,
       show_ip_bgp_prefix_cmd,
       "show ip bgp A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_prefix_pathtype,
       show_ip_bgp_prefix_pathtype_cmd,
       "show ip bgp A.B.C.D/M (bestpath|multipath)",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")
{
  if (strncmp (argv[1], "b", 1) == 0)
    return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_BESTPATH);
  else
    return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_MULTIPATH);
}

DEFUN (show_ip_bgp_ipv4_prefix,
       show_ip_bgp_ipv4_prefix_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 1, BGP_PATH_ALL);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_ipv4_prefix_pathtype,
       show_ip_bgp_ipv4_prefix_pathtype_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M (bestpath|multipath)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 1, BGP_PATH_BESTPATH);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 1, BGP_PATH_MULTIPATH);
  else
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_BESTPATH);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_MULTIPATH);
}

ALIAS (show_ip_bgp_ipv4_prefix_pathtype,
       show_bgp_ipv4_safi_prefix_pathtype_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D/M (bestpath|multipath)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")

DEFUN (show_ip_bgp_vpnv4_all_prefix,
       show_ip_bgp_vpnv4_all_prefix_cmd,
       "show ip bgp vpnv4 all A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_MPLS_VPN, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_l2vpn_evpn_all_prefix,
       show_bgp_l2vpn_evpn_all_prefix_cmd,
       "show bgp l2vpn evpn all A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_L2VPN, SAFI_EVPN, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_vpnv4_rd_prefix,
       show_ip_bgp_vpnv4_rd_prefix_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MPLS_VPN, &prd, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_l2vpn_evpn_rd_prefix,
       show_bgp_l2vpn_evpn_rd_prefix_cmd,
       "show bgp l2vpn evpn rd ASN:nn_or_IP-address:nn A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_L2VPN, SAFI_EVPN, &prd, 1, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_view,
       show_ip_bgp_view_cmd,
       "show ip bgp view WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n")
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}

  return bgp_show (vty, bgp, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

DEFUN (show_ip_bgp_view_route,
       show_ip_bgp_view_route_cmd,
       "show ip bgp view WORD A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_view_prefix,
       show_ip_bgp_view_prefix_cmd,
       "show ip bgp view WORD A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp,
       show_bgp_cmd,
       "show bgp",
       SHOW_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal,
                   NULL);
}

ALIAS (show_bgp,
       show_bgp_ipv6_cmd,
       "show bgp ipv6",
       SHOW_STR
       BGP_STR
       "Address family\n")

/* old command */
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal,
                   NULL);
}

DEFUN (show_bgp_route,
       show_bgp_route_cmd,
       "show bgp X:X::X:X",
       SHOW_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv4_safi,
       show_bgp_ipv4_safi_cmd,
       "show bgp ipv4 (unicast|multicast)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST, bgp_show_type_normal,
                     NULL);
 
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

DEFUN (show_bgp_ipv4_safi_route,
       show_bgp_ipv4_safi_route_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 0, BGP_PATH_ALL);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_route_pathtype,
       show_bgp_route_pathtype_cmd,
       "show bgp X:X::X:X (bestpath|multipath)",
       SHOW_STR
       BGP_STR
       "Network in the BGP routing table to display\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")
{
  if (strncmp (argv[1], "b", 1) == 0)
    return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_BESTPATH);
  else
    return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_MULTIPATH);
}

ALIAS (show_bgp_route_pathtype,
       show_bgp_ipv6_route_pathtype_cmd,
       "show bgp ipv6 X:X::X:X (bestpath|multipath)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Network in the BGP routing table to display\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")

DEFUN (show_bgp_ipv6_safi_route_pathtype,
       show_bgp_ipv6_safi_route_pathtype_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X (bestpath|multipath)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 0, BGP_PATH_BESTPATH);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 0, BGP_PATH_MULTIPATH);
  else
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_BESTPATH);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_MULTIPATH);
}

DEFUN (show_bgp_ipv4_vpn_route,
       show_bgp_ipv4_vpn_route_cmd,
       "show bgp ipv4 vpn A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_MPLS_VPN, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv6_vpn_route,
       show_bgp_ipv6_vpn_route_cmd,
       "show bgp ipv6 vpn X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MPLS_VPN, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv4_vpn_rd_route,
       show_bgp_ipv4_vpn_rd_route_cmd,
       "show bgp ipv4 vpn rd ASN:nn_or_IP-address:nn A.B.C.D",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MPLS_VPN, &prd, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_l2vpn_evpn_rd_route,
       show_bgp_l2vpn_evpn_rd_route_cmd,
       "show bgp l2vpn evpn rd ASN:nn_or_IP-address:nn A.B.C.D",
       SHOW_STR
       BGP_STR
       "Display L2VPN AFI information\n"
       "Display EVPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_L2VPN, SAFI_EVPN, &prd, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv6_vpn_rd_route,
       show_bgp_ipv6_vpn_rd_route_cmd,
       "show bgp ipv6 vpn rd ASN:nn_or_IP-address:nn X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MPLS_VPN, &prd, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_prefix_pathtype,
       show_bgp_prefix_pathtype_cmd,
       "show bgp X:X::X:X/M (bestpath|multipath)",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")
{
  if (strncmp (argv[1], "b", 1) == 0)
    return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_BESTPATH);
  else
    return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_MULTIPATH);
}

ALIAS (show_bgp_prefix_pathtype,
       show_bgp_ipv6_prefix_pathtype_cmd,
       "show bgp ipv6 X:X::X:X/M (bestpath|multipath)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")

DEFUN (show_bgp_ipv6_safi_prefix_pathtype,
       show_bgp_ipv6_safi_prefix_pathtype_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X/M (bestpath|multipath)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display only the bestpath\n"
       "Display only multipaths\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 1, BGP_PATH_BESTPATH);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 1, BGP_PATH_MULTIPATH);
  else
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_BESTPATH);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_MULTIPATH);
}

DEFUN (show_bgp_ipv4_encap_route,
       show_bgp_ipv4_encap_route_cmd,
       "show bgp ipv4 encap A.B.C.D",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display ENCAP NLRI specific information\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_ENCAP, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv6_encap_route,
       show_bgp_ipv6_encap_route_cmd,
       "show bgp ipv6 encap X:X::X:X",
       SHOW_STR
       BGP_STR
       IP6_STR
       "Display ENCAP NLRI specific information\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_ENCAP, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv4_safi_rd_route,
       show_bgp_ipv4_safi_rd_route_cmd,
       "show bgp ipv4 (encap|vpn) rd ASN:nn_or_IP-address:nn A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  int ret;
  struct prefix_rd prd;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  ret = str2prefix_rd (argv[1], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[2], AFI_IP, safi, &prd, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv6_safi_rd_route,
       show_bgp_ipv6_safi_rd_route_cmd,
       "show bgp ipv6 (encap|vpn) rd ASN:nn_or_IP-address:nn X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  int ret;
  struct prefix_rd prd;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  ret = str2prefix_rd (argv[1], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[2], AFI_IP6, SAFI_ENCAP, &prd, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv4_prefix,
       show_bgp_ipv4_prefix_cmd,
       "show bgp ipv4 A.B.C.D/M",
       SHOW_STR
       BGP_STR
       IP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv4_safi_prefix,
       show_bgp_ipv4_safi_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 1, BGP_PATH_ALL);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv4_vpn_prefix,
       show_bgp_ipv4_vpn_prefix_cmd,
       "show bgp ipv4 vpn A.B.C.D/M",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display VPN NLRI specific information\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_MPLS_VPN, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv6_vpn_prefix,
       show_bgp_ipv6_vpn_prefix_cmd,
       "show bgp ipv6 vpn X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Display VPN NLRI specific information\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MPLS_VPN, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv4_encap_prefix,
       show_bgp_ipv4_encap_prefix_cmd,
       "show bgp ipv4 encap A.B.C.D/M",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display ENCAP NLRI specific information\n"
       "Display information about ENCAP NLRIs\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_ENCAP, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv6_encap_prefix,
       show_bgp_ipv6_encap_prefix_cmd,
       "show bgp ipv6 encap X:X::X:X/M",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display ENCAP NLRI specific information\n"
       "Display information about ENCAP NLRIs\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_ENCAP, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv4_safi_rd_prefix,
       show_bgp_ipv4_safi_rd_prefix_cmd,
       "show bgp ipv4 (encap|vpn) rd ASN:nn_or_IP-address:nn A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int ret;
  struct prefix_rd prd;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  ret = str2prefix_rd (argv[1], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[2], AFI_IP, safi, &prd, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv6_safi_rd_prefix,
       show_bgp_ipv6_safi_rd_prefix_cmd,
       "show bgp ipv6 (encap|vpn) rd ASN:nn_or_IP-address:nn X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int ret;
  struct prefix_rd prd;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  ret = str2prefix_rd (argv[1], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[2], AFI_IP6, safi, &prd, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_afi_safi_view,
       show_bgp_afi_safi_view_cmd,
       "show bgp view WORD (ipv4|ipv6) (encap|mulicast|unicast|vpn)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address Family\n"
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       )
{
  struct bgp *bgp;
  safi_t	safi;
  afi_t		afi;

  if (bgp_parse_afi(argv[1], &afi)) {
    vty_out (vty, "Error: Bad AFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (bgp_parse_safi(argv[2], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}

  return bgp_show (vty, bgp, afi, safi, bgp_show_type_normal, NULL);
}

DEFUN (show_bgp_view_afi_safi_route,
       show_bgp_view_afi_safi_route_cmd,
       "show bgp view WORD (ipv4|ipv6) (encap|multicast|unicast|vpn) A.B.C.D",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address Family\n"
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Network in the BGP routing table to display\n")
{
  safi_t	safi;
  afi_t		afi;

  if (bgp_parse_afi(argv[1], &afi)) {
    vty_out (vty, "Error: Bad AFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (bgp_parse_safi(argv[2], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_route (vty, argv[0], argv[3], afi, safi, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_view_afi_safi_prefix,
       show_bgp_view_afi_safi_prefix_cmd,
       "show bgp view WORD (ipv4|ipv6) (encap|multicast|unicast|vpn) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address Family\n"
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  safi_t	safi;
  afi_t		afi;

  if (bgp_parse_afi(argv[1], &afi)) {
    vty_out (vty, "Error: Bad AFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (bgp_parse_safi(argv[2], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_route (vty, argv[0], argv[3], afi, safi, NULL, 1, BGP_PATH_ALL);
}

/* new001 */
DEFUN (show_bgp_afi,
       show_bgp_afi_cmd,
       "show bgp (ipv4|ipv6)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n")
{
  afi_t	afi;

  if (bgp_parse_afi(argv[0], &afi)) {
    vty_out (vty, "Error: Bad AFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show (vty, NULL, afi, SAFI_UNICAST, bgp_show_type_normal,
                   NULL);
}

DEFUN (show_bgp_ipv6_safi,
       show_bgp_ipv6_safi_cmd,
       "show bgp ipv6 (unicast|multicast)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST, bgp_show_type_normal,
                     NULL);

  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

DEFUN (show_bgp_ipv6_route,
       show_bgp_ipv6_route_cmd,
       "show bgp ipv6 X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_ipv6_safi_route,
       show_bgp_ipv6_safi_route_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 0, BGP_PATH_ALL);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

/* old command */
DEFUN (show_ipv6_bgp_route,
       show_ipv6_bgp_route_cmd,
       "show ipv6 bgp X:X::X:X",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_ipv6_bgp_vpnv6_all_route,
       show_ipv6_bgp_vpnv6_all_route_cmd,
       "show ipv6 bgp vpnv6 all X:X::X:X",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv6 NLRI specific information\n"
       "Display information about all VPNv6 NLRIs\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MPLS_VPN, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_ipv6_bgp_vpnv6_rd_route,
       show_ipv6_bgp_vpnv6_rd_route_cmd,
       "show ipv6 bgp vpnv6 rd ASN:nn_or_IP-address:nn X:X::X:X",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv6 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MPLS_VPN, &prd, 0, BGP_PATH_ALL);
}

DEFUN (show_ipv6_bgp_vpnv6_all_prefix,
       show_ipv6_bgp_vpnv6_all_prefix_cmd,
       "show ipv6 bgp vpnv6 all X:X::X:X/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv6 NLRI specific information\n"
       "Display information about all VPNv6 NLRIs\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MPLS_VPN, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_ipv6_bgp_vpnv6_rd_prefix,
       show_ipv6_bgp_vpnv6_rd_prefix_cmd,
       "show ipv6 bgp vpnv6 rd ASN:nn_or_IP-address:nn X:X::X:X/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv6 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MPLS_VPN, &prd, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_prefix,
       show_bgp_prefix_cmd,
       "show bgp X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}


/* new002 */
DEFUN (show_bgp_ipv6_prefix,
       show_bgp_ipv6_prefix_cmd,
       "show bgp ipv6 X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}
DEFUN (show_bgp_ipv6_safi_prefix,
       show_bgp_ipv6_safi_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 1, BGP_PATH_ALL);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

/* old command */
DEFUN (show_ipv6_bgp_prefix,
       show_ipv6_bgp_prefix_cmd,
       "show ipv6 bgp X:X::X:X/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_view,
       show_bgp_view_cmd,
       "show bgp view WORD",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n")
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
  
  return bgp_show (vty, bgp, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

DEFUN (show_bgp_view_ipv6,
       show_bgp_view_ipv6_cmd,
       "show bgp view WORD ipv6",
       SHOW_STR
       BGP_STR             
       "BGP view\n"
       "View name\n"
       "Address family\n")
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
  
  return bgp_show (vty, bgp, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal, NULL);
}
  
DEFUN (show_bgp_view_route,
       show_bgp_view_route_cmd,
       "show bgp view WORD X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_view_ipv6_route,
       show_bgp_view_ipv6_route_cmd,
       "show bgp view WORD ipv6 X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

/* old command */
DEFUN (show_ipv6_mbgp,
       show_ipv6_mbgp_cmd,
       "show ipv6 mbgp",
       SHOW_STR
       IP_STR
       MBGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST, bgp_show_type_normal,
                   NULL);
}

/* old command */
DEFUN (show_ipv6_mbgp_route,
       show_ipv6_mbgp_route_cmd,
       "show ipv6 mbgp X:X::X:X",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Network in the MBGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MULTICAST, NULL, 0, BGP_PATH_ALL);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix,
       show_ipv6_mbgp_prefix_cmd,
       "show ipv6 mbgp X:X::X:X/M",
       SHOW_STR
       IP_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MULTICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_view_prefix,
       show_bgp_view_prefix_cmd,
       "show bgp view WORD X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"       
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_view_ipv6_prefix,
       show_bgp_view_ipv6_prefix_cmd,
       "show bgp view WORD ipv6 X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "IPv6 prefix <network>/<length>\n")  
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

static int
bgp_show_regexp (struct vty *vty, int argc, const char **argv, afi_t afi,
		 safi_t safi, enum bgp_show_type type)
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;
  regex_t *regex;
  int rc;
  
  first = 0;
  b = buffer_new (1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	{
	  if ((strcmp (argv[i], "unicast") == 0) || (strcmp (argv[i], "multicast") == 0))
	    continue;
	  first = 1;
	}

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  regex = bgp_regcomp (regstr);
  XFREE(MTYPE_TMP, regstr);
  if (! regex)
    {
      vty_out (vty, "Can't compile regexp %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  rc = bgp_show (vty, NULL, afi, safi, type, regex);
  bgp_regex_free (regex);
  return rc;
}


DEFUN (show_ip_bgp_regexp, 
       show_ip_bgp_regexp_cmd,
       "show ip bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

DEFUN (show_ip_bgp_flap_regexp, 
       show_ip_bgp_flap_regexp_cmd,
       "show ip bgp flap-statistics regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
			  bgp_show_type_flap_regexp);
}

ALIAS (show_ip_bgp_flap_regexp,
       show_ip_bgp_damp_flap_regexp_cmd,
       "show ip bgp dampening flap-statistics regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

DEFUN (show_ip_bgp_ipv4_regexp, 
       show_ip_bgp_ipv4_regexp_cmd,
       "show ip bgp ipv4 (unicast|multicast) regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_MULTICAST,
			    bgp_show_type_regexp);

  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

DEFUN (show_bgp_regexp, 
       show_bgp_regexp_cmd,
       "show bgp regexp .LINE",
       SHOW_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

/* old command */
DEFUN (show_ipv6_bgp_regexp, 
       show_ipv6_bgp_regexp_cmd,
       "show ipv6 bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

/* old command */
DEFUN (show_ipv6_mbgp_regexp, 
       show_ipv6_mbgp_regexp_cmd,
       "show ipv6 mbgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the MBGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_MULTICAST,
			  bgp_show_type_regexp);
}

DEFUN (show_bgp_ipv4_safi_flap_regexp,
       show_bgp_ipv4_safi_flap_regexp_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics regexp .LINE",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }
    return bgp_show_regexp (vty, argc-1, argv+1, AFI_IP, safi,
	bgp_show_type_flap_regexp);
}

ALIAS (show_bgp_ipv4_safi_flap_regexp,
       show_bgp_ipv4_safi_damp_flap_regexp_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics regexp .LINE",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

DEFUN (show_bgp_ipv6_safi_flap_regexp,
       show_bgp_ipv6_safi_flap_regexp_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) flap-statistics regexp .LINE",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }
    return bgp_show_regexp (vty, argc-1, argv+1, AFI_IP6, safi,
	bgp_show_type_flap_regexp);
}

ALIAS (show_bgp_ipv6_safi_flap_regexp,
       show_bgp_ipv6_safi_damp_flap_regexp_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening flap-statistics regexp .LINE",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

DEFUN (show_bgp_ipv4_safi_regexp, 
       show_bgp_ipv4_safi_regexp_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) regexp .LINE",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show_regexp (vty, argc-1, argv+1, AFI_IP, safi,
			  bgp_show_type_regexp);
}

DEFUN (show_bgp_ipv6_safi_regexp, 
       show_bgp_ipv6_safi_regexp_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) regexp .LINE",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show_regexp (vty, argc-1, argv+1, AFI_IP6, safi,
			  bgp_show_type_regexp);
}

DEFUN (show_bgp_ipv6_regexp, 
       show_bgp_ipv6_regexp_cmd,
       "show bgp ipv6 regexp .LINE",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

static int
bgp_show_prefix_list (struct vty *vty, const char *prefix_list_str, afi_t afi,
		      safi_t safi, enum bgp_show_type type)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (afi, prefix_list_str);
  if (plist == NULL)
    {
      vty_out (vty, "%% %s is not a valid prefix-list name%s",
               prefix_list_str, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, plist);
}
DEFUN (show_ip_bgp_prefix_list, 
       show_ip_bgp_prefix_list_cmd,
       "show ip bgp prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

DEFUN (show_ip_bgp_flap_prefix_list, 
       show_ip_bgp_flap_prefix_list_cmd,
       "show ip bgp flap-statistics prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_flap_prefix_list);
}

ALIAS (show_ip_bgp_flap_prefix_list,
       show_ip_bgp_damp_flap_prefix_list_cmd,
       "show ip bgp dampening flap-statistics prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")

DEFUN (show_ip_bgp_ipv4_prefix_list, 
       show_ip_bgp_ipv4_prefix_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_prefix_list (vty, argv[1], AFI_IP, SAFI_MULTICAST,
			         bgp_show_type_prefix_list);

  return bgp_show_prefix_list (vty, argv[1], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

DEFUN (show_bgp_prefix_list, 
       show_bgp_prefix_list_cmd,
       "show bgp prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Display routes conforming to the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

ALIAS (show_bgp_prefix_list, 
       show_bgp_ipv6_prefix_list_cmd,
       "show bgp ipv6 prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes conforming to the prefix-list\n"
       "IPv6 prefix-list name\n")

/* old command */
DEFUN (show_ipv6_bgp_prefix_list, 
       show_ipv6_bgp_prefix_list_cmd,
       "show ipv6 bgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix_list, 
       show_ipv6_mbgp_prefix_list_cmd,
       "show ipv6 mbgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
			       bgp_show_type_prefix_list);
}

DEFUN (show_bgp_ipv4_prefix_list, 
       show_bgp_ipv4_prefix_list_cmd,
       "show bgp ipv4 prefix-list WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

DEFUN (show_bgp_ipv4_safi_flap_prefix_list, 
       show_bgp_ipv4_safi_flap_prefix_list_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics prefix-list WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_list (vty, argv[1], AFI_IP, safi,
			       bgp_show_type_flap_prefix_list);
}

ALIAS (show_bgp_ipv4_safi_flap_prefix_list, 
       show_bgp_ipv4_safi_damp_flap_prefix_list_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics prefix-list WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")

DEFUN (show_bgp_ipv6_safi_flap_prefix_list, 
       show_bgp_ipv6_safi_flap_prefix_list_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) flap-statistics prefix-list WORD",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_list (vty, argv[1], AFI_IP6, safi,
			       bgp_show_type_flap_prefix_list);
}
ALIAS (show_bgp_ipv6_safi_flap_prefix_list, 
       show_bgp_ipv6_safi_damp_flap_prefix_list_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening flap-statistics prefix-list WORD",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")

DEFUN (show_bgp_ipv4_safi_prefix_list, 
       show_bgp_ipv4_safi_prefix_list_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_list (vty, argv[1], AFI_IP, safi,
			       bgp_show_type_prefix_list);
}

DEFUN (show_bgp_ipv6_safi_prefix_list, 
       show_bgp_ipv6_safi_prefix_list_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_list (vty, argv[1], AFI_IP6, safi,
			       bgp_show_type_prefix_list);
}

static int
bgp_show_filter_list (struct vty *vty, const char *filter, afi_t afi,
		      safi_t safi, enum bgp_show_type type)
{
  struct as_list *as_list;

  as_list = as_list_lookup (filter);
  if (as_list == NULL)
    {
      vty_out (vty, "%% %s is not a valid AS-path access-list name%s", filter, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, as_list);
}

DEFUN (show_ip_bgp_filter_list, 
       show_ip_bgp_filter_list_cmd,
       "show ip bgp filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

DEFUN (show_ip_bgp_flap_filter_list, 
       show_ip_bgp_flap_filter_list_cmd,
       "show ip bgp flap-statistics filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_flap_filter_list);
}

ALIAS (show_ip_bgp_flap_filter_list, 
       show_ip_bgp_damp_flap_filter_list_cmd,
       "show ip bgp dampening flap-statistics filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

DEFUN (show_ip_bgp_ipv4_filter_list, 
       show_ip_bgp_ipv4_filter_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_filter_list (vty, argv[1], AFI_IP, SAFI_MULTICAST,
			         bgp_show_type_filter_list);
  
  return bgp_show_filter_list (vty, argv[1], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

DEFUN (show_bgp_filter_list, 
       show_bgp_filter_list_cmd,
       "show bgp filter-list WORD",
       SHOW_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

/* old command */
DEFUN (show_ipv6_bgp_filter_list, 
       show_ipv6_bgp_filter_list_cmd,
       "show ipv6 bgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

/* old command */
DEFUN (show_ipv6_mbgp_filter_list, 
       show_ipv6_mbgp_filter_list_cmd,
       "show ipv6 mbgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
			       bgp_show_type_filter_list);
}

DEFUN (show_ip_bgp_dampening_info,
       show_ip_bgp_dampening_params_cmd,
       "show ip bgp dampening parameters",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display detail of configured dampening parameters\n")
{
    return bgp_show_dampening_parameters (vty, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_bgp_ipv4_filter_list, 
       show_bgp_ipv4_filter_list_cmd,
       "show bgp ipv4 filter-list WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

DEFUN (show_bgp_ipv4_safi_flap_filter_list, 
       show_bgp_ipv4_safi_flap_filter_list_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics filter-list WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_filter_list (vty, argv[1], AFI_IP, safi,
			       bgp_show_type_flap_filter_list);
}

ALIAS (show_bgp_ipv4_safi_flap_filter_list, 
       show_bgp_ipv4_safi_damp_flap_filter_list_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics filter-list WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

DEFUN (show_bgp_ipv6_safi_flap_filter_list, 
       show_bgp_ipv6_safi_flap_filter_list_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) flap-statistics filter-list WORD",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_filter_list (vty, argv[1], AFI_IP6, safi,
			       bgp_show_type_flap_filter_list);
}
ALIAS (show_bgp_ipv6_safi_flap_filter_list, 
       show_bgp_ipv6_safi_damp_flap_filter_list_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening flap-statistics filter-list WORD",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

DEFUN (show_bgp_ipv4_safi_filter_list, 
       show_bgp_ipv4_safi_filter_list_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) filter-list WORD",
       SHOW_STR
       BGP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_filter_list (vty, argv[1], AFI_IP, safi,
			         bgp_show_type_filter_list);
}

DEFUN (show_bgp_ipv6_safi_filter_list, 
       show_bgp_ipv6_safi_filter_list_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) filter-list WORD",
       SHOW_STR
       BGP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_filter_list (vty, argv[1], AFI_IP6, safi,
			         bgp_show_type_filter_list);
}

DEFUN (show_bgp_ipv6_filter_list, 
       show_bgp_ipv6_filter_list_cmd,
       "show bgp ipv6 filter-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}


DEFUN (show_ip_bgp_ipv4_dampening_parameters, 
       show_ip_bgp_ipv4_dampening_parameters_cmd,
       "show ip bgp ipv4 (unicast|multicast) dampening parameters",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display detail of configured dampening parameters\n")
{
    if (strncmp(argv[0], "m", 1) == 0)
      return bgp_show_dampening_parameters (vty, AFI_IP, SAFI_MULTICAST);

    return bgp_show_dampening_parameters (vty, AFI_IP, SAFI_UNICAST);
}


DEFUN (show_ip_bgp_ipv4_dampening_flap_stats,
       show_ip_bgp_ipv4_dampening_flap_stats_cmd,
       "show ip bgp ipv4 (unicast|multicast) dampening flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n")
{
    if (strncmp(argv[0], "m", 1) == 0)      
      return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
                     bgp_show_type_flap_statistics, NULL);

    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
                 bgp_show_type_flap_statistics, NULL);
}

DEFUN (show_ip_bgp_ipv4_dampening_dampd_paths, 
       show_ip_bgp_ipv4_dampening_dampd_paths_cmd,
       "show ip bgp ipv4 (unicast|multicast) dampening dampened-paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display paths suppressed due to dampening\n")
{
    if (strncmp(argv[0], "m", 1) == 0)      
      return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
                     bgp_show_type_dampend_paths, NULL);

    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
                 bgp_show_type_dampend_paths, NULL);
}

static int
bgp_show_route_map (struct vty *vty, const char *rmap_str, afi_t afi,
		    safi_t safi, enum bgp_show_type type)
{
  struct route_map *rmap;

  rmap = route_map_lookup_by_name (rmap_str);
  if (! rmap)
    {
      vty_out (vty, "%% %s is not a valid route-map name%s",
	       rmap_str, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, rmap);
}

DEFUN (show_ip_bgp_route_map, 
       show_ip_bgp_route_map_cmd,
       "show ip bgp route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP, SAFI_UNICAST,
			     bgp_show_type_route_map);
}

DEFUN (show_ip_bgp_flap_route_map, 
       show_ip_bgp_flap_route_map_cmd,
       "show ip bgp flap-statistics route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP, SAFI_UNICAST,
			     bgp_show_type_flap_route_map);
}

ALIAS (show_ip_bgp_flap_route_map, 
       show_ip_bgp_damp_flap_route_map_cmd,
       "show ip bgp dampening flap-statistics route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")

DEFUN (show_ip_bgp_ipv4_route_map, 
       show_ip_bgp_ipv4_route_map_cmd,
       "show ip bgp ipv4 (unicast|multicast) route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route_map (vty, argv[1], AFI_IP, SAFI_MULTICAST,
			       bgp_show_type_route_map);

  return bgp_show_route_map (vty, argv[1], AFI_IP, SAFI_UNICAST,
			     bgp_show_type_route_map);
}

DEFUN (show_bgp_route_map, 
       show_bgp_route_map_cmd,
       "show bgp route-map WORD",
       SHOW_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			     bgp_show_type_route_map);
}

DEFUN (show_ip_bgp_cidr_only,
       show_ip_bgp_cidr_only_cmd,
       "show ip bgp cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display only routes with non-natural netmasks\n")
{
    return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		     bgp_show_type_cidr_only, NULL);
}

DEFUN (show_ip_bgp_flap_cidr_only,
       show_ip_bgp_flap_cidr_only_cmd,
       "show ip bgp flap-statistics cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display only routes with non-natural netmasks\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		   bgp_show_type_flap_cidr_only, NULL);
}

ALIAS (show_ip_bgp_flap_cidr_only,
       show_ip_bgp_damp_flap_cidr_only_cmd,
       "show ip bgp dampening flap-statistics cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display only routes with non-natural netmasks\n")

DEFUN (show_ip_bgp_ipv4_cidr_only,
       show_ip_bgp_ipv4_cidr_only_cmd,
       "show ip bgp ipv4 (unicast|multicast) cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display only routes with non-natural netmasks\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
		     bgp_show_type_cidr_only, NULL);

  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		     bgp_show_type_cidr_only, NULL);
}

DEFUN (show_ip_bgp_community_all,
       show_ip_bgp_community_all_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		     bgp_show_type_community_all, NULL);
}

DEFUN (show_ip_bgp_ipv4_community_all,
       show_ip_bgp_ipv4_community_all_cmd,
       "show ip bgp ipv4 (unicast|multicast) community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
		     bgp_show_type_community_all, NULL);
 
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		   bgp_show_type_community_all, NULL);
}

DEFUN (show_bgp_community_all,
       show_bgp_community_all_cmd,
       "show bgp community",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST,
		   bgp_show_type_community_all, NULL);
}

ALIAS (show_bgp_community_all,
       show_bgp_ipv6_community_all_cmd,
       "show bgp ipv6 community",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n")

/* old command */
DEFUN (show_ipv6_bgp_community_all,
       show_ipv6_bgp_community_all_cmd,
       "show ipv6 bgp community",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST,
		   bgp_show_type_community_all, NULL);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_all,
       show_ipv6_mbgp_community_all_cmd,
       "show ipv6 mbgp community",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST,
		   bgp_show_type_community_all, NULL);
}

DEFUN (show_bgp_ipv4_route_map, 
       show_bgp_ipv4_route_map_cmd,
       "show bgp ipv4 route-map WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP, SAFI_UNICAST,
			     bgp_show_type_route_map);
}

DEFUN (show_bgp_ipv4_safi_flap_route_map, 
       show_bgp_ipv4_safi_flap_route_map_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics route-map WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_route_map (vty, argv[1], AFI_IP, safi,
			     bgp_show_type_flap_route_map);
}

ALIAS (show_bgp_ipv4_safi_flap_route_map, 
       show_bgp_ipv4_safi_damp_flap_route_map_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics route-map WORD",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")

DEFUN (show_bgp_ipv6_safi_flap_route_map, 
       show_bgp_ipv6_safi_flap_route_map_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) flap-statistics route-map WORD",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_route_map (vty, argv[1], AFI_IP6, safi,
			     bgp_show_type_flap_route_map);
}
ALIAS (show_bgp_ipv6_safi_flap_route_map, 
       show_bgp_ipv6_safi_damp_flap_route_map_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening flap-statistics route-map WORD",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")

DEFUN (show_bgp_ipv4_safi_route_map, 
       show_bgp_ipv4_safi_route_map_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) route-map WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_route_map (vty, argv[1], AFI_IP, safi,
			     bgp_show_type_route_map);
}

DEFUN (show_bgp_ipv6_safi_route_map, 
       show_bgp_ipv6_safi_route_map_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) route-map WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  safi_t	safi;
  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_route_map (vty, argv[1], AFI_IP6, safi,
			     bgp_show_type_route_map);
}

DEFUN (show_bgp_ipv6_route_map, 
       show_bgp_ipv6_route_map_cmd,
       "show bgp ipv6 route-map WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			     bgp_show_type_route_map);
}

DEFUN (show_bgp_ipv4_cidr_only,
       show_bgp_ipv4_cidr_only_cmd,
       "show bgp ipv4 cidr-only",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display only routes with non-natural netmasks\n")
{
    return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		     bgp_show_type_cidr_only, NULL);
}

DEFUN (show_bgp_ipv4_safi_flap_cidr_only,
       show_bgp_ipv4_safi_flap_cidr_only_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics cidr-only",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display flap statistics of routes\n"
       "Display only routes with non-natural netmasks\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show (vty, NULL, AFI_IP, safi, bgp_show_type_flap_cidr_only, NULL);
}

ALIAS (show_bgp_ipv4_safi_flap_cidr_only,
       show_bgp_ipv4_safi_damp_flap_cidr_only_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics cidr-only",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display only routes with non-natural netmasks\n")

DEFUN (show_bgp_ipv4_safi_cidr_only,
       show_bgp_ipv4_safi_cidr_only_cmd,
       "show bgp ipv4 (unicast|multicast) cidr-only",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display only routes with non-natural netmasks\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
		     bgp_show_type_cidr_only, NULL);

  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		     bgp_show_type_cidr_only, NULL);
}

/* new046 */
DEFUN (show_bgp_afi_safi_community_all,
       show_bgp_afi_safi_community_all_cmd,
       "show bgp (ipv4|ipv6) (encap|multicast|unicast|vpn) community",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")
{
  safi_t	safi;
  afi_t		afi;

  if (bgp_parse_afi(argv[0], &afi)) {
    vty_out (vty, "Error: Bad AFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (bgp_parse_safi(argv[1], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show (vty, NULL, afi, safi, bgp_show_type_community_all, NULL);
}
DEFUN (show_bgp_afi_community_all,
       show_bgp_afi_community_all_cmd,
       "show bgp (ipv4|ipv6) community",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Display routes matching the communities\n")
{
  afi_t		afi;
  safi_t	safi = SAFI_UNICAST;

  if (bgp_parse_afi(argv[0], &afi)) {
    vty_out (vty, "Error: Bad AFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show (vty, NULL, afi, safi, bgp_show_type_community_all, NULL);
}

static int
bgp_show_community (struct vty *vty, const char *view_name, int argc,
		    const char **argv, int exact, afi_t afi, safi_t safi)
{
  struct community *com;
  struct buffer *b;
  struct bgp *bgp;
  int i;
  char *str;
  int first = 0;

  /* BGP structure lookup */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  b = buffer_new (1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
        buffer_putc (b, ' ');
      else
	{
	  if ((strcmp (argv[i], "unicast") == 0) || (strcmp (argv[i], "multicast") == 0))
	    continue;
	  first = 1;
	}
      
      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  com = community_str2com (str);
  XFREE (MTYPE_TMP, str);
  if (! com)
    {
      vty_out (vty, "%% Community malformed: %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, bgp, afi, safi,
                   (exact ? bgp_show_type_community_exact :
		            bgp_show_type_community), com);
}

DEFUN (show_ip_bgp_community,
       show_ip_bgp_community_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community2_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_community,
       show_ip_bgp_community3_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_community,
       show_ip_bgp_community4_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community2_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community3_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community4_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_ip_bgp_community_exact,
       show_ip_bgp_community_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community2_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community3_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community4_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community2_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community3_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
       
ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community4_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_bgp_community,
       show_bgp_community_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community,
       show_bgp_ipv6_community_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community2_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community2_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community3_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community3_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community4_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community4_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
DEFUN (show_ipv6_bgp_community,
       show_ipv6_bgp_community_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_UNICAST);
}

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community2_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community3_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community4_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_bgp_community_exact,
       show_bgp_community_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community2_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community2_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community3_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community3_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community4_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community4_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
DEFUN (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_UNICAST);
}

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community2_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community3_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community4_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
 
/* old command */
DEFUN (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_MULTICAST);
}

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community2_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community3_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community4_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
DEFUN (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_MULTICAST);
}

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community2_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community3_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community4_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_bgp_ipv4_community,
       show_bgp_ipv4_community_cmd,
       "show bgp ipv4 community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_bgp_ipv4_community,
       show_bgp_ipv4_community2_cmd,
       "show bgp ipv4 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_bgp_ipv4_community,
       show_bgp_ipv4_community3_cmd,
       "show bgp ipv4 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_bgp_ipv4_community,
       show_bgp_ipv4_community4_cmd,
       "show bgp ipv4 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_bgp_ipv4_safi_community,
       show_bgp_ipv4_safi_community_cmd,
       "show bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_bgp_ipv4_safi_community,
       show_bgp_ipv4_safi_community2_cmd,
       "show bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_bgp_ipv4_safi_community,
       show_bgp_ipv4_safi_community3_cmd,
       "show bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_bgp_ipv4_safi_community,
       show_bgp_ipv4_safi_community4_cmd,
       "show bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_bgp_view_afi_safi_community_all,
       show_bgp_view_afi_safi_community_all_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")
{
  int afi;
  int safi;
  struct bgp *bgp;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
    {
      vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  return bgp_show (vty, bgp, afi, safi, bgp_show_type_community_all, NULL);
}

DEFUN (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  int afi;
  int safi;

  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  return bgp_show_community (vty, argv[0], argc-3, &argv[3], 0, afi, safi);
}

ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community2_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community3_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community4_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_bgp_ipv4_community_exact,
       show_bgp_ipv4_community_exact_cmd,
       "show bgp ipv4 community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_bgp_ipv4_community_exact,
       show_bgp_ipv4_community2_exact_cmd,
       "show bgp ipv4 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_ipv4_community_exact,
       show_bgp_ipv4_community3_exact_cmd,
       "show bgp ipv4 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_ipv4_community_exact,
       show_bgp_ipv4_community4_exact_cmd,
       "show bgp ipv4 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_bgp_ipv4_safi_community4_exact,
       show_bgp_ipv4_safi_community_exact_cmd,
       "show bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_bgp_ipv4_safi_community4_exact,
       show_bgp_ipv4_safi_community2_exact_cmd,
       "show bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_ipv4_safi_community4_exact,
       show_bgp_ipv4_safi_community3_exact_cmd,
       "show bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
       
ALIAS (show_bgp_ipv4_safi_community4_exact,
       show_bgp_ipv4_safi_community4_exact_cmd,
       "show bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_bgp_ipv6_safi_community,
       show_bgp_ipv6_safi_community_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_community (vty, NULL, argc-1, argv+1, 0, AFI_IP6, safi);
}

ALIAS (show_bgp_ipv6_safi_community,
       show_bgp_ipv6_safi_community2_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_bgp_ipv6_safi_community,
       show_bgp_ipv6_safi_community3_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_ipv6_safi_community,
       show_bgp_ipv6_safi_community4_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")


DEFUN (show_bgp_ipv6_safi_community_exact,
       show_bgp_ipv6_safi_community_exact_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_community (vty, NULL, argc-1, argv+1, 1, AFI_IP6, safi);
}


ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_safi_community2_exact_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_safi_community3_exact_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_safi_community4_exact_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

static int
bgp_show_community_list (struct vty *vty, const char *com, int exact,
			 afi_t afi, safi_t safi)
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, com, COMMUNITY_LIST_MASTER);
  if (list == NULL)
    {
      vty_out (vty, "%% %s is not a valid community-list name%s", com,
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi,
                   (exact ? bgp_show_type_community_list_exact :
		            bgp_show_type_community_list), list);
}

DEFUN (show_ip_bgp_community_list,
       show_ip_bgp_community_list_cmd,
       "show ip bgp community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_community_list,
       show_ip_bgp_ipv4_community_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_MULTICAST);
  
  return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_community_list_exact,
       show_ip_bgp_community_list_exact_cmd,
       "show ip bgp community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_community_list_exact,
       show_ip_bgp_ipv4_community_list_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_bgp_community_list,
       show_bgp_community_list_cmd,
       "show bgp community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community_list,
       show_bgp_ipv6_community_list_cmd,
       "show bgp ipv6 community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")

/* old command */
DEFUN (show_ipv6_bgp_community_list,
       show_ipv6_bgp_community_list_cmd,
       "show ipv6 bgp community-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_UNICAST);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_list,
       show_ipv6_mbgp_community_list_cmd,
       "show ipv6 mbgp community-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_MULTICAST);
}

DEFUN (show_bgp_community_list_exact,
       show_bgp_community_list_exact_cmd,
       "show bgp community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community_list_exact,
       show_bgp_ipv6_community_list_exact_cmd,
       "show bgp ipv6 community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")

/* old command */
DEFUN (show_ipv6_bgp_community_list_exact,
       show_ipv6_bgp_community_list_exact_cmd,
       "show ipv6 bgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_UNICAST);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_list_exact,
       show_ipv6_mbgp_community_list_exact_cmd,
       "show ipv6 mbgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_MULTICAST);
}

DEFUN (show_bgp_ipv4_community_list,
       show_bgp_ipv4_community_list_cmd,
       "show bgp ipv4 community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_bgp_ipv4_safi_community_list,
       show_bgp_ipv4_safi_community_list_cmd,
       "show bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_MULTICAST);
  
  return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_bgp_ipv4_community_list_exact,
       show_bgp_ipv4_community_list_exact_cmd,
       "show bgp ipv4 community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       IP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_bgp_ipv4_safi_community_list_exact,
       show_bgp_ipv4_safi_community_list_exact_cmd,
       "show bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_bgp_ipv6_safi_community_list,
       show_bgp_ipv6_safi_community_list_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_community_list (vty, argv[1], 0, AFI_IP6, safi);
}

DEFUN (show_bgp_ipv6_safi_community_list_exact,
       show_bgp_ipv6_safi_community_list_exact_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_community_list (vty, argv[1], 1, AFI_IP6, safi);
}

static int
bgp_show_prefix_longer (struct vty *vty, const char *prefix, afi_t afi,
			safi_t safi, enum bgp_show_type type)
{
  int ret;
  struct prefix *p;

  p = prefix_new();

  ret = str2prefix (prefix, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = bgp_show (vty, NULL, afi, safi, type, p);
  prefix_free(p);
  return ret;
}

DEFUN (show_ip_bgp_prefix_longer,
       show_ip_bgp_prefix_longer_cmd,
       "show ip bgp A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

DEFUN (show_ip_bgp_flap_prefix_longer,
       show_ip_bgp_flap_prefix_longer_cmd,
       "show ip bgp flap-statistics A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_flap_prefix_longer);
}

ALIAS (show_ip_bgp_flap_prefix_longer,
       show_ip_bgp_damp_flap_prefix_longer_cmd,
       "show ip bgp dampening flap-statistics A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")

DEFUN (show_ip_bgp_ipv4_prefix_longer,
       show_ip_bgp_ipv4_prefix_longer_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_prefix_longer (vty, argv[1], AFI_IP, SAFI_MULTICAST,
				   bgp_show_type_prefix_longer);

  return bgp_show_prefix_longer (vty, argv[1], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

DEFUN (show_ip_bgp_flap_address,
       show_ip_bgp_flap_address_cmd,
       "show ip bgp flap-statistics A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_flap_address);
}

ALIAS (show_ip_bgp_flap_address,
       show_ip_bgp_damp_flap_address_cmd,
       "show ip bgp dampening flap-statistics A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_ip_bgp_flap_prefix,
       show_ip_bgp_flap_prefix_cmd,
       "show ip bgp flap-statistics A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_flap_prefix);
}

ALIAS (show_ip_bgp_flap_prefix,
       show_ip_bgp_damp_flap_prefix_cmd,
       "show ip bgp dampening flap-statistics A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_bgp_prefix_longer,
       show_bgp_prefix_longer_cmd,
       "show bgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

/* old command */
DEFUN (show_ipv6_bgp_prefix_longer,
       show_ipv6_bgp_prefix_longer_cmd,
       "show ipv6 bgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix_longer,
       show_ipv6_mbgp_prefix_longer_cmd,
       "show ipv6 mbgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
				 bgp_show_type_prefix_longer);
}

DEFUN (show_bgp_ipv4_prefix_longer,
       show_bgp_ipv4_prefix_longer_cmd,
       "show bgp ipv4 A.B.C.D/M longer-prefixes",
       SHOW_STR
       BGP_STR
       IP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

DEFUN (show_bgp_ipv4_safi_flap_prefix_longer,
       show_bgp_ipv4_safi_flap_prefix_longer_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics A.B.C.D/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_longer (vty, argv[1], AFI_IP, safi,
				 bgp_show_type_flap_prefix_longer);
}

ALIAS (show_bgp_ipv4_safi_flap_prefix_longer,
       show_bgp_ipv4_safi_damp_flap_prefix_longer_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics A.B.C.D/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")

DEFUN (show_bgp_ipv6_safi_flap_prefix_longer,
       show_bgp_ipv6_safi_flap_prefix_longer_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) flap-statistics X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_longer (vty, argv[1], AFI_IP6, safi,
				 bgp_show_type_flap_prefix_longer);
}
ALIAS (show_bgp_ipv6_safi_flap_prefix_longer,
       show_bgp_ipv6_safi_damp_flap_prefix_longer_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening flap-statistics X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")

DEFUN (show_bgp_ipv4_safi_prefix_longer,
       show_bgp_ipv4_safi_prefix_longer_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) A.B.C.D/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show_prefix_longer (vty, argv[1], AFI_IP, safi,
				   bgp_show_type_prefix_longer);
}

DEFUN (show_bgp_ipv6_safi_prefix_longer,
       show_bgp_ipv6_safi_prefix_longer_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show_prefix_longer (vty, argv[1], AFI_IP6, safi,
				   bgp_show_type_prefix_longer);
}

DEFUN (show_bgp_ipv4_safi_flap_address,
       show_bgp_ipv4_safi_flap_address_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_longer (vty, argv[1], AFI_IP, safi,
				 bgp_show_type_flap_address);
}
ALIAS (show_bgp_ipv4_safi_flap_address,
       show_bgp_ipv4_safi_damp_flap_address_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_ipv6_flap_address,
       show_bgp_ipv6_flap_address_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) flap-statistics A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_longer (vty, argv[1], AFI_IP, safi,
				 bgp_show_type_flap_address);
}
ALIAS (show_bgp_ipv6_flap_address,
       show_bgp_ipv6_damp_flap_address_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening flap-statistics A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_ipv4_safi_flap_prefix,
       show_bgp_ipv4_safi_flap_prefix_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, safi,
				 bgp_show_type_flap_prefix);
}

ALIAS (show_bgp_ipv4_safi_flap_prefix,
       show_bgp_ipv4_safi_damp_flap_prefix_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_bgp_ipv6_safi_flap_prefix,
       show_bgp_ipv6_safi_flap_prefix_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) flap-statistics X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, safi,
				 bgp_show_type_flap_prefix);
}

ALIAS (show_bgp_ipv6_safi_flap_prefix,
       show_bgp_ipv6_safi_damp_flap_prefix_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening flap-statistics X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_bgp_ipv6_prefix_longer,
       show_bgp_ipv6_prefix_longer_cmd,
       "show bgp ipv6 X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

static struct peer *
peer_lookup_in_view (struct vty *vty, const char *view_name, 
                     const char *ip_str)
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;
  union sockunion su;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (! bgp)
        {
          vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
          return NULL;
        }      
    }
  else
    {
      bgp = bgp_get_default ();
      if (! bgp)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return NULL;
        }
    }

  /* Get peer sockunion. */  
  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return NULL;
    }

  /* Peer structure lookup. */
  peer = peer_lookup (bgp, &su);
  if (! peer)
    {
      vty_out (vty, "No such neighbor%s", VTY_NEWLINE);
      return NULL;
    }
  
  return peer;
}

enum bgp_stats
{
  BGP_STATS_MAXBITLEN = 0,
  BGP_STATS_RIB,
  BGP_STATS_PREFIXES,
  BGP_STATS_TOTPLEN,
  BGP_STATS_UNAGGREGATEABLE,
  BGP_STATS_MAX_AGGREGATEABLE,
  BGP_STATS_AGGREGATES,
  BGP_STATS_SPACE,
  BGP_STATS_ASPATH_COUNT,
  BGP_STATS_ASPATH_MAXHOPS,
  BGP_STATS_ASPATH_TOTHOPS,
  BGP_STATS_ASPATH_MAXSIZE,
  BGP_STATS_ASPATH_TOTSIZE,
  BGP_STATS_ASN_HIGHEST,
  BGP_STATS_MAX,
};

static const char *table_stats_strs[] =
{
  [BGP_STATS_PREFIXES]            = "Total Prefixes",
  [BGP_STATS_TOTPLEN]             = "Average prefix length",
  [BGP_STATS_RIB]                 = "Total Advertisements",
  [BGP_STATS_UNAGGREGATEABLE]     = "Unaggregateable prefixes",
  [BGP_STATS_MAX_AGGREGATEABLE]   = "Maximum aggregateable prefixes",
  [BGP_STATS_AGGREGATES]          = "BGP Aggregate advertisements",
  [BGP_STATS_SPACE]               = "Address space advertised",
  [BGP_STATS_ASPATH_COUNT]        = "Advertisements with paths",
  [BGP_STATS_ASPATH_MAXHOPS]      = "Longest AS-Path (hops)",
  [BGP_STATS_ASPATH_MAXSIZE]      = "Largest AS-Path (bytes)",
  [BGP_STATS_ASPATH_TOTHOPS]      = "Average AS-Path length (hops)",
  [BGP_STATS_ASPATH_TOTSIZE]      = "Average AS-Path size (bytes)",
  [BGP_STATS_ASN_HIGHEST]         = "Highest public ASN",
  [BGP_STATS_MAX] = NULL,
};

struct bgp_table_stats
{
  struct bgp_table *table;
  unsigned long long counts[BGP_STATS_MAX];
  safi_t safi;
};

#if 0
#define TALLY_SIGFIG 100000
static unsigned long
ravg_tally (unsigned long count, unsigned long oldavg, unsigned long newval)
{
  unsigned long newtot = (count-1) * oldavg + (newval * TALLY_SIGFIG);
  unsigned long res = (newtot * TALLY_SIGFIG) / count;
  unsigned long ret = newtot / count;
  
  if ((res % TALLY_SIGFIG) > (TALLY_SIGFIG/2))
    return ret + 1;
  else
    return ret;
}
#endif

static void
bgp_table_stats_walker_internal (struct bgp_table_stats *ts, struct bgp_table *table)
{
  struct bgp_node *rn;
  unsigned int space = 0;
  struct bgp_node *top;

  if (!(top = bgp_table_top (table)))
      return;
  switch (top->p.family)
    {
      case AF_INET:
        space = IPV4_MAX_BITLEN;
        break;
      case AF_INET6:
        space = IPV6_MAX_BITLEN;
        break;
    }
    
  ts->counts[BGP_STATS_MAXBITLEN] = space;

  for (rn = top; rn; rn = bgp_route_next (rn))
    {
      struct bgp_info *ri;
      struct bgp_node *prn = bgp_node_parent_nolock (rn);
      unsigned int rinum = 0;
      
      if (rn == top)
        continue;
      
      if (!rn->info)
        continue;
      
      ts->counts[BGP_STATS_PREFIXES]++;
      ts->counts[BGP_STATS_TOTPLEN] += rn->p.prefixlen;

#if 0
      ts->counts[BGP_STATS_AVGPLEN]
        = ravg_tally (ts->counts[BGP_STATS_PREFIXES],
                      ts->counts[BGP_STATS_AVGPLEN],
                      rn->p.prefixlen);
#endif
      
      /* check if the prefix is included by any other announcements */
      while (prn && !prn->info)
        prn = bgp_node_parent_nolock (prn);
      
      if (prn == NULL || prn == top)
        {
          ts->counts[BGP_STATS_UNAGGREGATEABLE]++;
          /* announced address space */
          if (space)
            ts->counts[BGP_STATS_SPACE] += 1 << (space - rn->p.prefixlen);
        }
      else if (prn->info)
        ts->counts[BGP_STATS_MAX_AGGREGATEABLE]++;
      
      for (ri = rn->info; ri; ri = ri->next)
        {
          rinum++;
          ts->counts[BGP_STATS_RIB]++;
          
          if (ri->attr &&
              (CHECK_FLAG (ri->attr->flag,
                           ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE))))
            ts->counts[BGP_STATS_AGGREGATES]++;
          
          /* as-path stats */
          if (ri->attr && ri->attr->aspath)
            {
              unsigned int hops = aspath_count_hops (ri->attr->aspath);
              unsigned int size = aspath_size (ri->attr->aspath);
              as_t highest = aspath_highest (ri->attr->aspath);
              
              ts->counts[BGP_STATS_ASPATH_COUNT]++;
              
              if (hops > ts->counts[BGP_STATS_ASPATH_MAXHOPS])
                ts->counts[BGP_STATS_ASPATH_MAXHOPS] = hops;
              
              if (size > ts->counts[BGP_STATS_ASPATH_MAXSIZE])
                ts->counts[BGP_STATS_ASPATH_MAXSIZE] = size;
              
              ts->counts[BGP_STATS_ASPATH_TOTHOPS] += hops;
              ts->counts[BGP_STATS_ASPATH_TOTSIZE] += size;
#if 0
              ts->counts[BGP_STATS_ASPATH_AVGHOPS] 
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGHOPS],
                              hops);
              ts->counts[BGP_STATS_ASPATH_AVGSIZE]
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGSIZE],
                              size);
#endif
              if (highest > ts->counts[BGP_STATS_ASN_HIGHEST])
                ts->counts[BGP_STATS_ASN_HIGHEST] = highest;
            }
        }
    }
  return;
}

static int
bgp_table_stats_walker (struct thread *t)
{
  struct bgp_table *top;
  struct bgp_table_stats *ts = THREAD_ARG (t);

  top = ts->table;

  if (ts->safi == SAFI_MPLS_VPN || ts->safi == SAFI_ENCAP ||
      ts->safi == SAFI_EVPN)
    {
      struct bgp_table *table;
      struct bgp_node *rn;

      for (rn = bgp_table_top (top); rn;
           rn = bgp_route_next (rn))
        {
          if ((table = rn->info) != NULL)
            {
              bgp_table_stats_walker_internal (ts, table);
            }
        }
    }
  else
    bgp_table_stats_walker_internal (ts, top);
  return 0;
}
static int
bgp_table_stats (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi)
{
  struct bgp_table_stats ts;
  unsigned int i;
  
  if (!bgp->rib[afi][safi])
    {
      vty_out (vty, "%% No RIB exists for the specified AFI(%d)/SAFI(%d) %s",
               afi, safi, VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  memset (&ts, 0, sizeof (ts));
  ts.table = bgp->rib[afi][safi];
  ts.safi = safi;
  thread_execute (bm->master, bgp_table_stats_walker, &ts, 0);

  vty_out (vty, "BGP %s RIB statistics%s%s",
           afi_safi_print (afi, safi), VTY_NEWLINE, VTY_NEWLINE);
  
  for (i = 0; i < BGP_STATS_MAX; i++)
    {
      if (!table_stats_strs[i])
        continue;
      
      switch (i)
        {
#if 0
          case BGP_STATS_ASPATH_AVGHOPS:
          case BGP_STATS_ASPATH_AVGSIZE:
          case BGP_STATS_AVGPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     (float)ts.counts[i] / (float)TALLY_SIGFIG);
            break;
#endif
          case BGP_STATS_ASPATH_TOTHOPS:
          case BGP_STATS_ASPATH_TOTSIZE:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     ts.counts[i] ?
                     (float)ts.counts[i] / 
                      (float)ts.counts[BGP_STATS_ASPATH_COUNT]
                     : 0);
            break;
          case BGP_STATS_TOTPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     ts.counts[i] ?
                     (float)ts.counts[i] / 
                      (float)ts.counts[BGP_STATS_PREFIXES]
                     : 0);
            break;
          case BGP_STATS_SPACE:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12llu%s", ts.counts[i], VTY_NEWLINE);
            if (ts.counts[BGP_STATS_MAXBITLEN] < 9)
              break;
            vty_out (vty, "%30s: ", "%% announced ");
            vty_out (vty, "%12.2f%s", 
                     100 * (float)ts.counts[BGP_STATS_SPACE] / 
                       (float)((uint64_t)1UL << ts.counts[BGP_STATS_MAXBITLEN]),
                       VTY_NEWLINE);
            vty_out (vty, "%30s: ", "/8 equivalent ");
            vty_out (vty, "%12.2f%s", 
                     (float)ts.counts[BGP_STATS_SPACE] / 
                       (float)(1UL << (ts.counts[BGP_STATS_MAXBITLEN] - 8)),
                     VTY_NEWLINE);
            if (ts.counts[BGP_STATS_MAXBITLEN] < 25)
              break;
            vty_out (vty, "%30s: ", "/24 equivalent ");
            vty_out (vty, "%12.2f", 
                     (float)ts.counts[BGP_STATS_SPACE] / 
                       (float)(1UL << (ts.counts[BGP_STATS_MAXBITLEN] - 24)));
            break;
          default:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12llu", ts.counts[i]);
        }
        
      vty_out (vty, "%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

static int
bgp_table_stats_vty (struct vty *vty, const char *name,
                     const char *afi_str, const char *safi_str)
{
  struct bgp *bgp;
  afi_t afi;
  safi_t safi;
  
 if (name)
    bgp = bgp_lookup_by_name (name);
  else
    bgp = bgp_get_default ();

  if (!bgp)
    {
      vty_out (vty, "%% No such BGP instance exists%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (strncmp (afi_str, "ipv", 3) == 0)
    {
      if (strncmp (afi_str, "ipv4", 4) == 0)
        afi = AFI_IP;
      else if (strncmp (afi_str, "ipv6", 4) == 0)
        afi = AFI_IP6;
      else
        {
          vty_out (vty, "%% Invalid address family %s%s",
                   afi_str, VTY_NEWLINE);
          return CMD_WARNING;
        }
      switch (safi_str[0]) {
	case 'm':
	    safi = SAFI_MULTICAST;
	    break;
	case 'u':
	    safi = SAFI_UNICAST;
	    break;
	case 'v':
	    safi =  SAFI_MPLS_VPN;
	    break;
	case 'e':
	    safi = SAFI_ENCAP;
	    break;
	default:
	    vty_out (vty, "%% Invalid subsequent address family %s%s",
                   safi_str, VTY_NEWLINE);
            return CMD_WARNING;
      }
    }
  else
    {
      vty_out (vty, "%% Invalid address family \"%s\"%s",
               afi_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_table_stats (vty, bgp, afi, safi);
}

DEFUN (show_bgp_statistics,
       show_bgp_statistics_cmd,
       "show bgp (ipv4|ipv6) (encap|multicast|unicast|vpn) statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  return bgp_table_stats_vty (vty, NULL, argv[0], argv[1]);
}

ALIAS (show_bgp_statistics,
       show_bgp_statistics_vpnv4_cmd,
       "show bgp (ipv4) (vpnv4) statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")

DEFUN (show_bgp_statistics_view,
       show_bgp_statistics_view_cmd,
       "show bgp view WORD (ipv4|ipv6) (encap|multicast|unicast|vpn) statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  return bgp_table_stats_vty (vty, NULL, argv[0], argv[1]);
}

ALIAS (show_bgp_statistics_view,
       show_bgp_statistics_view_vpnv4_cmd,
       "show bgp view WORD (ipv4) (vpnv4) statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "Address family\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")

enum bgp_pcounts
{
  PCOUNT_ADJ_IN = 0,
  PCOUNT_DAMPED,
  PCOUNT_REMOVED,
  PCOUNT_HISTORY,
  PCOUNT_STALE,
  PCOUNT_VALID,
  PCOUNT_ALL,
  PCOUNT_COUNTED,
  PCOUNT_PFCNT, /* the figure we display to users */
  PCOUNT_MAX,
};

static const char *pcount_strs[] =
{
  [PCOUNT_ADJ_IN]  = "Adj-in",
  [PCOUNT_DAMPED]  = "Damped",
  [PCOUNT_REMOVED] = "Removed",
  [PCOUNT_HISTORY] = "History",
  [PCOUNT_STALE]   = "Stale",
  [PCOUNT_VALID]   = "Valid",
  [PCOUNT_ALL]     = "All RIB",
  [PCOUNT_COUNTED] = "PfxCt counted",
  [PCOUNT_PFCNT]   = "Useable",
  [PCOUNT_MAX]     = NULL,
};

struct peer_pcounts
{
  unsigned int count[PCOUNT_MAX];
  const struct peer *peer;
  const struct bgp_table *table;
};

static int
bgp_peer_count_walker (struct thread *t)
{
  struct bgp_node *rn;
  struct peer_pcounts *pc = THREAD_ARG (t);
  const struct peer *peer = pc->peer;

  for (rn = bgp_table_top (pc->table); rn; rn = bgp_route_next (rn))
    {
      struct bgp_adj_in *ain;
      struct bgp_info *ri;
      
      for (ain = rn->adj_in; ain; ain = ain->next)
        if (ain->peer == peer)
          pc->count[PCOUNT_ADJ_IN]++;

      for (ri = rn->info; ri; ri = ri->next)
        {
          char buf[SU_ADDRSTRLEN];
          
          if (ri->peer != peer)
            continue;
          
          pc->count[PCOUNT_ALL]++;
          
          if (CHECK_FLAG (ri->flags, BGP_INFO_DAMPED))
            pc->count[PCOUNT_DAMPED]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
            pc->count[PCOUNT_HISTORY]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_REMOVED))
            pc->count[PCOUNT_REMOVED]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_STALE|BGP_INFO_STALE_REFRESH))
            pc->count[PCOUNT_STALE]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_VALID))
            pc->count[PCOUNT_VALID]++;
          if (!CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
            pc->count[PCOUNT_PFCNT]++;
          
          if (CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
            {
              pc->count[PCOUNT_COUNTED]++;
              if (CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
                plog_warn (peer->log,
                           "%s [pcount] %s/%d is counted but flags 0x%x",
                           peer->host,
                           inet_ntop(rn->p.family, &rn->p.u.prefix,
                                     buf, SU_ADDRSTRLEN),
                           rn->p.prefixlen,
                           ri->flags);
            }
          else
            {
              if (!CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
                plog_warn (peer->log,
                           "%s [pcount] %s/%d not counted but flags 0x%x",
                           peer->host,
                           inet_ntop(rn->p.family, &rn->p.u.prefix,
                                     buf, SU_ADDRSTRLEN),
                           rn->p.prefixlen,
                           ri->flags);
            }
        }
    }
  return 0;
}

static void
bgp_peer_counts_internal (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
                          struct peer_pcounts *pcounts)
{
  unsigned int i;

  /* in-place call via thread subsystem so as to record execution time
   * stats for the thread-walk (i.e. ensure this can't be blamed on
   * on just vty_read()).
   */
  thread_execute (bm->master, bgp_peer_count_walker, pcounts, 0);
  
  vty_out (vty, "Prefix counts for %s, %s%s", 
           peer->host, afi_safi_print (afi, safi), VTY_NEWLINE);
  vty_out (vty, "PfxCt: %ld%s", peer->pcount[afi][safi], VTY_NEWLINE);
  vty_out (vty, "%sCounts from RIB table walk:%s%s", 
           VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

  for (i = 0; i < PCOUNT_MAX; i++)
      vty_out (vty, "%20s: %-10d%s",
               pcount_strs[i], pcounts->count[i], VTY_NEWLINE);

  if (pcounts->count[PCOUNT_PFCNT] != peer->pcount[afi][safi])
    {
      vty_out (vty, "%s [pcount] PfxCt drift!%s",
               peer->host, VTY_NEWLINE);
      vty_out (vty, "Please report this bug, with the above command output%s",
              VTY_NEWLINE);
    }
               
  return;
}

static int
bgp_peer_counts (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi)
{
  struct peer_pcounts pcounts = { .peer = peer };

  if (!peer || !peer->bgp || !peer->afc[afi][safi]
      || !peer->bgp->rib[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  memset (&pcounts, 0, sizeof(pcounts));
  pcounts.peer = peer;

  if (safi == SAFI_MPLS_VPN || safi == SAFI_EVPN)
    {
      struct bgp_node *rn;
      for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn; rn = bgp_route_next (rn))
        {
          /* look for neighbor in tables */
          if ((rn->info) != NULL)
            {
              char rd_str[RD_ADDRSTRLEN];
              prefix_rd2str ((struct prefix_rd *)rn->p.u.val, rd_str, RD_ADDRSTRLEN);
              vty_out (vty, "Prefix counts for %s%s", rd_str, VTY_NEWLINE);
              pcounts.table = bgp_table_top (peer->bgp->rib[afi][safi])->info;
              bgp_peer_counts_internal (vty, peer, afi, safi, &pcounts);
            }
        }
    }
  else
    {
      pcounts.table = peer->bgp->rib[afi][safi];
      bgp_peer_counts_internal (vty, peer, afi, safi, &pcounts);
    }
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbor_prefix_counts,
       show_ip_bgp_neighbor_prefix_counts_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);  
  if (! peer) 
    return CMD_WARNING;
 
  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_bgp_ipv6_neighbor_prefix_counts,
       show_bgp_ipv6_neighbor_prefix_counts_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);  
  if (! peer) 
    return CMD_WARNING;
 
  return bgp_peer_counts (vty, peer, AFI_IP6, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_neighbor_prefix_counts,
       show_ip_bgp_ipv4_neighbor_prefix_counts_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_peer_counts (vty, peer, AFI_IP, SAFI_MULTICAST);

  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_vpnv4_neighbor_prefix_counts,
       show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd,
       "show ip bgp vpnv4 all neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
  
  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_MPLS_VPN);
}

DEFUN (show_bgp_ipv4_safi_neighbor_prefix_counts,
       show_bgp_ipv4_safi_neighbor_prefix_counts_cmd,
       "show bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  return bgp_peer_counts (vty, peer, AFI_IP, safi);
}

DEFUN (show_ipv6_bgp_vpnv6_neighbor_prefix_counts,
       show_ipv6_bgp_vpnv6_neighbor_prefix_counts_cmd,
       "show ipv6 bgp vpnv6 all neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_peer_counts (vty, peer, AFI_IP6, SAFI_MPLS_VPN);
}

DEFUN (show_bgp_ipv6_safi_neighbor_prefix_counts,
       show_bgp_ipv6_safi_neighbor_prefix_counts_cmd,
       "show bgp ipv6 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  return bgp_peer_counts (vty, peer, AFI_IP6, safi);
}

DEFUN (show_ip_bgp_encap_neighbor_prefix_counts,
       show_ip_bgp_encap_neighbor_prefix_counts_cmd,
       "show ip bgp encap all neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
  
  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_ENCAP);
}


static void
show_adj_route (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
		int in)
{
  struct bgp_table *table;
  struct bgp_adj_in *ain;
  struct bgp_adj_out *adj;
  unsigned long output_count;
  struct bgp_node *rn;
  int header1 = 1;
  struct bgp *bgp;
  int header2 = 1;

  bgp = peer->bgp;

  if (! bgp)
    return;

  table = bgp->rib[afi][safi];

  output_count = 0;
	
  if (! in && CHECK_FLAG (peer->af_sflags[afi][safi],
			  PEER_STATUS_DEFAULT_ORIGINATE))
    {
      vty_out (vty, "BGP table version is 0, local router ID is %s%s", inet_ntoa (bgp->router_id), VTY_NEWLINE);
      vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
      vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);

      vty_out (vty, "Originating default network 0.0.0.0%s%s",
	       VTY_NEWLINE, VTY_NEWLINE);
      header1 = 0;
    }

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if (in)
      {
	for (ain = rn->adj_in; ain; ain = ain->next)
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
	      if (ain->attr)
		{ 
		  route_vty_out_tmp (vty, &rn->p, ain->attr, safi);
		  output_count++;
		}
	    }
      }
    else
      {
	for (adj = rn->adj_out; adj; adj = adj->next)
	  if (adj->peer == peer)
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
	      if (adj->attr)
		{	
		  route_vty_out_tmp (vty, &rn->p, adj->attr, safi);
		  output_count++;
		}
	    }
      }
  
  if (output_count != 0)
    vty_out (vty, "%sTotal number of prefixes %ld%s",
	     VTY_NEWLINE, output_count, VTY_NEWLINE);
}

static int
peer_adj_routes (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi, int in)
{    
  if (! peer || ! peer->afc[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (in && ! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
    {
      vty_out (vty, "%% Inbound soft reconfiguration not enabled%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  show_adj_route (vty, peer, afi, safi, in);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_view_neighbor_advertised_route,
       show_ip_bgp_view_neighbor_advertised_route_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer) 
    return CMD_WARNING;
 
  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 0);
}

ALIAS (show_ip_bgp_view_neighbor_advertised_route,
       show_ip_bgp_neighbor_advertised_route_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFUN (show_ip_bgp_ipv4_neighbor_advertised_route,
       show_ip_bgp_ipv4_neighbor_advertised_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    return peer_adj_routes (vty, peer, AFI_IP, SAFI_MULTICAST, 0);

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (show_bgp_view_neighbor_advertised_route,
       show_bgp_view_neighbor_advertised_route_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;    

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (show_bgp_view_neighbor_received_routes,
       show_bgp_view_neighbor_received_routes_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 1);
}

ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_neighbor_advertised_route_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
       
ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_ipv6_neighbor_advertised_route_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

/* old command */
ALIAS (show_bgp_view_neighbor_advertised_route,
       ipv6_bgp_neighbor_advertised_route_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
  
/* old command */
DEFUN (ipv6_mbgp_neighbor_advertised_route,
       ipv6_mbgp_neighbor_advertised_route_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;  

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_MULTICAST, 0);
}

DEFUN (show_ip_bgp_view_neighbor_received_routes,
       show_ip_bgp_view_neighbor_received_routes_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 1);
}

ALIAS (show_ip_bgp_view_neighbor_received_routes,
       show_ip_bgp_neighbor_received_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_ipv6_neighbor_received_routes_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFUN (show_bgp_neighbor_received_prefix_filter,
       show_bgp_neighbor_received_prefix_filter_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
    }

  return CMD_SUCCESS;
}

/* old command */
ALIAS (show_bgp_view_neighbor_received_routes,
       ipv6_bgp_neighbor_received_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_received_routes,
       ipv6_mbgp_neighbor_received_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_MULTICAST, 1);
}

DEFUN (show_bgp_view_neighbor_received_prefix_filter,
       show_bgp_view_neighbor_received_prefix_filter_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  struct bgp *bgp;
  int count, ret;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
  {  
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
  
  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (bgp, &su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
    }

  return CMD_SUCCESS;
}


DEFUN (show_ip_bgp_ipv4_neighbor_received_routes,
       show_ip_bgp_ipv4_neighbor_received_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
  
  if (strncmp (argv[0], "m", 1) == 0)
    return peer_adj_routes (vty, peer, AFI_IP, SAFI_MULTICAST, 1);

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 1);
}

DEFUN (show_bgp_ipv4_safi_neighbor_advertised_route,
       show_bgp_ipv4_safi_neighbor_advertised_route_cmd,
       "show bgp ipv4 (multicast|unicast) neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP, safi, 0);
}

DEFUN (show_bgp_ipv6_safi_neighbor_advertised_route,
       show_bgp_ipv6_safi_neighbor_advertised_route_cmd,
       "show bgp ipv6 (multicast|unicast) neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP6, safi, 0);
}

DEFUN (show_bgp_view_ipv6_neighbor_advertised_route,
       show_bgp_view_ipv6_neighbor_advertised_route_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;    

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (show_bgp_view_ipv6_neighbor_received_routes,
       show_bgp_view_ipv6_neighbor_received_routes_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 1);
}

DEFUN (show_bgp_ipv4_safi_neighbor_received_routes,
       show_bgp_ipv4_safi_neighbor_received_routes_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
  
  return peer_adj_routes (vty, peer, AFI_IP, safi, 1);
}

DEFUN (show_bgp_ipv6_safi_neighbor_received_routes,
       show_bgp_ipv6_safi_neighbor_received_routes_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
  
  return peer_adj_routes (vty, peer, AFI_IP6, safi, 1);
}

DEFUN (show_bgp_view_afi_safi_neighbor_adv_recd_routes,
       show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) (advertised-routes|received-routes)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the advertised routes to neighbor\n"
       "Display the received routes from neighbor\n")
{
  int afi;
  int safi;
  int in;
  struct peer *peer;

  peer = peer_lookup_in_view (vty, argv[0], argv[3]);

  if (! peer)
    return CMD_WARNING;

  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  in = (strncmp (argv[4], "r", 1) == 0) ? 1 : 0;

  return peer_adj_routes (vty, peer, afi, safi, in);
}

DEFUN (show_ip_bgp_neighbor_received_prefix_filter,
       show_ip_bgp_neighbor_received_prefix_filter_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv4 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP, name);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_neighbor_received_prefix_filter,
       show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;

  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    {
      sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_MULTICAST);
      count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
      if (count)
	{
	  vty_out (vty, "Address family: IPv4 Multicast%s", VTY_NEWLINE);
	  prefix_bgp_show_prefix_list (vty, AFI_IP, name);
	}
    }
  else 
    {
      sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_UNICAST);
      count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
      if (count)
	{
	  vty_out (vty, "Address family: IPv4 Unicast%s", VTY_NEWLINE);
	  prefix_bgp_show_prefix_list (vty, AFI_IP, name);
	}
    }

  return CMD_SUCCESS;
}

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_neighbor_received_routes_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFUN (show_bgp_ipv4_safi_neighbor_received_prefix_filter,
       show_bgp_ipv4_safi_neighbor_received_prefix_filter_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP, safi);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
  if (count) {
      vty_out (vty, "Address family: IPv4 %s%s", safi2str(safi), VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP, name);
  }

  return CMD_SUCCESS;
}

DEFUN (show_bgp_ipv6_safi_neighbor_received_prefix_filter,
       show_bgp_ipv6_safi_neighbor_received_prefix_filter_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, safi);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count) {
      vty_out (vty, "Address family: IPv6 %s%s", safi2str(safi), VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
  }

  return CMD_SUCCESS;
}

DEFUN (show_bgp_ipv6_neighbor_received_prefix_filter,
       show_bgp_ipv6_neighbor_received_prefix_filter_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
    }

  return CMD_SUCCESS;
}

DEFUN (show_bgp_view_ipv6_neighbor_received_prefix_filter,
       show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  struct bgp *bgp;
  int count, ret;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
  {  
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
  
  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (bgp, &su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
    }

  return CMD_SUCCESS;
}

static int
bgp_show_neighbor_route (struct vty *vty, struct peer *peer, afi_t afi,
			 safi_t safi, enum bgp_show_type type)
{
  if (! peer || ! peer->afc[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
 
  return bgp_show (vty, peer->bgp, afi, safi, type, &peer->su);
}
DEFUN (show_ip_bgp_neighbor_routes,
       show_ip_bgp_neighbor_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
				  bgp_show_type_neighbor);
}

DEFUN (show_ip_bgp_neighbor_flap,
       show_ip_bgp_neighbor_flap_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
				  bgp_show_type_flap_neighbor);
}

DEFUN (show_ip_bgp_neighbor_damp,
       show_ip_bgp_neighbor_damp_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
				  bgp_show_type_damp_neighbor);
}

DEFUN (show_ip_bgp_ipv4_neighbor_routes,
       show_ip_bgp_ipv4_neighbor_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
 
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_MULTICAST,
				    bgp_show_type_neighbor);

  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
				  bgp_show_type_neighbor);
}

DEFUN (show_ip_bgp_view_rsclient,
       show_ip_bgp_view_rsclient_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  struct bgp_table *table;
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP][SAFI_UNICAST];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL, 0);
}

ALIAS (show_ip_bgp_view_rsclient,
       show_ip_bgp_rsclient_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

DEFUN (show_bgp_view_ipv4_safi_rsclient,
       show_bgp_view_ipv4_safi_rsclient_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  struct bgp_table *table;
  struct peer *peer;
  safi_t safi;

  if (argc == 3) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP][safi];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL, 0);
}

ALIAS (show_bgp_view_ipv4_safi_rsclient,
       show_bgp_ipv4_safi_rsclient_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

DEFUN (show_ip_bgp_view_rsclient_route,
       show_ip_bgp_view_rsclient_route_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }
 
  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][SAFI_UNICAST], 
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

ALIAS (show_ip_bgp_view_rsclient_route,
       show_ip_bgp_rsclient_route_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_ipv4_safi_neighbor_flap,
       show_bgp_ipv4_safi_neighbor_flap_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP, safi,
				  bgp_show_type_flap_neighbor);
}

DEFUN (show_bgp_ipv6_safi_neighbor_flap,
       show_bgp_ipv6_safi_neighbor_flap_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP6, safi,
				  bgp_show_type_flap_neighbor);
}

DEFUN (show_bgp_ipv4_safi_neighbor_damp,
       show_bgp_ipv4_safi_neighbor_damp_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP, safi,
				  bgp_show_type_damp_neighbor);
}

DEFUN (show_bgp_ipv6_safi_neighbor_damp,
       show_bgp_ipv6_safi_neighbor_damp_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP6, safi,
				  bgp_show_type_damp_neighbor);
}

DEFUN (show_bgp_ipv4_safi_neighbor_routes,
       show_bgp_ipv4_safi_neighbor_routes_cmd,
       "show bgp ipv4 (multicast|unicast) neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
 
  return bgp_show_neighbor_route (vty, peer, AFI_IP, safi,
				  bgp_show_type_neighbor);
}

DEFUN (show_bgp_ipv6_safi_neighbor_routes,
       show_bgp_ipv6_safi_neighbor_routes_cmd,
       "show bgp ipv6 (multicast|unicast) neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       NEIGHBOR_ADDR_STR
       NEIGHBOR_ADDR_STR
       "Display routes learned from neighbor\n")
{
  struct peer *peer;
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
 
  return bgp_show_neighbor_route (vty, peer, AFI_IP6, safi,
				  bgp_show_type_neighbor);
}

DEFUN (show_bgp_view_ipv4_safi_rsclient_route,
       show_bgp_view_ipv4_safi_rsclient_route_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP, safi, NULL, 0, BGP_PATH_ALL);
}

ALIAS (show_bgp_view_ipv4_safi_rsclient_route,
       show_bgp_ipv4_safi_rsclient_route_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")


DEFUN (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_view_ipv4_safi_rsclient_prefix_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
{
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP, safi, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_ip_bgp_view_rsclient_prefix,
       show_ip_bgp_view_rsclient_prefix_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
  peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;
    
  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
{
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }
    
  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][SAFI_UNICAST], 
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

ALIAS (show_ip_bgp_view_rsclient_prefix,
       show_ip_bgp_rsclient_prefix_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

ALIAS (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_ipv4_safi_rsclient_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_bgp_view_ipv6_neighbor_routes,
       show_bgp_view_ipv6_neighbor_routes_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);
   
  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_neighbor);
}

DEFUN (show_bgp_view_neighbor_damp,
       show_bgp_view_neighbor_damp_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_damp_neighbor);
}

DEFUN (show_bgp_view_ipv6_neighbor_damp,
       show_bgp_view_ipv6_neighbor_damp_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_damp_neighbor);
}

DEFUN (show_bgp_view_ipv6_neighbor_flap,
       show_bgp_view_ipv6_neighbor_flap_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_flap_neighbor);
}

DEFUN (show_bgp_view_neighbor_flap,
       show_bgp_view_neighbor_flap_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_flap_neighbor);
}

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_neighbor_flap_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_neighbor_damp_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")

DEFUN (show_bgp_view_neighbor_routes,
       show_bgp_view_neighbor_routes_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);
   
  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_neighbor);
}

ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_neighbor_routes_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_ipv6_neighbor_routes_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

/* old command */
ALIAS (show_bgp_view_neighbor_routes,
       ipv6_bgp_neighbor_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_routes,
       ipv6_mbgp_neighbor_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
 
  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_MULTICAST,
				  bgp_show_type_neighbor);
}

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_ipv6_neighbor_flap_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_ipv6_neighbor_damp_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")

DEFUN (show_bgp_view_rsclient,
       show_bgp_view_rsclient_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  struct bgp_table *table;
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP6][SAFI_UNICAST];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL, 0);
}

ALIAS (show_bgp_view_rsclient,
       show_bgp_rsclient_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

DEFUN (show_bgp_view_ipv4_rsclient,
       show_bgp_view_ipv4_rsclient_cmd,
       "show bgp view WORD ipv4 rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address Family\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR2)
{
  struct bgp_table	*table;
  struct peer		*peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP][SAFI_UNICAST];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL, 0);
}
DEFUN (show_bgp_view_ipv6_rsclient,
       show_bgp_view_ipv6_rsclient_cmd,
       "show bgp view WORD ipv6 rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address Family\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR2)
{
  struct bgp_table	*table;
  struct peer		*peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP6][SAFI_UNICAST];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL, 0);
}

ALIAS (show_bgp_view_ipv4_rsclient,
       show_bgp_ipv4_rsclient_cmd,
       "show bgp ipv4 rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR2)

ALIAS (show_bgp_view_ipv6_rsclient,
       show_bgp_ipv6_rsclient_cmd,
       "show bgp ipv6 rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR2)

DEFUN (show_bgp_view_ipv6_safi_rsclient,
       show_bgp_view_ipv6_safi_rsclient_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  struct bgp_table *table;
  struct peer *peer;
  safi_t safi;

  if (argc == 3) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP6][safi];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL, 0);
}

ALIAS (show_bgp_view_ipv6_safi_rsclient,
       show_bgp_ipv6_safi_rsclient_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

DEFUN (show_bgp_view_rsclient_route,
       show_bgp_view_rsclient_route_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

DEFUN (show_bgp_view_ipv6_rsclient_route,
       show_bgp_view_ipv6_rsclient_route_cmd,
       "show bgp view WORD ipv6 rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "IP6_STR"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL);
}

ALIAS (show_bgp_view_ipv6_rsclient_route,
       show_bgp_rsclient_route_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

ALIAS (show_bgp_view_ipv6_rsclient_route,
       show_bgp_ipv6_rsclient_route_cmd,
       "show bgp ipv6 rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       IP6_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_ipv6_safi_rsclient_route,
       show_bgp_view_ipv6_safi_rsclient_route_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP6, safi, NULL, 0, BGP_PATH_ALL);
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_route,
       show_bgp_ipv6_safi_rsclient_route_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")


DEFUN (show_bgp_view_rsclient_prefix,
       show_bgp_view_rsclient_prefix_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

DEFUN (show_bgp_view_ipv6_rsclient_prefix,
       show_bgp_view_ipv6_rsclient_prefix_cmd,
       "show bgp view WORD ipv6 rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       IP6_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL);
}

ALIAS (show_bgp_view_ipv6_rsclient_prefix,
       show_bgp_rsclient_prefix_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

ALIAS (show_bgp_view_ipv6_rsclient_prefix,
       show_bgp_ipv6_rsclient_prefix_cmd,
       "show bgp ipv6 rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

DEFUN (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_view_ipv6_safi_rsclient_prefix_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
{
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP6, safi, NULL, 1, BGP_PATH_ALL);
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_ipv6_safi_rsclient_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")

struct bgp_table *bgp_distance_table;

struct bgp_distance
{
  /* Distance value for the IP source prefix. */
  u_char distance;

  /* Name of the access-list to be matched. */
  char *access_list;
};

static struct bgp_distance *
bgp_distance_new (void)
{
  return XCALLOC (MTYPE_BGP_DISTANCE, sizeof (struct bgp_distance));
}

static void
bgp_distance_free (struct bgp_distance *bdistance)
{
  XFREE (MTYPE_BGP_DISTANCE, bdistance);
}

static int
bgp_distance_set (struct vty *vty, const char *distance_str, 
                  const char *ip_str, const char *access_list_str)
{
  int ret;
  struct prefix p;
  u_char distance;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  ret = str2prefix (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  /* Get BGP distance node. */
  rn = bgp_node_get (bgp_distance_table, (struct prefix *) &p);
  if (rn->info)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);
    }
  else
    {
      bdistance = bgp_distance_new ();
      rn->info = bdistance;
    }

  /* Set distance value. */
  bdistance->distance = distance;

  /* Reset access-list configuration. */
  if (bdistance->access_list)
    {
      free (bdistance->access_list);
      bdistance->access_list = NULL;
    }
  if (access_list_str)
    bdistance->access_list = strdup (access_list_str);

  return CMD_SUCCESS;
}

static int
bgp_distance_unset (struct vty *vty, const char *distance_str, 
                    const char *ip_str, const char *access_list_str)
{
  int ret;
  struct prefix p;
  u_char distance;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  ret = str2prefix (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  rn = bgp_node_lookup (bgp_distance_table, (struct prefix *)&p);
  if (! rn)
    {
      vty_out (vty, "Can't find specified prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bdistance = rn->info;
  
  if (bdistance->distance != distance)
    {
       vty_out (vty, "Distance does not match configured%s", VTY_NEWLINE);
       return CMD_WARNING;
    }
  
  if (bdistance->access_list)
    free (bdistance->access_list);
  bgp_distance_free (bdistance);

  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

/* Apply BGP information to distance method. */
u_char
bgp_distance_apply (struct prefix *p, struct bgp_info *rinfo, struct bgp *bgp)
{
  struct bgp_node *rn;
  struct prefix_ipv4 q;
  struct peer *peer;
  struct bgp_distance *bdistance;
  struct access_list *alist;
  struct bgp_static *bgp_static;

  if (! bgp)
    return 0;

  if (p->family != AF_INET)
    return 0;

  peer = rinfo->peer;

  if (peer->su.sa.sa_family != AF_INET)
    return 0;

  memset (&q, 0, sizeof (struct prefix_ipv4));
  q.family = AF_INET;
  q.prefix = peer->su.sin.sin_addr;
  q.prefixlen = IPV4_MAX_BITLEN;

  /* Check source address. */
  rn = bgp_node_match (bgp_distance_table, (struct prefix *) &q);
  if (rn)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);

      if (bdistance->access_list)
	{
	  alist = access_list_lookup (AFI_IP, bdistance->access_list);
	  if (alist && access_list_apply (alist, p) == FILTER_PERMIT)
	    return bdistance->distance;
	}
      else
	return bdistance->distance;
    }

  /* Backdoor check. */
  rn = bgp_node_lookup (bgp->route[AFI_IP][SAFI_UNICAST], p);
  if (rn)
    {
      bgp_static = rn->info;
      bgp_unlock_node (rn);

      if (bgp_static->backdoor)
	{
	  if (bgp->distance_local)
	    return bgp->distance_local;
	  else
	    return ZEBRA_IBGP_DISTANCE_DEFAULT;
	}
    }

  if (peer->sort == BGP_PEER_EBGP)
    {
      if (bgp->distance_ebgp)
	return bgp->distance_ebgp;
      return ZEBRA_EBGP_DISTANCE_DEFAULT;
    }
  else
    {
      if (bgp->distance_ibgp)
	return bgp->distance_ibgp;
      return ZEBRA_IBGP_DISTANCE_DEFAULT;
    }
}

#ifdef HAVE_IPV6
/* Apply BGP information to ipv6 distance method. */
u_char
ipv6_bgp_distance_apply (struct prefix *p, struct bgp_info *rinfo, struct bgp *bgp)
{
  struct bgp_node *rn;
  struct prefix_ipv6 q;
  struct peer *peer;
  struct bgp_distance *bdistance;
  struct access_list *alist;
  struct bgp_static *bgp_static;

  if (! bgp)
    return 0;

  if (p->family != AF_INET6)
    return 0;

  peer = rinfo->peer;

  if (peer->su.sa.sa_family != AF_INET6)
    return 0;

  memset (&q, 0, sizeof (struct prefix_ipv6));
  q.family = AF_INET;
  q.prefix = peer->su.sin6.sin6_addr;
  q.prefixlen = IPV6_MAX_BITLEN;

  /* Check source address. */
  rn = bgp_node_match (bgp_distance_table, (struct prefix *) &q);
  if (rn)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);

      if (bdistance->access_list)
        {
          alist = access_list_lookup (AFI_IP6, bdistance->access_list);
          if (alist && access_list_apply (alist, p) == FILTER_PERMIT)
            return bdistance->distance;
        }
      else
        return bdistance->distance;
    }
  /* Backdoor check. */
  rn = bgp_node_lookup (bgp->route[AFI_IP6][SAFI_UNICAST], p);
  if (rn)
    {
      bgp_static = rn->info;
      bgp_unlock_node (rn);

      if (bgp_static->backdoor)
        {
          if (bgp->ipv6_distance_local)
            return bgp->ipv6_distance_local;
          else
            return ZEBRA_IBGP_DISTANCE_DEFAULT;
        }
    }

  if (peer_sort (peer) == BGP_PEER_EBGP)
    {
      if (bgp->ipv6_distance_ebgp)
        return bgp->ipv6_distance_ebgp;
      return ZEBRA_EBGP_DISTANCE_DEFAULT;
    }
  else
    {
      if (bgp->ipv6_distance_ibgp)
        return bgp->ipv6_distance_ibgp;
      return ZEBRA_IBGP_DISTANCE_DEFAULT;
    }
}
#endif /* HAVE_IPV6 */

DEFUN (bgp_distance,
       bgp_distance_cmd,
       "distance bgp <1-255> <1-255> <1-255>",
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->distance_ebgp = atoi (argv[0]);
  bgp->distance_ibgp = atoi (argv[1]);
  bgp->distance_local = atoi (argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance,
       no_bgp_distance_cmd,
       "no distance bgp <1-255> <1-255> <1-255>",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->distance_ebgp= 0;
  bgp->distance_ibgp = 0;
  bgp->distance_local = 0;
  return CMD_SUCCESS;
}

ALIAS (no_bgp_distance,
       no_bgp_distance2_cmd,
       "no distance bgp",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n")

DEFUN (bgp_distance_source,
       bgp_distance_source_cmd,
       "distance <1-255> A.B.C.D/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_set (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source,
       no_bgp_distance_source_cmd,
       "no distance <1-255> A.B.C.D/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (bgp_distance_source_access_list,
       bgp_distance_source_access_list_cmd,
       "distance <1-255> A.B.C.D/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_set (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source_access_list,
       no_bgp_distance_source_access_list_cmd,
       "no distance <1-255> A.B.C.D/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_distance,
       ipv6_bgp_distance_cmd,
       "distance bgp <1-255> <1-255> <1-255>",
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->ipv6_distance_ebgp = atoi (argv[0]);
  bgp->ipv6_distance_ibgp = atoi (argv[1]);
  bgp->ipv6_distance_local = atoi (argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_distance,
       no_ipv6_bgp_distance_cmd,
       "no distance bgp <1-255> <1-255> <1-255>",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->ipv6_distance_ebgp= 0;
  bgp->ipv6_distance_ibgp = 0;
  bgp->ipv6_distance_local = 0;
  return CMD_SUCCESS;
}

ALIAS (no_ipv6_bgp_distance,
       no_ipv6_bgp_distance2_cmd,
       "no distance bgp",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n")

DEFUN (ipv6_bgp_distance_source,
       ipv6_bgp_distance_source_cmd,
       "distance <1-255> X:X::X:X/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_set (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_distance_source,
       no_ipv6_bgp_distance_source_cmd,
       "no distance <1-255> X:X::X:X/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_distance_source_access_list,
       ipv6_bgp_distance_source_access_list_cmd,
       "distance <1-255> X:X::X:X/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_set (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_distance_source_access_list,
       no_ipv6_bgp_distance_source_access_list_cmd,
       "no distance <1-255> X:X::X:X/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}
#endif

DEFUN (bgp_damp_set,
       bgp_damp_set_cmd,
       "bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
  struct bgp *bgp;
  int half = DEFAULT_HALF_LIFE * 60;
  int reuse = DEFAULT_REUSE;
  int suppress = DEFAULT_SUPPRESS;
  int max = 4 * half;

  if (argc == 4)
    {
      half = atoi (argv[0]) * 60;
      reuse = atoi (argv[1]);
      suppress = atoi (argv[2]);
      max = atoi (argv[3]) * 60;
    }
  else if (argc == 1)
    {
      half = atoi (argv[0]) * 60;
      max = 4 * half;
    }

  bgp = vty->index;

  if (suppress < reuse)
    {
      vty_out (vty, "Suppress value cannot be less than reuse value %s",
                    VTY_NEWLINE);
      return 0;
    }

  return bgp_damp_enable (bgp, bgp_node_afi (vty), bgp_node_safi (vty),
			  half, reuse, suppress, max);
}

ALIAS (bgp_damp_set,
       bgp_damp_set2_cmd,
       "bgp dampening <1-45>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n")

ALIAS (bgp_damp_set,
       bgp_damp_set3_cmd,
       "bgp dampening",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")

DEFUN (bgp_damp_unset,
       bgp_damp_unset_cmd,
       "no bgp dampening",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  return bgp_damp_disable (bgp, bgp_node_afi (vty), bgp_node_safi (vty));
}

ALIAS (bgp_damp_unset,
       bgp_damp_unset2_cmd,
       "no bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")

DEFUN (show_ip_bgp_dampened_paths,
       show_ip_bgp_dampened_paths_cmd,
       "show ip bgp dampened-paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display paths suppressed due to dampening\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_dampend_paths,
                   NULL);
}

ALIAS (show_ip_bgp_dampened_paths,
       show_ip_bgp_damp_dampened_paths_cmd,
       "show ip bgp dampening dampened-paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display paths suppressed due to dampening\n")

DEFUN (show_ip_bgp_flap_statistics,
       show_ip_bgp_flap_statistics_cmd,
       "show ip bgp flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
                   bgp_show_type_flap_statistics, NULL);
}

ALIAS (show_ip_bgp_flap_statistics,
       show_ip_bgp_damp_flap_statistics_cmd,
       "show ip bgp dampening flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n")

DEFUN (show_bgp_ipv4_safi_dampened_paths,
       show_bgp_ipv4_safi_dampened_paths_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampened-paths",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display paths suppressed due to dampening\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show (vty, NULL, AFI_IP, safi, bgp_show_type_dampend_paths, NULL);
}
ALIAS (show_bgp_ipv4_safi_dampened_paths,
       show_bgp_ipv4_safi_damp_dampened_paths_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening dampened-paths",
       SHOW_STR
       BGP_STR
       IP_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display paths suppressed due to dampening\n")

DEFUN (show_bgp_ipv6_safi_dampened_paths,
       show_bgp_ipv6_safi_dampened_paths_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampened-paths",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display paths suppressed due to dampening\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show (vty, NULL, AFI_IP6, safi, bgp_show_type_dampend_paths, NULL);
}
ALIAS (show_bgp_ipv6_safi_dampened_paths,
       show_bgp_ipv6_safi_damp_dampened_paths_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening dampened-paths",
       SHOW_STR
       BGP_STR
       IPV6_STR
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display paths suppressed due to dampening\n")

DEFUN (show_bgp_ipv4_safi_flap_statistics,
       show_bgp_ipv4_safi_flap_statistics_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) flap-statistics",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show (vty, NULL, AFI_IP, safi, bgp_show_type_flap_statistics, NULL);
}
ALIAS (show_bgp_ipv4_safi_flap_statistics,
       show_bgp_ipv4_safi_damp_flap_statistics_cmd,
       "show bgp ipv4 (encap|multicast|unicast|vpn) dampening flap-statistics",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n")

DEFUN (show_bgp_ipv6_safi_flap_statistics,
       show_bgp_ipv6_safi_flap_statistics_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) flap-statistics",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display flap statistics of routes\n")
{
  safi_t	safi;

  if (bgp_parse_safi(argv[0], &safi)) {
    vty_out (vty, "Error: Bad SAFI: %s%s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  return bgp_show (vty, NULL, AFI_IP6, safi, bgp_show_type_flap_statistics, NULL);
}
ALIAS (show_bgp_ipv6_safi_flap_statistics,
       show_bgp_ipv6_safi_damp_flap_statistics_cmd,
       "show bgp ipv6 (encap|multicast|unicast|vpn) dampening flap-statistics",
       SHOW_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n")

/* Display specified route of BGP table. */
static int
bgp_clear_damp_route (struct vty *vty, const char *view_name, 
                      const char *ip_str, afi_t afi, safi_t safi, 
                      struct prefix_rd *prd, int prefix_check)
{
  int ret;
  struct prefix match;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_info *ri_temp;
  struct bgp *bgp;
  struct bgp_table *table;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
	{
	  vty_out (vty, "%% Can't find BGP view %s%s", view_name, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "%% No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "%% address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = afi2family (afi);

  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
    {
      for (rn = bgp_table_top (bgp->rib[AFI_IP][safi]); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

	  if ((table = rn->info) != NULL)
	    if ((rm = bgp_node_match (table, &match)) != NULL)
              {
                if (! prefix_check || rm->p.prefixlen == match.prefixlen)
                  {
                    ri = rm->info;
                    while (ri)
                      {
                        if (ri->extra && ri->extra->damp_info)
                          {
                            ri_temp = ri->next;
                            bgp_damp_info_free (ri->extra->damp_info, 1);
                            ri = ri_temp;
                          }
                        else
                          ri = ri->next;
                      }
                  }

                bgp_unlock_node (rm);
              }
        }
    }
  else
    {
      if ((rn = bgp_node_match (bgp->rib[afi][safi], &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              ri = rn->info;
              while (ri)
                {
                  if (ri->extra && ri->extra->damp_info)
                    {
                      ri_temp = ri->next;
                      bgp_damp_info_free (ri->extra->damp_info, 1);
                      ri = ri_temp;
                    }
                  else
                    ri = ri->next;
                }
            }

          bgp_unlock_node (rn);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening,
       clear_ip_bgp_dampening_cmd,
       "clear ip bgp dampening",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n")
{
  bgp_damp_info_clean ();
  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening_prefix,
       clear_ip_bgp_dampening_prefix_cmd,
       "clear ip bgp dampening A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_clear_damp_route (vty, NULL, argv[0], AFI_IP,
			       SAFI_UNICAST, NULL, 1);
}

DEFUN (clear_ip_bgp_dampening_address,
       clear_ip_bgp_dampening_address_cmd,
       "clear ip bgp dampening A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n")
{
  return bgp_clear_damp_route (vty, NULL, argv[0], AFI_IP,
			       SAFI_UNICAST, NULL, 0);
}

DEFUN (clear_ip_bgp_dampening_address_mask,
       clear_ip_bgp_dampening_address_mask_cmd,
       "clear ip bgp dampening A.B.C.D A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_clear_damp_route (vty, NULL, prefix_str, AFI_IP,
			       SAFI_UNICAST, NULL, 0);
}

/* also used for encap safi */
static int
bgp_config_write_network_vpn (struct vty *vty, struct bgp *bgp,
				afi_t afi, safi_t safi, int *write)
{
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct prefix *p;
  struct prefix_rd *prd;
  struct bgp_static *bgp_static;
  char buf[SU_ADDRSTRLEN];
  char rdbuf[RD_ADDRSTRLEN];
  char lblbuf[BUFSIZ];
  
  /* Network configuration. */
  for (prn = bgp_table_top (bgp->route[afi][safi]); prn; prn = bgp_route_next (prn))
    if ((table = prn->info) != NULL)
      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn)) 
	if ((bgp_static = rn->info) != NULL)
	  {
	    p = &rn->p;
	    prd = (struct prefix_rd *) &prn->p;

	    /* "address-family" display.  */
	    bgp_config_write_family_header (vty, afi, safi, write);

	    /* "network" configuration display.  */
	    prefix_rd2str (prd, rdbuf, RD_ADDRSTRLEN);
            labels2str (lblbuf, sizeof(lblbuf),
                        bgp_static->labels, bgp_static->nlabels);

	    vty_out (vty, " network %s/%d rd %s tag %s",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN), 
		     p->prefixlen,
		     rdbuf, lblbuf);
	    if (bgp_static->rmap.name){
              vty_out (vty, " route-map %s",bgp_static->rmap.name);
            }
	    vty_out (vty, "%s", VTY_NEWLINE);
	  }
  return 0;
}

static int
bgp_config_write_network_evpn (struct vty *vty, struct bgp *bgp,
                               afi_t afi, safi_t safi, int *write)
{
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct prefix *p;
  struct prefix_rd *prd;
  struct bgp_static *bgp_static;
  char buf[SU_ADDRSTRLEN];
  char buf2[SU_ADDRSTRLEN];
  char rdbuf[RD_ADDRSTRLEN];
  char lblbuf[BUFSIZ];

  /* Network configuration. */
  for (prn = bgp_table_top (bgp->route[afi][safi]); prn; prn = bgp_route_next (prn))
    if ((table = prn->info) != NULL)
      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn)) 
	if ((bgp_static = rn->info) != NULL)
	  {
            char *macrouter = NULL;
            char *esi = NULL;

            if(bgp_static->router_mac)
              macrouter = mac2str(bgp_static->router_mac);
            if(bgp_static->eth_s_id)
              esi = esi2str(bgp_static->eth_s_id);
	    p = &rn->p;
	    prd = (struct prefix_rd *) &prn->p;

	    /* "address-family" display.  */
	    bgp_config_write_family_header (vty, afi, safi, write);

	    /* "network" configuration display.  */
	    prefix_rd2str (prd, rdbuf, RD_ADDRSTRLEN);
            labels2str (lblbuf, sizeof(lblbuf),
                        bgp_static->labels, bgp_static->nlabels);
            inet_ntop (AF_INET, &bgp_static->igpnexthop, buf2, SU_ADDRSTRLEN);

            if(p->family == AF_L2VPN)
              {
                if (p->u.prefix_evpn.route_type == 3)
                  {

                    if (p->u.prefix_evpn.u.prefix_imethtag.ip_len == IPV4_MAX_BITLEN)
                      inet_ntop (AF_INET, &(p->u.prefix_evpn.u.prefix_imethtag.ip.in4),
                                 buf2, SU_ADDRSTRLEN);
                    else
                      inet_ntop (AF_INET6, &(p->u.prefix_evpn.u.prefix_imethtag.ip.in6),
                                 buf2, SU_ADDRSTRLEN);

                    vty_out (vty, " network rt3 rd %s ethtag %u routerip %s",
                             rdbuf,
                             p->u.prefix_evpn.u.prefix_imethtag.eth_tag_id,
                             buf2);

                  }
                else
                  {
                    char *mac = mac2str((char *)&p->u.prefix_evpn.u.prefix_macip);
                    vty_out (vty, " network %s rd %s ethtag %u mac %s esi %s l2label %u l3label %u routermac %s",
                             inet_ntop (AF_INET, &(p->u.prefix_evpn.u.prefix_macip.ip.in4),
                                        buf2, SU_ADDRSTRLEN),
                             rdbuf, bgp_static->eth_t_id, mac, esi,
                             bgp_static->labels[0], bgp_static->labels[1] >> 4 ,
                             macrouter);
                    if (mac)
                      XFREE (MTYPE_BGP_MAC, mac);
                  }
              } 
            else
              {
                if (safi == SAFI_EVPN && bgp_static->nlabels == 1)
                  sprintf(lblbuf, "%d", bgp_static->labels[0]);
                vty_out (vty, " network %s/%d rd %s ethtag %u label %s esi %s gwip %s routermac %s",
                         inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN), 
                         p->prefixlen,
                         rdbuf, bgp_static->eth_t_id, lblbuf, esi, buf2 , macrouter);
              }
	    vty_out (vty, "%s", VTY_NEWLINE);
            if (macrouter)
              XFREE (MTYPE_BGP_MAC, macrouter);
            if (esi)
              XFREE (MTYPE_BGP_ESI, esi);
	  }
  return 0;
}

/* Configuration of static route announcement and aggregate
   information. */
int
bgp_config_write_network (struct vty *vty, struct bgp *bgp,
			  afi_t afi, safi_t safi, int *write)
{
  struct bgp_node *rn;
  struct prefix *p;
  struct bgp_static *bgp_static;
  struct bgp_aggregate *bgp_aggregate;
  char buf[SU_ADDRSTRLEN];

  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
    return bgp_config_write_network_vpn (vty, bgp, afi, safi, write);

  if (afi == AFI_L2VPN && safi == SAFI_EVPN)
    return bgp_config_write_network_evpn (vty, bgp, afi, safi, write);

  /* Network configuration. */
  for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn)) 
    if ((bgp_static = rn->info) != NULL)
      {
	p = &rn->p;

	/* "address-family" display.  */
	bgp_config_write_family_header (vty, afi, safi, write);

	/* "network" configuration display.  */
	if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && afi == AFI_IP)
	  {
	    u_int32_t destination; 
	    struct in_addr netmask;

	    destination = ntohl (p->u.prefix4.s_addr);
	    masklen2ip (p->prefixlen, &netmask);
	    vty_out (vty, " network %s",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN));

	    if ((IN_CLASSC (destination) && p->prefixlen == 24)
		|| (IN_CLASSB (destination) && p->prefixlen == 16)
		|| (IN_CLASSA (destination) && p->prefixlen == 8)
		|| p->u.prefix4.s_addr == 0)
	      {
		/* Natural mask is not display. */
	      }
	    else
	      vty_out (vty, " mask %s", inet_ntoa (netmask));
	  }
	else
	  {
	    vty_out (vty, " network %s/%d",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN), 
		     p->prefixlen);
	  }

	if (bgp_static->rmap.name)
	  vty_out (vty, " route-map %s", bgp_static->rmap.name);
	else 
	  {
	    if (bgp_static->backdoor)
	      vty_out (vty, " backdoor");
          }

	vty_out (vty, "%s", VTY_NEWLINE);
      }

  /* Aggregate-address configuration. */
  for (rn = bgp_table_top (bgp->aggregate[afi][safi]); rn; rn = bgp_route_next (rn))
    if ((bgp_aggregate = rn->info) != NULL)
      {
	p = &rn->p;

	/* "address-family" display.  */
	bgp_config_write_family_header (vty, afi, safi, write);

	if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && afi == AFI_IP)
	  {
	    struct in_addr netmask;

	    masklen2ip (p->prefixlen, &netmask);
	    vty_out (vty, " aggregate-address %s %s",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		     inet_ntoa (netmask));
	  }
	else
	  {
	    vty_out (vty, " aggregate-address %s/%d",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		     p->prefixlen);
	  }

	if (bgp_aggregate->as_set)
	  vty_out (vty, " as-set");
	
	if (bgp_aggregate->summary_only)
	  vty_out (vty, " summary-only");

	vty_out (vty, "%s", VTY_NEWLINE);
      }

  return 0;
}

int
bgp_config_write_distance (struct vty *vty, struct bgp *bgp,
                           afi_t afi, safi_t safi, int *write)
{
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  if (afi == AFI_IP && safi == SAFI_UNICAST)
    {
      /* Distance configuration. */
      if (bgp->distance_ebgp
          && bgp->distance_ibgp
          && bgp->distance_local
          && (bgp->distance_ebgp != ZEBRA_EBGP_DISTANCE_DEFAULT
              || bgp->distance_ibgp != ZEBRA_IBGP_DISTANCE_DEFAULT
              || bgp->distance_local != ZEBRA_IBGP_DISTANCE_DEFAULT))
        vty_out (vty, " distance bgp %d %d %d%s",
                 bgp->distance_ebgp, bgp->distance_ibgp, bgp->distance_local,
                 VTY_NEWLINE);

      for (rn = bgp_table_top (bgp_distance_table); rn; rn = bgp_route_next (rn))
        if ((bdistance = rn->info) != NULL)
          {
            vty_out (vty, " distance %d %s/%d %s%s", bdistance->distance,
                     inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
                     bdistance->access_list ? bdistance->access_list : "",
                     VTY_NEWLINE);
          }
    }

#ifdef HAVE_IPV6
  else if (afi == AFI_IP6 && safi == SAFI_UNICAST)
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      if (bgp->ipv6_distance_ebgp
          && bgp->ipv6_distance_ibgp
          && bgp->ipv6_distance_local
          && (bgp->ipv6_distance_ebgp != ZEBRA_EBGP_DISTANCE_DEFAULT
              || bgp->ipv6_distance_ibgp != ZEBRA_IBGP_DISTANCE_DEFAULT
              || bgp->ipv6_distance_local != ZEBRA_IBGP_DISTANCE_DEFAULT))
        vty_out (vty, " distance bgp %d %d %d%s",
                 bgp->ipv6_distance_ebgp, bgp->ipv6_distance_ibgp, bgp->ipv6_distance_local,
                 VTY_NEWLINE);

        for (rn = bgp_table_top (bgp_distance_table); rn; rn = bgp_route_next (rn))
          if ((bdistance = rn->info) != NULL)
            {
              vty_out (vty, " distance %d %s/%d %s%s", bdistance->distance,
                       inet6_ntoa (rn->p.u.prefix6), rn->p.prefixlen,
                       bdistance->access_list ? bdistance->access_list : "",
                       VTY_NEWLINE);
            }
    }
#endif /* HAVE_IPV6 */

  return 0;
}

/* Allocate routing table structure and install commands. */
void
bgp_route_init (void)
{
  /* Init BGP distance table. */
  bgp_distance_table = bgp_table_init (AFI_IP, SAFI_UNICAST);

  /* IPv4 BGP commands. */
  install_element (BGP_NODE, &bgp_network_cmd);
  install_element (BGP_NODE, &bgp_network_mask_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_cmd);
  install_element (BGP_NODE, &bgp_network_route_map_cmd);
  install_element (BGP_NODE, &bgp_network_mask_route_map_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_NODE, &bgp_network_backdoor_cmd);
  install_element (BGP_NODE, &bgp_network_mask_backdoor_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_backdoor_cmd);
  install_element (BGP_NODE, &no_bgp_network_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_cmd);
  install_element (BGP_NODE, &no_bgp_network_route_map_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_route_map_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_NODE, &no_bgp_network_backdoor_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_backdoor_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_backdoor_cmd);

  install_element (BGP_NODE, &aggregate_address_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_NODE, &aggregate_address_summary_only_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_summary_only_cmd);
  install_element (BGP_NODE, &aggregate_address_as_set_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_as_set_cmd);
  install_element (BGP_NODE, &aggregate_address_as_set_summary_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_NODE, &aggregate_address_summary_as_set_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_summary_as_set_cmd);
  install_element (BGP_NODE, &no_aggregate_address_cmd);
  install_element (BGP_NODE, &no_aggregate_address_summary_only_cmd);
  install_element (BGP_NODE, &no_aggregate_address_as_set_cmd);
  install_element (BGP_NODE, &no_aggregate_address_as_set_summary_cmd);
  install_element (BGP_NODE, &no_aggregate_address_summary_as_set_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_summary_only_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_as_set_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_summary_as_set_cmd);

  /* IPv4 unicast configuration.  */
  install_element (BGP_IPV4_NODE, &bgp_network_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_natural_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_route_map_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_route_map_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_natural_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_route_map_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_route_map_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_natural_route_map_cmd);
  
  install_element (BGP_IPV4_NODE, &aggregate_address_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_summary_only_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_summary_only_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_as_set_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_as_set_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_as_set_summary_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_summary_as_set_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_summary_as_set_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_summary_only_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_as_set_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_as_set_summary_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_summary_as_set_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_summary_only_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_as_set_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_summary_as_set_cmd);

  /* IPv4 multicast configuration.  */
  install_element (BGP_IPV4M_NODE, &bgp_network_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_natural_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_natural_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_summary_only_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_summary_only_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_as_set_summary_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_summary_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_summary_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_summary_only_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_as_set_summary_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_summary_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_summary_only_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_summary_as_set_cmd);

  install_element (VIEW_NODE, &show_bgp_ipv4_safi_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_rd_route_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_rd_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_rd_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_encap_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_encap_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_rd_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_rd_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_vpn_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_vpn_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_encap_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_encap_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_rd_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_rd_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_afi_safi_view_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_cidr_only_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_cidr_only_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community_all_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community2_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community3_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community4_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community2_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community3_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community4_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_dampened_paths_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_dampened_paths_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_dampened_paths_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_damp_dampened_paths_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_statistics_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_flap_statistics_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_statistics_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_damp_flap_statistics_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_address_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_flap_address_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_address_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_flap_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_damp_flap_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_cidr_only_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_cidr_only_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_flap_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_damp_flap_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_flap_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_damp_flap_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_flap_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_damp_flap_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_flap_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_damp_flap_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_flap_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_flap_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_damp_flap_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_damp_flap_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv4_safi_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv4_safi_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv4_safi_rsclient_prefix_cmd);
  
  /* Restricted node: VIEW_NODE - (set of dangerous commands) */
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_vpn_rd_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_l2vpn_evpn_rd_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_vpn_rd_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_rd_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_rd_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_vpn_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_vpn_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_encap_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_encap_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_rd_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_rd_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community_all_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv4_safi_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv4_safi_rsclient_prefix_cmd);

  /* BGP dampening clear commands */
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_prefix_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_address_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_address_mask_cmd);

  /* New config IPv6 BGP commands.  */
  install_element (BGP_IPV6_NODE, &ipv6_bgp_network_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_network_route_map_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_network_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_network_route_map_cmd);

  install_element (BGP_IPV6_NODE, &ipv6_aggregate_address_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_aggregate_address_summary_only_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_aggregate_address_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_aggregate_address_summary_only_cmd);

  install_element (BGP_IPV6M_NODE, &ipv6_bgp_network_cmd);
  install_element (BGP_IPV6M_NODE, &no_ipv6_bgp_network_cmd);

  /* Old config IPv6 BGP commands.  */
  install_element (BGP_NODE, &old_ipv6_bgp_network_cmd);
  install_element (BGP_NODE, &old_no_ipv6_bgp_network_cmd);

  install_element (BGP_NODE, &old_ipv6_aggregate_address_cmd);
  install_element (BGP_NODE, &old_ipv6_aggregate_address_summary_only_cmd);
  install_element (BGP_NODE, &old_no_ipv6_aggregate_address_cmd);
  install_element (BGP_NODE, &old_no_ipv6_aggregate_address_summary_only_cmd);

  install_element (VIEW_NODE, &show_bgp_ipv6_safi_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community2_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community3_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community4_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_community_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_damp_cmd); 
  install_element (VIEW_NODE, &show_bgp_view_ipv4_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_safi_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_safi_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_safi_rsclient_prefix_cmd);
  
  /* Restricted:
   * VIEW_NODE - (set of dangerous commands) - (commands dependent on prev) 
   */
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_safi_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_safi_rsclient_prefix_cmd);

  /* Statistics */
  install_element (ENABLE_NODE, &show_bgp_statistics_cmd);
  install_element (ENABLE_NODE, &show_bgp_statistics_view_cmd);  

  install_element (BGP_NODE, &bgp_distance_cmd);
  install_element (BGP_NODE, &no_bgp_distance_cmd);
  install_element (BGP_NODE, &no_bgp_distance2_cmd);
  install_element (BGP_NODE, &bgp_distance_source_cmd);
  install_element (BGP_NODE, &no_bgp_distance_source_cmd);
  install_element (BGP_NODE, &bgp_distance_source_access_list_cmd);
  install_element (BGP_NODE, &no_bgp_distance_source_access_list_cmd);
#ifdef HAVE_IPV6
  install_element (BGP_IPV6_NODE, &ipv6_bgp_distance_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_distance_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_distance2_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_distance_source_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_distance_source_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_distance_source_access_list_cmd);
#endif /* HAVE_IPV6 */

  install_element (BGP_NODE, &bgp_damp_set_cmd);
  install_element (BGP_NODE, &bgp_damp_set2_cmd);
  install_element (BGP_NODE, &bgp_damp_set3_cmd);
  install_element (BGP_NODE, &bgp_damp_unset_cmd);
  install_element (BGP_NODE, &bgp_damp_unset2_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_set_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_set2_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_set3_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_unset_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_unset2_cmd);

  /* IPv4 Multicast Mode */
  install_element (BGP_IPV4M_NODE, &bgp_damp_set_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_damp_set2_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_damp_set3_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_damp_unset_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_damp_unset2_cmd);

  
  /* Deprecated AS-Pathlimit commands */
  install_element (BGP_NODE, &bgp_network_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_mask_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_backdoor_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_NODE, &no_bgp_network_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_backdoor_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_IPV4_NODE, &bgp_network_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_backdoor_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_IPV4_NODE, &no_bgp_network_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_backdoor_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_IPV4M_NODE, &bgp_network_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_backdoor_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_IPV4M_NODE, &no_bgp_network_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_backdoor_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_natural_backdoor_ttl_cmd);

  install_element (BGP_IPV6_NODE, &ipv6_bgp_network_ttl_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_network_ttl_cmd);

  /* old style commands */
  install_element (VIEW_NODE, &show_ip_bgp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vrf_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vrf_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vrf_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vrf_all_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vrf_neighbor_received_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vrf_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vrf_tags_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vrf_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vrf_all_tags_cmd);
  install_element (VIEW_NODE, &show_l2vpn_bgp_vrf_cmd);
  install_element (VIEW_NODE, &show_l2vpn_bgp_vrf_tags_cmd);
  install_element (VIEW_NODE, &show_l2vpn_bgp_vrf_all_cmd);
  install_element (VIEW_NODE, &show_l2vpn_bgp_vrf_all_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vrf_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vrf_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_route_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_l2vpn_evpn_all_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_map_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_route_map_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_cidr_only_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_cidr_only_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community2_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community3_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community2_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community3_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_dampening_params_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_dampening_parameters_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_dampened_paths_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_dampening_dampd_paths_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_dampening_flap_stats_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_damp_dampened_paths_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_statistics_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_damp_flap_statistics_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_address_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_damp_flap_address_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_cidr_only_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_damp_flap_cidr_only_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_damp_flap_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_damp_flap_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_damp_flap_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_route_map_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_damp_flap_route_map_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_rsclient_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_rsclient_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_rsclient_prefix_cmd);
  
  install_element (RESTRICTED_NODE, &show_ip_bgp_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vrf_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_l2vpn_evpn_all_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_l2vpn_evpn_all_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_view_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_view_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community2_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community3_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community4_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community2_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community3_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community4_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_view_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_view_rsclient_prefix_cmd);
  
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_prefix_counts_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_prefix_counts_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd);
  install_element (VIEW_NODE, &show_bgp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_cmd);
  install_element (VIEW_NODE, &show_bgp_route_cmd);
  install_element (VIEW_NODE, &show_bgp_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_community_all_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community_all_cmd);
  install_element (VIEW_NODE, &show_bgp_community_cmd);
  install_element (VIEW_NODE, &show_bgp_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community_list_cmd);
  install_element (VIEW_NODE, &show_bgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_bgp_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_view_cmd);
  install_element (VIEW_NODE, &show_bgp_view_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_bgp_view_rsclient_cmd);
  
  install_element (RESTRICTED_NODE, &show_bgp_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_neighbor_received_prefix_filter_cmd);

  install_element (ENABLE_NODE, &show_bgp_statistics_vpnv4_cmd);
  install_element (ENABLE_NODE, &show_bgp_statistics_view_vpnv4_cmd);

  install_element (VIEW_NODE, &show_ipv6_bgp_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vpnv6_all_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vpnv6_rd_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vpnv6_all_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vpnv6_rd_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vpnv6_neighbor_prefix_counts_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community2_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community3_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community4_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community2_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community3_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community4_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_longer_cmd);
  install_element (VIEW_NODE, &ipv6_bgp_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &ipv6_bgp_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &ipv6_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_routes_cmd);
  /* old with name safi collision */
  install_element (VIEW_NODE, &show_bgp_ipv6_community_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community2_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community3_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community4_exact_cmd);

  install_element (VIEW_NODE, &show_bgp_ipv6_community_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community_list_exact_cmd);

  install_element (VIEW_NODE, &show_bgp_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_rsclient_prefix_cmd);

  install_element (VIEW_NODE, &show_bgp_view_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_rsclient_prefix_cmd);
}

void
bgp_route_finish (void)
{
  bgp_table_unlock (bgp_distance_table);
  bgp_distance_table = NULL;
}
