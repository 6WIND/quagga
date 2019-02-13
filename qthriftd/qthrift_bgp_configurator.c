 /* qthrift thrift BGP Configurator Server Part
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of GNU Quagga.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
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
#include <zebra.h>
#include <stdio.h>

#include "qthriftd/qthrift_thrift_wrapper.h"
#include "qthriftd/qthrift_master.h"
#include "qthriftd/qthrift_memory.h"
#include "qthriftd/bgp_updater.h"
#include "qthriftd/bgp_configurator.h"
#include "qthriftd/qthrift_bgp_configurator.h"
#include "qthriftd/qthrift_vpnservice.h"
#include "qthrift_debug.h"
#include "qzmq.h"
#include "qzc.h"
#include "qzc.capnp.h"
#include "bgp.bcapnp.h"
#include "bgp_mpath.h"

#include "command.h"

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif
#define QTHRIFT_MAXPATH_DEFAULT_VAL   8

/* ---------------------------------------------------------------- */

static gboolean
instance_bgp_configurator_handler_create_peer(BgpConfiguratorIf *iface,
                                              gint32* ret, const gchar *routerId,
                                              const gint64 asNumber, GError **error);
static gboolean
instance_bgp_configurator_handler_start_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint64 asNumber,
                                            const gchar * routerId, const gint32 port, const gint32 holdTime,
                                            const gint32 keepAliveTime, const gint32 stalepathTime,
                                            const gboolean announceFbit, GError **error);
gboolean
instance_bgp_configurator_handler_set_ebgp_multihop(BgpConfiguratorIf *iface, gint32* _return,
                                                    const gchar * peerIp, const gint32 nHops, GError **error);
gboolean
instance_bgp_configurator_handler_unset_ebgp_multihop(BgpConfiguratorIf *iface, gint32* _return,
                                                      const gchar * peerIp, GError **error);
gboolean
instance_bgp_configurator_handler_push_route(BgpConfiguratorIf *iface, gint32* _return, const gchar * prefix,
                                             const gchar * nexthop, const gchar * rd, const gint32 label, GError **error);
gboolean
instance_bgp_configurator_handler_withdraw_route(BgpConfiguratorIf *iface, gint32* _return, const gchar * prefix,
                                                 const gchar * rd, GError **error);
gboolean
instance_bgp_configurator_handler_stop_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint64 asNumber, GError **error);
gboolean
instance_bgp_configurator_handler_delete_peer(BgpConfiguratorIf *iface, gint32* _return, const gchar * ipAddress, GError **error);
gboolean
instance_bgp_configurator_handler_add_vrf(BgpConfiguratorIf *iface, gint32* _return, const gchar * rd,
                                          const GPtrArray * irts, const GPtrArray * erts, GError **error);
gboolean
instance_bgp_configurator_handler_del_vrf(BgpConfiguratorIf *iface, gint32* _return, const gchar * rd, GError **error);
gboolean
instance_bgp_configurator_handler_set_update_source (BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                     const gchar * srcIp, GError **error);
gboolean
instance_bgp_configurator_handler_unset_update_source (BgpConfiguratorIf *iface, gint32* _return, 
                                                       const gchar * peerIp, GError **error);
gboolean
instance_bgp_configurator_handler_enable_address_family(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                        const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_disable_address_family(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                         const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_set_log_config (BgpConfiguratorIf *iface, gint32* _return, const gchar * logFileName,
                                                  const gchar * logLevel, GError **error);
gboolean
instance_bgp_configurator_handler_enable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return,
                                                           const gint32 stalepathTime, GError **error);
gboolean
instance_bgp_configurator_handler_disable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return, GError **error);
gboolean
instance_bgp_configurator_handler_enable_default_originate(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                           const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_disable_default_originate(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                            const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_get_routes (BgpConfiguratorIf *iface, Routes ** _return, const gint32 optype,
                                              const gint32 winSize, GError **error);

gboolean
instance_bgp_configurator_handler_enable_multipath(BgpConfiguratorIf *iface, gint32* _return,
                                                   const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_disable_multipath(BgpConfiguratorIf *iface, gint32* _return,
                                                    const af_afi afi, const af_safi safi, GError **error);
gboolean
instance_bgp_configurator_handler_multipaths(BgpConfiguratorIf *iface, gint32* _return,
                                             const gchar * rd, const gint32 maxPath, GError **error);

gboolean
instance_bgp_configurator_enable_eor_delay(BgpConfiguratorIf *iface, gint32* _return,
                                           const gint32 delay, GError **error);
gboolean
instance_bgp_configurator_send_eor(BgpConfiguratorIf *iface, gint32* _return, GError **error);
static void instance_bgp_configurator_handler_finalize(GObject *object);

/*
 * utilities functions for thrift <-> capnproto exchange
 * some of those functions implement a cache mecanism for some objects
 * like VRF, and Neighbors
 */
static uint64_t
qthrift_bgp_configurator_find_peer(struct qthrift_vpnservice *ctxt, const gchar *peerIp, gint32* _return);

/* enable/disable address family bgp neighbor, using capnp */
static gboolean
qthrift_bgp_afi_config(struct qthrift_vpnservice *ctxt,  gint32* _return, const gchar * peerIp, \
                       const af_afi afi, const af_safi safi, gboolean value, GError **error);

static gboolean
qthrift_bgp_set_multihops(struct qthrift_vpnservice *ctxt,  gint32* _return, const gchar * peerIp, \
                          const gint32 nHops, GError **error);

static gboolean
qthrift_bgp_peer_af_flag_config(struct qthrift_vpnservice *ctxt,  gint32* _return,
                                const gchar * peerIp, const af_afi afi,
                                const af_safi safi, gint16 value, gboolean update,
                                GError **error);

static gboolean
qthrift_bgp_set_log_config(struct qthrift_vpnservice *ctxt, 
                           struct qthrift_vpnservice_bgp_context *bgp_ctxt,
                           gint32* _return,  GError **error);

static gboolean
qthrift_bgp_set_multipath_internal(struct qthrift_vpnservice *ctxt,  gint32* _return,
                                   afi_t af, safi_t saf, const gint32 enable, GError **error);

static af_afi qthrift_afi_value (afi_t afi);
static af_safi qthrift_safi_value (safi_t safi);

/* The implementation of InstanceBgpConfiguratorHandler follows. */

G_DEFINE_TYPE (InstanceBgpConfiguratorHandler,
               instance_bgp_configurator_handler,
               TYPE_BGP_CONFIGURATOR_HANDLER)

/* Each of a handler's methods accepts at least two parameters: A
   pointer to the service-interface implementation (the handler object
   itself) and a handle to a GError structure to receive information
   about any error that occurs.
   On success, a handler method returns TRUE. A return value of FALSE
   indicates an error occurred and the error parameter has been
   set. (Methods should not return FALSE without first setting the
   error parameter.) */

/*
 * thrift error messages returned
 * in case bgp_configurator has to trigger a thrift exception
 */
#define ERROR_BGP_AS_STARTED g_error_new(1, BGP_ERR_ACTIVE, "Already active");
#define ERROR_BGP_RD_NOTFOUND g_error_new(1, BGP_ERR_PARAM, "BGP RD %s not configured", rd);
#define ERROR_BGP_AS_NOT_STARTED g_error_new(1, BGP_ERR_INACTIVE, "Already inactive");
#define ERROR_BGP_AFISAFI_NOTSUPPORTED g_error_new(1, BGP_ERR_PARAM, "BGP Afi/Safi %d/%d not supported", afi, safi);
#define ERROR_BGP_PEER_NOTFOUND g_error_new(1, BGP_ERR_PARAM, "BGP Peer %s not configured", peerIp);
#define ERROR_BGP_NO_ROUTES_FOUND g_error_new(1, 6, "BGP GetRoutes: no routes");
#define ERROR_BGP_INVALID_MAXPATH g_error_new(1, BGP_ERR_PARAM, "BGP maxpaths: out of range value 0 < %d < 8", maxPath);
#define ERROR_BGP_INTERNAL g_error_new(1, BGP_ERR_FAILED, "Error reported by BGP, check log file");
#define ERROR_BGP_INVALID_UPDATE_DELAY g_error_new(1, BGP_ERR_PARAM, "BGP EOR update delay: out of range value 0 <= %d <= %d", delay, MAX_EOR_UPDATE_DELAY);
#define ERROR_BGP_INVALID_NEXTHOP g_error_new(1, BGP_ERR_PARAM, "BGP nexthop: invalid IPv4 address %s", nexthop);
#define ERROR_BGP_INVALID_PREFIX g_error_new(1, BGP_ERR_PARAM, "BGP prefix: invalid IPv4 prefix %s", prefix);
#define ERROR_BGP_INVALID_VRF_RTS g_error_new(1, BGP_ERR_PARAM, "BGP VRF: invalid rts \"%s\"", rts);
#define BGP_ERR_INTERNAL 110

/*
 * capnproto node identifiers used for qthrift<->bgp exchange
 * those node identifiers identify which structure and which action
 * to perform on this structure
 * example of structure handled:
 * - bgp master, bgp main instance, bgp neighbor, bgp vrf, route entry
 * example of action done:
 * - creation of a structure, get structure, set structure, remove structure
 */
/* bgp well know number. identifier used to recognize peer qzc */
uint64_t bgp_bm_wkn = 0x37b64fdb20888a50;
/* bgp master context */
uint64_t bgp_bm_nid;
/* bgp AS instance context */
uint64_t bgp_inst_nid;
/* bgp datatype */
uint64_t bgp_datatype_bgp = 0xfd0316f1800ae916; /* create_bgp_master_1 , get_bgp_1, set_bgp_1 */
/* handling bgpvrf structure
 * functions called in bgp : create_bgp_3. bgp_vrf_create. get_bgp_vrf_1, set_bgp_vrf_1
 */
uint64_t bgp_datatype_bgpvrf = 0x912c4b0c412022b1;
/* handling peer structure
 * functions called in bgp : struct peer. get_peer_3, set_peer_3
 */
uint64_t bgp_datatype_peer_3 = 0x8a3b3cd8d134cad1;
/* functions using this node identifier : struct peer. get_peer_2, set_peer_2 */
uint64_t bgp_datatype_create_bgp_2 = 0xd1f1619cff93fcb9;
/* node identifier defining afi safi context type */
uint64_t bgp_ctxttype_afisafi= 0x9af9aec34821d76a;
/* handling bgpvrf routes*/
/* get_bgp_vrf_2 XXX itertype, get_bgp_vrf_3, [un]set_bgp_vrf_3 */
uint64_t bgp_datatype_bgpvrfroute = 0x8f217eb4bad6c06f;
/* node identifier defining afi safi context type */
uint64_t bgp_ctxttype_afisafi_set_bgp_vrf_3= 0xac25a73c3ff455c0;
/* handling getRoutes - node information for getRoutes() */
/* functions using this node identifier: get_bgp_vrf_2, get_bgp_vrf_3 */
uint64_t bgp_ctxtype_bgpvrfroute = 0xac25a73c3ff455c0;
/* functions using this node identifier : get_bgp_vrf_2, get_bgp_vrf_3 */
uint64_t bgp_itertype_bgpvrfroute = 0xeb8ab4f58b7753ee;

int bgp_eor_update_delay = 0;

static const char* af_flag_str[] = {
  "SendCommunity",
  "SendExtCommunity",
  "NextHopSelf",
  "ReflectorClient",
  "RServerClient",
  "SoftReconfig",
  "AsPathUnchanged",
  "NextHopUnchanged",
  "MedUnchanged",
  "DefaultOriginate",
  "RemovePrivateAS",
  "AllowAsIn",
  "OrfPrefixSm",
  "OrfPrefixRm",
  "MaxPrefix",
  "MaxPrefixWarning",
  "NextHopLocalUnchanged",
  "NextHopSelfAll"
};

static const char*
qthrift_af_flag2str(guint32 af_flag)
{
  int i = 0;

  while(af_flag)
    {
      af_flag = af_flag >> 1;
      if(af_flag)
        i++;
    }
  return af_flag_str[i];
}

static af_afi qthrift_afi_value (afi_t afi)
{
  if (afi == AFI_IP)
    return AFI_IP;
  return AFI_IP;
}

static af_safi qthrift_safi_value (safi_t safi)
{
  if (safi == SAFI_MPLS_VPN)
    return AF_SAFI_SAFI_MPLS_VPN;
  return AF_SAFI_SAFI_MPLS_VPN;
}

/*
 * lookup routine that searches for a matching vrf
 * it searches first in the qthrift cache, then if not found,
 * it searches in BGP a vrf context.
 * It returns the capnp node identifier related to peer context,
 * 0 otherwise.
 */
uint64_t
qthrift_bgp_configurator_find_vrf(struct qthrift_vpnservice *ctxt, struct prefix_rd *rd, gint32* _return)
{
  struct listnode *node, *nnode;
  struct qthrift_vpnservice_cache_bgpvrf *entry;

  /* lookup in cache context, first */
  if (!list_isempty(ctxt->bgp_vrf_list))
    for (ALL_LIST_ELEMENTS(ctxt->bgp_vrf_list, node, nnode, entry))
      if(0 == prefix_rd_cmp(&(entry->outbound_rd), rd))
        {
          if(IS_QTHRIFT_DEBUG_CACHE)
            zlog_debug ("CACHE_VRF: match lookup entry %llx", (long long unsigned int)entry->bgpvrf_nid);
          return entry->bgpvrf_nid; /* match */
        }
  return 0;
}

/*
 * lookup routine that searches for a matching peer
 * it searches first in the qthrift cache, then if not found,
 * it searches in BGP a peer context.
 * It returns the capnp node identifier related to peer context,
 * 0 otherwise.
 */
static uint64_t
qthrift_bgp_configurator_find_peer(struct qthrift_vpnservice *ctxt, const gchar *peerIp, gint32* _return)
{
  struct listnode *node, *nnode;
  struct qthrift_cache_peer *entry;

  /* lookup in cache context, first */
  if (!list_isempty(ctxt->bgp_peer_list))
    for (ALL_LIST_ELEMENTS(ctxt->bgp_peer_list, node, nnode, entry))
      if(0 == strcmp(entry->peerIp, peerIp))
        {
          if(IS_QTHRIFT_DEBUG_CACHE)
            zlog_debug ("CACHE_PEER : match lookup entry %s", entry->peerIp);
          return entry->peer_nid; /* match */
        }
  return 0;
}

/* enable/disable address family bgp neighbor, using capnp */
static gboolean
qthrift_bgp_afi_config(struct qthrift_vpnservice *ctxt,  gint32* _return, const gchar * peerIp, \
                       const af_afi afi, const af_safi safi, gboolean value, GError **error)
{
  uint64_t peer_nid;
  struct capn rc;
  struct capn_segment *cs;
  capn_ptr afisafi_ctxt, peer_ctxt;
  struct peer peer;
  int af, saf;
  int ret;
  struct QZCGetRep *grep_peer;

  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(peerIp == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if(afi != AF_AFI_AFI_IP)
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if(safi != AF_SAFI_SAFI_MPLS_VPN)
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  peer_nid = qthrift_bgp_configurator_find_peer(ctxt, peerIp, _return);
  if(peer_nid == 0)
    {
      *_return = BGP_ERR_PARAM;
      *error = ERROR_BGP_PEER_NOTFOUND;
      return FALSE;
    }
  /* prepare afisafi context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  afisafi_ctxt = qcapn_new_AfiSafiKey(cs);
  af = AFI_IP;
  saf = SAFI_MPLS_VPN;
  capn_write8(afisafi_ctxt, 0, af);
  capn_write8(afisafi_ctxt, 1, saf);
  /* retrieve peer context */
  grep_peer = qzcclient_getelem (ctxt->p_qzc_sock, &peer_nid, 3, \
                                 &afisafi_ctxt, &bgp_ctxttype_afisafi,\
                                 NULL, NULL);
  if(grep_peer == NULL)
    {
      *_return = BGP_ERR_INTERNAL;
      capn_free(&rc);
      return FALSE;
    }
  /* change address family local context of peer */
  memset(&peer, 0, sizeof(struct peer));
  qcapn_BGPPeerAfiSafi_read(&peer, grep_peer->data, af, saf);
  if(TRUE == value)
    peer.afc[af][saf] = 1;
  else
    peer.afc[af][saf] = 0;
  /* reset qzc reply and rc context */
  qzcclient_qzcgetrep_free( grep_peer);
  /* prepare QZCSetRequest context */
  peer_ctxt = qcapn_new_BGPPeerAfiSafi(cs);
  /* set address family for peer */
  qcapn_BGPPeerAfiSafi_write(&peer, peer_ctxt, af, saf);
  ret = qzcclient_setelem (ctxt->p_qzc_sock, &peer_nid, 3, \
                           &peer_ctxt, &bgp_datatype_peer_3, \
                           &afisafi_ctxt, &bgp_ctxttype_afisafi);
  if(ret == 0)
    {
      *_return = BGP_ERR_INTERNAL;
      capn_free(&rc);
      return FALSE;
    }
  if(IS_QTHRIFT_DEBUG)
    {
      if(TRUE == value)
        zlog_info ("enableAddressFamily( %s, afi %d, safi %d) OK", peerIp, afi, safi);
      else
        zlog_info ("disableAddressFamily( %s, afi %d, safi %d) OK", peerIp, afi, safi);
    }
  *_return = 0;
  capn_free(&rc);
  return TRUE;
}

/* enable/disable any af flag of bgp neighbor, using capnp */
static gboolean
qthrift_bgp_peer_af_flag_config(struct qthrift_vpnservice *ctxt,  gint32* _return,
                                const gchar * peerIp, const af_afi afi,
                                const af_safi safi, gint16 value, gboolean update,
                                GError **error)
{
  uint64_t peer_nid;
  struct capn rc;
  struct capn_segment *cs;
  capn_ptr afisafi_ctxt, peer_ctxt;
  struct peer peer;
  int af, saf;
  int ret;
  struct QZCGetRep *grep_peer;

  if(   qthrift_vpnservice_get_bgp_context(ctxt) == NULL
     || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(peerIp == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if(afi != AF_AFI_AFI_IP)
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if(safi != AF_SAFI_SAFI_MPLS_VPN)
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  peer_nid = qthrift_bgp_configurator_find_peer(ctxt, peerIp, _return);
  if(peer_nid == 0)
    {
      *_return = BGP_ERR_PARAM;
      *error = ERROR_BGP_PEER_NOTFOUND;
      return FALSE;
    }
  /* prepare afisafi context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  afisafi_ctxt = qcapn_new_AfiSafiKey(cs);
  af = AFI_IP;
  saf = SAFI_MPLS_VPN;
  capn_write8(afisafi_ctxt, 0, af);
  capn_write8(afisafi_ctxt, 1, saf);
  /* retrieve peer context */
  grep_peer = qzcclient_getelem (ctxt->p_qzc_sock, &peer_nid, 3,
                                 &afisafi_ctxt, &bgp_ctxttype_afisafi,
                                 NULL, NULL);
  if(grep_peer == NULL)
    {
      *_return = BGP_ERR_INTERNAL;
      capn_free(&rc);
      return FALSE;
    }
  /* change address family local context of peer */
  memset(&peer, 0, sizeof(struct peer));
  qcapn_BGPPeerAfiSafi_read(&peer, grep_peer->data, af, saf);
  if(TRUE == update)
    peer.af_flags[af][saf] |= value;
  else
    peer.af_flags[af][saf] &= ~value;
  /* reset qzc reply and rc context */
  qzcclient_qzcgetrep_free( grep_peer);
  /* prepare QZCSetRequest context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  peer_ctxt = qcapn_new_BGPPeerAfiSafi(cs);
  /* set address family for peer */
  qcapn_BGPPeerAfiSafi_write(&peer, peer_ctxt, af, saf);
  ret = qzcclient_setelem (ctxt->p_qzc_sock, &peer_nid, 3, &peer_ctxt,
                           &bgp_datatype_peer_3, &afisafi_ctxt, &bgp_ctxttype_afisafi);
  if(ret == 0)
    {
      *_return = BGP_ERR_INTERNAL;
      capn_free(&rc);
      return FALSE;
    }
  if(IS_QTHRIFT_DEBUG)
    {
      if(TRUE == update)
        zlog_debug ("enable%s for peer %s in af_flag[%d][%d] OK", qthrift_af_flag2str(value),
                    peerIp, afi, safi);
      else
        zlog_debug ("disable%s for peer %s in af_flag[%d][%d] OK", qthrift_af_flag2str(value),
                    peerIp, afi, safi);
    }
  _return = 0;
  capn_free(&rc);
  return TRUE;
}

static gboolean
qthrift_bgp_set_log_config(struct qthrift_vpnservice *ctxt,
                           struct qthrift_vpnservice_bgp_context*bgp_ctxt,  
                           gint32* _return,  GError **error)
{
  struct capn rc;
  struct capn_segment *cs;
  struct bgp inst;
  struct QZCGetRep *grep;
  struct capn_ptr bgp;

  /* get bgp_master configuration */
  grep = qzcclient_getelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
  if(grep == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  memset(&inst, 0, sizeof(struct bgp));
  qcapn_BGP_read(&inst, grep->data);
  qzcclient_qzcgetrep_free( grep);
  /* update bgp configuration with logLevel and logText */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgp = qcapn_new_BGP(cs);
  /* set default stalepath time */
  if (bgp_ctxt->logFile == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if (inst.logLevel)
    free ( inst.logLevel);
  if (inst.logFile)
    free ( inst.logFile);
  if(bgp_ctxt->logLevel)
    inst.logLevel = strdup (bgp_ctxt->logLevel);
  else
    inst.logLevel = NULL;
  if(bgp_ctxt->logFile)
    inst.logFile = strdup (bgp_ctxt->logFile);
  qcapn_BGP_write(&inst, bgp);
  qzcclient_setelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1,          \
                     &bgp, &bgp_datatype_bgp, NULL, NULL);
  if(IS_QTHRIFT_DEBUG)
    zlog_info ("setLogConfig(%s, %s) OK", 
                bgp_ctxt->logFile,
                bgp_ctxt->logLevel==NULL?"none":
                bgp_ctxt->logLevel);
  capn_free(&rc);
  if (inst.notify_zmq_url)
    free (inst.notify_zmq_url);
  if (inst.logLevel)
    free ( inst.logLevel);
  if (inst.logFile)
    free ( inst.logFile);
  return TRUE;
}


/* 
 * Enable and change EBGP maximum number of hops for a given bgp neighbor 
 * If Peer is not configured, it returns an error
 * If nHops is set to 0, then the EBGP peers must be connected
 */
static gboolean
qthrift_bgp_set_multihops(struct qthrift_vpnservice *ctxt,  gint32* _return, const gchar * peerIp, const gint32 nHops, GError **error)
{
  uint64_t peer_nid;
  struct capn rc;
  struct capn_segment *cs;
  capn_ptr peer_ctxt;
  struct peer peer;
  struct QZCGetRep *grep_peer;

  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(peerIp == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  peer_nid = qthrift_bgp_configurator_find_peer(ctxt, peerIp, _return);
  if(peer_nid == 0)
    {
      *_return = BGP_ERR_PARAM;
      *error = ERROR_BGP_PEER_NOTFOUND;
      return FALSE;
    }
  /* retrieve peer context */
  grep_peer = qzcclient_getelem (ctxt->p_qzc_sock, &peer_nid, 2, \
                                 NULL, NULL, NULL, NULL);
  if(grep_peer == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  /* change nHops */
  qcapn_BGPPeer_read(&peer, grep_peer->data);
  peer.ttl = nHops;
  qzcclient_qzcgetrep_free( grep_peer);
  /* prepare QZCSetRequest context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  peer_ctxt = qcapn_new_BGPPeer(cs);
  qcapn_BGPPeer_write(&peer, peer_ctxt);
  if(qzcclient_setelem (ctxt->p_qzc_sock, &peer_nid, \
                        2, &peer_ctxt, &bgp_datatype_create_bgp_2, \
                        NULL, NULL))
    {
      if(IS_QTHRIFT_DEBUG)
        {
          if(nHops == 0)
            zlog_info ("unsetEbgpMultiHop(%s) OK", peerIp);
          else
            zlog_info ("setEbgpMultiHop(%s, %d) OK", peerIp, nHops);
        }
    }
  capn_free(&rc);
  return TRUE;
}

/*
 * Start a Create a BGP neighbor for a given routerId, and asNumber
 * If BGP is already started, then an error is returned : BGP_ERR_ACTIVE
 */
static gboolean
instance_bgp_configurator_handler_start_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint64 asNumber,
                                            const gchar * routerId, const gint32 port, const gint32 holdTime,
                                            const gint32 keepAliveTime, const gint32 stalepathTime,
                                            const gboolean announceFbit, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  struct qthrift_vpnservice_bgp_context *bgp_ctxt;
  int ret = 0;
  struct bgp inst;
  pid_t pid;
  char s_port[16];
  char s_zmq_sock[64];
  struct QZCReply *rep;
  char *parmList[] =  {(char *)"",\
                       (char *)BGPD_ARGS_STRING_1,\
                       (char *)"",                \
                       (char *)BGPD_ARGS_STRING_3,\
                       (char *)"",
                       NULL};

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  /* check bgp already started */
  if(qthrift_vpnservice_get_bgp_context(ctxt))
    {
      if(qthrift_vpnservice_get_bgp_context(ctxt)->asNumber)
        {
          *_return = BGP_ERR_ACTIVE;
          *error = ERROR_BGP_AS_STARTED;
          return FALSE;
        }
    }
  else
    {
      qthrift_vpnservice_setup_bgp_context(ctxt);
    }
  if (asNumber < 0)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* run BGP process */
  parmList[0] = ctxt->bgpd_execution_path;
  sprintf(s_port, "%d", port);
  sprintf(s_zmq_sock, "%s-%u", ctxt->zmq_sock, (as_t)asNumber);
  parmList[2] = s_port;
  parmList[4] = s_zmq_sock;
  if ((pid = fork()) ==-1)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  else if (pid == 0)
    {
      ret = execve((const char *)ctxt->bgpd_execution_path, parmList, NULL);
      /* return not expected */
      if(IS_QTHRIFT_DEBUG)
        zlog_err ("execve failed: bgpd return not expected (%d)", errno);
      exit(1);
    }
  /* store process id */
  qthrift_vpnservice_get_bgp_context(ctxt)->proc = pid;
  /* creation of capnproto context - bgp configurator */
  /* creation of qzc client context */
  ctxt->qzc_sock = qzcclient_connect(s_zmq_sock, QZC_CLIENT_ZMQ_LIMIT_TX);
  if(ctxt->qzc_sock == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  ctxt->p_qzc_sock = &ctxt->qzc_sock;
  /* send ping msg. wait for pong */
  rep = qzcclient_do(ctxt->p_qzc_sock, NULL);
  if( rep == NULL || rep->which != QZCReply_pong)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  /* check well known number agains node identifier */
  bgp_bm_nid = qzcclient_wkn(ctxt->p_qzc_sock, &bgp_bm_wkn);
  if(IS_QTHRIFT_DEBUG)
    zlog_info ("startBgp. bgpd called (AS %u, proc %d, .., stalepath %u, announceFbit %s)", \
                (as_t)asNumber, pid, stalepathTime, announceFbit == true?"true":"false");
  /* from bgp_master, create bgp and retrieve bgp as node identifier */
  {
    struct capn_ptr bgp;
    struct capn rc;
    struct capn_segment *cs;

    capn_init_malloc(&rc);
    cs = capn_root(&rc).seg;
    memset(&inst, 0, sizeof(struct bgp));
    inst.as = (as_t)asNumber;
    if(routerId)
      inet_aton(routerId, &inst.router_id_static);
    bgp = qcapn_new_BGP(cs);
    qcapn_BGP_write(&inst, bgp);
    bgp_inst_nid = qzcclient_createchild (ctxt->p_qzc_sock, &bgp_bm_nid, \
                                          1, &bgp, &bgp_datatype_bgp);
    capn_free(&rc);
    if (bgp_inst_nid == 0)
      {
        *_return = BGP_ERR_FAILED;
        return FALSE;
      }
  }

  /* from bgp_master, inject configuration, and send zmq message to BGP */
  {
    struct capn_ptr bgp;
    struct capn rc;
    struct capn_segment *cs;
    struct QZCGetRep *grep;

    /* get bgp_master configuration */
    grep = qzcclient_getelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
    if(grep == NULL)
      {
        *_return = BGP_ERR_FAILED;
        return FALSE;
      }
    memset(&inst, 0, sizeof(struct bgp));
    qcapn_BGP_read(&inst, grep->data);
    qzcclient_qzcgetrep_free( grep);

    if (inst.notify_zmq_url)
      free (inst.notify_zmq_url);
    if (inst.logFile)
      free (inst.logFile);
    if (inst.logLevel)
      free (inst.logLevel);

    bgp_ctxt = qthrift_vpnservice_get_bgp_context(ctxt);
    bgp_ctxt->asNumber = (as_t) asNumber;
    /* set new configuration */
    inst.as = (as_t)asNumber;
    if(routerId)
      inet_aton (routerId, &inst.router_id_static);
    inst.notify_zmq_url = XSTRDUP(MTYPE_QTHRIFT, ctxt->zmq_subscribe_sock);

    /* log file and log level */
    if (bgp_ctxt->logLevel)
      inst.logLevel = XSTRDUP(MTYPE_QTHRIFT, bgp_ctxt->logLevel);
    else
      inst.logLevel = NULL;
    if (bgp_ctxt->logFile)
      inst.logFile = XSTRDUP(MTYPE_QTHRIFT, bgp_ctxt->logFile);

    inst.default_holdtime = holdTime;
    inst.default_keepalive= keepAliveTime;
    if (stalepathTime)
      inst.stalepath_time = stalepathTime;
    else
      inst.stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
    inst.restart_time = BGP_DEFAULT_RESTART_TIME;
    bgp_flag_set(&inst, BGP_FLAG_GRACEFUL_RESTART);
    if (announceFbit == TRUE)
      bgp_flag_set(&inst, BGP_FLAG_GR_PRESERVE_FWD);
    else
      bgp_flag_unset(&inst, BGP_FLAG_GR_PRESERVE_FWD);
    bgp_flag_set(&inst, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
    if (bgp_eor_update_delay)
      inst.v_update_delay = bgp_eor_update_delay;
    capn_init_malloc(&rc);
    cs = capn_root(&rc).seg;
    bgp = qcapn_new_BGP(cs);
    qcapn_BGP_write(&inst, bgp);
    ret = qzcclient_setelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1, \
                             &bgp, &bgp_datatype_bgp, \
                             NULL, NULL);
    XFREE(MTYPE_QTHRIFT, inst.notify_zmq_url);
    inst.notify_zmq_url = NULL;
    XFREE(MTYPE_QTHRIFT, inst.logFile);
    inst.logFile = NULL;
    if (inst.logLevel)
      {
        XFREE(MTYPE_QTHRIFT, inst.logLevel);
        inst.logLevel = NULL;
      }
    capn_free(&rc);
  }

  if(IS_QTHRIFT_DEBUG)
    {
      if(ret)
        {
          zlog_info ("setLogConfig(%s, %s) OK",
                      bgp_ctxt->logFile,
                      bgp_ctxt->logLevel==NULL?"none":
                      bgp_ctxt->logLevel);
          zlog_info ("startBgp(%u, %s, .., %u, %s) OK",
                      (as_t)asNumber, routerId,
                      stalepathTime,
                      announceFbit == true?"true":"false");
        }
      else
        zlog_err ("startBgp(%u, %s, ..., %u, %s) NOK",
                  (as_t)asNumber, routerId,
                  stalepathTime,
                  announceFbit == true?"true":"false");
    }
  {
    int i, j;
    for (i = 0; i < AFI_MAX;i++ )
      for (j = 0; j < SAFI_MAX; j++)
        if (qthrift_vpnservice_get_bgp_context(ctxt)->multipath_on[i][j])
          ret = qthrift_bgp_set_multipath_internal (ctxt, _return, i, j, 1, error);
  }
  if (ret)
    return TRUE;
  else
    return FALSE;
}

/*
 * Enable and change EBGP maximum number of hops for a given bgp neighbor
 * If Peer is not configured, it returns an error
 * If nHops is set to 0, then the EBGP peers must be connected
 */
gboolean
instance_bgp_configurator_handler_set_ebgp_multihop(BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                    const gint32 nHops, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return qthrift_bgp_set_multihops(ctxt, _return, peerIp, nHops, error);
}

/*
 * Disable EBGP multihop mode by setting the TTL between
 * EBGP neighbors to 0
 * If Peer is not configured, it returns an error
 */
gboolean
instance_bgp_configurator_handler_unset_ebgp_multihop(BgpConfiguratorIf *iface, gint32* _return,
                                                      const gchar * peerIp, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return qthrift_bgp_set_multihops(ctxt, _return, peerIp, 0, error);
}

/*
 * Push Route for a given Route Distinguisher.
 * This route contains an IPv4 prefix, as well as an IPv4 nexthop.
 * A label is also set in the given Route.
 * If no VRF has been found matching the route distinguisher, then
 * an error is returned
 */
gboolean
instance_bgp_configurator_handler_push_route(BgpConfiguratorIf *iface, gint32* _return,
                                             const gchar * prefix, const gchar * nexthop,
                                             const gchar * rd, const gint32 label, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  struct bgp_api_route inst;
  struct prefix_rd rd_inst;
  uint64_t bgpvrf_nid = 0;
  afi_t afi = AFI_IP;
  struct capn_ptr bgpvrfroute;
  struct capn_ptr afikey;
  struct capn rc;
  struct capn_segment *cs;
  int ret;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }

  if (!rd)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* get route distinguisher internal representation */
  memset(&rd_inst, 0, sizeof(struct prefix_rd));
  if (!prefix_str2rd((char *)rd, &rd_inst))
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }

  /* if vrf not found, return an error */
  bgpvrf_nid = qthrift_bgp_configurator_find_vrf(ctxt, &rd_inst, _return);
  if(bgpvrf_nid == 0)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* prepare route entry for AFI=IP */
  memset(&inst, 0, sizeof(struct bgp_api_route));
  inst.label = label;
  if (inet_aton (nexthop, &inst.nexthop) == 0)
    {
      *error = ERROR_BGP_INVALID_NEXTHOP;
      return FALSE;
    }
  if (str2prefix_ipv4(prefix,&inst.prefix) == 0)
    {
      *error = ERROR_BGP_INVALID_PREFIX;
      return FALSE;
    }

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgpvrfroute = qcapn_new_BGPVRFRoute(cs, 0);
  qcapn_BGPVRFRoute_write(&inst, bgpvrfroute);
  /* prepare afi context */
  afikey = qcapn_new_AfiKey(cs);
  capn_write8(afikey, 0, afi);
  /* set route within afi context using QZC set request */
  ret = qzcclient_setelem (ctxt->p_qzc_sock, &bgpvrf_nid, \
                           3, &bgpvrfroute, &bgp_datatype_bgpvrfroute,  \
                           &afikey, &bgp_ctxttype_afisafi_set_bgp_vrf_3);
  if(ret == 0)
    *_return = BGP_ERR_FAILED;
  else
    {
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("pushRoute(prefix %s, nexthop %s, rd %s, label %d) OK", prefix, nexthop, rd, label);
    }
  capn_free(&rc);
  if (ret)
    return TRUE;
  else
    return FALSE;
}

/*
 * Withdraw Route for a given Route Distinguisher and IPv4 prefix
 * If no VRF has been found matching the route distinguisher, then
 * an error is returned
 */
gboolean
instance_bgp_configurator_handler_withdraw_route(BgpConfiguratorIf *iface, gint32* _return,
                                                 const gchar * prefix, const gchar * rd, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  struct bgp_api_route inst;
  struct prefix_rd rd_inst;
  uint64_t bgpvrf_nid = 0;
  afi_t afi = AFI_IP;
  struct capn_ptr bgpvrfroute;
  struct capn_ptr afikey;
  struct capn rc;
  struct capn_segment *cs;
  int ret;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }

  if (!rd)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* get route distinguisher internal representation */
  if (!prefix_str2rd((char *)rd, &rd_inst))
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* if vrf not found, return an error */
  bgpvrf_nid = qthrift_bgp_configurator_find_vrf(ctxt, &rd_inst, _return);
  if(bgpvrf_nid == 0)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* prepare route entry for AFI=IP */
  memset(&inst, 0, sizeof(struct bgp_api_route));
  if (str2prefix_ipv4(prefix,&inst.prefix) == 0)
    {
      *error = ERROR_BGP_INVALID_PREFIX;
      return FALSE;
    }

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgpvrfroute = qcapn_new_BGPVRFRoute(cs, 0);
  qcapn_BGPVRFRoute_write(&inst, bgpvrfroute);
  /* prepare afi context */
  afikey = qcapn_new_AfiKey(cs);
  capn_write8(afikey, 0, afi);
  /* set route within afi context using QZC set request */
  ret = qzcclient_unsetelem (ctxt->p_qzc_sock, &bgpvrf_nid, 3, \
                             &bgpvrfroute, &bgp_datatype_bgpvrfroute, \
                             &afikey, &bgp_ctxttype_afisafi_set_bgp_vrf_3);
  if(ret == 0)
    *_return = BGP_ERR_FAILED;
  else
    {
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("withdrawRoute(prefix %s, rd %s) OK", prefix, rd);
    }
  capn_free(&rc);
  if (ret)
    return TRUE;
  else
    return FALSE;
}

/* 
 * Stop BGP Router for a given AS Number
 * If BGP is already stopped, or give AS is not present, an error is returned
 */
gboolean
instance_bgp_configurator_handler_stop_bgp(BgpConfiguratorIf *iface, gint32* _return,
                                           const gint64 asNumber, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_INACTIVE;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_INACTIVE;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(asNumber < 0)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if((as_t)asNumber != qthrift_vpnservice_get_bgp_context(ctxt)->asNumber)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if (qthrift_kill_in_progress)
    return TRUE;
  qthrift_kill_in_progress = 1;
  /* kill BGP Daemon */
  qthrift_vpnservice_terminate_qzc(ctxt);
  qthrift_vpnservice_terminate_thrift_bgp_cache(ctxt);
  qthrift_vpnservice_terminate_bgp_context(ctxt);
  /* creation of capnproto context */
  qthrift_vpnservice_setup_thrift_bgp_cache(ctxt);
  qthrift_vpnservice_setup_qzc(ctxt);
  qthrift_vpnservice_setup_bgp_context (ctxt);
  if(IS_QTHRIFT_DEBUG)
    zlog_info ("stopBgp(AS %u) OK", (as_t)asNumber);
  qthrift_kill_in_progress = 0;
  qthrift_stopbgp_called = 1;
  return TRUE;
}

/*
 * Create a BGP neighbor for a given routerId, and asNumber
 * If Peer fails to be created, an error is returned.
 * If BGP Router is not started, BGP Peer creation fails,
 * and an error is returned.
 * VPNv4 address family is enabled by default with this neighbor.
 */
gboolean
instance_bgp_configurator_handler_create_peer(BgpConfiguratorIf *iface, gint32* _return,
                                              const gchar *routerId, const gint64 asNumber, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  struct peer inst;
  struct capn_ptr bgppeer;
  struct capn rc;
  struct capn_segment *cs;
  struct qthrift_cache_peer *entry;
  uint64_t peer_nid;
  gboolean ret = FALSE;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(asNumber < 0)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  peer_nid = qthrift_bgp_configurator_find_peer(ctxt, routerId, _return);
  if (peer_nid)
    {
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("createPeer(%s) already present. do nothing.", routerId);
      return TRUE;
    }
  memset(&inst, 0, sizeof(struct peer));
  inst.host = XSTRDUP(MTYPE_QTHRIFT, routerId);
  inst.as = (as_t)asNumber;
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgppeer = qcapn_new_BGPPeer(cs);
  qcapn_BGPPeer_write(&inst, bgppeer);

  peer_nid = qzcclient_createchild (ctxt->p_qzc_sock, &bgp_inst_nid, 2, \
                                  &bgppeer, &bgp_datatype_create_bgp_2);
  capn_free(&rc);
  XFREE(MTYPE_QTHRIFT, inst.host);
  if (peer_nid == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      XFREE(MTYPE_QTHRIFT, inst.host);
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("createPeer(%s,%u) NOK (capnproto error 1)", routerId, (as_t)asNumber);
      return FALSE;
    }
  if(IS_QTHRIFT_DEBUG)
    zlog_info ("createPeer(%s,%u) OK", routerId, (as_t)asNumber);
  /* add peer entry in cache */
  entry = XCALLOC(MTYPE_QTHRIFT, sizeof(struct qthrift_cache_peer));
  entry->peerIp = XSTRDUP(MTYPE_QTHRIFT, routerId);
  entry->peer_nid = peer_nid;
  entry->asNumber = (as_t)asNumber;
  if(IS_QTHRIFT_DEBUG_CACHE)
    zlog_info ("CACHE_PEER : add entry %llx", (long long unsigned int)peer_nid);
  listnode_add(ctxt->bgp_peer_list, entry);

  /* set aficfg */
  ret = qthrift_bgp_afi_config(ctxt, _return, routerId, \
                               AF_AFI_AFI_IP, AF_SAFI_SAFI_MPLS_VPN, TRUE, error);
  if (ret == FALSE && *_return == BGP_ERR_INTERNAL)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("createPeer(%s,%u) NOK (capnproto error 2)", routerId, (as_t)asNumber);
      return FALSE;
    }

  ret = qthrift_bgp_peer_af_flag_config(ctxt, _return, routerId, \
                                        AF_AFI_AFI_IP, AF_SAFI_SAFI_MPLS_VPN,
                                        PEER_FLAG_NEXTHOP_UNCHANGED, TRUE,
                                        error);
  if (ret == FALSE && *_return == BGP_ERR_INTERNAL)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("createPeer(%s,%u) NOK (capnproto error 3)", routerId, (as_t)asNumber);
      return FALSE;
    }
  ret = qthrift_bgp_peer_af_flag_config(ctxt, _return, routerId, \
                                        AF_AFI_AFI_IP, AF_SAFI_SAFI_MPLS_VPN,
                                        PEER_FLAG_SOFT_RECONFIG, TRUE,
                                        error);
  if (ret == FALSE && *_return == BGP_ERR_INTERNAL)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("createPeer(%s,%u) NOK (capnproto error 4)", routerId, (as_t)asNumber);
      return FALSE;
    }
  if (ret)
    return TRUE;
  else
    return FALSE;
}

/*
 * Delete a BGP neighbor for a given IP
 * If BGP neighbor does not exist, an error is returned
 * It returns TRUE if operation succeeded.
 */
gboolean
instance_bgp_configurator_handler_delete_peer(BgpConfiguratorIf *iface, gint32* _return,
                                              const gchar * peerIp, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  uint64_t bgppeer_nid;
  struct qthrift_cache_peer *entry;
  struct listnode *node, *nnode;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  /* if vrf not found, return an error */
  bgppeer_nid = qthrift_bgp_configurator_find_peer(ctxt, peerIp, _return);
  if(bgppeer_nid == 0)
    {
      *_return = BGP_ERR_PARAM;
      *error = ERROR_BGP_PEER_NOTFOUND;
      return FALSE;
    }
  /* destroy node id */
  if( qzcclient_deletenode(ctxt->p_qzc_sock, &bgppeer_nid))
    {
      for (ALL_LIST_ELEMENTS(ctxt->bgp_peer_list, node, nnode, entry))
        if(0 == strcmp(entry->peerIp, peerIp))
        {
          if(IS_QTHRIFT_DEBUG_CACHE)
            zlog_debug ("CACHE_PEER: del entry %llx", (long long unsigned int)entry->peer_nid);
          listnode_delete (ctxt->bgp_peer_list, entry);
          XFREE (MTYPE_QTHRIFT, entry->peerIp);
          entry->peerIp = NULL;
          XFREE (MTYPE_QTHRIFT, entry);
          break;
        }
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("deletePeer(%s) OK", peerIp);
      return TRUE;
    }
  else
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("deletePeer(%s) NOK (capnproto error)", peerIp);
    }
  return FALSE;
}

/*
 * Add a VRF entry for a given route distinguisher
 * Optionally, imported and exported route distinguisher are given.
 * An error is returned if VRF entry already exists.
 * VRF must be removed before being updated
 */
gboolean
instance_bgp_configurator_handler_add_vrf(BgpConfiguratorIf *iface, gint32* _return, const gchar * rd,
                                          const GPtrArray * irts, const GPtrArray * erts, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  struct bgp_vrf instvrf, *bgpvrf_ptr;
  int ret;
  unsigned int i;
  char *rts, *rts_ptr;
  struct capn_ptr bgpvrf;
  struct capn rc;
  struct capn_segment *cs;
  uint64_t bgpvrf_nid;
  struct qthrift_vpnservice_cache_bgpvrf *entry;
  struct ecommunity *rt_import = NULL;
  struct ecommunity *rt_export = NULL;

  /* setup context */
  *_return = 0;
  bgpvrf_ptr = &instvrf;
  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_INACTIVE;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(rd == NULL)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }

  memset(&instvrf, 0, sizeof(struct bgp_vrf));
  /* get route distinguisher internal representation */
  if (!prefix_str2rd((char *)rd, &instvrf.outbound_rd))
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }

  /* check irts and erts */
  /* irts and erts have to be concatenated into temp string */
  rts = XMALLOC(MTYPE_QTHRIFT,2048);
  memset(rts, 0, 2048);
  rts_ptr = rts;
  for(i = 0; i < irts->len; i++){
    rts_ptr+=sprintf(rts_ptr, "rt %s ",(char *)g_ptr_array_index(irts, i));
  }
  if(irts->len)
    {
      rt_import = ecommunity_str2com(rts, ECOMMUNITY_ROUTE_TARGET, 1);
      if (!rt_import)
        {
          *error = ERROR_BGP_INVALID_VRF_RTS;
          XFREE(MTYPE_QTHRIFT, rts);
          return FALSE;
        }
    }

  memset(rts, 0, 2048);
  rts_ptr = rts;
  i = 0;
  for(i = 0; i < erts->len; i++){
    rts_ptr+=sprintf(rts_ptr, "rt %s ",(char *)g_ptr_array_index(erts, i));
  }
  if(erts->len)
    {
      rt_export = ecommunity_str2com(rts, ECOMMUNITY_ROUTE_TARGET, 1);
      if (!rt_export)
        {
          *error = ERROR_BGP_INVALID_VRF_RTS;
          XFREE(MTYPE_QTHRIFT, rts);
          return FALSE;
        }
    }
  XFREE(MTYPE_QTHRIFT, rts);

  /* retrive bgpvrf context or create new bgpvrf context */
  bgpvrf_nid = qthrift_bgp_configurator_find_vrf(ctxt, &instvrf.outbound_rd, _return);
  if(bgpvrf_nid == 0)
    {
      /* allocate bgpvrf structure */
      capn_init_malloc(&rc);
      cs = capn_root(&rc).seg;
      bgpvrf = qcapn_new_BGPVRF(cs);
      qcapn_BGPVRF_write(&instvrf, bgpvrf);
      bgpvrf_nid = qzcclient_createchild (ctxt->p_qzc_sock, &bgp_inst_nid, 3, \
                                          &bgpvrf, &bgp_datatype_bgpvrf);
      capn_free(&rc);
      if (bgpvrf_nid == 0)
        {
          *_return = BGP_ERR_FAILED;
          return FALSE;
        }
      /* add vrf entry in qthrift list */
      entry = XCALLOC(MTYPE_QTHRIFT, sizeof(struct qthrift_vpnservice_cache_bgpvrf));
      entry->outbound_rd = instvrf.outbound_rd;
      entry->bgpvrf_nid = bgpvrf_nid;
      if(IS_QTHRIFT_DEBUG_CACHE)
        zlog_debug ("CACHE_VRF: add entry %llx", (long long unsigned int)bgpvrf_nid);
      listnode_add(ctxt->bgp_vrf_list, entry);
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("addVrf(%s) OK", rd);
    }
  /* max_mpath has been set in bgpd with a default value owned by bgpd itself
   * must get back this value before going further else max_mpath will be overwritten
   * by first bgpvrf read */
  {
    struct QZCGetRep *grep_vrf;
    grep_vrf = qzcclient_getelem (ctxt->p_qzc_sock, &bgpvrf_nid, 1,       \
                                  NULL, NULL, NULL, NULL);
    if(grep_vrf == NULL)
      {
        *_return = BGP_ERR_FAILED;
        return FALSE;
      }
    memset(&instvrf, 0, sizeof(struct bgp_vrf));
    qcapn_BGPVRF_read(&instvrf, grep_vrf->data);
    /* reset qzc reply and rc context */
    qzcclient_qzcgetrep_free( grep_vrf);
  }

  /* Unintern import and export communities set in qcapn_BGPVRF_read */
  if (instvrf.rt_import)
    {
      ecommunity_unintern (&instvrf.rt_import);
      instvrf.rt_import = NULL;
    }
  if (instvrf.rt_export)
    {
      ecommunity_unintern (&instvrf.rt_export);
      instvrf.rt_export = NULL;
    }

  /* configuring bgp vrf with import and export communities */
  if(irts->len)
    instvrf.rt_import = rt_import;
  if(erts->len)
    instvrf.rt_export = rt_export;

  /* allocate bgpvrf structure for set */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgpvrf = qcapn_new_BGPVRF(cs);
  qcapn_BGPVRF_write(&instvrf, bgpvrf);
  ret = qzcclient_setelem (ctxt->p_qzc_sock, &bgpvrf_nid, 1, \
                           &bgpvrf, &bgp_datatype_bgpvrf,\
                           NULL, NULL);
  if(ret == 0)
    {
      *_return = BGP_ERR_FAILED;
    }
  if (bgpvrf_ptr->rt_import)
    ecommunity_free (&bgpvrf_ptr->rt_import);
  if (bgpvrf_ptr->rt_export)
    ecommunity_free (&bgpvrf_ptr->rt_export);
  capn_free(&rc);
  if (ret)
    return TRUE;
  else
    return FALSE;
}

/*
 * Delete a VRF entry for a given route distinguisher
 * An error is returned if VRF entry does not exist
 */
gboolean instance_bgp_configurator_handler_del_vrf(BgpConfiguratorIf *iface, gint32* _return,
                                                   const gchar * rd, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  uint64_t bgpvrf_nid;
  struct prefix_rd rd_inst;
  struct qthrift_vpnservice_cache_bgpvrf *entry;
  struct listnode *node, *nnode;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(rd == NULL)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* get route distinguisher internal representation */
  memset(&rd_inst, 0, sizeof(struct prefix_rd));
  if (!prefix_str2rd((char *)rd, &rd_inst))
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* if vrf not found, return an error */
  bgpvrf_nid = qthrift_bgp_configurator_find_vrf(ctxt, &rd_inst, _return);
  if(bgpvrf_nid == 0)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if( qzcclient_deletenode(ctxt->p_qzc_sock, &bgpvrf_nid))
    {
      for (ALL_LIST_ELEMENTS(ctxt->bgp_vrf_list, node, nnode, entry))
        if(0 == prefix_rd_cmp(&entry->outbound_rd, &rd_inst))
        {
          if(IS_QTHRIFT_DEBUG_CACHE)
            zlog_debug ("CACHE_VRF: del entry %llx", (long long unsigned int)entry->bgpvrf_nid);
          listnode_delete (ctxt->bgp_vrf_list, entry);
          XFREE (MTYPE_QTHRIFT, entry);
          if(IS_QTHRIFT_DEBUG)
            {
              zlog_info ("delVrf(%s) OK", rd);
            }
          return TRUE;
        }
    }
  else
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("delVrf(%s) NOK (capnproto error)", rd);
    }
  return FALSE;
}

/*
 * Force Source Address of BGP Speaker
 * An error is returned if neighbor is not configured
 * if srcIp is not set, then the command will unset
 * BGP Speaker Source address
 */
gboolean
instance_bgp_configurator_handler_set_update_source (BgpConfiguratorIf *iface, gint32* _return, const gchar * peerIp,
                                                     const gchar * srcIp, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  uint64_t peer_nid;
  capn_ptr peer_ctxt;
  struct QZCGetRep *grep_peer;
  struct peer peer;
  struct capn rc;
  struct capn_segment *cs;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *error = g_error_new(0, 0, "BGP AS not started");
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  if(peerIp == NULL)
    {
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* if peer not found, return an error */
  peer_nid = qthrift_bgp_configurator_find_peer(ctxt, peerIp, _return);
  if(peer_nid == 0)
    {
      *_return = BGP_ERR_PARAM;
      *error = ERROR_BGP_PEER_NOTFOUND;
      return FALSE;
    }
  /* retrieve peer context */
  grep_peer = qzcclient_getelem (ctxt->p_qzc_sock, &peer_nid, 2, \
                                 NULL, NULL, NULL, NULL);
  if(grep_peer == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  memset(&peer, 0, sizeof(struct peer));
  qcapn_BGPPeer_read(&peer, grep_peer->data);
  /* change updateSource */
  if(srcIp)
    {
      peer.update_source = (char *)srcIp;
      /* force to set update source only */
      peer.flags |=  PEER_FLAG_USE_CONFIGURED_SOURCE;
    }
  else
    {
      if (peer.update_source)
        free (peer.update_source);
      peer.update_source = NULL;
      /* unset update source flag */
      peer.flags &= ~PEER_FLAG_USE_CONFIGURED_SOURCE;
    }
  qzcclient_qzcgetrep_free( grep_peer);
  /* prepare QZCSetRequest context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  peer_ctxt = qcapn_new_BGPPeer(cs);
  qcapn_BGPPeer_write(&peer, peer_ctxt);
  if(qzcclient_setelem (ctxt->p_qzc_sock, &peer_nid, 2, \
                        &peer_ctxt, &bgp_datatype_create_bgp_2, \
                        NULL, NULL))
    {
      if(IS_QTHRIFT_DEBUG)
        {
          if(srcIp == 0)
            zlog_info ("unsetUpdateSource(%s) OK", peerIp);
          else
            zlog_info ("setUpdateSource(%s, %s) OK", peerIp, srcIp);
        }
    }
  else
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      if(IS_QTHRIFT_DEBUG)
        {
          if(srcIp == 0)
            zlog_info ("unsetUpdateSource(%s) NOK (capnproto error)", peerIp);
          else
            zlog_info ("setUpdateSource(%s) NOK (capnproto error)", peerIp);
        }
    }
  capn_free(&rc);
  return TRUE;
}
 
/*
 * Unset Source Address of BGP Speaker
 * An error is returned if neighbor is not configured
 */
gboolean
instance_bgp_configurator_handler_unset_update_source (BgpConfiguratorIf *iface, gint32* _return,
                                                       const gchar * peerIp, GError **error)
{
  return instance_bgp_configurator_handler_set_update_source( iface, _return, peerIp, NULL, error);
}

/*
 * enable MP-BGP routing information exchange with a given neighbor
 * for a given address family identifier and subsequent address family identifier.
 */
gboolean instance_bgp_configurator_handler_enable_address_family(BgpConfiguratorIf *iface, gint32* _return,
                                                                 const gchar * peerIp, const af_afi afi,
                                                                 const af_safi safi, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  gboolean ret;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  ret = qthrift_bgp_afi_config(ctxt, _return, peerIp, afi, safi, TRUE, error);
  if (ret == FALSE && *_return == BGP_ERR_INTERNAL)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("enableAddressFamily(%s, %u, %u) NOK (capnproto error)", peerIp, afi, safi);
    }
  if (ret)
    return TRUE;
  else
    return FALSE;
}

/*
 * disable MP-BGP routing information exchange with a given neighbor
 * for a given address family identifier and subsequent address family identifier.
 */
gboolean
instance_bgp_configurator_handler_disable_address_family(BgpConfiguratorIf *iface, gint32* _return,
                                                         const gchar * peerIp, const af_afi afi,
                                                         const af_safi safi, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  gboolean ret;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  ret = qthrift_bgp_afi_config(ctxt, _return, peerIp, afi, safi, FALSE, error);
  if (ret == FALSE && *_return == BGP_ERR_INTERNAL)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_INTERNAL;
      if(IS_QTHRIFT_DEBUG)
        zlog_info ("disableAddressFamily(%s, %u, %u) NOK (capnproto error)", peerIp, afi, safi);
    }
  if (ret)
    return TRUE;
  else
    return FALSE;
}

gboolean
instance_bgp_configurator_handler_set_log_config (BgpConfiguratorIf *iface, gint32* _return, const gchar * logFileName,
                                                  const gchar * logLevel, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL)
    {
      qthrift_vpnservice_setup_bgp_context(ctxt);
    }
  if (qthrift_vpnservice_get_bgp_context(ctxt)->logFile)
    {
      free (qthrift_vpnservice_get_bgp_context(ctxt)->logFile);
      qthrift_vpnservice_get_bgp_context(ctxt)->logFile = NULL;
    }
  if (qthrift_vpnservice_get_bgp_context(ctxt)->logLevel)
    {
      free (qthrift_vpnservice_get_bgp_context(ctxt)->logLevel);
      qthrift_vpnservice_get_bgp_context(ctxt)->logLevel = NULL;
    }
  if (logFileName)
    {
      qthrift_vpnservice_get_bgp_context(ctxt)->logFile = strdup ( logFileName);
    }
  else
    {
      qthrift_vpnservice_get_bgp_context(ctxt)->logFile = strdup ( BGP_DEFAULT_LOG_FILE);
    }
  if (logLevel)
    {
      qthrift_vpnservice_get_bgp_context(ctxt)->logLevel = strdup ( logLevel);
    }
  else
    {
      qthrift_vpnservice_get_bgp_context(ctxt)->logLevel = strdup ( BGP_DEFAULT_LOG_LEVEL);
    }
  /* configure log settings to qthrift daemon too */
  set_log_file_with_level (logFileName, logLevel);
  /* config stored, but not sent to BGP. silently return */
  if (qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      return TRUE;
    }
  return qthrift_bgp_set_log_config (ctxt, qthrift_vpnservice_get_bgp_context(ctxt), _return, error);
}

/*
 * enable Graceful Restart for BGP Router, as well as stale path timer.
 * if the stalepathTime is set to 0, then the graceful restart feature will be disabled
 */
gboolean
instance_bgp_configurator_handler_enable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return,
                                                           const gint32 stalepathTime, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  struct capn_ptr bgp;
  struct capn rc;
  struct capn_segment *cs;
  struct bgp inst;
  struct QZCGetRep *grep;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }
  /* get bgp_master configuration */
  grep = qzcclient_getelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
  if(grep == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  memset(&inst, 0, sizeof(struct bgp));
  qcapn_BGP_read(&inst, grep->data);
  qzcclient_qzcgetrep_free( grep);
  /* update bgp configuration with graceful status */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgp = qcapn_new_BGP(cs);
  /* set default stalepath time */
  if(stalepathTime == 0)
    inst.stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
  else
    inst.stalepath_time = stalepathTime;
  if(stalepathTime)
    bgp_flag_set(&inst, BGP_FLAG_GRACEFUL_RESTART);
  else
    bgp_flag_unset(&inst, BGP_FLAG_GRACEFUL_RESTART);
  inst.restart_time = BGP_DEFAULT_RESTART_TIME;
  qcapn_BGP_write(&inst, bgp);
  qzcclient_setelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1, \
                     &bgp, &bgp_datatype_bgp, NULL, NULL);
  capn_free(&rc);
  if (inst.notify_zmq_url)
    free (inst.notify_zmq_url);
  if (inst.logFile)
    free (inst.logFile);
  if (inst.logLevel)
    free (inst.logLevel);
  return TRUE;
}

/* disable Graceful Restart for BGP Router */
gboolean
instance_bgp_configurator_handler_disable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return, GError **error)
{
  return instance_bgp_configurator_handler_enable_graceful_restart(iface, _return, 0, error);
}

struct tbliter_v4 *prev_iter_table_ptr = NULL;
struct tbliter_v4 prev_iter_table_entry;
gboolean
instance_bgp_configurator_handler_get_routes (BgpConfiguratorIf *iface, Routes ** _return,
                                              const gint32 optype, const gint32 winSize, GError **error)
{
  struct capn_ptr afikey, iter_table, *iter_table_ptr = NULL;
  struct capn rc;
  struct capn_segment *cs;
  afi_t afi = AFI_IP;
  struct qthrift_vpnservice *ctxt = NULL;
  uint64_t bgpvrf_nid;
  struct QZCGetRep *grep_route = NULL;
  struct bgp_api_route inst_route;
  struct qthrift_vpnservice_cache_bgpvrf *entry, *entry2;
  struct listnode *node, *nnode;
  char rdstr[RD_ADDRSTRLEN];
  int route_updates_max, route_updates;
  Update *upd;

  qthrift_vpnservice_get_context (&ctxt);
  if (ctxt == NULL
      || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      (*_return)->errcode = BGP_ERR_FAILED;
      (*_return)->__isset_errcode = TRUE;
      return FALSE;
    }
  /* for first getRoutes, setup the list of bgpvrfs entries */
  if(optype == GET_RTS_INIT)
    {
      for (ALL_LIST_ELEMENTS(ctxt->bgp_get_routes_list, node, nnode, entry))
        {
          listnode_delete(ctxt->bgp_get_routes_list, entry);
          XFREE (MTYPE_QTHRIFT, entry);
        }
      for (ALL_LIST_ELEMENTS(ctxt->bgp_vrf_list, node, nnode, entry))
        {
          entry2 = XCALLOC(MTYPE_QTHRIFT, sizeof(struct qthrift_vpnservice_cache_bgpvrf));
          entry2->outbound_rd = entry->outbound_rd;
          entry2->bgpvrf_nid = entry->bgpvrf_nid;
          listnode_add(ctxt->bgp_get_routes_list, entry2);
        }
      prev_iter_table_ptr = NULL;
      memset(&prev_iter_table_entry, 0, sizeof(struct tbliter_v4));
    }
  /* initialise context */
  route_updates_max = MAX(winSize/96, 1);
  route_updates = 0;
  (*_return)->more = 1;
  (*_return)->__isset_more = TRUE;
  (*_return)->errcode = 0;
  (*_return)->__isset_updates = TRUE;
  entry2 = NULL;
  /* parse current vrfs and vrfs not already parsed */
  for (ALL_LIST_ELEMENTS(ctxt->bgp_get_routes_list, node, nnode, entry))
    {
      unsigned long mpath_iter_ptr = 0;

      /* remove current bgpvrf entry, all routes have been parsed */
      if(entry2)
        {
          listnode_delete(ctxt->bgp_get_routes_list, entry2);
          if(entry2)
            XFREE (MTYPE_QTHRIFT, entry2);
          entry2 = NULL;
        }
      if(IS_QTHRIFT_DEBUG_CACHE)
        zlog_debug ("RTS: parsing vrf nid %llx", (long long unsigned int)entry->bgpvrf_nid);
      bgpvrf_nid = entry->bgpvrf_nid;
      do
        {
           /* prepare afi context */
          capn_init_malloc(&rc);
          cs = capn_root(&rc).seg;
          afikey = qcapn_new_AfiKey(cs);
          capn_resolve(&afikey);
          capn_write8(afikey, 0, afi);
	  if(prev_iter_table_ptr)
	  {
                 iter_table = qcapn_new_VRFTableIter(cs);
                 qcapn_VRFTableIter_write(&prev_iter_table_entry, iter_table);
                 iter_table_ptr = &iter_table;
	  }
	  else
	  {
                 iter_table_ptr = NULL;
	  }
          /* get route entry from the vrf rib table */
          /* currently entries from the vrf route table XXX */
          grep_route = qzcclient_getelem (ctxt->p_qzc_sock, &bgpvrf_nid, 2, \
                                          &afikey, &bgp_ctxtype_bgpvrfroute, \
                                          iter_table_ptr, &bgp_itertype_bgpvrfroute);
          if(grep_route == NULL || grep_route->datatype == 0)
            {
              /* goto next vrf */
              prev_iter_table_ptr = NULL;
              qzcclient_qzcgetrep_free(grep_route);
              capn_free(&rc);
              break;
            }
          memset(&inst_route, 0, sizeof(struct bgp_api_route));
          qcapn_BGPVRFRoute_read(&inst_route, grep_route->data);
          if(grep_route->datatype != 0)
            {
              /* if datatype is valid, iter type may be valid. continue */
              qcapn_BGPVRFRoute_read(&inst_route, grep_route->data);

              /* this is possibly a multipath route, get additionnal data in the
               same grep_route->data exchange channel to get a pointer to the
               next bgp_info struct linked to that route.
               The offset of CAPN_BGPVRF_ROUTE_DEF_SIZE is because such data has a
               8 bytes offset with usual VRFRoute exchanged via capn'proto */
              qcapn_BGPVRFInfoIter_read(&mpath_iter_ptr, grep_route->data, CAPN_BGPVRF_ROUTE_DEF_SIZE);
            }

          if(grep_route->itertype != 0)
            {
              memset(&prev_iter_table_entry, 0, sizeof(prev_iter_table_entry));
              qcapn_VRFTableIter_read(&prev_iter_table_entry, grep_route->nextiter);
              prev_iter_table_ptr = &prev_iter_table_entry;
            }
          else
            {
              prev_iter_table_ptr = NULL;
            }
          qzcclient_qzcgetrep_free(grep_route);
          capn_free(&rc);
          /* bypass route entries with zeroes */
          if ( (inst_route.nexthop.s_addr == 0) &&              \
               (inst_route.prefix.prefix.s_addr == 0) &&        \
               (inst_route.prefix.prefixlen == 0) &&            \
               (inst_route.label == 0))
            {
              if(prev_iter_table_ptr != NULL)
                {
                  continue;
                }
              else
                {
                  /* goto next vrf */
                  break;
                }
            }
          /* add entry in update */
          upd = g_object_new (TYPE_UPDATE, NULL);
          upd->type = BGP_RT_ADD;
          upd->prefixlen = inst_route.prefix.prefixlen;
          upd->prefix = g_strdup(inet_ntop(AF_INET, &(inst_route.prefix.prefix), rdstr, RD_ADDRSTRLEN));
          upd->nexthop = g_strdup(inet_ntop(AF_INET, &(inst_route.nexthop), rdstr, RD_ADDRSTRLEN));
          upd->label = inst_route.label;
          upd->rd = g_strdup(prefix_rd2str(&(entry->outbound_rd), rdstr, RD_ADDRSTRLEN));

          if(IS_QTHRIFT_DEBUG_SHOW)
            zlog_info("getRoutes(rd %s,pfx %s/%d, nh %s, label %u)",
                      upd->rd, upd->prefix, upd->prefixlen, upd->nexthop, upd->label);

          g_ptr_array_add((*_return)->updates, upd);
          route_updates++;

          /* multipath specific loop */
          while (mpath_iter_ptr)
            {
              struct QZCGetRep *grep_multipath_route = NULL;
              struct capn_ptr iter_table_bim;
              struct capn_segment *csi;
              struct bgp_api_route inst_multipath_route;

               /* prepare context, it will be dedicated to loop on multipath routes attached to a vpnv4 route */
              capn_init_malloc(&rc);
              csi = capn_root(&rc).seg;
              iter_table_bim = qcapn_new_BGPVRFInfoIter(csi);
              /* provide internal pointer value to the next struct bgp_info of a route is has one */
              qcapn_BGPVRFInfoIter_write(mpath_iter_ptr, iter_table_bim, 0);

              /* get route entry from the vrf rib table */
              grep_multipath_route = qzcclient_getelem (ctxt->p_qzc_sock, &bgpvrf_nid, 4, \
                                              NULL, NULL, \
                                              &iter_table_bim, &bgp_itertype_bgpvrfroute);
              if(grep_multipath_route == NULL || grep_multipath_route->datatype == 0)
                {
                  /* goto next prefix */
                  qzcclient_qzcgetrep_free(grep_multipath_route);
                  capn_free(&rc);
                  break;
                }
              memset(&inst_multipath_route, 0, sizeof(struct bgp_api_route));
              qcapn_BGPVRFRoute_read(&inst_multipath_route, grep_multipath_route->data);
              if(grep_route->datatype != 0)
                {
                  /* if datatype is valid, iter type may be valid. continue */
                  qcapn_BGPVRFRoute_read(&inst_multipath_route, grep_multipath_route->data);
                }

              mpath_iter_ptr = 0;
              /* look for another multipath entry with that check */
              if(grep_multipath_route->itertype != 0)
                {
                  /* there is another multipath entry after this one, store it into mpath_iter_ptr */
                  qcapn_BGPVRFInfoIter_read(&mpath_iter_ptr, grep_multipath_route->nextiter, 0);
                }
              qzcclient_qzcgetrep_free(grep_multipath_route);
              capn_free(&rc);

              /* bypass route entries with zeroes */
              if ( (inst_multipath_route.nexthop.s_addr == 0) &&              \
                   (inst_multipath_route.prefix.prefix.s_addr == 0) &&        \
                   (inst_multipath_route.prefix.prefixlen == 0) &&            \
                   (inst_multipath_route.label == 0))
                {
                  break;
                }
              /* add entry in update */
              upd = g_object_new (TYPE_UPDATE, NULL);
              upd->type = BGP_RT_ADD;
              upd->prefixlen = inst_route.prefix.prefixlen; /* keep prefix from main loop */
              upd->prefix = g_strdup(inet_ntop(AF_INET, &(inst_route.prefix.prefix), rdstr, RD_ADDRSTRLEN));
              upd->nexthop = g_strdup(inet_ntop(AF_INET, &(inst_multipath_route.nexthop), rdstr, RD_ADDRSTRLEN));
              upd->label = inst_multipath_route.label;
              upd->rd = g_strdup(prefix_rd2str(&(entry->outbound_rd), rdstr, RD_ADDRSTRLEN));
              if(IS_QTHRIFT_DEBUG_SHOW)
                zlog_info("getRoutes(rd %s,pfx %s/%d, nh %s, label %u)",
                          upd->rd, upd->prefix, upd->prefixlen, upd->nexthop, upd->label);
              g_ptr_array_add((*_return)->updates, upd);
              route_updates++;

              if (!mpath_iter_ptr)
                break; /* no more nexthop with MULTIPATH flag, go to next prefix */
            }

          /* prepare next extraction */
          if(prev_iter_table_ptr == NULL)
            {
              /* goto next vrf */
              break;
            }
          if(route_updates >= route_updates_max)
            {
              /* save last iteration table */
              return TRUE;
            }
        } while(1);
      entry2 = entry;
    }
  if(route_updates == 0)
    {
      (*_return)->errcode = BGP_ERR_NOT_ITER;
      (*_return)->__isset_errcode = TRUE;
    }
  (*_return)->more = 0;
  (*_return)->__isset_more = TRUE;
  return TRUE;
}

/*
 * Enable/disable multipath feature. capnproto exchange
 */
static gboolean
qthrift_bgp_set_multipath_internal(struct qthrift_vpnservice *ctxt,  gint32* _return,
                                   afi_t af, safi_t saf, const gint32 enable, GError **error)
{
  struct capn rc;
  struct capn_segment *cs;
  struct bgp inst;
  struct QZCGetRep *grep;
  capn_ptr afisafi_ctxt, nctxt;

  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  afisafi_ctxt = qcapn_new_AfiSafiKey(cs);
  capn_write8(afisafi_ctxt, 0, af);
  capn_write8(afisafi_ctxt, 1, saf);
  /* retrieve bgp context */
  grep = qzcclient_getelem (ctxt->p_qzc_sock, &bgp_inst_nid, 3, \
                            &afisafi_ctxt, &bgp_ctxttype_afisafi,\
                            NULL, NULL);
  if(grep == NULL)
    {
      *_return = BGP_ERR_FAILED;
      capn_free(&rc);
      return FALSE;
    }
  memset(&inst, 0, sizeof(struct bgp));
  /* prepare afisafi context */
  memset(&inst, 0, sizeof(struct bgp));
  qcapn_BGPAfiSafi_read(&inst, grep->data, af, saf);
  /* set flag per afi/safi */
  if(enable)
    {
      bgp_af_flag_set(&inst, af, saf, BGP_CONFIG_ASPATH_MULTIPATH_RELAX);
      bgp_af_flag_set(&inst, af, saf, BGP_CONFIG_MULTIPATH);
    }
  else
    {
      bgp_af_flag_unset(&inst, af, saf, BGP_CONFIG_ASPATH_MULTIPATH_RELAX);
      bgp_af_flag_unset(&inst, af, saf, BGP_CONFIG_MULTIPATH);
    }

  /* reset qzc reply and rc context */
  qzcclient_qzcgetrep_free(grep);
  /* prepare QZCSetRequest context */
  nctxt = qcapn_new_BGPAfiSafi(cs);
  qcapn_BGPAfiSafi_write(&inst, nctxt, af, saf);
  /* put max value as a supplementary data in pipe */
  capn_write8(nctxt, 3, QTHRIFT_MAXPATH_DEFAULT_VAL);
  if(qzcclient_setelem (ctxt->p_qzc_sock, &bgp_inst_nid, 2, \
                        &nctxt, &bgp_datatype_bgp,\
                        &afisafi_ctxt, &bgp_ctxttype_afisafi))
  {
    if(IS_QTHRIFT_DEBUG)
      {
        if(enable)
          zlog_info ("enableMultipath for afi:%d safi:%d OK",
                     qthrift_afi_value (af), qthrift_safi_value (saf));
        else
          zlog_info ("disableMultipath for afi:%d safi:%d OK",
                     qthrift_afi_value (af), qthrift_safi_value (saf));
      }
  }
  capn_free(&rc);
  return TRUE;
}

/*
 * Enable/disable multipath feature for VPNv4 address family
 */
static gboolean
qthrift_bgp_set_multipath(struct qthrift_vpnservice *ctxt,  gint32* _return, const af_afi afi,
                          const af_safi safi, const gint32 enable, GError **error)
{
  int af, saf;
  gboolean ret;

  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL)
    {
      qthrift_vpnservice_setup_bgp_context(ctxt);
    }
  if(afi != AF_AFI_AFI_IP)
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  else
    af = AFI_IP;
  if(safi != AF_SAFI_SAFI_MPLS_VPN)
    {
      *error = ERROR_BGP_AFISAFI_NOTSUPPORTED;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  else
    saf = SAFI_MPLS_VPN;
  ret = qthrift_vpnservice_set_bgp_context_multipath (qthrift_vpnservice_get_bgp_context(ctxt),
                                                      afi, safi, (uint8_t) enable, _return, error);
  /* silently leave command if bgp did not start */
  if((ret == TRUE) && IS_QTHRIFT_DEBUG)
    {
      if(enable)
        zlog_info ("enableMultipath config for afi:%d safi:%d OK",
                   afi, safi);
      else
        zlog_info ("disableMultipath config for afi:%d safi:%d OK",
                   afi, safi);
    }
  if (qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      if (ret)
        return TRUE;
      else
        return FALSE;
    }
  ret = qthrift_bgp_set_multipath_internal (ctxt, _return, af, saf,
                                            enable, error);
  if (ret)
    return TRUE;
  else
    return FALSE;
}

gboolean
instance_bgp_configurator_handler_enable_multipath(BgpConfiguratorIf *iface, gint32* _return,
                                                   const af_afi afi, const af_safi safi, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return qthrift_bgp_set_multipath(ctxt, _return, afi, safi, 1, error);
}

gboolean
instance_bgp_configurator_handler_disable_multipath(BgpConfiguratorIf *iface, gint32* _return,
                                                    const af_afi afi, const af_safi safi, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  return qthrift_bgp_set_multipath(ctxt, _return, afi, safi, 0, error);
}


/*
 * Enable/disable multipath feature for VPNv4 address family
 */
gboolean
instance_bgp_configurator_handler_multipaths(BgpConfiguratorIf *iface, gint32* _return,
                                             const gchar * rd, const gint32 maxPath, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  struct capn_ptr bgpvrf;
  struct capn rc;
  struct capn_segment *cs;
  struct bgp_vrf instvrf;
  uint64_t bgpvrf_nid;
  struct prefix_rd rd_inst;
  struct QZCGetRep *grep_vrf;
  int ret;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
  {
    *_return = BGP_ERR_FAILED;
    return FALSE;
  }

  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }

  if(maxPath < 1 || maxPath > 64)
    {
      *error = ERROR_BGP_INVALID_MAXPATH;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  if(rd == NULL)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }

  /* get route distinguisher internal representation */
  memset(&rd_inst, 0, sizeof(struct prefix_rd));
  if (!prefix_str2rd((char *)rd, &rd_inst))
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }
  /* if vrf not found, return an error */
  bgpvrf_nid = qthrift_bgp_configurator_find_vrf(ctxt, &rd_inst, _return);
  if(bgpvrf_nid == 0)
    {
      *error = ERROR_BGP_RD_NOTFOUND;
      *_return = BGP_ERR_PARAM;
      return FALSE;
    }

  grep_vrf = qzcclient_getelem (ctxt->p_qzc_sock, &bgpvrf_nid, 1, \
                                NULL, NULL, NULL, NULL);
  if(grep_vrf == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }
  memset(&instvrf, 0, sizeof(struct bgp_vrf));
  qcapn_BGPVRF_read(&instvrf, grep_vrf->data);

  /* update max_mpath */
  instvrf.max_mpath_configured = maxPath;
  /* reset qzc reply and rc context */
  qzcclient_qzcgetrep_free( grep_vrf);
  /* prepare QZCSetRequest context */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgpvrf = qcapn_new_BGPVRF(cs);
  qcapn_BGPVRF_write(&instvrf, bgpvrf);
  ret = qzcclient_setelem (ctxt->p_qzc_sock, &bgpvrf_nid, 1, \
                           &bgpvrf, &bgp_datatype_bgpvrf,\
                           NULL, NULL);
  capn_free(&rc);
  if(ret == 0)
  {
    *_return = BGP_ERR_FAILED;
    return FALSE;
  }
  else
  {
    if(IS_QTHRIFT_DEBUG)
      {
        zlog_info ("maximum path for VRF %s set to %d", rd, maxPath);
      }
  }

  /* Unintern import and export communities set in qcapn_BGPVRF_read */
  if (instvrf.rt_import)
    {
      ecommunity_unintern (&instvrf.rt_import);
      instvrf.rt_import = NULL;
    }
  if (instvrf.rt_export)
    {
      ecommunity_unintern (&instvrf.rt_export);
      instvrf.rt_export = NULL;
    }

  return TRUE;
}

/*
 * Enable eor and configure the update delay time.
 */
gboolean
instance_bgp_configurator_enable_eor_delay(BgpConfiguratorIf *iface, gint32* _return,
                                           const gint32 delay, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
  struct capn_ptr bgp;
  struct capn rc;
  struct capn_segment *cs;
  struct bgp inst;
   struct QZCGetRep *grep;
  int ret;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
  {
    *_return = BGP_ERR_FAILED;
    return FALSE;
  }

  if (delay < 0 || delay > MAX_EOR_UPDATE_DELAY)
    {
      *_return = BGP_ERR_PARAM;
      *error = ERROR_BGP_INVALID_UPDATE_DELAY;
      return FALSE;
    }

  bgp_eor_update_delay = delay;

  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      return TRUE;
    }

  /* get bgp_master configuration */
  grep = qzcclient_getelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
  if(grep == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }

  memset(&inst, 0, sizeof(struct bgp));
  qcapn_BGP_read(&inst, grep->data);
  qzcclient_qzcgetrep_free( grep);

  if (inst.v_update_delay == delay)
    return TRUE;

  /* update bgp configuration with graceful status */
  capn_init_malloc(&rc);
  cs = capn_root(&rc).seg;
  bgp = qcapn_new_BGP(cs);
  inst.v_update_delay = delay;
  qcapn_BGP_write(&inst, bgp);
  qzcclient_setelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1,            \
                     &bgp, &bgp_datatype_bgp, NULL, NULL);
  capn_free(&rc);
  if (inst.notify_zmq_url)
    free (inst.notify_zmq_url);
  if (inst.logFile)
    free (inst.logFile);
  if (inst.logLevel)
    free (inst.logLevel);
  
  if(IS_QTHRIFT_DEBUG)
      zlog_info ("enableEORDelay (%d) OK", delay);
  return TRUE;
}

/* Send EoR message */
gboolean
instance_bgp_configurator_send_eor(BgpConfiguratorIf *iface, gint32* _return, GError **error)
{
  struct qthrift_vpnservice *ctxt = NULL;
   struct QZCGetRep *grep;
  int ret;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
  {
    *_return = BGP_ERR_FAILED;
    return FALSE;
  }

  if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL || qthrift_vpnservice_get_bgp_context(ctxt)->asNumber == 0)
    {
      *_return = BGP_ERR_FAILED;
      *error = ERROR_BGP_AS_NOT_STARTED;
      return FALSE;
    }

  /* get bgp_master configuration */
  grep = qzcclient_getelem (ctxt->p_qzc_sock, &bgp_inst_nid, 1, NULL, NULL, NULL, NULL);
  if(grep == NULL)
    {
      *_return = BGP_ERR_FAILED;
      return FALSE;
    }

  /* notify bgp to send EOR */
  qzcclient_setelem (ctxt->p_qzc_sock, &bgp_inst_nid, 3,            \
                     &grep->data, &bgp_datatype_bgp, NULL, NULL);
  qzcclient_qzcgetrep_free( grep);

  if (IS_QTHRIFT_DEBUG)
    zlog_info ("send EOR() OK");

  return TRUE;
}

static void
  instance_bgp_configurator_handler_finalize(GObject *object)
{
  G_OBJECT_CLASS (instance_bgp_configurator_handler_parent_class)->finalize (object);
}

/* InstanceBgpConfiguratorHandler's class initializer */
static void
instance_bgp_configurator_handler_class_init (InstanceBgpConfiguratorHandlerClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  BgpConfiguratorHandlerClass *bgp_configurator_handler_class = BGP_CONFIGURATOR_HANDLER_CLASS (klass);

  /* Register our destructor */
  gobject_class->finalize = instance_bgp_configurator_handler_finalize;

  /* Register our implementations of CalculatorHandler's methods */
  bgp_configurator_handler_class->create_peer =
    instance_bgp_configurator_handler_create_peer;
 
  bgp_configurator_handler_class->start_bgp =
    instance_bgp_configurator_handler_start_bgp;

  bgp_configurator_handler_class->stop_bgp =
    instance_bgp_configurator_handler_stop_bgp;

  bgp_configurator_handler_class->delete_peer =
    instance_bgp_configurator_handler_delete_peer;

  bgp_configurator_handler_class->add_vrf =
    instance_bgp_configurator_handler_add_vrf;

  bgp_configurator_handler_class->del_vrf =
    instance_bgp_configurator_handler_del_vrf;

  bgp_configurator_handler_class->push_route =
    instance_bgp_configurator_handler_push_route;

  bgp_configurator_handler_class->withdraw_route =
    instance_bgp_configurator_handler_withdraw_route;

 bgp_configurator_handler_class->set_ebgp_multihop =
   instance_bgp_configurator_handler_set_ebgp_multihop;

 bgp_configurator_handler_class->unset_ebgp_multihop =
   instance_bgp_configurator_handler_unset_ebgp_multihop;

 bgp_configurator_handler_class->set_update_source = 
   instance_bgp_configurator_handler_set_update_source;

 bgp_configurator_handler_class->unset_update_source = 
   instance_bgp_configurator_handler_unset_update_source;

 bgp_configurator_handler_class->enable_address_family =
   instance_bgp_configurator_handler_enable_address_family;

 bgp_configurator_handler_class->disable_address_family = 
   instance_bgp_configurator_handler_disable_address_family;

 bgp_configurator_handler_class->set_log_config = 
   instance_bgp_configurator_handler_set_log_config;

 bgp_configurator_handler_class->enable_graceful_restart = 
   instance_bgp_configurator_handler_enable_graceful_restart;

 bgp_configurator_handler_class->disable_graceful_restart = 
   instance_bgp_configurator_handler_disable_graceful_restart;

 bgp_configurator_handler_class->get_routes = 
   instance_bgp_configurator_handler_get_routes;

 bgp_configurator_handler_class->enable_multipath =
   instance_bgp_configurator_handler_enable_multipath;

 bgp_configurator_handler_class->disable_multipath =
   instance_bgp_configurator_handler_disable_multipath;

 bgp_configurator_handler_class->multipaths =
   instance_bgp_configurator_handler_multipaths;

 bgp_configurator_handler_class->enable_e_o_r_delay =
   instance_bgp_configurator_enable_eor_delay;

 bgp_configurator_handler_class->send_e_o_r =
   instance_bgp_configurator_send_eor;
}

/* InstanceBgpConfiguratorHandler's instance initializer (constructor) */
static void
instance_bgp_configurator_handler_init(InstanceBgpConfiguratorHandler *self)
{
  ecommunity_init();
  return;
}

