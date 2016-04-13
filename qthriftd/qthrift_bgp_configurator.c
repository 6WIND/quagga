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

/* ---------------------------------------------------------------- */

static gboolean
instance_bgp_configurator_handler_create_peer(BgpConfiguratorIf *iface,
                                              gint32* ret, const gchar *routerId,
                                              const gint32 asNumber, GError **error);
static gboolean
instance_bgp_configurator_handler_start_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint32 asNumber,
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
instance_bgp_configurator_handler_stop_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint32 asNumber, GError **error);
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

static void instance_bgp_configurator_handler_finalize(GObject *object);

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
 * Start a Create a BGP neighbor for a given routerId, and asNumber
 * If BGP is already started, then an error is returned : BGP_ERR_ACTIVE
 */
static gboolean
instance_bgp_configurator_handler_start_bgp(BgpConfiguratorIf *iface, gint32* _return, const gint32 asNumber,
                                            const gchar * routerId, const gint32 port, const gint32 holdTime,
                                            const gint32 keepAliveTime, const gint32 stalepathTime,
                                            const gboolean announceFbit, GError **error)
{
  return TRUE;
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
  return TRUE;
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
  return TRUE;
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
  return TRUE;
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
  return TRUE;
}

/* 
 * Stop BGP Router for a given AS Number
 * If BGP is already stopped, or give AS is not present, an error is returned
 */
gboolean
instance_bgp_configurator_handler_stop_bgp(BgpConfiguratorIf *iface, gint32* _return,
                                           const gint32 asNumber, GError **error)
{
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
                                              const gchar *routerId, const gint32 asNumber, GError **error)
{
  return TRUE;
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
  return TRUE;
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
  return TRUE;
}

/*
 * Delete a VRF entry for a given route distinguisher
 * An error is returned if VRF entry does not exist
 */
gboolean instance_bgp_configurator_handler_del_vrf(BgpConfiguratorIf *iface, gint32* _return,
                                                   const gchar * rd, GError **error)
{
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
  return TRUE;
}

/*
 * enable MP-BGP routing information exchange with a given neighbor
 * for a given address family identifier and subsequent address family identifier.
 */
gboolean instance_bgp_configurator_handler_enable_address_family(BgpConfiguratorIf *iface, gint32* _return,
                                                                 const gchar * peerIp, const af_afi afi,
                                                                 const af_safi safi, GError **error)
{
  return TRUE;
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
  return TRUE;
}

gboolean
instance_bgp_configurator_handler_set_log_config (BgpConfiguratorIf *iface, gint32* _return, const gchar * logFileName,
                                                  const gchar * logLevel, GError **error)
{
  return TRUE;
}

/*
 * enable Graceful Restart for BGP Router, as well as stale path timer.
 * if the stalepathTime is set to 0, then the graceful restart feature will be disabled
 */
gboolean
instance_bgp_configurator_handler_enable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return,
                                                           const gint32 stalepathTime, GError **error)
{
  return TRUE;
}

/* disable Graceful Restart for BGP Router */
gboolean
instance_bgp_configurator_handler_disable_graceful_restart (BgpConfiguratorIf *iface, gint32* _return, GError **error)
{
  return TRUE;
}

gboolean
instance_bgp_configurator_handler_get_routes (BgpConfiguratorIf *iface, Routes ** _return,
                                              const gint32 optype, const gint32 winSize, GError **error)
{
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
}

/* InstanceBgpConfiguratorHandler's instance initializer (constructor) */
static void
instance_bgp_configurator_handler_init(InstanceBgpConfiguratorHandler *self)
{
  return;
}

