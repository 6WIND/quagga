/* qthrift thrift BGP Updater Client Part
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

#include <stdio.h>
#include "qthriftd/qthrift_thrift_wrapper.h"
#include "qthriftd/bgp_updater.h"
#include "qthriftd/bgp_configurator.h"
#include "qthriftd/qthrift_bgp_updater.h"
#include "qthriftd/qthrift_bgp_configurator.h"
#include "zebra.h"
#include "log.h"
#include "prefix.h"
#include "qthriftd/qthrift_vpnservice.h"
#include "qthriftd/qthrift_debug.h"

/*
 * update push route notification message
 * sent when a vpnv4 route is pushed
 */
gboolean
qthrift_bgp_updater_on_update_push_route (const gchar * rd, const gchar * prefix, \
                                          const gint32 prefixlen, const gchar * nexthop, const gint32 label)
{
  GError *error = NULL;
  gboolean response;
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_send_on_update_push_route(ctxt->bgp_updater_client, \
                                                            rd, prefix, prefixlen, nexthop, label, &error);
  if(IS_QTHRIFT_DEBUG_NOTIFICATION)
    zlog_info ("onUpdatePushRoute(rd %s, pfx %s, nh %s, label %d) sent %s", \
             rd, prefix, nexthop, label,\
             (response == TRUE)?"OK":"NOK");
  return response;
}

/*
 * update withdraw route notification message
 * sent when a vpnv4 route is withdrawn
 */
gboolean
qthrift_bgp_updater_on_update_withdraw_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen)
{
  GError *error = NULL;
  gboolean response;
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_on_update_withdraw_route(ctxt->bgp_updater_client, \
                                                         rd, prefix, prefixlen, &error);
  if(IS_QTHRIFT_DEBUG_NOTIFICATION)
    zlog_debug ("onUpdateWithdrawRoute(rd %s, pfx %s/%d) sent %s", \
             rd, prefix, prefixlen, \
             (response == TRUE)?"OK":"NOK");
  return response;
}

/*
 * start config resync notification message sent
 * when qthriftd has started and is ready and
 * available to receive thrift configuration commands
 */
gboolean
qthrift_bgp_updater_on_start_config_resync_notification (void)
{
  GError *error = NULL;
  gboolean response;
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_on_start_config_resync_notification(ctxt->bgp_updater_client, &error);
  if(IS_QTHRIFT_DEBUG_NOTIFICATION)
    zlog_debug ("onStartConfigResyncNotification() sent %s", \
             (response == TRUE)?"OK":"NOK");
  return response;
}

/*
 * send event notification message
 */
gboolean
qthrift_bgp_updater_on_notification_send_event (const gchar * prefix, const gint8 errCode, const gint8 errSubcode)
{
  return TRUE;
}
