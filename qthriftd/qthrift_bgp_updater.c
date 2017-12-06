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

extern qthrift_status qthrift_transport_current_status;
extern void qthrift_transport_check_response(struct qthrift_vpnservice *setup, gboolean response);
extern void qthrift_transport_cancel_monitor(struct qthrift_vpnservice *setup);
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
  if (error != NULL)
    {
      if (error->domain == THRIFT_TRANSPORT_ERROR &&
          error->code == THRIFT_TRANSPORT_ERROR_SEND)
        {
          ctxt->bgp_update_thrift_lost_msgs++;
          zlog_info ("onUpdatePushRoute(): sent error %s", error->message);
          qthrift_transport_cancel_monitor(ctxt);
          response = FALSE;
          qthrift_transport_check_response(ctxt, FALSE);
        }
      g_clear_error (&error);
      error = NULL;
    }
  if(IS_QTHRIFT_DEBUG_NOTIFICATION && response == TRUE)
    zlog_info ("onUpdatePushRoute(rd %s, pfx %s, nh %s, label %d)", \
               rd, prefix, nexthop, label);

  return response;
}

/*
 * update withdraw route notification message
 * sent when a vpnv4 route is withdrawn
 */
gboolean
qthrift_bgp_updater_on_update_withdraw_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen, const gchar * nexthop,  const gint32 label)
{
  GError *error = NULL;
  gboolean response;
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_on_update_withdraw_route(ctxt->bgp_updater_client, \
                                                         rd, prefix, prefixlen, nexthop,
                                                         label, &error);
  if (error != NULL)
    {
      if (error->domain == THRIFT_TRANSPORT_ERROR &&
          error->code == THRIFT_TRANSPORT_ERROR_SEND)
        {
          ctxt->bgp_update_thrift_lost_msgs++;
          zlog_info ("onUpdateWithdrawRoute(): sent error %s", error->message);
          qthrift_transport_cancel_monitor(ctxt);
          response = FALSE;
          qthrift_transport_check_response(ctxt, FALSE);
        }
      g_clear_error (&error);
      error = NULL;
    }
  if(IS_QTHRIFT_DEBUG_NOTIFICATION && response == TRUE)
    zlog_info ("onUpdateWithdrawRoute(rd %s, pfx %s/%d, nh %s, label %d)", \
                rd, prefix, prefixlen, nexthop, label);
  return response;
}



gboolean
qthrift_bgp_updater_on_start_config_resync_notification_quick (struct qthrift_vpnservice *ctxt, gboolean restart)
{
  gboolean response;
  GError *error = NULL;
  response = bgp_updater_client_on_start_config_resync_notification(ctxt->bgp_updater_client, &error);
  if (error != NULL)
    {
      if (error->domain == THRIFT_TRANSPORT_ERROR &&
          error->code == THRIFT_TRANSPORT_ERROR_SEND)
        {
          zlog_info ("onStartConfigResyncNotification(): sent error %s", error->message);
          response = FALSE;
          ctxt->bgp_update_lost_msgs++;
          if (restart == TRUE)
            {
              qthrift_transport_cancel_monitor(ctxt);
              qthrift_transport_check_response(ctxt, FALSE);
            }
        }
      g_clear_error (&error);
      error = NULL;
    }
  if(IS_QTHRIFT_DEBUG_NOTIFICATION)
    zlog_info ("onStartConfigResyncNotification() %s", response == FALSE?"NOK":"OK");
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
  struct qthrift_vpnservice *ctxt = NULL;
  static gboolean client_ready;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
      return FALSE;
  if((ctxt->bgp_updater_client == NULL) ||
     (qthrift_transport_current_status == QTHRIFT_TO_SDN_UNKNOWN) ||
     (qthrift_transport_current_status == QTHRIFT_TO_SDN_FALSE))
    {
      if(ctxt->bgp_updater_client)
        qthrift_vpnservice_terminate_thrift_bgp_updater_client(ctxt);
      /* start the retry mecanism */
      client_ready = qthrift_vpnservice_setup_thrift_bgp_updater_client(ctxt);
      qthrift_transport_check_response(ctxt, client_ready);
      if(client_ready == FALSE)
        {
          if(IS_QTHRIFT_DEBUG_NOTIFICATION)
            zlog_debug ("bgp->sdnc message failed to be sent");
        }
    }
  return TRUE;
}

/*
 * send event notification message
 */
gboolean
qthrift_bgp_updater_on_notification_send_event (const gchar * prefix, const gint8 errCode, const gint8 errSubcode)
{
  GError *error = NULL;
  gboolean response;
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  response = bgp_updater_client_on_notification_send_event(ctxt->bgp_updater_client, \
                                                           prefix, errCode, errSubcode, &error); 
  if (error != NULL)
    {
      if (error->domain == THRIFT_TRANSPORT_ERROR &&
          error->code == THRIFT_TRANSPORT_ERROR_SEND)
        {
          ctxt->bgp_update_thrift_lost_msgs++;
          zlog_info ("onNotificationSendEvent(): sent error %s", error->message);
          response = FALSE;
          qthrift_transport_cancel_monitor(ctxt);
          qthrift_transport_check_response(ctxt, response);
        }
      g_clear_error (&error);
      error = NULL;
    }
  if(IS_QTHRIFT_DEBUG_NOTIFICATION)
    zlog_info ("onNotificationSendEvent(%s, errCode %d, errSubCode %d) %s",
               prefix, errCode, errSubcode, response == FALSE?"NOK":"OK");
  return response;
}
