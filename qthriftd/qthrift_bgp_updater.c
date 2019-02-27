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

#include <zebra.h>
#include <stdio.h>
#include "qthriftd/qthrift_thrift_wrapper.h"
#include "qthriftd/qthrift_master.h"
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

static bool qthrift_bgp_updater_handle_response(struct qthrift_vpnservice *ctxt,
                                                bool *response,
                                                GError **perror,
                                                const char *name)
{
  bool should_retry = FALSE;
  GError *error = NULL;

    if (perror != NULL)
      {
        error = *perror;
        if (error && error->domain == THRIFT_TRANSPORT_ERROR &&
            error->code == THRIFT_TRANSPORT_ERROR_SEND)
          {
            /* errors that are worth to be retried */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              int fd = qthrift_vpnservice_get_bgp_updater_socket(ctxt);
              fd_set wrfds;
              struct timeval tout;
              int optval, optlen;

              zlog_info ("%s: sent error %s (%d), using select (%d sec) to retry",
                         name, error->message, errno, tm->qthrift_select_time);
              FD_ZERO(&wrfds);
              FD_SET(fd, &wrfds);

              tout.tv_sec = 0;
              tout.tv_usec = tm->qthrift_select_time * 1000 * 1000;
              optval = -1;
              optlen = sizeof (optval);
              ctxt->bgp_update_thrift_retries++;
              ctxt->bgp_updater_select_in_progress = TRUE;
              if ((select(FD_SETSIZE, NULL, &wrfds, NULL, &tout) <= 0) ||
                  (getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, (socklen_t *)&optlen) < 0) ||
                  (optval != 0)) {
                ctxt->bgp_updater_select_in_progress = FALSE;
                zlog_info ("%s: sent error %s (%d), resetting connection",
                           name, error->message, errno);
                ctxt->bgp_update_thrift_lost_msgs++;
                qthrift_transport_cancel_monitor(ctxt);
                should_retry = FALSE;
                *response = FALSE;
                qthrift_transport_check_response(ctxt, FALSE);
              } else {
                ctxt->bgp_updater_select_in_progress = FALSE;
                ctxt->bgp_update_thrift_retries_successfull++;
                should_retry = TRUE;
              }
            } else {
              zlog_info ("%s: sent error %s (%d), resetting connection",
                         name, error->message, errno);
              /* other errors fall in error */
              ctxt->bgp_update_thrift_lost_msgs++;
              qthrift_transport_cancel_monitor(ctxt);
              should_retry = FALSE;
              *response = FALSE;
              qthrift_transport_check_response(ctxt, FALSE);
            }
            g_clear_error (&error);
            error = NULL;
          }
      }
    return should_retry;
}

/*
 * update push route notification message
 * sent when a vpnv4 route is pushed
 */
gboolean
qthrift_bgp_updater_on_update_push_route (const gchar * rd, const gchar * prefix, \
                                          const gint32 prefixlen, const gchar * nexthop, const gint32 label)
{
  GError *error = NULL, **perror;
  gboolean response;
  struct qthrift_vpnservice *ctxt = NULL;
  int thrift_tries;
  char buff[255];

  perror = &error;
  sprintf(buff, "onUpdatePushRoute(rd %s,pfx %s/%d, nh %s, label %u)",
          rd, prefix, prefixlen, nexthop, label);
  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_send_on_update_push_route(ctxt->bgp_updater_client, \
                                                          rd, prefix, prefixlen,
                                                          nexthop, label, perror);
    if (qthrift_bgp_updater_handle_response(ctxt, (bool *)&response, perror, buff) == FALSE)
      break;
    error = NULL;
  }
  if(IS_QTHRIFT_DEBUG_NOTIFICATION && response == TRUE)
    zlog_info ("%s", buff);
  return response;
}

/*
 * update withdraw route notification message
 * sent when a vpnv4 route is withdrawn
 */
gboolean
qthrift_bgp_updater_on_update_withdraw_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen, const gchar * nexthop,  const gint32 label)
{
  GError *error = NULL, **perror;
  gboolean response;
  struct qthrift_vpnservice *ctxt = NULL;
  int thrift_tries;
  char buff[255];

  perror = &error;
  sprintf(buff, "onUpdateWithdrawRoute(rd %s, pfx %s/%d, nh %s, label %u)",
          rd, prefix, prefixlen, nexthop, label);
  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_on_update_withdraw_route(ctxt->bgp_updater_client, \
                                                          rd, prefix, prefixlen,
                                                          nexthop, label, perror);
    if (qthrift_bgp_updater_handle_response(ctxt, (bool *)&response, perror, buff) == FALSE)
      break;
    error = NULL;
  }
  if(IS_QTHRIFT_DEBUG_NOTIFICATION && response == TRUE)
    zlog_info ("%s", buff);
  return response;
}



gboolean
qthrift_bgp_updater_on_start_config_resync_notification_quick (struct qthrift_vpnservice *ctxt, gboolean restart)
{
  gboolean response;
  GError *error = NULL, **perror;
  int thrift_tries;

  perror = &error;
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_on_start_config_resync_notification(ctxt->bgp_updater_client, perror);
    if (qthrift_bgp_updater_handle_response(ctxt, (bool *)&response, perror, "onStartConfigResyncNotification()") == FALSE)
      break;
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
int
qthrift_bgp_updater_on_start_config_resync_notification (struct thread *thread)
{
  struct qthrift_vpnservice *ctxt = NULL;
  static gboolean client_ready;

  ctxt = THREAD_ARG (thread);
  assert (ctxt);
  if((ctxt->bgp_updater_client == NULL) ||
     (qthrift_transport_current_status == QTHRIFT_TO_SDN_UNKNOWN) ||
     (qthrift_transport_current_status == QTHRIFT_TO_SDN_FALSE))
    {
      if(ctxt->bgp_updater_client)
        {
          qthrift_vpnservice_terminate_thrift_bgp_updater_client(ctxt);
        }
      /* start the retry mecanism */
      client_ready = qthrift_vpnservice_setup_thrift_bgp_updater_client(ctxt);
      qthrift_transport_check_response(ctxt, client_ready);
      if(client_ready == FALSE)
        {
          if(IS_QTHRIFT_DEBUG_NOTIFICATION)
            zlog_debug ("bgp->sdnc message failed to be sent");
        }
    }
  ctxt->bgp_update_total++;
  return 0;
}

/*
 * send event notification message
 */
gboolean
qthrift_bgp_updater_on_notification_send_event (const gchar * prefix, const gint8 errCode, const gint8 errSubcode)
{
  GError *error = NULL, **perror;
  gboolean response;
  struct qthrift_vpnservice *ctxt = NULL;
  int thrift_tries;
  char buff[256];

  perror = &error;
  sprintf(buff, "onNotificationSendEvent(%s, errCode %d, errSubCode %d)",
          prefix, errCode, errSubcode);

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt || !ctxt->bgp_updater_client)
      return FALSE;
  for (thrift_tries = 0; thrift_tries < 2; thrift_tries++) {
    response = bgp_updater_client_on_notification_send_event(ctxt->bgp_updater_client, \
                                                             prefix, errCode,
                                                             errSubcode, perror);
    if (qthrift_bgp_updater_handle_response(ctxt, (bool *)&response, perror, buff) == FALSE)
      break;
    error = NULL;
  }
  if(IS_QTHRIFT_DEBUG_NOTIFICATION)
    zlog_info ("%s %s", buff, response == FALSE?"NOK":"OK");
  return response;
}
