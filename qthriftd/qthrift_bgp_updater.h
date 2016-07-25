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

#ifndef _QTHRIFT_BGP_UPDATER_H
#define _QTHRIFT_BGP_UPDATER_H


gboolean
qthrift_bgp_updater_on_notification_send_event (const gchar * prefix, const gint8 errCode, const gint8 errSubcode);

gboolean
qthrift_bgp_updater_on_start_config_resync_notification (void);

gboolean
qthrift_bgp_updater_on_update_withdraw_route (const gchar * rd, const gchar * prefix, const gint32 prefixlen,
                                              const gchar * nexthop, const gint32 label);

gboolean
qthrift_bgp_updater_on_update_push_route (const gchar * rd, const gchar * prefix, \
                                          const gint32 prefixlen, const gchar * nexthop, const gint32 label);

#endif /* _QTHRIFT_BGP_UPDATER_H */
