/*
 * bgpd ZeroMQ/Cap'n'Proto event update feed
 * Copyright (C) 2016  David Lamparter, for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <zebra.h>
#include <zmq.h>
#include "command.h"
#include "memory.h"

#include "prefix.h"
#include "memory.h"
#include "log.h"
#include "qzmq.h"
#include "bgp.bcapnp.h"

#include "bgpd.h"
#include "bgpd/bgp_vty.h"

#define BGP_NOTIFY_ZMQ_LIMIT     1500000
#define BGP_NOTIFY_ZMQ_MIN_LIMIT 60000
#define BGP_NOTIFY_ZMQ_MAX_LIMIT 4000000

int bgp_zmq_notify_send_counter;
uint32_t bgp_notify_zmq_limit = BGP_NOTIFY_ZMQ_LIMIT;

void
bgp_notify_cleanup (struct bgp *bgp)
{
  if (bgp->notify_zmq_url)
    XFREE (MTYPE_ZMQ_NOTIFY, bgp->notify_zmq_url);
  if (bgp->notify_zmq)
    zmq_close (bgp->notify_zmq);
}

DEFUN (debug_bgp_notify_zmq_set_limit,
       debug_bgp_notify_zmq_set_limit_cmd,
       "debug bgp zmq notification-limit [60000-4000000]",
       DEBUG_STR
       BGP_STR
       "BGP ZMQ debugging\n"
       "Notification Threshold\n"
       "Size of storage queue bgp->sdnc\n"
       )
{
  uint32_t limit;
  struct bgp *bgp = bgp_get_default();

  if (!bgp)
    return CMD_SUCCESS;
  limit = atol (argv[0]);
  if (limit < BGP_NOTIFY_ZMQ_MIN_LIMIT || limit > BGP_NOTIFY_ZMQ_MAX_LIMIT)
    return CMD_SUCCESS;
  if (limit != bgp_notify_zmq_limit)
    {
      bgp_notify_zmq_limit = limit;
      if (bgp->notify_zmq)
        zmq_setsockopt (bgp->notify_zmq, ZMQ_SNDHWM, &limit, sizeof(limit));
    }
  return CMD_SUCCESS;
}

int
bgp_notify_zmq_url_set (struct bgp *bgp, const char *url)
{
  /* maximum capacity of messages that can be stored on queue */
  uint32_t limit = bgp_notify_zmq_limit;

  if (bgp->notify_zmq_url)
    {
      if (url && !strcmp (url, bgp->notify_zmq_url))
        return 0;

      XFREE (MTYPE_ZMQ_NOTIFY, bgp->notify_zmq_url);
      bgp->notify_zmq_url = NULL;
    }
  if (bgp->notify_zmq)
    {
      zmq_close (bgp->notify_zmq);
      bgp->notify_zmq = NULL;
    }

  if (!url || !*url)
    return 0;

  bgp->notify_zmq_url = XSTRDUP (MTYPE_ZMQ_NOTIFY, url);
  bgp->notify_zmq = zmq_socket (qzmq_context, ZMQ_PUB);
  if (!bgp->notify_zmq)
    {
      zlog_err ("failed to open ZeroMQ PUB socket: %s (%d)",
                strerror (errno), errno);
      return -1;
    }
  zmq_setsockopt (bgp->notify_zmq, ZMQ_SNDHWM, &limit, sizeof(limit));
  if (zmq_bind (bgp->notify_zmq, bgp->notify_zmq_url))
    {
      zlog_err ("ZeroMQ event PUB bind failed: %s (%d)",
                strerror (errno), errno);
      zmq_close (bgp->notify_zmq);
      return -1;
    }
  return 0;
}

static void
bgp_notify_send (struct bgp *bgp, struct bgp_event_vrf *update)
{
  struct capn rc;
  capn_init_malloc(&rc);
  struct capn_segment *cs = capn_root(&rc).seg;
  capn_ptr p = qcapn_new_BGPEventVRFRoute (cs);
  qcapn_BGPEventVRFRoute_write (update, p);
  capn_setp(capn_root(&rc), 0, p);

  uint8_t buf[4096];
  ssize_t rs = capn_write_mem(&rc, buf, sizeof(buf), 0);
  capn_free(&rc);
  bgp_zmq_notify_send_counter++;
  zmq_send (bgp->notify_zmq, buf, rs, 0);
}

void
bgp_notify_route (struct bgp *bgp, struct bgp_event_vrf *update)
{
  bgp_notify_send (bgp, update);
}

void
bgp_notify_shut (struct bgp *bgp, struct bgp_event_shut *shut)
{
  struct bgp_event_vrf msg;

  /* encapsulate message in bgp_event_vrf structure */
  memset(&msg, 0, sizeof(struct bgp_event_vrf));
  msg.announce = BGP_EVENT_SHUT;
  msg.nexthop = shut->peer;
  msg.label = shut->type;
  msg.prefix.u.prefix4.s_addr = shut->subtype;
  bgp_notify_send (bgp, &msg);
}

void
bgp_notify_bfd_status (struct bgp *bgp, struct bgp_event_bfd_status *status)
{
  struct bgp_event_vrf msg;

  /* encapsulate message in bgp_event_vrf structure */
  memset(&msg, 0, sizeof(struct bgp_event_vrf));
  msg.announce = BGP_EVENT_BFD_STATUS;
  msg.nexthop = status->peer;
  msg.label = (uint32_t)status->as;
  msg.prefix.family = AF_INET;
  msg.prefix.u.prefix4.s_addr = status->up_down;
  bgp_notify_send (bgp, &msg);
}

static int bgp_zmq_delay;
static int bgp_zmq_occurence;

DEFUN (show_debugging_bgp_zmq_simulate,
       show_debugging_bgp_zmq_simulate_cmd,
       "show debugging bgp zmq delay <0-20> occurence <1-500>",
       SHOW_STR
       DEBUG_STR
       BGP_STR
       "ZMQ information"
       "Simulate an extra Delay before sending REP"
       "Delay in seconds"
       "Simulate the occurence of the event 1 out of X"
       "X in number of occurences")
{
  bgp_zmq_delay = atoi(argv[0]);
  bgp_zmq_occurence = atoi(argv[1]);
  qzc_configure_simulation_delay (bgp_zmq_delay, bgp_zmq_occurence);
}

DEFUN (show_debugging_bgp_zmq,
       show_debugging_bgp_zmq_cmd,
       "show debugging bgp zmq",
       SHOW_STR
       DEBUG_STR
       BGP_STR
       "ZMQ information")
{
  vty_out (vty, "BGP ZMQ notifications : %u%s", bgp_zmq_notify_send_counter, VTY_NEWLINE);
  vty_out (vty, "BGP ZMQ queue storage limit : %u%s", bgp_notify_zmq_limit, VTY_NEWLINE);
  vty_out (vty, "BGP ZMQ Heavy Work Simulation: sleep %u sec. occurence 1 out of %d%s",
           bgp_zmq_delay, bgp_zmq_occurence, VTY_NEWLINE);
  vty_out (vty, "BGP ZMQ REP reconnect %u%s", qzcserver_get_nb_reconnect(), VTY_NEWLINE);
  return CMD_SUCCESS;
}

void
bgp_notify_zmq_init (void)
{
  bgp_notify_zmq_limit = BGP_NOTIFY_ZMQ_LIMIT;
  install_element (ENABLE_NODE, &show_debugging_bgp_zmq_cmd);
  install_element (ENABLE_NODE, &show_debugging_bgp_zmq_simulate_cmd);
  install_element (ENABLE_NODE, &debug_bgp_notify_zmq_set_limit_cmd);
  install_element (CONFIG_NODE, &debug_bgp_notify_zmq_set_limit_cmd);
}
