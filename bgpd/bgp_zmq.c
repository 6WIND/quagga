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
#include "bgp_memory.h"

#include "prefix.h"
#include "memory.h"
#include "log.h"
#include "qzmq.h"
#include "bgp.bcapnp.h"

#include "bgpd.h"

DEFINE_MTYPE_STATIC(BGPD, ZMQ_NOTIFY, "BGP ZeroMQ notification feed")

void
bgp_notify_cleanup (struct bgp *bgp)
{
  if (bgp->notify_zmq_url)
    XFREE (MTYPE_ZMQ_NOTIFY, bgp->notify_zmq_url);
  if (bgp->notify_zmq)
    zmq_close (bgp->notify_zmq);
}

int
bgp_notify_zmq_url_set (struct bgp *bgp, const char *url)
{
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
  msg.nexthop.s_addr = shut->peer.s_addr;
  msg.label = shut->type;
  msg.prefix.u.prefix4.s_addr = shut->subtype;
  bgp_notify_send (bgp, &msg);
}
