/* BGP CapnProto Library
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
#include <stdbool.h>
#include "c-capnproto/capn.h"
#include "bgp.bcapnp.h"

#include "zebra.h"
#include "bgpd.h"

capn_ptr qcapn_new_BGP(struct capn_segment *s)
{
    return capn_new_struct(s, 32, 3);
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
