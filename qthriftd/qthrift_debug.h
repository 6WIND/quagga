/* qthrift debug routines
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

#ifndef _QTHRIFT_DEBUG_H
#define _QTHRIFT_DEBUG_H

/* THRIFT debug event flags. */
#define QTHRIFT_DEBUG               0x01
#define QTHRIFT_DEBUG_NOTIFICATION  0x02
#define QTHRIFT_DEBUG_CACHE         0x04
#define QTHRIFT_DEBUG_NETWORK       0x08
#define QTHRIFT_DEBUG_SHOW          0x10

/* Debug related macro. */
#define IS_QTHRIFT_DEBUG  (qthrift_debug & QTHRIFT_DEBUG)
#define IS_QTHRIFT_DEBUG_NOTIFICATION  (qthrift_debug & QTHRIFT_DEBUG_NOTIFICATION)
#define IS_QTHRIFT_DEBUG_SHOW  (qthrift_debug & QTHRIFT_DEBUG_SHOW)
#define IS_QTHRIFT_DEBUG_NETWORK  (qthrift_debug & QTHRIFT_DEBUG_NETWORK)
#define IS_QTHRIFT_DEBUG_CACHE  (qthrift_debug & QTHRIFT_DEBUG_CACHE)
#define CONF_QTHRIFT_DEBUG(a, b)    (conf_thrift_debug_ ## a & QTHRIFT_DEBUG_ ## b)

extern unsigned long qthrift_debug;

extern void qthrift_debug_init (void);
extern void qthrift_debug_reset (void);

#endif /* _QTHRIFT_DEBUG_H */
