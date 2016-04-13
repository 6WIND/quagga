/* qthrift thrift network interface
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
#ifndef _QTHRIFT_NETWORK_H
#define _QTHRIFT_NETWORK_H

extern void qthrift_server_socket (struct qthrift *qthrift);
extern int qthrift_server_listen (struct qthrift *qthrift);
extern void qthrift_close (void);
extern int qthrift_connect (struct qthrift_peer *);
extern void qthrift_getsockname (struct qthrift_peer *);
extern int qthrift_accept (struct thread *thread);
extern int qthrift_read_packet (struct thread *thread);

#endif /* _QTHRIFT_NETWORK_H */
