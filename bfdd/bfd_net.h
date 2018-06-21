/*
 * BFDD - bfd_net.h   
 *
 * Copyright (C) 2007   Jaroslaw Adam Gralak
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifndef _QUAGGA_BFD_NET_H
#define _QUAGGA_BFD_NET_H

int bfd_server_socket_init (int family, uint16_t port);
void bfd_sendsock_init (struct bfd_neigh *neighp);
void bfd_sockclose (int sock);

int bfd_read4_1hop (struct thread *t);
int bfd_read4_mhop (struct thread *t);
#ifdef HAVE_IPV6
int bfd_read6_1hop (struct thread *t);
int bfd_read6_mhop (struct thread *t);
#endif /* HAVE_IPV6 */

#endif /* _QUAGGA_BFD_NET_H */
