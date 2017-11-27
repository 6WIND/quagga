/*
 * ZEBRA - zserv_bfd.h   
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


#ifndef _ZEBRA_ZSERV_BFD_H
#define _ZEBRA_ZSERV_BFD_H

void bfd_cneigh_init (void);

int zread_bfd_register (struct zserv *client, u_short length);

int zread_ipv4_bfd_cneigh_list (struct zserv *client, u_short length);
int zread_ipv4_bfd_cneigh_add (struct zserv *client, u_short length);
int zread_ipv4_bfd_cneigh_del (struct zserv *client, u_short length);
int zread_ipv4_bfd_neigh_up (struct zserv *client, u_short length);
int zread_ipv4_bfd_neigh_down (struct zserv *client, u_short length);
#ifdef HAVE_IPV6
int zread_ipv6_bfd_cneigh_list (struct zserv *client, u_short length);
int zread_ipv6_bfd_cneigh_add (struct zserv *client, u_short length);
int zread_ipv6_bfd_cneigh_del (struct zserv *client, u_short length);
int zread_ipv6_bfd_neigh_up (struct zserv *client, u_short length);
int zread_ipv6_bfd_neigh_down (struct zserv *client, u_short length);
#endif /* HAVE_IPV6 */

#endif /*_ZEBRA_ZSERV_BFD_H */
