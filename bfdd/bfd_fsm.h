/*
 * BFDD - bfd_fsm.h
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


#ifndef _QUAGGA_BFD_FSM_H
#define _QUAGGA_BFD_FSM_H

#define FSM_S_AdminDown	    1
#define FSM_S_Down	    2
#define FSM_S_Init	    3
#define FSM_S_Up	    4
#define FSM_S_MAX	    5

#define FSM_E_RecvAdminDown 1
#define FSM_E_RecvDown	    2
#define FSM_E_RecvInit	    3
#define FSM_E_RecvUp	    4
#define FSM_E_Timer	    5
#define FSM_E_Delete	    6
#define FSM_E_MAX	    7

int bfd_event (struct bfd_neigh *neighp, int event);
int bfd_fsm_timer (struct thread *thread);
int bfd_fsm_stimeout (struct thread *thread);
int bfd_fsm_neigh_del (struct bfd_neigh *neighp);
int bfd_fsm_neigh_add (struct bfd_neigh *neighp);

#endif /* _QUAGGA_BFD_FSM_H */
