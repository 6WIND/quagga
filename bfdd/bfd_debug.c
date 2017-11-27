/*
 * BFDD - bfd_debug.c   
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


#include <zebra.h>
#include "command.h"
#include "zclient.h"
#include "hash.h"
#include "prefix.h"
#include "table.h"

#include "bfd.h"
#include "bfdd/bfdd.h"
#include "bfdd/bfd_debug.h"
#include "bfdd/bfd_zebra.h"
#include "bfdd/bfd_fsm.h"

extern struct zclient *zclient;

struct message bfd_status_msg[] = {
  {0, "null"},
  {FSM_S_AdminDown, "AdminDown"},
  {FSM_S_Down, "Down"},
  {FSM_S_Init, "Init"},
  {FSM_S_Up, "Up"},
};
int bfd_status_msg_max = FSM_S_MAX;

const char *bfd_state_str[] = {
  "AdminDown",
  "Down",
  "Init",
  "Up",
};

const char *bfd_neigh_cmd_str[] = {
  NULL,
  "BFD_NEIGH_ADD",
  "BFD_NEIGH_DEL",
};


/* Debug node. */
struct cmd_node debug_node = {
  DEBUG_NODE,
  "",
  1
};

static int
config_write_debug (struct vty *vty)
{
  int write = 0;
  if (BFD_IF_DEBUG_ZEBRA)
    {
      vty_out (vty, "debug bfd zebra%s", VTY_NEWLINE);
      write++;
    }
  if (BFD_IF_DEBUG_FSM)
    {
      vty_out (vty, "debug bfd fsm%s", VTY_NEWLINE);
      write++;
    }
  return write;
}

DEFUN (show_debugging_bfd,
       show_debugging_bfd_cmd,
       "show debugging bfd", SHOW_STR DEBUG_STR BFD_STR)
{
  vty_out (vty, "BFD debugging status:%s", VTY_NEWLINE);
  if (BFD_IF_DEBUG_ZEBRA)
    vty_out (vty, "debug bfd zebra%s", VTY_NEWLINE);
  if (BFD_IF_DEBUG_FSM)
    vty_out (vty, "debug bfd fsm%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (debug_bfd_zebra,
       debug_bfd_zebra_cmd,
       "debug bfd zebra", DEBUG_STR BFD_STR "BFD and ZEBRA communication\n")
{
  bfd->debug |= BFD_DEBUG_ZEBRA;
  return CMD_SUCCESS;
}

DEFUN (no_debug_bfd_zebra,
       no_debug_bfd_zebra_cmd,
       "no debug bfd zebra",
       NO_STR DEBUG_STR BFD_STR "BFD and ZEBRA communication\n")
{
  bfd->debug &= ~BFD_DEBUG_ZEBRA;
  return CMD_SUCCESS;
}

DEFUN (debug_bfd_fsm,
       debug_bfd_fsm_cmd, "debug bfd fsm", DEBUG_STR BFD_STR "BFD FSM\n")
{
  bfd->debug |= BFD_DEBUG_FSM;
  return CMD_SUCCESS;
}

DEFUN (no_debug_bfd_fsm,
       no_debug_bfd_fsm_cmd,
       "no debug bfd fsm", NO_STR DEBUG_STR BFD_STR "BFD FSM\n")
{
  bfd->debug &= ~BFD_DEBUG_FSM;
  return CMD_SUCCESS;
}


void
bfd_vty_debug_init (void)
{
  install_node (&debug_node, config_write_debug);

  install_element (ENABLE_NODE, &show_debugging_bfd_cmd);

  install_element (ENABLE_NODE, &debug_bfd_zebra_cmd);
  install_element (ENABLE_NODE, &no_debug_bfd_zebra_cmd);
  install_element (ENABLE_NODE, &debug_bfd_fsm_cmd);
  install_element (ENABLE_NODE, &no_debug_bfd_fsm_cmd);
}
