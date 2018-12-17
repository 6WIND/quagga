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

#include <zebra.h>
#include "command.h"
#include "qthriftd/qthrift_debug.h"
#include "qthriftd/qthrift_thrift_wrapper.h"
#include "qthriftd/bgp_configurator.h"
#include "qthriftd/bgp_updater.h"
#include "qthriftd/qthrift_bgp_configurator.h"
#include "qthriftd/qthrift_bgp_updater.h"
#include "qthriftd/qthrift_vpnservice.h"
/* For debug statement. */
unsigned long qthrift_debug = 0;

DEFUN (show_debugging_qthrift_stats,
       show_debugging_qthrift_stats_cmd,
       "show debugging qthrift stats",
       SHOW_STR
       DEBUG_STR
       QTHRIFT_STR
       "QTHRIFT Statistics")
{
  struct qthrift_vpnservice *ctxt = NULL;

  qthrift_vpnservice_get_context (&ctxt);
  if(!ctxt)
    {
      return CMD_SUCCESS;
    }
  vty_out (vty, "BGP ZMQ notifications total %u lost %u%s",
           ctxt->bgp_update_total,
           ctxt->bgp_update_lost_msgs,
           VTY_NEWLINE);
  vty_out (vty, "BGP Thrift retries %u, successfull %u, lost %u%s",
           ctxt->bgp_update_thrift_retries,
           ctxt->bgp_update_thrift_retries_successfull,
           ctxt->bgp_update_thrift_lost_msgs,
           VTY_NEWLINE);
  vty_out (vty, "BGP ZMQ REQ reconnections %u%s",
	   qzcclient_get_nb_reconnect(),
           VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (show_debugging_qthrift_errno,
       show_debugging_qthrift_errno_cmd,
       "show debugging qthrift errno",
       SHOW_STR
       DEBUG_STR
       QTHRIFT_STR
       "QTHRIFT errno with 6644")
{
  int i;
  for (i = 0 ; i < QTHRIFT_MAX_ERRNO; i++)
    {
      if (notification_socket_errno[i] > 0)
        {
          vty_out (vty, " %s(%u) = %u%s", strerror(i), i, notification_socket_errno[i], VTY_NEWLINE);
        }
    }
  return CMD_SUCCESS;
}

static int qthrift_zmq_delay;
static int qthrift_zmq_occurence;

DEFUN (show_debugging_qthrift_simulate,
       show_debugging_qthrift_simulate_cmd,
       "show debugging qthrift delay <0-20> occurence <1-500>",
       SHOW_STR
       DEBUG_STR
       QTHRIFT_STR
       "Simulate an extra delay before waiting for REP"
       "Delay in seconds"
       "Simulate the occurence of the event 1 out of X"
       "X in number of occurences")
{
  qthrift_zmq_delay = atoi(argv[0]);
  qthrift_zmq_occurence = atoi(argv[1]);
  qzc_configure_simulation_delay (qthrift_zmq_delay, qthrift_zmq_occurence);
}

DEFUN (show_debugging_qthrift,
       show_debugging_qthrift_cmd,
       "show debugging qthrift",
       SHOW_STR
       DEBUG_STR
       QTHRIFT_STR)
{
  vty_out (vty, "QTHRIFT debugging status:%s", VTY_NEWLINE);

  if (IS_QTHRIFT_DEBUG)
    vty_out (vty, "  QTHRIFT debugging is on%s", VTY_NEWLINE);
  if (IS_QTHRIFT_DEBUG_NOTIFICATION)
    vty_out (vty, "  QTHRIFT debugging notification is on%s", VTY_NEWLINE);
  if (IS_QTHRIFT_DEBUG_SHOW)
    vty_out (vty, "  QTHRIFT debugging show is on%s", VTY_NEWLINE);
  if (IS_QTHRIFT_DEBUG_NETWORK)
    vty_out (vty, "  QTHRIFT debugging network is on%s", VTY_NEWLINE);
  if (IS_QTHRIFT_DEBUG_CACHE)
    vty_out (vty, "  THRIFT debugging cache is on%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (debug_qthrift,
       debug_qthrift_cmd,
       "debug qthrift",
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug |= QTHRIFT_DEBUG;
  return CMD_WARNING;
}

DEFUN (no_debug_qthrift,
       no_debug_qthrift_cmd,
       "no debug qthrift",
       NO_STR
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug &= ~QTHRIFT_DEBUG;
  return CMD_SUCCESS;
}

DEFUN (debug_qthrift_notification,
       debug_qthrift_notification_cmd,
       "debug qthrift notification",
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug |= QTHRIFT_DEBUG_NOTIFICATION;
  return CMD_WARNING;
}

DEFUN (no_debug_qthrift_notification,
       no_debug_qthrift_notification_cmd,
       "no debug qthrift notification",
       NO_STR
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug &= ~QTHRIFT_DEBUG_NOTIFICATION;
  return CMD_SUCCESS;
}

DEFUN (debug_qthrift_show,
       debug_qthrift_show_cmd,
       "debug qthrift show",
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug |= QTHRIFT_DEBUG_SHOW;
  return CMD_WARNING;
}

DEFUN (no_debug_qthrift_show,
       no_debug_qthrift_show_cmd,
       "no debug qthrift show",
       NO_STR
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug &= ~QTHRIFT_DEBUG_SHOW;
  return CMD_SUCCESS;
}

DEFUN (debug_qthrift_network,
       debug_qthrift_network_cmd,
       "debug qthrift network",
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug |= QTHRIFT_DEBUG_NETWORK;
  return CMD_WARNING;
}

DEFUN (no_debug_qthrift_network,
       no_debug_qthrift_network_cmd,
       "no debug qthrift network",
       NO_STR
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug &= ~QTHRIFT_DEBUG_NETWORK;
  return CMD_SUCCESS;
}

DEFUN (debug_qthrift_cache,
       debug_qthrift_cache_cmd,
       "debug qthrift cache",
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug |= QTHRIFT_DEBUG_CACHE;
  return CMD_WARNING;
}

DEFUN (no_debug_qthrift_cache,
       no_debug_qthrift_cache_cmd,
       "no debug qthrift cache",
       NO_STR
       DEBUG_STR
       QTHRIFT_STR
       "THRIFT\n")
{
  qthrift_debug &= ~QTHRIFT_DEBUG_CACHE;
  return CMD_SUCCESS;
}

/* Debug node. */
static struct cmd_node debug_node =
{
  DEBUG_NODE,
  "",				/* Debug node has no interface. */
  1
};

static int
config_write_debug (struct vty *vty)
{
  int write = 0;

  if (IS_QTHRIFT_DEBUG)
    {
      vty_out (vty, "debug qthrift%s", VTY_NEWLINE);
      write++;
    }
  if (IS_QTHRIFT_DEBUG_NOTIFICATION)
    {
      vty_out (vty, "debug qthrift notification%s", VTY_NEWLINE);
      write++;
    }
  if (IS_QTHRIFT_DEBUG_CACHE)
    {
      vty_out (vty, "debug qthrift cache%s", VTY_NEWLINE);
      write++;
    }
  return write;
}

void
qthrift_debug_reset (void)
{
  qthrift_debug = 0;
}

void
qthrift_debug_init (void)
{
  qthrift_debug = 0;
  qthrift_debug |=QTHRIFT_DEBUG;
  qthrift_debug |=QTHRIFT_DEBUG_NOTIFICATION;
  qthrift_debug |=QTHRIFT_DEBUG_SHOW;

  install_node (&debug_node, config_write_debug);
  install_element (ENABLE_NODE, &show_debugging_qthrift_cmd);
  install_element (ENABLE_NODE, &show_debugging_qthrift_simulate_cmd);
  install_element (ENABLE_NODE, &debug_qthrift_cmd);
  install_element (ENABLE_NODE, &no_debug_qthrift_cmd);
  install_element (ENABLE_NODE, &debug_qthrift_notification_cmd);
  install_element (ENABLE_NODE, &no_debug_qthrift_notification_cmd);
  install_element (ENABLE_NODE, &debug_qthrift_show_cmd);
  install_element (ENABLE_NODE, &no_debug_qthrift_show_cmd);
  install_element (ENABLE_NODE, &debug_qthrift_cache_cmd);
  install_element (ENABLE_NODE, &no_debug_qthrift_cache_cmd);
  install_element (ENABLE_NODE, &show_debugging_qthrift_stats_cmd);
  install_element (ENABLE_NODE, &show_debugging_qthrift_errno_cmd);
}
