/*
 * Test program to verify that scheduled timers are executed in the
 * correct order.
 *
 * Copyright (C) 2013 by Open Source Routing.
 * Copyright (C) 2013 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2015 by David Lamparter, for NetDEF, Inc.
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <stdio.h>
#include <unistd.h>

#include <zebra.h>

#include "qzmq.h"
#include "thread.h"
#include "memory.h"
#include "pqueue.h"
#include "prng.h"
#include "log.h"
#include "command.h"
#include "common-cli.h"

static int dummy_req = 0, dummy_rep = 1;

static void callback (void *arg, void *zmqsock, zmq_msg_t *msg)
{
  int64_t more = 0;
  size_t more_size;
  int ret;

  do
    {
      void *data = zmq_msg_data (msg);
      size_t size = zmq_msg_size (msg);

      zlog_info ("msg: %zu(%p) %s", size, data, (const char *)data);

      more_size = sizeof (more);
      ret = zmq_getsockopt (zmqsock, ZMQ_RCVMORE, &more, &more_size);
      zlog_info ("more data: (%d)%lld", ret, (long long)more);

      if (more)
        {
          ret = zmq_msg_recv (msg, zmqsock, ZMQ_NOBLOCK);
          if (ret < 0)
            {
              zlog_err ("zmq_msg_recv failed: %s (%d)", strerror (errno), errno);
              return;
            }
        }
    }
  while (more);

  if (arg == (void *)&dummy_rep)
    {
      zlog_info ("REP socket, sending reply");
      zmq_send_const (zmqsock, "ACK\0", 4, 0);
    }
}

DEFUN (zmq_open_rep,
       zmq_open_rep_cmd,
       "zmq open rep URL",
       "ZeroMQ\n"
       "open a socket\n"
       "ZeroMQ REPly type\n"
       "socket URL")
{
  void *rep = zmq_socket (qzmq_context, ZMQ_REP);

  if (!rep)
    {
      vty_out (vty, "zmq_socket failed: %s (%d)%s", strerror (errno), errno,
                    VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (zmq_bind (rep, argv[0]))
    {
      vty_out (vty, "zmq_bind failed: %s (%d)%s", strerror (errno), errno,
                    VTY_NEWLINE);
      return CMD_WARNING;
    }
  qzmq_thread_read_msg (master, callback, &dummy_rep, rep);

  vty_out (vty, "zmq socket %p%s", rep, VTY_NEWLINE);
  return CMD_SUCCESS;
}

void *last_req_opened = NULL;

DEFUN (zmq_open_req,
       zmq_open_req_cmd,
       "zmq open req URL",
       "ZeroMQ\n"
       "open a socket\n"
       "ZeroMQ REQuest type\n"
       "socket URL")
{
  void *req = zmq_socket (qzmq_context, ZMQ_REQ);
  if (!req)
    {
      vty_out (vty, "zmq_socket failed: %s (%d)%s", strerror (errno), errno,
                    VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (zmq_connect (req, argv[0]))
    {
      vty_out (vty, "zmq_connect failed: %s (%d)%s", strerror (errno), errno,
                    VTY_NEWLINE);
      return CMD_WARNING;
    }
  qzmq_thread_read_msg (master, callback, &dummy_req, req);

  last_req_opened = req;

  vty_out (vty, "zmq socket %p%s", req, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (zmq_do_send,
       zmq_do_send_cmd,
       "zmq send .LINE",
       "ZeroMQ\n"
       "send operation\n"
       "data to send")
{
  if (!last_req_opened)
    {
      vty_out (vty, "open a REQ socket first please%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (zmq_send (last_req_opened, argv[0], strlen (argv[0]) + 1, 0) < 0)
    {
      vty_out (vty, "zmq_send failed: %s (%d)%s", strerror (errno), errno,
                    VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (zmq_exit,
       zmq_exit_cmd,
       "zmq exit",
       "ZeroMQ\n"
       "clean exit")
{
  qzmq_finish ();
  return CMD_SUCCESS;
}

void test_init (void)
{
  qzmq_init ();
  install_element (ENABLE_NODE, &zmq_open_req_cmd);
  install_element (ENABLE_NODE, &zmq_open_rep_cmd);
  install_element (ENABLE_NODE, &zmq_do_send_cmd);
  install_element (ENABLE_NODE, &zmq_exit_cmd);

  return;
}
