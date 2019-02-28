/* qthrift master
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of GNU Quagga.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
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
#ifndef _QTHRIFT_MASTER_H_ /* _QTHRIFT_MASTER_H_ */
#define _QTHRIFT_MASTER_H_

/* Thrift master for system wide configurations and variables.  */
struct qthrift_master
{
  /* QTHRIFT only instance  */
  struct qthrift *qthrift;

  /* BGP thread master.  */
  struct thread_master *master;

  /* Listening sockets */
  struct list *listen_sockets;

  /* Listener address */
  char *address;

  /* qthriftd parameters */
  uint16_t qthrift_notification_port;
  uint16_t qthrift_listen_port;
  uint16_t qthrift_select_time;
  char *qthrift_notification_address;
};

/* Master thread strucutre. */
extern struct thread_master *master;

extern struct qthrift_master *tm;

extern int qthrift_kill_in_progress;
extern int qthrift_disable_stdout;
extern int qthrift_stopbgp_called;
extern int qthrift_silent_leave;
extern int qthrift_withdraw_permit;
extern int qthrift_stalemarker_timer;
#endif /* _QTHRIFT_MASTER_H_ */
