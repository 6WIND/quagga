/* qthrift main program
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

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "getopt.h"
#include "thread.h"
#include <lib/version.h>
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "workqueue.h"
#include "memory_cli.h"
#include "qthriftd/qthrift_debug.h"
#include "qthriftd/qthrift_vty.h"
#include "qthriftd/qthriftd.h"
#include "qthriftd/qthrift_network.h"

#include "qthriftd/qthrift_thrift_wrapper.h"
#include "qthriftd/bgp_configurator.h"
#include "qthriftd/bgp_updater.h"
#include "qthriftd/qthrift_bgp_configurator.h"
#include "qthriftd/qthrift_bgp_updater.h"
#include "qthriftd/qthrift_vpnservice.h"

#include <sys/types.h>
#include <sys/wait.h>

/* qthriftd options, we use GNU getopt library. */
static const struct option longopts[] =
{
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "thrift_port",    required_argument, NULL, 'p'},
  { "thrift_notif_port",    required_argument, NULL, 'n'},
  { "thrift_notif_address",    required_argument, NULL, 'N'},
  { "select_timeout_max",    required_argument, NULL, 'S'},
  { "withdraw_if_no_vrf",    no_argument, NULL, 'W'},
  { "stalemarker", required_argument, NULL, 'M'},
  { "help", 0, NULL, 'h'},
  { NULL, 0, NULL, 0}
};

/* signal definitions */
void sighup (void);
void sigint (void);
void sigusr1 (void);
void sigchild (void);

static void qthrift_exit (int);

static struct quagga_signal_t qthrift_signals[] = 
{
  { 
    .signal = SIGHUP, 
    .handler = &sighup,
  },
  {
    .signal = SIGUSR1,
    .handler = &sigusr1,
  },
  {
    .signal = SIGINT,
    .handler = &sigint,
  },
  {
    .signal = SIGTERM,
    .handler = &sigint,
  },
  {
    .signal = SIGCHLD,
    .handler = &sigchild,
  }
};

/* Route retain mode flag. */
static int retain_mode = 0;
int  qthrift_silent_leave = 0;
int qthrift_stalemarker_timer = 0;

/* Manually specified configuration file name.  */
char *config_file = NULL;

/* VTY port number and address.  */
int vty_port = 0;
char *vty_addr = NULL;
int qthrift_kill_in_progress = 0;
int qthrift_disable_stdout = 0;
int qthrift_stopbgp_called = 0;
int qthrift_withdraw_permit = 0;

/* privileges */
static zebra_capabilities_t _caps_p [] =  
{
    ZCAP_BIND, 
    ZCAP_NET_RAW,
    ZCAP_NET_ADMIN,
};

struct zebra_privs_t qthriftd_privs =
{
#if defined(QUAGGA_USER) && defined(QUAGGA_GROUP)
  .user = QUAGGA_USER,
  .group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = array_size(_caps_p),
  .cap_num_i = 0,
};

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {
      printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages thrift configuration/updates\n\n\
qthrift configuration across thrift defined model : vpnservice.\n\n\
-D                          Disable default logging to stdout \n\
-P, --thrift_port           Set thrift's config port number\n\
-p, --thrift_notif_port     Set thrift's notif update port number\n\
-N, --thrift_notif_address  Set thrift's notif update specified address\n\
-S, --select_timeout_max    Set thrift's select timeout max calue in seconds\n\
-W, --withdraw_if_no_vrf    Send back withdraw messages, when VRF not present\n\
-M, --stalemarker           Change stalemarker expiration timer in seconds\n\
-h, --help                  Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}

/* SIGHUP handler. */
void 
sighup (void)
{
  zlog (NULL, LOG_INFO, "SIGHUP received");

  /* Terminate all thread. */
  qthrift_terminate ();
  qthrift_reset ();
  zlog_notice ("qthriftd restarting!");

  /* Create VTY's socket */
  if (vty_port)
    vty_serv_sock (vty_addr, vty_port, QTHRIFT_VTYSH_PATH);

  /* Try to return to normal operation. */
}

static void
sigint_internal (void)
{
  zlog_notice ("Terminating on signal");
  if (! retain_mode) 
    {
      qthrift_terminate ();
      zprivs_terminate (&qthriftd_privs);
    }
  qthrift_exit (0);
}

/* SIGCHLD handler. */
void
sigchild (void)
{
  pid_t p;
  int status;
  struct qthrift_vpnservice *ctxt = NULL;
  as_t asNumber;

  while ((p=waitpid(-1, &status, WNOHANG)) != -1)
    {
      /* Handle the death of pid p */
      if (p == 0)
        return;
      if (qthrift_kill_in_progress)
        return;
      zlog_err("BGPD terminated (%u)",p);
      qthrift_vpnservice_get_context (&ctxt);
      /* kill BGP Daemon */
      if(ctxt == NULL)
        {
          sigint_internal();
        }
      if(qthrift_vpnservice_get_bgp_context(ctxt) == NULL)
        /* nothing to be done - BGP config already flushed */
        return;
      if (!qthrift_stopbgp_called)
        qthrift_silent_leave = 1;
      asNumber = qthrift_vpnservice_get_bgp_context(ctxt)->asNumber;
      /* reset Thrift Context */
      qthrift_kill_in_progress = 1;
      qthrift_vpnservice_terminate_bgp_context(ctxt);
      qthrift_vpnservice_terminate_thrift_bgp_cache(ctxt);
      qthrift_vpnservice_terminate_qzc(ctxt);
      /* creation of capnproto context */
      qthrift_vpnservice_setup_thrift_bgp_cache(ctxt);
      qthrift_vpnservice_setup_qzc(ctxt);
      qthrift_vpnservice_setup_bgp_context (ctxt);
      if(asNumber)
        zlog_err ("stopBgp(AS %u) OK", (as_t)asNumber);
      qthrift_kill_in_progress = 0;
      if (qthrift_stopbgp_called == 0)
        sigint();
      else
        qthrift_stopbgp_called = 0;
    }
}


/* SIGINT handler. */
void
sigint (void)
{
  qthrift_silent_leave = 1;
  sigint_internal();
}

/* SIGUSR1 handler. */
void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

void
qthrift_reset (void)
{
  vty_reset ();
}


/*
  Try to free up allocations we know about so that diagnostic tools such as
  valgrind are able to better illuminate leaks.

  Zebra route removal and protocol teardown are not meant to be done here.
  For example, "retain_mode" may be set.
*/
static void
qthrift_exit (int status)
{
  /* it only makes sense for this to be called on a clean exit */
  assert (status == 0);

  /* reverse qthrift_master_init */
  if(tm->qthrift)
    {
      qthrift_delete (tm->qthrift);
      XFREE(MTYPE_QTHRIFT,tm->qthrift);
      tm->qthrift = NULL;
    }
  
  cmd_terminate ();
  vty_terminate ();

  /* reverse qthrift_master_init */
  if (tm->master)
    thread_master_free (tm->master);

  if (zlog_default)
    closezlog (zlog_default);

  if (IS_QTHRIFT_DEBUG)
    log_memstats_stderr ("qthriftd");

  exit (status);
}

/* Main routine of thriftd. Treatment of argument and start thrift finite
   state machine is handled at here. */
int
main (int argc, char **argv)
{
  char *p;
  char *progname;
  struct thread thread;
  struct qthrift *qthrift;
  int tmp_port, opt, tmp_select;
  char vtydisplay[20];

  /* Set umask before anything for security */
  umask (0027);

  pid_t pid = proc_find(argv[0]);
  if (pid != -1)
    { 
      printf("%s: pid %u already present. cancel execution\r\n",argv[0], pid);
      return 0;
    }
  /* Preserve name of myself. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  zlog_default = openzlog (progname, ZLOG_QTHRIFT,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  /* THRIFT master init. */
  qthrift_master_init ();

  qthrift_stalemarker_timer = STALEMARKER_TIMER_DEFAULT;
  tm->qthrift_select_time = QTHRIFT_SELECT_TIME_SEC;
  /* Command line argument treatment. */
  while (1)
    {
      opt = getopt_long (argc, argv, "A:P:p:M:S:N:n:DWh", longopts, 0);
      if (opt == EOF)
	break;
      switch (opt)
	{
	case 'D':
          qthrift_disable_stdout = 1;
          break;
	case 'W':
          qthrift_withdraw_permit = 1;
          break;
	case 'M':
          qthrift_stalemarker_timer = atoi(optarg);
	  if (qthrift_stalemarker_timer < STALEMARKER_TIMER_MIN
              || qthrift_stalemarker_timer > STALEMARKER_TIMER_MAX)
            qthrift_stalemarker_timer = STALEMARKER_TIMER_DEFAULT;
          break;
	case 'A':
	  vty_addr = optarg;
	  break;
	case 'P':
          /* Deal with atoi() returning 0 on failure, and bgpd not
             listening on bgp port... */
          if (strcmp(optarg, "0") == 0)
            {
              vty_port = 0;
              break;
            }
          vty_port = atoi (optarg);
	  if (vty_port < 0 || vty_port > 0xffff)
	    vty_port = 0;
	  break;
	case 'p':
	  tmp_port = atoi (optarg);
	  if (tmp_port <= 0 || tmp_port > 0xffff)
	    tm->qthrift_listen_port = QTHRIFT_LISTEN_PORT;
	  else
	    tm->qthrift_listen_port = tmp_port;
	  break;
        case 'S':
	  tmp_select = atoi (optarg);
	  if (tmp_select <= 0 || tmp_select > 0xffff)
	    tm->qthrift_select_time = QTHRIFT_SELECT_TIME_SEC;
	  else
	    tm->qthrift_select_time = tmp_select;
	  break;
	case 'N':
          if(tm->qthrift_notification_address)
            free(tm->qthrift_notification_address);
          tm->qthrift_notification_address = strdup(optarg);
          break;
	  /* listenon implies -n */
	case 'n':
	  tmp_port = atoi (optarg);
	  if (tmp_port <= 0 || tmp_port > 0xffff)
	    tm->qthrift_notification_port = QTHRIFT_NOTIFICATION_PORT;
	  else
	    tm->qthrift_notification_port = tmp_port;
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	}
    }

  /* Initializations. */
  srandom (time (NULL));
  signal_init (tm->master, array_size(qthrift_signals), qthrift_signals);
  /* do not change uid/gid to quagga, because qthriftd needs to relaunch quagga */
  cmd_init (1);
  vty_init (tm->master);
  memory_init ();

  /* qthrift related initialization.  */
  qthrift_init (); /* XXX temporary - thrift vty - for debugging */

  host.password = XSTRDUP (MTYPE_HOST, "zebra");
  host.name = XSTRDUP (MTYPE_HOST, "qthriftd");

  /* create listen context */
  default_log_set_priority(1);
  zlog_set_level (NULL, ZLOG_DEST_STDOUT, 7);
  zlog_set_level (NULL, ZLOG_DEST_MONITOR, 7);
  zlog_set_level (NULL, ZLOG_DEST_SYSLOG, 7);
  qthrift_create_context (&qthrift);
  tm->qthrift = qthrift;

  /* Make thrift- vty socket. */
  if (vty_port)
    {
    vty_serv_sock (vty_addr, vty_port, QTHRIFT_VTYSH_PATH);
    sprintf (vtydisplay, "vty@%d,", vty_port);
    }
  else
    sprintf (vtydisplay, "");
  /* Print banner. */
  zlog_notice ("qthriftd starting: %s qthrift@%s:%d pid %d",
	       vtydisplay,
	       (tm->address ? tm->address : "<all>"),
	       qthrift_vpnservice_get_thrift_bgp_configurator_server_port(qthrift->qthrift_vpnservice),
	       getpid ());

  /* connect updater server and send notification */
  struct qthrift_vpnservice *ctxt = NULL;
  qthrift_vpnservice_get_context (&ctxt);
  ctxt->bgp_updater_client_thread = NULL;
  THREAD_TIMER_MSEC_ON(tm->master, ctxt->bgp_updater_client_thread,    \
                       qthrift_bgp_updater_on_start_config_resync_notification, \
                       ctxt, 10);
  /* Start finite state machine, here we go! */
  while (thread_fetch (tm->master, &thread))
    thread_call (&thread);

  /* Not reached. */
  return (0);
}
