/*
 * BFDD - bfdd.h   
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


#ifndef _QUAGGA_BFDD_H
#define _QUAGGA_BFDD_H

#include <zebra.h>
#include "linklist.h"
#include "qzc.h"
#include "bfd.h"

extern struct thread_master *master;
extern struct bfd *bfd;
extern struct neightbl *neightbl;
extern int force_cbit_to_unset;

#define BFDD_VERSION "0.90.1"

#define BFDD_DEFAULT_CONFIG	"bfdd.conf"
#define BFDD_VTY_PORT		2609

#define BFD_PORT_1HOP		3784
#define BFD_PORT_1HOP_ECHO	3785
#define BFD_PORT_MHOP		4784

#define BFD_SOURCEPORT_MIN	49152
#define BFD_SOURCEPORT_MAX	65535

				 /* 15sec */
#define BFD_STIMEOUT		15000
#define BFD_ADMINDOWN_TIMEOUT	10000

#define BFD_NEIGH_MAX		2048
#define BFD_NEIGH_HASH_SIZE	BFD_NEIGH_MAX

#define BFD_DEBUG_ZEBRA		(1<<0)
#define BFD_DEBUG_FSM		(1<<1)
#define BFD_DEBUG_NET		(1<<2)

#define BFD_OK			0
#define BFD_ERR			-1

#define BFD_MONITOR_INTERVAL   5

struct bfd_if_info
{
  int enabled;			/* enabled flag */
  int passive;			/* passive flag */
  uint32_t interval;		/* desmintx */
  uint32_t minrx;		/* reqminrx */
  uint32_t multiplier;
};

struct bfd
{
  struct list *wqueue;		/* neighbor's wait queue */
  uint32_t debug;		/* Debug flags */

  /* Sockets */
  int sock4_1hop;
  int sock4_mhop;
  int sock4_1hop_echo;

  /* Threads serving sockets (incoming IPv4 packets) */
  struct thread *t_read4_1hop;
  struct thread *t_read4_mhop;
  struct thread *t_read4_1hop_echo;
#ifdef HAVE_IPV6
  /* Sockets */
  int sock6_1hop;
  int sock6_mhop;
  int sock6_1hop_echo;

  /* Threads serving sockets (incoming IPv6 packets ) */
  struct thread *t_read6_1hop;
  struct thread *t_read6_mhop;
  struct thread *t_read6_1hop_echo;
#endif				/* HAVE_IPV6 */

  u_char     config_data_version;
  u_int32_t  rx_interval;
  u_char     failure_threshold;
  u_int32_t  tx_interval;
  u_int32_t  debounce_down;
  u_int32_t  debounce_up;
  uint8_t    multihop;

  /* local desired mintx and required minrx
   * before bfd session gets UP */
  u_int32_t  ldesmintx;
  u_int32_t  lreqminrx;

  /* number of all bfd neighbors */
  u_int16_t  nr_all_neighs;
  /* number of available bfd neighbors. One available bfd neighbor means that
   * its bfd state is UP and the BFD state has been notified to zebra.
   */
  u_int16_t  nr_available_neighs;

  int      underlay_limit_enable;
  int      never_send_down_event;
  /* In seconds, after this time NEIGH_DOWN will be sent to zebra */
  u_int16_t underlay_limit_timeout;
#define DEFAULT_BFD_UNDERLAY_LIMIT_TIMEOUT 180

  char *logFile;
  char *logLevel;
  char *logLevelSyslog;

  /* passive is applicable only at the start time of one bfd session */
  int    passive_startup_only;

  struct bfd_if_info global_info;
  uint32_t total_rx_cnt;
  uint32_t total_rx_cnt_drop;

  QZC_NODE
};

struct neighstruct
{
  struct route_table *raddr;
};

struct neightbl
{
  struct hash *ldisc;
  struct neighstruct *v4;
#ifdef HAVE_IPV6
  struct neighstruct *v6;
#endif				/* HAVE_IPV6 */
};

struct bfd_addrtreehdr
{
  int count;			/* Number of nodes in radix tree */
  struct route_table *info;	/* BFD subnode tree, 
				   for storing local addr part of socket */
};

struct bfd_lport
{
  uint16_t v4;
#ifdef HAVE_IPV6
  uint16_t v6;
#endif				/* HAVE_IPV6 */
};

struct bfd_server_addr
{
  struct in_addr ipv4_addr;
  struct in6_addr ipv6_addr;
};

struct bfd_neigh
{
  /* Sesion ID, state and diagnostic */
  uint8_t lstate;		/* Local Session State */
  uint8_t rstate;		/* Remote Session State */

  uint8_t ldiag;		/* Local Diagnostic */
  uint8_t rdiag;		/* Remote Diag */

  uint32_t ldisc;		/* Local Discriminator */
  uint32_t rdisc;		/* Remote Discriminator */

  /* Timers */
  uint32_t ldesmintx;		/* Local Desired Min Tx Interval */
  uint32_t ldesmintx_a;		/* Local Desired Min Tx Interval advertised */
  uint32_t rdesmintx;		/* Remote Desired Min Tx Interval */

  uint32_t lreqminrx;		/* Local Required Min Rx Interval */
  uint32_t lreqminrx_a;		/* Local Required Min Rx Interval advertised */
  uint32_t rreqminrx;		/* Remote Required Min Rx Interval */

  uint32_t negtxint;		/* Negotiated TX interval */
  uint32_t negrxint;		/* Negotiated RX interval */
  uint32_t txint;		/* Negotiated TX interval minus jitter */

  uint32_t lreqminechorx;	/* Local  Required Min Echo RX Interval */
  uint32_t rreqminechorx;	/* Remote Required Min Echo RX Interval */

  uint8_t lmulti;		/* Local detect Multiplier */
  uint8_t rmulti;		/* Remote detect Multiplier */

  uint32_t dtime;		/* Detection Time */

  /* Authentication */
  uint8_t authtype;		/* Authentication Type */
  uint32_t rcvauthseq;		/* Received Authentication Sequence */
  uint32_t xmitauthseq;		/* Transmitted Authentication Sequence */
  uint8_t authseqknown;		/* Authentication Sequence Known */

  /* Packet info */
  uint8_t llen;			/* Local packet length */
  uint8_t rlen;			/* Remote packet length */
  uint8_t lver;			/* Local  BFD CP version */
  uint8_t rver;			/* Remote BFD CP version */

  /* Bits (flags) */
#define BFD_BIT_M  (1<<0)	/* Multipoint */
#define BFD_BIT_D  (1<<1)	/* Demand */
#define BFD_BIT_A  (1<<2)	/* Authentication Present */
#define BFD_BIT_C  (1<<3)	/* Control Plane Independent */
#define BFD_BIT_F  (1<<4)	/* Final */
#define BFD_BIT_P  (1<<5)	/* Poll */
  uint8_t lbits;		/* Local BFD bits (flags) */
  uint8_t rbits;		/* Remote BFD bits (flags) */

  /* FSM States */
  int status;			/* FSM State */
  int ostatus;			/* Old FSM State */

  /* Threads */
  struct thread *t_timer;	/* BFD FSM Timer (holdown) */
  struct thread *t_hello;	/* BFD cntl pkt periodic transmission thread */
  struct thread *t_session;	/* Session "timeout" (amount of time for which
				   we maintain the session in "Down" state when 
				   no BFD CP are received). When timer elapses session
				   is cleared */
  struct thread *t_admindown;	/* Session admindown timeout, the thread is launched after
				   BFD CP with "AdminDown" state is received from remote in
				   order to reset bfd timers */
  struct thread *t_delete;	/* Session delete timer (period of time that we xmit
				   BFD control packets  with "AdminDown" state 
				   after which neighbor(session) is removed */
  struct thread *t_debounce_up;   /* A timer to notify zebra the state change to "Up"*/
  struct thread *t_debounce_down; /* A timer to notify zebra the state change to "Down"*/
  int wanted_state;               /* The expected next state, used for debounce timer */

  struct thread *t_underlay_limit;/* A timer to send NEIGH_DOWN which was suppressed by
                                     underlay limit */
#define UNDERLAY_LIMIT_STATE_NORMAL     0  /* NEIGH_DOWN is sent immediately */
#define UNDERLAY_LIMIT_STATE_NEVER_SEND 1  /* NEIGH_DOWN is never sent */
#define UNDERLAY_LIMIT_STATE_DELAY_SEND 2  /* NEIGH_DOWN is delayed to be sent */
#define UNDERLAY_LIMIT_STATE_DELAY_SENT 3  /* NEIGH_DOWN is sent at the expiry of underlay limit timer */
  int underlay_limit_state;       /* BFD underlay limit state of a neighbor */

  /* Misc */
  uint32_t flags;		/* Flags (do not confuse with bits from BFDCP).
				   These flags contains requirements from BFD clients
				   to bfd session. (e.g. 1HOP or MHOP, ASYNCH or DEMAND */
  int notify;			/* Flag that indicates if FSM debug message was 
				   logged already or not. Is used also for checking
				   if notification about state change was send to zebra */
  int del;			/* Flags that indicates that session started delete procedure */


  /* Sockets and stuff */
  int sock;			/* Socket */
  uint16_t lport;		/* Local (source) port for BFDCP transmission */
  unsigned int ifindex;		/* ifindex of the BFD connection. */
  union sockunion *su_local;	/* Sockunion of local address.  */
  union sockunion *su_remote;	/* Sockunion of remote address.  */

  /* Statistics */
  time_t uptime;		/* Up/Down state uptime  */
  time_t last_xmit;		/* Time of last transmitted packet  */
  time_t last_recv;		/* Time of last received packet  */
  uint32_t xmit_cnt;		/* Total number of transmitted packets */
  uint32_t recv_cnt;		/* Total number of received not discarded packets */
  uint32_t discard_cnt; 	/* Total number of discarded packets */
  uint32_t orecv_cnt;		/* Snapshot of recv_cnt for session timeout detect. */
  uint32_t timer_cnt;		/* Number of "TIMER" events */
  uint32_t down_cnt;		/* Number of bfd "DOWN" events */
  uint32_t up_cnt;		/* Number of bfd "UP" events */
  uint32_t notify_down_cnt;	/* Number of notifying zebra the state change to "DOWN" */
  uint32_t notify_up_cnt;	/* Number of notifying zebra the state change to "UP" */
};

#define BFD_TIMER_MSEC_ON(T,F,V) THREAD_TIMER_MSEC_ON(master,(T),(F),neighp,(V))
#define BFD_TIMER_OFF(T) THREAD_TIMER_OFF(T)

#define BFD_READ_ON(T,F,V) THREAD_READ_ON(master,T,F,bfd,V)

#define bfd_check_neigh_family(NEIGHP) (((NEIGHP)->su_local)->sa.sa_family)

/* Macros for checking local and remote flags */
#define bfd_neigh_check_lbit_p(NEIGHP) ((((NEIGHP)->lbits) & BFD_BIT_P) ? 1 : 0)
#define bfd_neigh_check_lbit_f(NEIGHP) ((((NEIGHP)->lbits) & BFD_BIT_F) ? 1 : 0)
#define bfd_neigh_check_lbit_c(NEIGHP) ((((NEIGHP)->lbits) & BFD_BIT_C) ? 1 : 0)
#define bfd_neigh_check_lbit_a(NEIGHP) ((((NEIGHP)->lbits) & BFD_BIT_A) ? 1 : 0)
#define bfd_neigh_check_lbit_d(NEIGHP) ((((NEIGHP)->lbits) & BFD_BIT_D) ? 1 : 0)
#define bfd_neigh_check_lbit_m(NEIGHP) ((((NEIGHP)->lbits) & BFD_BIT_M) ? 1 : 0)

#define bfd_neigh_check_rbit_d(NEIGHP) ((((NEIGHP)->rbits) & BFD_BIT_D) ? 1 : 0)
#define bfd_neigh_check_rbit_f(NEIGHP) ((((NEIGHP)->rbits) & BFD_BIT_F) ? 1 : 0)
#define bfd_neigh_check_rbit_p(NEIGHP) ((((NEIGHP)->rbits) & BFD_BIT_P) ? 1 : 0)
#define bfd_neigh_check_rbit_c(NEIGHP) ((((NEIGHP)->rbits) & BFD_BIT_C) ? 1 : 0)
#define bfd_neigh_check_rbit_a(NEIGHP) ((((NEIGHP)->rbits) & BFD_BIT_A) ? 1 : 0)

/* Packet legth */
#define bfd_neigh_check_lplen(NEIGHP)  ((bfd_neigh_check_lbit_a(NEIGHP)) \
					? BFD_PACKET_SIZE_AUTH \
					: BFD_PACKET_SIZE_NOAUTH )

extern struct bfd_server_addr bfd_srv_addr;

void bfd_init (void);
void bfd_terminate (void);
void bfd_cfg (void);

struct bfd_neigh *bfd_neigh_init (struct bfd_cneigh *cneighp);

struct bfd_neigh *bfd_cneigh_to_neigh (struct bfd_cneigh *cneighp);

#define BFD_NEIGH_ADD    1
#define BFD_NEIGH_DEL    2
#define bfd_neightbl_raddr_add(NEIGHP) \
  bfd_neightbl_raddr_adddel(BFD_NEIGH_ADD, NEIGHP)
#define bfd_neightbl_raddr_del(NEIGHP) \
  bfd_neightbl_raddr_adddel(BFD_NEIGH_DEL, NEIGHP)

struct bfd_neigh *bfd_find_neigh (struct prefix *raddr, struct prefix *laddr,
				  unsigned int ifindex);

int bfd_neigh_add (struct bfd_neigh *neighp);
int bfd_neigh_del (struct bfd_neigh *neighp);
int bfd_cneigh_del (struct bfd_cneigh *cneighp);
struct bfd_neigh *bfd_wqueue_lookup (struct bfd_neigh *neighp);

/* BFD uptime string length.  */
#define BFD_UPTIME_LEN 25

char *bfd_neigh_uptime (time_t uptime2, char *buf, size_t len);

#endif /* _ZEBRA_BFD_H */
