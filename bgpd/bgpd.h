/* BGP message definition header.
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGPD_H
#define _QUAGGA_BGPD_H

/* For union sockunion.  */
#include "sockunion.h"
#include "bgp_ecommunity.h"
#include "prefix.h"
#include "filter.h"
#include "vty.h"
#include "qzc.h"

/* Typedef BGP specific types.  */
typedef u_int32_t as_t;
typedef u_int16_t as16_t; /* we may still encounter 16 Bit asnums */
typedef u_int16_t bgp_size_t;

struct bgp_node;

/* BGP router distinguisher value.  */
#define BGP_RD_SIZE                8
#define BGP_MAX_LABELS 6

struct bgp_rd
{
  u_char val[BGP_RD_SIZE];
};

/* BGP master for system wide configurations and variables.  */
struct bgp_master
{
  /* BGP instance list.  */
  struct list *bgp;

  /* BGP thread master.  */
  struct thread_master *master;

  /* Monitor thriftd. If thriftd dies, force bgpd to exit. */
  struct thread *bgp_monitor_thread;
#define BGP_MONITOR_INTERVAL   5

  /* work queues */
  struct work_queue *process_main_queue;
  struct work_queue *process_rsclient_queue;
  struct work_queue *process_vrf_queue;
  
  /* Listening sockets */
  struct list *listen_sockets;
  
  /* BGP port number.  */
  u_int16_t port;

  /* Listener address */
  char *address;

  /* BGP start time.  */
  time_t start_time;

  /* Various BGP global configuration.  */
  u_char options;
#define BGP_OPT_NO_FIB                   (1 << 0)
#define BGP_OPT_MULTIPLE_INSTANCE        (1 << 1)
#define BGP_OPT_CONFIG_CISCO             (1 << 2)
#define BGP_OPT_NO_LISTEN                (1 << 3)

  QZC_NODE
};

/* BGP instance structure.  */
struct bgp 
{
  /* AS number of this BGP instance.  */
  as_t as;

  /* Name of this BGP instance.  */
  char *name;
  
  /* Reference count to allow peer_delete to finish after bgp_delete */
  int lock;

  /* Self peer.  */
  struct peer *peer_self;

  /* BGP peer. */
  struct list *peer;

  /* BGP peer group.  */
  struct list *group;

  /* BGP route-server-clients. */
  struct list *rsclient;

  /* BGP configuration.  */
  u_int16_t config;
#define BGP_CONFIG_ROUTER_ID              (1 << 0)
#define BGP_CONFIG_CLUSTER_ID             (1 << 1)
#define BGP_CONFIG_CONFEDERATION          (1 << 2)

  /* BGP router identifier.  */
  struct in_addr router_id;
  struct in_addr router_id_static;

  /* BGP route reflector cluster ID.  */
  struct in_addr cluster_id;

  /* BGP confederation information.  */
  as_t confed_id;
  as_t *confed_peers;
  int confed_peers_cnt;

  struct thread *t_startup;

  /* BGP flags. */
  u_int32_t flags;
#define BGP_FLAG_ALWAYS_COMPARE_MED       (1 << 0)
#define BGP_FLAG_DETERMINISTIC_MED        (1 << 1)
#define BGP_FLAG_MED_MISSING_AS_WORST     (1 << 2)
#define BGP_FLAG_MED_CONFED               (1 << 3)
#define BGP_FLAG_NO_DEFAULT_IPV4          (1 << 4)
#define BGP_FLAG_NO_CLIENT_TO_CLIENT      (1 << 5)
#define BGP_FLAG_ENFORCE_FIRST_AS         (1 << 6)
#define BGP_FLAG_COMPARE_ROUTER_ID        (1 << 7)
#define BGP_FLAG_ASPATH_IGNORE            (1 << 8)
#define BGP_FLAG_IMPORT_CHECK             (1 << 9)
#define BGP_FLAG_NO_FAST_EXT_FAILOVER     (1 << 10)
#define BGP_FLAG_LOG_NEIGHBOR_CHANGES     (1 << 11)
#define BGP_FLAG_GRACEFUL_RESTART         (1 << 12)
#define BGP_FLAG_ASPATH_CONFED            (1 << 13)
#define BGP_FLAG_ASPATH_MULTIPATH_RELAX   (1 << 14)
#define BGP_FLAG_DELETING                 (1 << 15)
#define BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY (1 << 16)
#define BGP_FLAG_GR_PRESERVE_FWD          (1 << 17)
#define BGP_FLAG_BFD_SYNC                 (1 << 18)
#define BGP_FLAG_BFD_MULTIHOP             (1 << 19)

  /* BGP Per AF flags */
  u_int16_t af_flags[AFI_MAX][SAFI_MAX];
#define BGP_CONFIG_DAMPENING              (1 << 0)
#define BGP_CONFIG_ASPATH_MULTIPATH_RELAX (1 << 1)
#define BGP_CONFIG_MULTIPATH              (1 << 2)

  /* Static route configuration.  */
  struct bgp_table *route[AFI_MAX][SAFI_MAX];

  /* Aggregate address configuration.  */
  struct bgp_table *aggregate[AFI_MAX][SAFI_MAX];

  /* BGP routing information base.  */
  struct bgp_table *rib[AFI_MAX][SAFI_MAX];

  /* BGP redistribute configuration. */
  u_char redist[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* BGP redistribute metric configuration. */
  u_char redist_metric_flag[AFI_MAX][ZEBRA_ROUTE_MAX];
  u_int32_t redist_metric[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* BGP redistribute route-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } rmap[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* BGP distance configuration.  */
  u_char distance_ebgp;
  u_char distance_ibgp;
  u_char distance_local;

  /* BGP ipv6 distance configuration.  */
  u_char ipv6_distance_ebgp;
  u_char ipv6_distance_ibgp;
  u_char ipv6_distance_local;
  
  /* BGP default local-preference.  */
  u_int32_t default_local_pref;

  /* BGP default timer.  */
  u_int32_t default_holdtime;
  u_int32_t default_keepalive;

  /* BGP graceful restart */
  u_int32_t restart_time;
  u_int32_t stalepath_time;

  /* Maximum-paths configuration */
  struct bgp_maxpaths_cfg {
    u_int16_t maxpaths_ebgp;
    u_int16_t maxpaths_ibgp;
  } maxpaths[AFI_MAX][SAFI_MAX];

  /* VRFs */
  struct list *vrfs;

  struct hash *rt_subscribers;

  /* outbound update feeds */
  char *notify_zmq_url;
  void *notify_zmq;

#define MAX_EOR_UPDATE_DELAY 3600
  u_int16_t v_update_delay;
#define MAX_BGP_SELECTION_DEFERRAL 720000
  u_int32_t v_selection_deferral;

  QZC_NODE
};

struct bgp_rt_sub
{
  struct ecommunity_val rt;

  struct list *vrfs;
};

/* Next hop self address. */
struct bgp_nexthop
{
  struct interface *ifp;
  struct in_addr v4;
  struct in6_addr v6_global;
  struct in6_addr v6_local;
};

typedef enum
{
  BGP_LAYER_TYPE_2 = 1,
  BGP_LAYER_TYPE_3 = 2,
} bgp_layer_type_t;

struct bgp_vrf
{
  struct bgp *bgp;

  char *name;

  /* TYPE2 for EVPN MAC/IP routes, TYPE3 for others */
  bgp_layer_type_t ltype;

  /* RD used for route advertisements */
  struct prefix_rd outbound_rd;

  /* import and export lists */
  struct ecommunity *rt_import;
  struct ecommunity *rt_export;

  /* BGP routing information base.  */
  struct bgp_table *rib[AFI_MAX];

  /* Static route configuration.  */
  struct bgp_table *route[AFI_MAX];

  /* Enable VRF table configuration */
  uint8_t afc[AFI_MAX][SAFI_MAX];

  /* maximum multipath entries for the VRF */
  uint32_t max_mpath_configured;
  uint32_t max_mpath[AFI_MAX][SAFI_MAX];
  /* default route */
  struct bgp_nexthop nh;

  /* labels of Route Distinguishers */
  uint32_t labels[BGP_MAX_LABELS];
  size_t nlabels;
  /* EVPN information */
  uint32_t ethtag;
  char *esi;
  char *mac_router;
  struct in_addr ipv4_gatewayIp;
  struct in6_addr ipv6_gatewayIp;

  /* internal flag */
#define BGP_VRF_RD_UNSET 1
#define BGP_VRF_MPATH_CHANGE 1   /* this vrf's multipath has been changed */
  uint16_t flag;

  /* List of auto discovery statically set */
  struct list *static_evpn_ad;
  struct list *rx_evpn_ad;
  /* for import processing */
  struct list *import_processing_evpn_ad;

  QZC_NODE
};

struct bgp_event_vrf
{
#define BGP_EVENT_MASK_ANNOUNCE 0x1
#define BGP_EVENT_SHUT 0x2
#define BGP_EVENT_BFD_STATUS 0x3
  uint8_t announce;
  struct prefix_rd outbound_rd; /* dummy for event_shut */
  struct prefix prefix; /* alias subtype */
  struct prefix nexthop; /* alias peer */
  uint32_t label; /* alias type */
  uint32_t ethtag;
  uint32_t l2label;
  char *esi;
  char *mac_router;
  char *gatewayIp;
};

struct bgp_event_shut
{
  struct prefix peer;
  uint8_t type, subtype;
};

struct bgp_event_bfd_status
{
  struct prefix peer;
  as_t   as;
  uint8_t up_down;
#define BGP_EVENT_BFD_STATUS_UP   1
#define BGP_EVENT_BFD_STATUS_DOWN 0
};

#define ROUTE_TYPE_LABELED_UNICAST  1
#define ROUTE_TYPE_MPLSVPN          2
#define ROUTE_TYPE_EVPN             3

struct bgp_api_route
{
  struct prefix prefix;
  struct prefix nexthop;
  uint32_t label;
  uint32_t l2label;
  uint32_t ethtag;
  char *esi;
  char *mac_router;
  struct prefix gatewayIp;
};

/* BGP peer-group support. */
struct peer_group
{
  /* Name of the peer-group. */
  char *name;

  /* Pointer to BGP.  */
  struct bgp *bgp;
  
  /* Peer-group client list. */
  struct list *peer;

  /* Peer-group config */
  struct peer *conf;
};

/* BGP Notify message format. */
struct bgp_notify 
{
  u_char code;
  u_char subcode;
  char *data;
  bgp_size_t length;
};

#define RMAP_IN           0
#define RMAP_OUT        1
#define RMAP_IMPORT   2
#define RMAP_EXPORT   3
#define RMAP_MAX        4

/* BGP filter structure. */
struct bgp_filter
{
  /* Distribute-list.  */
  struct 
  {
    char *name;
    struct access_list *alist;
  } dlist[FILTER_MAX];

  /* Prefix-list.  */
  struct
  {
    char *name;
    struct prefix_list *plist;
  } plist[FILTER_MAX];

  /* Filter-list.  */
  struct
  {
    char *name;
    struct as_list *aslist;
  } aslist[FILTER_MAX];

  /* Route-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } map[RMAP_MAX];

  /* Unsuppress-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } usmap;
};

/* IBGP/EBGP identifier.  We also have a CONFED peer, which is to say,
   a peer who's AS is part of our Confederation.  */
typedef enum
{
  BGP_PEER_IBGP = 1,
  BGP_PEER_EBGP,
  BGP_PEER_INTERNAL,
  BGP_PEER_CONFED,
} bgp_peer_sort_t;

#define BGP_MAX_PACKET_SIZE_OVERFLOW          1024

enum bgp_clear_route_type
{
  BGP_CLEAR_ROUTE_NORMAL,
  BGP_CLEAR_ROUTE_MY_RSCLIENT,
  BGP_CLEAR_ROUTE_REFRESH
};

/* BGP neighbor structure. */
struct peer
{
  /* BGP structure.  */
  struct bgp *bgp;

  /* reference count, primarily to allow bgp_process'ing of route_node's
   * to be done after a struct peer is deleted.
   *
   * named 'lock' for hysterical reasons within Quagga.
   */
  int lock;

  /* BGP peer group.  */
  struct peer_group *group;
  u_char af_group[AFI_MAX][SAFI_MAX];

  /* Peer's remote AS number. */
  as_t as;			

  /* Peer's local AS number. */
  as_t local_as;

  bgp_peer_sort_t sort;

  /* Peer's Change local AS number. */
  as_t change_local_as;

  /* Remote router ID. */
  struct in_addr remote_id;

  /* Local router ID. */
  struct in_addr local_id;

  /* Peer specific RIB when configured as route-server-client. */
  struct bgp_table *rib[AFI_MAX][SAFI_MAX];

  /* Packet receive and send buffer. */
  struct stream *ibuf;
  struct stream_fifo *obuf;
  struct stream *work;

  /* We use a separate stream to encode MP_REACH_NLRI for efficient
   * NLRI packing. peer->work stores all the other attributes. The
   * actual packet is then constructed by concatenating the two.
   */
  struct stream *scratch;

  /* Status of the peer. */
  int status;
  int ostatus;

  /* Peer index, used for dumping TABLE_DUMP_V2 format */
  uint16_t table_dump_index;

  /* Peer information */
  int fd;			/* File descriptor */
  int ttl;			/* TTL of TCP connection to the peer. */
  int rtt;			/* Estimated round-trip-time from TCP_INFO */
  int gtsm_hops;		/* minimum hopcount to peer */
  char *desc;			/* Description of the peer. */
  unsigned short port;          /* Destination port for peer */
  char *host;			/* Printable address of the peer. */
  union sockunion su;		/* Sockunion address of the peer. */
  time_t uptime;		/* Last Up/Down time */
  time_t readtime;		/* Last read time */
  time_t resettime;		/* Last reset time */
  
  ifindex_t ifindex;		/* ifindex of the BGP connection. */
  char *ifname;			/* bind interface name. */
  char *update_if;
  union sockunion *update_source;
  struct zlog *log;

  union sockunion *su_local;	/* Sockunion of local address.  */
  union sockunion *su_remote;	/* Sockunion of remote address.  */
  int shared_network;		/* Is this peer shared same network. */
  struct bgp_nexthop nexthop;	/* Nexthop */

  /* BFD section */
  union sockunion *bfd_su_local;/* src address for transmission of BFD CP */
  unsigned int bfd_ifindex;     /* interface for session */
  int bfd_flags;                /* flags passed to zebra/bfd */
  int bfd_status;               /* status of BFD session */
#define PEER_BFD_STATUS_NEW     1 /* fall-over bfd command was executed 
                                     but zebra/bfd weren't notied yet 
				     (waiting for ESTABLISHED state) */
#define PEER_BFD_STATUS_ADDED   2 /* request for adding neighbor has been sent*/
#define PEER_BFD_STATUS_DELETED 3 /* neighbor will be deleted soon */
#define PEER_BFD_STATUS_UP      5 /* zebra/bfd reported that 
				     neighbor(session) is up */
#define PEER_BFD_STATUS_DOWN    6 /* zebra/bfd reported that
				     neighbor(session) is down */
#define BGP_PEER_BFD_STATUS_MAX 7

  /* Peer address family configuration. */
  u_char afc[AFI_MAX][SAFI_MAX];
  u_char afc_nego[AFI_MAX][SAFI_MAX];
  u_char afc_adv[AFI_MAX][SAFI_MAX];
  u_char afc_recv[AFI_MAX][SAFI_MAX];

  /* Capability flags (reset in bgp_stop) */
  u_int16_t cap;
#define PEER_CAP_REFRESH_ADV                (1 << 0) /* refresh advertised */
#define PEER_CAP_REFRESH_OLD_RCV            (1 << 1) /* refresh old received */
#define PEER_CAP_REFRESH_NEW_RCV            (1 << 2) /* refresh rfc received */
#define PEER_CAP_DYNAMIC_ADV                (1 << 3) /* dynamic advertised */
#define PEER_CAP_DYNAMIC_RCV                (1 << 4) /* dynamic received */
#define PEER_CAP_RESTART_ADV                (1 << 5) /* restart advertised */
#define PEER_CAP_RESTART_RCV                (1 << 6) /* restart received */
#define PEER_CAP_AS4_ADV                    (1 << 7) /* as4 advertised */
#define PEER_CAP_AS4_RCV                    (1 << 8) /* as4 received */
#define PEER_CAP_RESTART_BIT_ADV            (1 << 9) /* sent restart state */
#define PEER_CAP_RESTART_BIT_RCV            (1 << 10) /* peer restart state */

  /* Capability flags (reset in bgp_stop) */
  u_int16_t af_cap[AFI_MAX][SAFI_MAX];
#define PEER_CAP_ORF_PREFIX_SM_ADV          (1 << 0) /* send-mode advertised */
#define PEER_CAP_ORF_PREFIX_RM_ADV          (1 << 1) /* receive-mode advertised */
#define PEER_CAP_ORF_PREFIX_SM_RCV          (1 << 2) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_RCV          (1 << 3) /* receive-mode received */
#define PEER_CAP_ORF_PREFIX_SM_OLD_RCV      (1 << 4) /* send-mode received */
#define PEER_CAP_ORF_PREFIX_RM_OLD_RCV      (1 << 5) /* receive-mode received */
#define PEER_CAP_RESTART_AF_RCV             (1 << 6) /* graceful restart afi/safi received */
#define PEER_CAP_RESTART_AF_PRESERVE_RCV    (1 << 7) /* graceful restart afi/safi F-bit received */

  /* Global configuration flags. */
  u_int32_t flags;
#define PEER_FLAG_PASSIVE                   (1 << 0) /* passive mode */
#define PEER_FLAG_SHUTDOWN                  (1 << 1) /* shutdown */
#define PEER_FLAG_DONT_CAPABILITY           (1 << 2) /* dont-capability */
#define PEER_FLAG_OVERRIDE_CAPABILITY       (1 << 3) /* override-capability */
#define PEER_FLAG_STRICT_CAP_MATCH          (1 << 4) /* strict-match */
#define PEER_FLAG_DYNAMIC_CAPABILITY        (1 << 5) /* dynamic capability */
#define PEER_FLAG_DISABLE_CONNECTED_CHECK   (1 << 6) /* disable-connected-check */
#define PEER_FLAG_LOCAL_AS_NO_PREPEND       (1 << 7) /* local-as no-prepend */
#define PEER_FLAG_LOCAL_AS_REPLACE_AS       (1 << 8) /* local-as no-prepend replace-as */
#define PEER_FLAG_USE_CONFIGURED_SOURCE     (1 << 9) /* use configured source-only */
#define PEER_FLAG_MULTIHOP                  (1 << 10) /* multihop */
#define PEER_FLAG_BFD                       (1 << 11) /* fall-over bfd */
#define PEER_FLAG_BFD_SYNC                  (1 << 12) /* fall-over bfd sync */

  /* NSF mode (graceful restart) */
  u_char nsf[AFI_MAX][SAFI_MAX];

  /* Per AF configuration flags. */
  u_int32_t af_flags[AFI_MAX][SAFI_MAX];
#define PEER_FLAG_SEND_COMMUNITY            (1 << 0) /* send-community */
#define PEER_FLAG_SEND_EXT_COMMUNITY        (1 << 1) /* send-community ext. */
#define PEER_FLAG_NEXTHOP_SELF              (1 << 2) /* next-hop-self */
#define PEER_FLAG_REFLECTOR_CLIENT          (1 << 3) /* reflector-client */
#define PEER_FLAG_RSERVER_CLIENT            (1 << 4) /* route-server-client */
#define PEER_FLAG_SOFT_RECONFIG             (1 << 5) /* soft-reconfiguration */
#define PEER_FLAG_AS_PATH_UNCHANGED         (1 << 6) /* transparent-as */
#define PEER_FLAG_NEXTHOP_UNCHANGED         (1 << 7) /* transparent-next-hop */
#define PEER_FLAG_MED_UNCHANGED             (1 << 8) /* transparent-next-hop */
#define PEER_FLAG_DEFAULT_ORIGINATE         (1 << 9) /* default-originate */
#define PEER_FLAG_REMOVE_PRIVATE_AS         (1 << 10) /* remove-private-as */
#define PEER_FLAG_ALLOWAS_IN                (1 << 11) /* set allowas-in */
#define PEER_FLAG_ORF_PREFIX_SM             (1 << 12) /* orf capability send-mode */
#define PEER_FLAG_ORF_PREFIX_RM             (1 << 13) /* orf capability receive-mode */
#define PEER_FLAG_MAX_PREFIX                (1 << 14) /* maximum prefix */
#define PEER_FLAG_MAX_PREFIX_WARNING        (1 << 15) /* maximum prefix warning-only */
#define PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED   (1 << 16) /* leave link-local nexthop unchanged */
#define PEER_FLAG_NEXTHOP_SELF_ALL          (1 << 17) /* next-hop-self all */

 /* list of EVPN and VPNv4 default route configured (bgp_vrf*) */
 struct list *def_route_rd_vpnv4;
 struct list *def_route_rd_vpnv6;
 struct list *def_route_rd_evpn;

  /* MD5 password */
  char *password;

  /* default-originate route-map.  */
  struct
  {
    char *name;
    struct route_map *map;
  } default_rmap[AFI_MAX][SAFI_MAX];

  /* Peer status flags. */
  u_int16_t sflags;
#define PEER_STATUS_ACCEPT_PEER	      (1 << 0) /* accept peer */
#define PEER_STATUS_PREFIX_OVERFLOW   (1 << 1) /* prefix-overflow */
#define PEER_STATUS_CAPABILITY_OPEN   (1 << 2) /* capability open send */
#define PEER_STATUS_HAVE_ACCEPT       (1 << 3) /* accept peer's parent */
#define PEER_STATUS_GROUP             (1 << 4) /* peer-group conf */
#define PEER_STATUS_NSF_MODE          (1 << 5) /* NSF aware peer */
#define PEER_STATUS_NSF_WAIT          (1 << 6) /* wait comeback peer */
#define PEER_STATUS_BFD_CBIT          (1 << 7) /* BFD C-bit from peer */
#define PEER_STATUS_HOLDTIME_EXPIRED  (1 << 8) /* TCP Hold timer expired */
#define PEER_STATUS_CLOSE_SESSION     (1 << 9) /* peer closed session without graceful restart */
#define PEER_STATUS_PEER_UP_SENT      (1 << 10)/* peerUp() sent */
#define PEER_STATUS_PEER_DOWN_SENT    (1 << 11)/* peerDown() sent */

  /* Peer status af flags (reset in bgp_stop) */
  u_int16_t af_sflags[AFI_MAX][SAFI_MAX];
#define PEER_STATUS_ORF_PREFIX_SEND   (1 << 0) /* prefix-list send peer */
#define PEER_STATUS_ORF_WAIT_REFRESH  (1 << 1) /* wait refresh received peer */
#define PEER_STATUS_DEFAULT_ORIGINATE (1 << 2) /* default-originate peer */
#define PEER_STATUS_PREFIX_THRESHOLD  (1 << 3) /* exceed prefix-threshold */
#define PEER_STATUS_PREFIX_LIMIT      (1 << 4) /* exceed prefix-limit */
#define PEER_STATUS_EOR_SEND          (1 << 5) /* end-of-rib send to peer */
#define PEER_STATUS_EOR_RECEIVED      (1 << 6) /* end-of-rib received from peer */
#define PEER_STATUS_EORR_READY_TO_SEND (1 << 7) /* end-of-rib marker for sender */
#define PEER_STATUS_SELECTION_DEFERRAL_EXPIRED (1 << 8) /* bgp path selection deferral timer expired */


  /* Default attribute value for the peer. */
  u_int32_t config;
#define PEER_CONFIG_WEIGHT            (1 << 0) /* Default weight. */
#define PEER_CONFIG_TIMER             (1 << 1) /* keepalive & holdtime */
#define PEER_CONFIG_CONNECT           (1 << 2) /* connect */
#define PEER_CONFIG_ROUTEADV          (1 << 3) /* route advertise */
#define PEER_CONFIG_SENDLABEL_IPV4    (1 << 4) /* for labeled unicast */
#define PEER_CONFIG_SENDLABEL_IPV6    (1 << 5) /* for labeled unicast */
  u_int32_t weight;
  u_int32_t holdtime;
  u_int32_t keepalive;
  u_int32_t connect;
  u_int32_t routeadv;

  /* Timer values. */
  u_int32_t v_start;
  u_int32_t v_connect;
  u_int32_t v_holdtime;
  u_int32_t v_keepalive;
  u_int32_t v_routeadv;
  u_int32_t v_pmax_restart;
  u_int32_t v_gr_restart;
  u_int32_t v_refresh_expire;
  struct peer_afi_safi *v_refresh_ctxt[AFI_MAX][SAFI_MAX];
  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_start;
  struct thread *t_connect;
  struct thread *t_holdtime;
  struct thread *t_keepalive;
  struct thread *t_routeadv;
  struct thread *t_pmax_restart;
  struct thread *t_gr_restart;
  struct thread *t_gr_stale;
  struct thread *t_refresh_expire[AFI_MAX][SAFI_MAX];
  
  /* workqueues */
  struct work_queue *clear_node_queue;
  
  /* Statistics field */
  u_int32_t open_in;		/* Open message input count */
  u_int32_t open_out;		/* Open message output count */
  u_int32_t update_in;		/* Update message input count */
  u_int32_t update_out;		/* Update message ouput count */
  time_t update_time;		/* Update message received time. */
  u_int32_t keepalive_in;	/* Keepalive input count */
  u_int32_t keepalive_out;	/* Keepalive output count */
  u_int32_t notify_in;		/* Notify input count */
  u_int32_t notify_out;		/* Notify output count */
  u_int32_t refresh_in;		/* Route Refresh input count */
  u_int32_t refresh_out;	/* Route Refresh output count */
  u_int32_t dynamic_cap_in;	/* Dynamic Capability input count.  */
  u_int32_t dynamic_cap_out;	/* Dynamic Capability output count.  */

  /* BGP state count */
  u_int32_t established;	/* Established */
  u_int32_t dropped;		/* Dropped */

  /* Syncronization list and time.  */
  struct bgp_synchronize *sync[AFI_MAX][SAFI_MAX];
  time_t synctime;

  /* Send prefix count. */
  unsigned long scount[AFI_MAX][SAFI_MAX];

  /* Announcement attribute hash.  */
  struct hash *hash[AFI_MAX][SAFI_MAX];

  /* Notify data. */
  struct bgp_notify notify;

  /* Whole packet size to be read. */
  unsigned long packet_size;

  /* Filter structure. */
  struct bgp_filter filter[AFI_MAX][SAFI_MAX];

  /* ORF Prefix-list */
  struct prefix_list *orf_plist[AFI_MAX][SAFI_MAX];

  /* Prefix count. */
  unsigned long pcount[AFI_MAX][SAFI_MAX];

  /* Max prefix count. */
  unsigned long pmax[AFI_MAX][SAFI_MAX];
  u_char pmax_threshold[AFI_MAX][SAFI_MAX];
  u_int16_t pmax_restart[AFI_MAX][SAFI_MAX];
#define MAXIMUM_PREFIX_THRESHOLD_DEFAULT 75

  /* allowas-in. */
  char allowas_in[AFI_MAX][SAFI_MAX];

  /* peer reset cause */
  char last_reset;
#define PEER_DOWN_RID_CHANGE             1 /* bgp router-id command */
#define PEER_DOWN_REMOTE_AS_CHANGE       2 /* neighbor remote-as command */
#define PEER_DOWN_LOCAL_AS_CHANGE        3 /* neighbor local-as command */
#define PEER_DOWN_CLID_CHANGE            4 /* bgp cluster-id command */
#define PEER_DOWN_CONFED_ID_CHANGE       5 /* bgp confederation identifier command */
#define PEER_DOWN_CONFED_PEER_CHANGE     6 /* bgp confederation peer command */
#define PEER_DOWN_RR_CLIENT_CHANGE       7 /* neighbor route-reflector-client command */
#define PEER_DOWN_RS_CLIENT_CHANGE       8 /* neighbor route-server-client command */
#define PEER_DOWN_UPDATE_SOURCE_CHANGE   9 /* neighbor update-source command */
#define PEER_DOWN_AF_ACTIVATE           10 /* neighbor activate command */
#define PEER_DOWN_USER_SHUTDOWN         11 /* neighbor shutdown command */
#define PEER_DOWN_USER_RESET            12 /* clear ip bgp command */
#define PEER_DOWN_NOTIFY_RECEIVED       13 /* notification received */
#define PEER_DOWN_NOTIFY_SEND           14 /* notification send */
#define PEER_DOWN_CLOSE_SESSION         15 /* tcp session close */
#define PEER_DOWN_NEIGHBOR_DELETE       16 /* neghbor delete */
#define PEER_DOWN_RMAP_BIND             17 /* neghbor peer-group command */
#define PEER_DOWN_RMAP_UNBIND           18 /* no neighbor peer-group command */
#define PEER_DOWN_CAPABILITY_CHANGE     19 /* neighbor capability command */
#define PEER_DOWN_PASSIVE_CHANGE        20 /* neighbor passive command */
#define PEER_DOWN_MULTIHOP_CHANGE       21 /* neighbor multihop command */
#define PEER_DOWN_NSF_CLOSE_SESSION     22 /* NSF tcp session close */
#define PEER_DOWN_LOCAL_SEND_LABEL      23 /* Send Label changed */
#define PEER_DOWN_BFD_NEIGHBOR_DOWN     24 /* BFD session to neighbor went down */

  /* The kind of route-map Flags.*/
  u_char rmap_type;
#define PEER_RMAP_TYPE_IN             (1 << 0) /* neighbor route-map in */
#define PEER_RMAP_TYPE_OUT            (1 << 1) /* neighbor route-map out */
#define PEER_RMAP_TYPE_NETWORK        (1 << 2) /* network route-map */
#define PEER_RMAP_TYPE_REDISTRIBUTE   (1 << 3) /* redistribute route-map */
#define PEER_RMAP_TYPE_DEFAULT        (1 << 4) /* default-originate route-map */
#define PEER_RMAP_TYPE_NOSET          (1 << 5) /* not allow to set commands */
#define PEER_RMAP_TYPE_IMPORT         (1 << 6) /* neighbor route-map import */
#define PEER_RMAP_TYPE_EXPORT         (1 << 7) /* neighbor route-map export */

  struct thread *t_update_delay[AFI_MAX][SAFI_MAX];
  struct thread *t_selection_deferral[AFI_MAX][SAFI_MAX];

  /* Clear purpose configuration flags. */
  enum bgp_clear_route_type clear_purpose;

  QZC_NODE
};

struct peer_afi_safi
{
  struct peer *peer;
  afi_t afi;
  safi_t safi;
};

#define PEER_PASSWORD_MINLEN	(1)
#define PEER_PASSWORD_MAXLEN	(80)

/* This structure's member directly points incoming packet data
   stream. */
struct bgp_nlri
{
  /* AFI.  */
  afi_t afi;

  /* SAFI.  */
  safi_t safi;

  /* Pointer to NLRI byte stream.  */
  u_char *nlri;

  /* Length of whole NLRI.  */
  bgp_size_t length;
};

/* BGP versions.  */
#define BGP_VERSION_4		                 4

/* Default BGP port number.  */
#define BGP_PORT_DEFAULT                       179

/* BGP message header and packet size.  */
#define BGP_MARKER_SIZE		                16
#define BGP_HEADER_SIZE		                19
#define BGP_MAX_PACKET_SIZE                   4096

/* BGP minimum message size.  */
#define BGP_MSG_OPEN_MIN_SIZE                   (BGP_HEADER_SIZE + 10)
#define BGP_MSG_UPDATE_MIN_SIZE                 (BGP_HEADER_SIZE + 4)
#define BGP_MSG_NOTIFY_MIN_SIZE                 (BGP_HEADER_SIZE + 2)
#define BGP_MSG_KEEPALIVE_MIN_SIZE              (BGP_HEADER_SIZE + 0)
#define BGP_MSG_ROUTE_REFRESH_MIN_SIZE          (BGP_HEADER_SIZE + 4)
#define BGP_MSG_CAPABILITY_MIN_SIZE             (BGP_HEADER_SIZE + 3)

/* BGP message types.  */
#define	BGP_MSG_OPEN		                 1
#define	BGP_MSG_UPDATE		                 2
#define	BGP_MSG_NOTIFY		                 3
#define	BGP_MSG_KEEPALIVE	                 4
#define BGP_MSG_ROUTE_REFRESH_NEW                5
#define BGP_MSG_CAPABILITY                       6
#define BGP_MSG_ROUTE_REFRESH_OLD              128

/* BGP open optional parameter.  */
#define BGP_OPEN_OPT_AUTH                        1
#define BGP_OPEN_OPT_CAP                         2

/* BGP4 attribute type codes.  */
#define BGP_ATTR_ORIGIN                          1
#define BGP_ATTR_AS_PATH                         2
#define BGP_ATTR_NEXT_HOP                        3
#define BGP_ATTR_MULTI_EXIT_DISC                 4
#define BGP_ATTR_LOCAL_PREF                      5
#define BGP_ATTR_ATOMIC_AGGREGATE                6
#define BGP_ATTR_AGGREGATOR                      7
#define BGP_ATTR_COMMUNITIES                     8
#define BGP_ATTR_ORIGINATOR_ID                   9
#define BGP_ATTR_CLUSTER_LIST                   10
#define BGP_ATTR_DPA                            11
#define BGP_ATTR_ADVERTISER                     12
#define BGP_ATTR_RCID_PATH                      13
#define BGP_ATTR_MP_REACH_NLRI                  14
#define BGP_ATTR_MP_UNREACH_NLRI                15
#define BGP_ATTR_EXT_COMMUNITIES                16
#define BGP_ATTR_AS4_PATH                       17
#define BGP_ATTR_AS4_AGGREGATOR                 18
#define BGP_ATTR_AS_PATHLIMIT                   21
#define BGP_ATTR_ENCAP                          23

/* BGP update origin.  */
#define BGP_ORIGIN_IGP                           0
#define BGP_ORIGIN_EGP                           1
#define BGP_ORIGIN_INCOMPLETE                    2

/* BGP notify message codes.  */
#define BGP_NOTIFY_HEADER_ERR                    1
#define BGP_NOTIFY_OPEN_ERR                      2
#define BGP_NOTIFY_UPDATE_ERR                    3
#define BGP_NOTIFY_HOLD_ERR                      4
#define BGP_NOTIFY_FSM_ERR                       5
#define BGP_NOTIFY_CEASE                         6
#define BGP_NOTIFY_CAPABILITY_ERR                7
#define BGP_NOTIFY_MAX	                         8

#define BGP_NOTIFY_SUBCODE_UNSPECIFIC            0

/* BGP_NOTIFY_HEADER_ERR sub codes.  */
#define BGP_NOTIFY_HEADER_NOT_SYNC               1
#define BGP_NOTIFY_HEADER_BAD_MESLEN             2
#define BGP_NOTIFY_HEADER_BAD_MESTYPE            3
#define BGP_NOTIFY_HEADER_MAX                    4

/* BGP_NOTIFY_OPEN_ERR sub codes.  */
#define BGP_NOTIFY_OPEN_UNSPECIFIC               0
#define BGP_NOTIFY_OPEN_UNSUP_VERSION            1
#define BGP_NOTIFY_OPEN_BAD_PEER_AS              2
#define BGP_NOTIFY_OPEN_BAD_BGP_IDENT            3
#define BGP_NOTIFY_OPEN_UNSUP_PARAM              4
#define BGP_NOTIFY_OPEN_AUTH_FAILURE             5
#define BGP_NOTIFY_OPEN_UNACEP_HOLDTIME          6
#define BGP_NOTIFY_OPEN_UNSUP_CAPBL              7
#define BGP_NOTIFY_OPEN_MAX                      8

/* BGP_NOTIFY_UPDATE_ERR sub codes.  */
#define BGP_NOTIFY_UPDATE_MAL_ATTR               1
#define BGP_NOTIFY_UPDATE_UNREC_ATTR             2
#define BGP_NOTIFY_UPDATE_MISS_ATTR              3
#define BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR          4
#define BGP_NOTIFY_UPDATE_ATTR_LENG_ERR          5
#define BGP_NOTIFY_UPDATE_INVAL_ORIGIN           6
#define BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP          7
#define BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP         8
#define BGP_NOTIFY_UPDATE_OPT_ATTR_ERR           9
#define BGP_NOTIFY_UPDATE_INVAL_NETWORK         10
#define BGP_NOTIFY_UPDATE_MAL_AS_PATH           11
#define BGP_NOTIFY_UPDATE_MAX                   12

/* BGP_NOTIFY_CEASE sub codes (RFC 4486).  */
#define BGP_NOTIFY_CEASE_MAX_PREFIX              1
#define BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN          2
#define BGP_NOTIFY_CEASE_PEER_UNCONFIG           3
#define BGP_NOTIFY_CEASE_ADMIN_RESET             4
#define BGP_NOTIFY_CEASE_CONNECT_REJECT          5
#define BGP_NOTIFY_CEASE_CONFIG_CHANGE           6
#define BGP_NOTIFY_CEASE_COLLISION_RESOLUTION    7
#define BGP_NOTIFY_CEASE_OUT_OF_RESOURCE         8
#define BGP_NOTIFY_CEASE_MAX                     9

/* BGP_NOTIFY_CAPABILITY_ERR sub codes (draft-ietf-idr-dynamic-cap-02). */
#define BGP_NOTIFY_CAPABILITY_INVALID_ACTION     1
#define BGP_NOTIFY_CAPABILITY_INVALID_LENGTH     2
#define BGP_NOTIFY_CAPABILITY_MALFORMED_CODE     3
#define BGP_NOTIFY_CAPABILITY_MAX                4

/* BGP refresh optional parameter.  */
#define BGP_REFRESH_BORR                         1
#define BGP_REFRESH_EORR                         2

/* BGP finite state machine status.  */
#define Idle                                     1
#define Connect                                  2
#define Active                                   3
#define OpenSent                                 4
#define OpenConfirm                              5
#define Established                              6
#define Clearing                                 7
#define Deleted                                  8
#define BGP_STATUS_MAX                           9

/* BGP finite state machine events.  */
#define BGP_Start                                1
#define BGP_Stop                                 2
#define TCP_connection_open                      3
#define TCP_connection_closed                    4
#define TCP_connection_open_failed               5
#define TCP_fatal_error                          6
#define ConnectRetry_timer_expired               7
#define Hold_Timer_expired                       8
#define KeepAlive_timer_expired                  9
#define Receive_OPEN_message                    10
#define Receive_KEEPALIVE_message               11
#define Receive_UPDATE_message                  12
#define Receive_NOTIFICATION_message            13
#define Clearing_Completed                      14
#define NHT_Update                              15
#define BGP_EVENTS_MAX                          16

/* BGP timers default value.  */
#define BGP_INIT_START_TIMER                     1
#define BGP_DEFAULT_HOLDTIME                   180
#define BGP_DEFAULT_KEEPALIVE                   60 
#define BGP_DEFAULT_EBGP_ROUTEADV               30
#define BGP_DEFAULT_IBGP_ROUTEADV                5
#define BGP_CLEAR_CONNECT_RETRY                 20
#define BGP_DEFAULT_CONNECT_RETRY               1
#define BGP_DEFAULT_SELECTION_DEFERRAL        360000

/* BGP default local preference.  */
#define BGP_DEFAULT_LOCAL_PREF                 100

/* BGP graceful restart  */
#define BGP_DEFAULT_RESTART_TIME               120
#define BGP_DEFAULT_STALEPATH_TIME             360

/* RFC4364 */
#define SAFI_MPLS_LABELED_VPN                  128

/* Max TTL value.  */
#define TTL_MAX                                255

/* BGP uptime string length.  */
#define BGP_UPTIME_LEN 25

/* Default configuration settings for bgpd.  */
#define BGP_VTY_PORT                          2605
#define BGP_DEFAULT_CONFIG             "bgpd.conf"

/* Check AS path loop when we send NLRI.  */
/* #define BGP_SEND_ASPATH_CHECK */

/* Flag for peer_clear_soft().  */
enum bgp_clear_type
{
  BGP_CLEAR_SOFT_NONE,
  BGP_CLEAR_SOFT_OUT,
  BGP_CLEAR_SOFT_IN,
  BGP_CLEAR_SOFT_BOTH,
  BGP_CLEAR_SOFT_IN_ORF_PREFIX,
  BGP_CLEAR_SOFT_RSCLIENT
};

/* Macros. */
#define BGP_INPUT(P)         ((P)->ibuf)
#define BGP_INPUT_PNT(P)     (STREAM_PNT(BGP_INPUT(P)))
#define BGP_IS_VALID_STATE_FOR_NOTIF(S)\
        (((S) == OpenSent) || ((S) == OpenConfirm) || ((S) == Established))

/* BGP error codes.  */
#define BGP_SUCCESS                               0
#define BGP_ERR_INVALID_VALUE                    -1
#define BGP_ERR_INVALID_FLAG                     -2
#define BGP_ERR_INVALID_AS                       -3
#define BGP_ERR_INVALID_BGP                      -4
#define BGP_ERR_PEER_GROUP_MEMBER                -5
#define BGP_ERR_MULTIPLE_INSTANCE_USED           -6
#define BGP_ERR_PEER_GROUP_MEMBER_EXISTS         -7
#define BGP_ERR_PEER_BELONGS_TO_GROUP            -8
#define BGP_ERR_PEER_GROUP_AF_UNCONFIGURED       -9
#define BGP_ERR_PEER_GROUP_NO_REMOTE_AS         -10
#define BGP_ERR_PEER_GROUP_CANT_CHANGE          -11
#define BGP_ERR_PEER_GROUP_MISMATCH             -12
#define BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT  -13
#define BGP_ERR_MULTIPLE_INSTANCE_NOT_SET       -14
#define BGP_ERR_AS_MISMATCH                     -15
#define BGP_ERR_PEER_INACTIVE                   -16
#define BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER   -17
#define BGP_ERR_PEER_GROUP_HAS_THE_FLAG         -18
#define BGP_ERR_PEER_FLAG_CONFLICT              -19
#define BGP_ERR_PEER_GROUP_SHUTDOWN             -20
#define BGP_ERR_PEER_FILTER_CONFLICT            -21
#define BGP_ERR_NOT_INTERNAL_PEER               -22
#define BGP_ERR_REMOVE_PRIVATE_AS               -23
#define BGP_ERR_AF_UNCONFIGURED                 -24
#define BGP_ERR_SOFT_RECONFIG_UNCONFIGURED      -25
#define BGP_ERR_INSTANCE_MISMATCH               -26
#define BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP  -27
#define BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS    -28
#define BGP_ERR_TCPSIG_FAILED			-29
#define BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK	-30
#define BGP_ERR_NO_IBGP_WITH_TTLHACK		-31
#define BGP_ERR_MAX				-32
#define BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS_REMOTE_AS    -33

extern struct bgp_master *bm;
extern int bgp_exit_procedure;
extern int  bgp_order_send_eor;
extern int bgp_selection_deferral_tmr;

/* Prototypes. */
extern void bgp_terminate (void);
extern void bgp_reset (void);
extern time_t bgp_clock (void);
extern void bgp_zclient_reset (void);
extern int bgp_is_zebra_connected (void);
extern int bgp_nexthop_set (union sockunion *, union sockunion *, 
		     struct bgp_nexthop *, struct peer *);
extern struct bgp *bgp_get_default (void);
extern struct bgp *bgp_lookup (as_t, const char *);
extern struct bgp *bgp_lookup_by_name (const char *);
extern struct bgp *bgp_create_api (struct bgp_master *, as_t as);
extern struct peer *peer_lookup (struct bgp *, union sockunion *);
extern struct peer_group *peer_group_lookup (struct bgp *, const char *);
extern struct peer_group *peer_group_get (struct bgp *, const char *);
extern struct peer *peer_lookup_with_open (union sockunion *, as_t, struct in_addr *,
				    int *);

/*
 * Peers are incredibly easy to memory leak
 * due to the various ways that they are actually used
 * Provide some functionality to debug locks and unlocks
 */
extern struct peer *peer_lock_with_caller(const char *, struct peer *);
extern struct peer *peer_unlock_with_caller(const char *, struct peer *);
#define peer_unlock(A) peer_unlock_with_caller(__FUNCTION__, (A))
#define peer_lock(B) peer_lock_with_caller(__FUNCTION__, (B))

extern bgp_peer_sort_t peer_sort (struct peer *peer);
extern int peer_active (struct peer *);
extern int peer_active_nego (struct peer *);
extern struct peer *peer_create_accept (struct bgp *);
extern char *peer_uptime (time_t, char *, size_t);
extern int bgp_config_write (struct vty *);
extern void bgp_config_write_family_header (struct vty *, afi_t, safi_t, int *);

extern void bgp_master_init (void);

extern void bgp_init (void);
extern void bgp_route_map_init (void);

extern int bgp_option_set (int);
extern int bgp_option_unset (int);
extern int bgp_option_check (int);

extern int bgp_get (struct bgp **, as_t *, const char *);
extern int bgp_delete (struct bgp *);

extern int bgp_flag_set (struct bgp *, int);
extern int bgp_flag_unset (struct bgp *, int);
extern int bgp_flag_check (struct bgp *, int);
extern int bgp_af_flag_set (struct bgp *, afi_t, safi_t, int);
extern int bgp_af_flag_unset (struct bgp *, afi_t, safi_t, int);

extern void bgp_lock (struct bgp *);
extern void bgp_unlock (struct bgp *);

extern void bgp_router_id_zebra_bump (void);
extern int bgp_router_id_set (struct bgp *, struct in_addr *);
extern int bgp_router_id_static_set (struct bgp *, struct in_addr);

extern int bgp_cluster_id_set (struct bgp *, struct in_addr *);
extern int bgp_cluster_id_unset (struct bgp *);

extern int bgp_confederation_id_set (struct bgp *, as_t);
extern int bgp_confederation_id_unset (struct bgp *);
extern int bgp_confederation_peers_check (struct bgp *, as_t);

extern int bgp_confederation_peers_add (struct bgp *, as_t);
extern int bgp_confederation_peers_remove (struct bgp *, as_t);

extern int bgp_timers_set (struct bgp *, u_int32_t keepalive, u_int32_t holdtime);
extern int bgp_timers_unset (struct bgp *);

extern int bgp_default_local_preference_set (struct bgp *, u_int32_t);
extern int bgp_default_local_preference_unset (struct bgp *);

extern int bgp_peer_bfd_sync(struct bgp *);
extern int bgp_bfd_sync_set(struct bgp *);
extern int bgp_bfd_sync_unset(struct bgp *);
extern int bgp_peer_status_get(const struct peer *s);
extern int bgp_peer_bfd_sync_by_local_addr(struct bgp *, struct prefix *);

extern void bgp_notify_zmq_init (void);
extern int bgp_notify_zmq_url_set (struct bgp *, const char *url);
extern void bgp_notify_route (struct bgp *, struct bgp_event_vrf *update);
extern void bgp_notify_shut (struct bgp *, struct bgp_event_shut *shut);
extern void bgp_notify_bfd_status (struct bgp *bgp, struct bgp_event_bfd_status *status);
extern void bgp_notify_cleanup (struct bgp *);

extern int peer_rsclient_active (struct peer *);

extern int peer_remote_as (struct bgp *, union sockunion *, as_t *, afi_t, safi_t);
extern int peer_group_remote_as (struct bgp *, const char *, as_t *);
extern struct peer *peer_create_api (struct bgp *, const char * host, as_t as);
extern int peer_delete (struct peer *peer);
extern int peer_group_delete (struct peer_group *);
extern int peer_group_remote_as_delete (struct peer_group *);

extern int peer_activate (struct peer *, afi_t, safi_t);
extern int peer_deactivate (struct peer *, afi_t, safi_t);
extern int peer_afc_set (struct peer *, afi_t, safi_t, int);
extern void peer_nsf_stop (struct peer *);

extern int peer_group_bind (struct bgp *, union sockunion *, struct peer_group *,
		     afi_t, safi_t, as_t *);
extern int peer_group_unbind (struct bgp *, struct peer *, struct peer_group *,
		       afi_t, safi_t);

extern int peer_flag_set (struct peer *, u_int32_t);
extern int peer_flag_unset (struct peer *, u_int32_t);

extern int peer_af_flag_set (struct peer *, afi_t, safi_t, u_int32_t);
extern int peer_af_flag_unset (struct peer *, afi_t, safi_t, u_int32_t);
extern int peer_af_flag_check (struct peer *, afi_t, safi_t, u_int32_t);

extern int peer_ebgp_multihop_set (struct peer *, int);
extern int peer_ebgp_multihop_unset (struct peer *);

extern int peer_description_set (struct peer *, const char *);
extern int peer_description_unset (struct peer *);

extern int peer_update_source_if_set (struct peer *, const char *);
extern int peer_update_source_addr_set (struct peer *, const union sockunion *);
extern int peer_update_source_unset (struct peer *);
extern int peer_connect_with_update_source_only_set (struct peer *peer, int enable);

extern int peer_default_originate_set (struct peer *, afi_t, safi_t, const char *);
extern int peer_default_originate_unset (struct peer *, afi_t, safi_t);
extern int peer_default_originate_set_rd (struct peer *peer, struct prefix_rd *rd,
                                          afi_t afi, safi_t safi,
                                          const struct bgp_api_route *route);
extern int peer_default_originate_unset_rd (struct peer *peer, afi_t afi,
                                            safi_t safi, struct prefix_rd *rd);


extern int peer_port_set (struct peer *, u_int16_t);
extern int peer_port_unset (struct peer *);

extern int peer_weight_set (struct peer *, u_int16_t);
extern int peer_weight_unset (struct peer *);

extern int peer_timers_set (struct peer *, u_int32_t keepalive, u_int32_t holdtime);
extern int peer_timers_unset (struct peer *);

extern int peer_timers_connect_set (struct peer *, u_int32_t);
extern int peer_timers_connect_unset (struct peer *);

extern int peer_advertise_interval_set (struct peer *, u_int32_t);
extern int peer_advertise_interval_unset (struct peer *);

extern int peer_interface_set (struct peer *, const char *);
extern int peer_interface_unset (struct peer *);

extern int peer_distribute_set (struct peer *, afi_t, safi_t, int, const char *);
extern int peer_distribute_unset (struct peer *, afi_t, safi_t, int);

extern int peer_allowas_in_set (struct peer *, afi_t, safi_t, int);
extern int peer_allowas_in_unset (struct peer *, afi_t, safi_t);

extern int peer_local_as_set (struct peer *, as_t, int, int);
extern int peer_local_as_unset (struct peer *);

extern int peer_prefix_list_set (struct peer *, afi_t, safi_t, int, const char *);
extern int peer_prefix_list_unset (struct peer *, afi_t, safi_t, int);

extern int peer_aslist_set (struct peer *, afi_t, safi_t, int, const char *);
extern int peer_aslist_unset (struct peer *,afi_t, safi_t, int);

extern int peer_route_map_set (struct peer *, afi_t, safi_t, int, const char *);
extern int peer_route_map_unset (struct peer *, afi_t, safi_t, int);

extern int peer_unsuppress_map_set (struct peer *, afi_t, safi_t, const char *);

extern int peer_password_set (struct peer *, const char *);
extern int peer_password_unset (struct peer *);

extern int peer_unsuppress_map_unset (struct peer *, afi_t, safi_t);

extern int peer_maximum_prefix_set (struct peer *, afi_t, safi_t, u_int32_t, u_char, int, u_int16_t);
extern int peer_maximum_prefix_unset (struct peer *, afi_t, safi_t);

extern int peer_clear (struct peer *);
extern int peer_clear_soft (struct peer *, afi_t, safi_t, enum bgp_clear_type);

extern int peer_ttl_security_hops_set (struct peer *, int);
extern int peer_ttl_security_hops_unset (struct peer *);

extern void bgp_scan_finish (void);
extern void bgp_vrf_delete_rd (struct bgp_vrf *vrf);
extern void bgp_vrf_update_rd_layer (struct bgp_vrf *vrf, bgp_layer_type_t type);
extern struct bgp_vrf *bgp_vrf_update_rd (struct bgp *bgp, struct bgp_vrf *vrf, struct prefix_rd *outbound_rd);
extern struct bgp_vrf *bgp_vrf_lookup (struct bgp *bgp, struct prefix_rd *outbound_rd);
extern struct bgp_vrf *bgp_vrf_lookup_per_name (struct bgp *bgp, const char *name, int create);
extern struct bgp_vrf *bgp_vrf_lookup_per_rn (struct bgp *bgp, int afi, struct bgp_node *vrf_rn);
extern void bgp_vrf_delete (struct bgp_vrf *vrf);
extern void bgp_vrf_rt_export_set (struct bgp_vrf *vrf, struct ecommunity *rt_export);
extern void bgp_vrf_rt_import_set (struct bgp_vrf *vrf, struct ecommunity *rt_import);
extern void bgp_vrf_clean_tables (struct bgp_vrf *vrf);
extern void bgp_vrf_rt_import_unset (struct bgp_vrf *vrf);
extern void bgp_vrf_rt_export_unset (struct bgp_vrf *vrf);
extern void bgp_vrf_enable(struct bgp_vrf *vrf, afi_t afi, safi_t safi);
extern void bgp_vrf_disable(struct bgp_vrf *vrf, afi_t afi, safi_t safi);
extern void bgp_vrf_enable_perafisafi (struct bgp_vrf *vrf, afi_t afi, safi_t safi);
extern void bgp_vrf_disable_perafisafi (struct bgp_vrf *vrf, afi_t afi, safi_t safi);
extern int bgp_vrf_static_set (struct bgp_vrf *vrf, afi_t afi, const struct bgp_api_route *route);
extern int bgp_vrf_static_unset (struct bgp_vrf *vrf, afi_t afi, const struct bgp_api_route *route);
extern bool bgp_api_route_get (struct bgp_vrf *vrf,
                               struct bgp_api_route *out, 
                               struct bgp_node *bn,
                               int iter_on_multipath, 
                               void **next);
extern bool bgp_api_route_get_main (struct bgp_api_route *out, 
                                    struct bgp_node *bn,
                                    int iter_on_multipath, 
                                    void **next);
extern bool bgp_api_static_get (struct bgp_api_route *out, struct bgp_node *bn);

extern void bgp_vrf_maximum_paths_set(struct bgp_vrf *vrf);
extern void bgp_vrfs_maximum_paths_set(struct bgp *bgp, afi_t afi, safi_t safi, u_int16_t maxpaths);
extern void bgp_send_eor (struct peer *peer);
extern void bgp_send_eor_to_peers(struct bgp *bgp);
extern int bgp_refresh_timer_expire (struct thread *thread);

extern void bgp_bfd_init (void);

#endif /* _QUAGGA_BGPD_H */
