/*
 * Memory type definitions. This file is parsed by memtypes.awk to extract
 * MTYPE_ and memory_list_.. information in order to autogenerate 
 * memtypes.h.
 *
 * The script is sensitive to the format (though not whitespace), see
 * the top of memtypes.awk for more details.
 */

#include "zebra.h"
#include "memory.h"

DEFINE_MGROUP(LIB, "libzebra")
DEFINE_MTYPE(LIB, TMP,			"Temporary memory")
DEFINE_MTYPE(LIB, STRVEC,			"String vector")
DEFINE_MTYPE(LIB, VECTOR,			"Vector")
DEFINE_MTYPE(LIB, VECTOR_INDEX,		"Vector index")
DEFINE_MTYPE(LIB, LINK_LIST,		"Link List")
DEFINE_MTYPE(LIB, LINK_NODE,		"Link Node")
DEFINE_MTYPE(LIB, THREAD,			"Thread")
DEFINE_MTYPE(LIB, THREAD_MASTER,		"Thread master")
DEFINE_MTYPE(LIB, THREAD_STATS,		"Thread stats")
DEFINE_MTYPE(LIB, VTY,			"VTY")
DEFINE_MTYPE(LIB, VTY_OUT_BUF,		"VTY output buffer")
DEFINE_MTYPE(LIB, VTY_HIST,		"VTY history")
DEFINE_MTYPE(LIB, IF,			"Interface")
DEFINE_MTYPE(LIB, CONNECTED,		"Connected")
DEFINE_MTYPE(LIB, CONNECTED_LABEL,		"Connected interface label")
DEFINE_MTYPE(LIB, BUFFER,			"Buffer")
DEFINE_MTYPE(LIB, BUFFER_DATA,		"Buffer data")
DEFINE_MTYPE(LIB, STREAM,			"Stream")
DEFINE_MTYPE(LIB, STREAM_DATA,		"Stream data")
DEFINE_MTYPE(LIB, STREAM_FIFO,		"Stream FIFO")
DEFINE_MTYPE(LIB, PREFIX,			"Prefix")
DEFINE_MTYPE(LIB, PREFIX_IPV4,		"Prefix IPv4")
DEFINE_MTYPE(LIB, PREFIX_IPV6,		"Prefix IPv6")
DEFINE_MTYPE(LIB, HASH,			"Hash")
DEFINE_MTYPE(LIB, HASH_BACKET,		"Hash Bucket")
DEFINE_MTYPE(LIB, HASH_INDEX,		"Hash Index")
DEFINE_MTYPE(LIB, ROUTE_TABLE,		"Route table")
DEFINE_MTYPE(LIB, ROUTE_NODE,		"Route node")
DEFINE_MTYPE(LIB, DISTRIBUTE,		"Distribute list")
DEFINE_MTYPE(LIB, DISTRIBUTE_IFNAME,	"Dist-list ifname")
DEFINE_MTYPE(LIB, ACCESS_LIST,		"Access List")
DEFINE_MTYPE(LIB, ACCESS_LIST_STR,		"Access List Str")
DEFINE_MTYPE(LIB, ACCESS_FILTER,		"Access Filter")
DEFINE_MTYPE(LIB, PREFIX_LIST,		"Prefix List")
DEFINE_MTYPE(LIB, PREFIX_LIST_ENTRY,	"Prefix List Entry")
DEFINE_MTYPE(LIB, PREFIX_LIST_STR,		"Prefix List Str")
DEFINE_MTYPE(LIB, ROUTE_MAP,		"Route map")
DEFINE_MTYPE(LIB, ROUTE_MAP_NAME,		"Route map name")
DEFINE_MTYPE(LIB, ROUTE_MAP_INDEX,		"Route map index")
DEFINE_MTYPE(LIB, ROUTE_MAP_RULE,		"Route map rule")
DEFINE_MTYPE(LIB, ROUTE_MAP_RULE_STR,	"Route map rule str")
DEFINE_MTYPE(LIB, ROUTE_MAP_COMPILED,	"Route map compiled")
DEFINE_MTYPE(LIB, CMD_TOKENS,		"Command desc")
DEFINE_MTYPE(LIB, KEY,			"Key")
DEFINE_MTYPE(LIB, KEYCHAIN,		"Key chain")
DEFINE_MTYPE(LIB, IF_RMAP,			"Interface route map")
DEFINE_MTYPE(LIB, IF_RMAP_NAME,		"I.f. route map name")
DEFINE_MTYPE(LIB, SOCKUNION,		"Socket union")
DEFINE_MTYPE(LIB, PRIVS,			"Privilege information")
DEFINE_MTYPE(LIB, ZLOG,			"Logging")
DEFINE_MTYPE(LIB, ZCLIENT,			"Zclient")
DEFINE_MTYPE(LIB, WORK_QUEUE,		"Work queue")
DEFINE_MTYPE(LIB, WORK_QUEUE_ITEM,		"Work queue item")
DEFINE_MTYPE(LIB, WORK_QUEUE_NAME,		"Work queue name string")
DEFINE_MTYPE(LIB, PQUEUE,			"Priority queue")
DEFINE_MTYPE(LIB, PQUEUE_DATA,		"Priority queue data")
DEFINE_MTYPE(LIB, HOST, "host configuration")
DEFINE_MTYPE(LIB, VRF,			"VRF")
DEFINE_MTYPE(LIB, VRF_NAME,		"VRF name")
DEFINE_MTYPE(LIB, VRF_BITMAP,		"VRF bit-map")



DEFINE_MGROUP(ZEBRA, "zebra")
DEFINE_MTYPE(ZEBRA, RTADV_PREFIX,		"Router Advertisement Prefix")
DEFINE_MTYPE(ZEBRA, ZEBRA_VRF,	"ZEBRA VRF")
DEFINE_MTYPE(ZEBRA, NEXTHOP,		"Nexthop")
DEFINE_MTYPE(ZEBRA, RIB,			"RIB")
DEFINE_MTYPE(ZEBRA, RIB_QUEUE,		"RIB process work queue")
DEFINE_MTYPE(ZEBRA, STATIC_ROUTE,		"Static route")
DEFINE_MTYPE(ZEBRA, RIB_DEST,		"RIB destination")
DEFINE_MTYPE(ZEBRA, RIB_TABLE_INFO,	"RIB table info")
DEFINE_MTYPE(ZEBRA, NETLINK_NAME,	"Netlink name")


DEFINE_MGROUP(RIPD, "ripd")
DEFINE_MTYPE(RIPD, RIP,			"RIP structure")
DEFINE_MTYPE(RIPD, RIP_INFO,		"RIP route info")
DEFINE_MTYPE(RIPD, RIP_INTERFACE,		"RIP interface")
DEFINE_MTYPE(RIPD, RIP_PEER,		"RIP peer")
DEFINE_MTYPE(RIPD, RIP_OFFSET_LIST,	"RIP offset list")
DEFINE_MTYPE(RIPD, RIP_DISTANCE,		"RIP distance")



DEFINE_MGROUP(RIPNGD, "ripngd")
DEFINE_MTYPE(RIPNGD, RIPNG,		"RIPng structure")
DEFINE_MTYPE(RIPNGD, RIPNG_ROUTE,		"RIPng route info")
DEFINE_MTYPE(RIPNGD, RIPNG_AGGREGATE,	"RIPng aggregate")
DEFINE_MTYPE(RIPNGD, RIPNG_PEER,		"RIPng peer")
DEFINE_MTYPE(RIPNGD, RIPNG_OFFSET_LIST,	"RIPng offset lst")
DEFINE_MTYPE(RIPNGD, RIPNG_RTE_DATA,	"RIPng rte data")



DEFINE_MGROUP(BABELD, "babeld")
DEFINE_MTYPE(BABELD, BABEL,		"Babel structure")
DEFINE_MTYPE(BABELD, BABEL_IF,		"Babel interface")



DEFINE_MGROUP(ISISD, "isisd")
DEFINE_MTYPE(ISISD, ISIS,               "ISIS")
DEFINE_MTYPE(ISISD, ISIS_TMP,           "ISIS TMP")
DEFINE_MTYPE(ISISD, ISIS_CIRCUIT,       "ISIS circuit")
DEFINE_MTYPE(ISISD, ISIS_LSP,           "ISIS LSP")
DEFINE_MTYPE(ISISD, ISIS_ADJACENCY,     "ISIS adjacency")
DEFINE_MTYPE(ISISD, ISIS_AREA,          "ISIS area")
DEFINE_MTYPE(ISISD, ISIS_AREA_ADDR,     "ISIS area address")
DEFINE_MTYPE(ISISD, ISIS_TLV,           "ISIS TLV")
DEFINE_MTYPE(ISISD, ISIS_DYNHN,         "ISIS dyn hostname")
DEFINE_MTYPE(ISISD, ISIS_SPFTREE,       "ISIS SPFtree")
DEFINE_MTYPE(ISISD, ISIS_VERTEX,        "ISIS vertex")
DEFINE_MTYPE(ISISD, ISIS_ROUTE_INFO,    "ISIS route info")
DEFINE_MTYPE(ISISD, ISIS_NEXTHOP,       "ISIS nexthop")
DEFINE_MTYPE(ISISD, ISIS_NEXTHOP6,      "ISIS nexthop6")
DEFINE_MTYPE(ISISD, ISIS_DICT,          "ISIS dictionary")
DEFINE_MTYPE(ISISD, ISIS_DICT_NODE,     "ISIS dictionary node")



DEFINE_MGROUP(PIMD, "pimd")
DEFINE_MTYPE(PIMD, PIM_CHANNEL_OIL,       "PIM SSM (S,G) channel OIL")
DEFINE_MTYPE(PIMD, PIM_INTERFACE,         "PIM interface")
DEFINE_MTYPE(PIMD, PIM_IGMP_JOIN,         "PIM interface IGMP static join")
DEFINE_MTYPE(PIMD, PIM_IGMP_SOCKET,       "PIM interface IGMP socket")
DEFINE_MTYPE(PIMD, PIM_IGMP_GROUP,        "PIM interface IGMP group")
DEFINE_MTYPE(PIMD, PIM_IGMP_GROUP_SOURCE, "PIM interface IGMP source")
DEFINE_MTYPE(PIMD, PIM_NEIGHBOR,          "PIM interface neighbor")
DEFINE_MTYPE(PIMD, PIM_IFCHANNEL,         "PIM interface (S,G) state")
DEFINE_MTYPE(PIMD, PIM_UPSTREAM,          "PIM upstream (S,G) state")
DEFINE_MTYPE(PIMD, PIM_SSMPINGD,          "PIM sspimgd socket")
DEFINE_MTYPE(PIMD, PIM_STATIC_ROUTE,      "PIM Static Route")



DEFINE_MGROUP(MVTYSH, "vtysh")
DEFINE_MTYPE(MVTYSH, VTYSH_CONFIG,		"Vtysh configuration")
DEFINE_MTYPE(MVTYSH, VTYSH_CONFIG_LINE,	"Vtysh configuration line")


