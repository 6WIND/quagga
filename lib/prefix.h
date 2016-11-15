/*
 * Prefix structure.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _ZEBRA_PREFIX_H
#define _ZEBRA_PREFIX_H

#ifdef SUNOS_5
# include <sys/ethernet.h>
# define ETHER_ADDR_LEN ETHERADDRL
#else
# include <net/ethernet.h>
#endif
#include "sockunion.h"

#ifdef __GNUC__
#  ifdef __LP64__               /* is m64, 8 byte align */
#    define PREFIX_GCC_ALIGN_ATTRIBUTES __attribute__ ((aligned (8)))
#  else                         /* must be m32, 4 byte align */
#    define PREFIX_GCC_ALIGN_ATTRIBUTES __attribute__ ((aligned (4)))
#  endif
#else                           /* not GCC, no alignment attributes */
#  define PREFIX_GCC_ALIGN_ATTRIBUTES
#endif


/*
 * there isn't a portable ethernet address type. We define our
 * own to simplify internal handling
 */
struct ethaddr {
  u_char octet[ETHER_ADDR_LEN];
} __attribute__ ((packed));

/*
 * RFC7432 , part 7.2 MAC/IP Advertisement Route ( Route Type 2)
 * enlarges the definition of prefix as quoted below:
 * "the Ethernet Tag ID, MAC Address Length, MAC Address, IP Address Length,
 * and IP Address fields are considered to be part of the prefix in the NLRI"
 */
struct macipaddr {
  u_int32_t eth_tag_id;
  u_int8_t mac_len;
  struct ethaddr mac;
  u_int8_t ip_len;
  union
  {
    struct in_addr in4;             /* AF_INET */
#ifdef HAVE_IPV6
    struct in6_addr in6;            /* AF_INET6 */
#endif /* HAVE_IPV6 */
  } ip __attribute__ ((packed));
};

struct ipvrfaddr {
  u_int32_t eth_tag_id;
  u_int8_t ip_len;
  union
  {
    struct in_addr in4;             /* AF_INET */
#ifdef HAVE_IPV6
    struct in6_addr in6;            /* AF_INET6 */
#endif /* HAVE_IPV6 */
  } ip __attribute__ ((packed));
};


/*
 * A struct prefix contains an address family, a prefix length, and an
 * address.  This can represent either a 'network prefix' as defined
 * by CIDR, where the 'host bits' of the prefix are 0
 * (e.g. AF_INET:10.0.0.0/8), or an address and netmask
 * (e.g. AF_INET:10.0.0.9/8), such as might be configured on an
 * interface.
 */

/* different OSes use different names */
#if defined(AF_PACKET)
#define AF_ETHERNET AF_PACKET
#else
#if defined(AF_LINK)
#define AF_ETHERNET AF_LINK
#endif
#endif

/* arbitrarily defined using unused value from kernel
 * include/linux/socket.h
 */
#define AF_L2VPN 44
#define L2VPN_NOIP_PREFIX_LEN ((ETHER_ADDR_LEN + 4 /*ethtag*/+ 2 /*mac len + ip len*/) * 8)
#define L2VPN_IPV4_PREFIX_LEN ((ETHER_ADDR_LEN + 4 /*ethtag*/+ 4 /*IP address*/ + 2 /*mac len + ip len*/) * 8)
#define L2VPN_IPV6_PREFIX_LEN ((ETHER_ADDR_LEN + 4 /*ethtag*/+ 16 /*IP address*/ + 2 /*mac len + ip len*/) * 8)

/* IPv4 and IPv6 unified prefix structure. */
struct prefix
{
  u_char family;
  u_char prefixlen;
  union 
  {
    u_char prefix;
    struct in_addr prefix4;             /* AF_INET */
#ifdef HAVE_IPV6
    struct in6_addr prefix6;            /* AF_INET6 */
#endif /* HAVE_IPV6 */
    struct 
    {
      struct in_addr id;
      struct in_addr adv_router;
    } lp;
    struct ethaddr prefix_eth;          /* AF_ETHERNET */
    struct macipaddr prefix_macip;      /* AF_L2VPN */
    struct macipaddr prefix_ipvrf;      /* AF_L2VPN */
    u_char val[8];
    uintptr_t ptr;
  } u __attribute__ ((aligned (8)));
};


/* IPv4 prefix structure. */
struct prefix_ipv4
{
  u_char family;
  u_char prefixlen;
  struct in_addr prefix PREFIX_GCC_ALIGN_ATTRIBUTES;
};

/* IPv6 prefix structure. */
#ifdef HAVE_IPV6
struct prefix_ipv6
{
  u_char family;
  u_char prefixlen;
  struct in6_addr prefix PREFIX_GCC_ALIGN_ATTRIBUTES;
};
#endif /* HAVE_IPV6 */

struct prefix_ls
{
  u_char family;
  u_char prefixlen;
  struct in_addr id PREFIX_GCC_ALIGN_ATTRIBUTES;
  struct in_addr adv_router;
};

/* Prefix for routing distinguisher. */
struct prefix_rd
{
  u_char family;
  u_char prefixlen;
  u_char val[8] PREFIX_GCC_ALIGN_ATTRIBUTES;
};

/* Prefix for ethernet. */
struct prefix_eth
{
  u_char family;
  u_char prefixlen;
  struct ethaddr eth_addr;      /* AF_ETHERNET */
};

/* Prefix for a generic pointer */
struct prefix_ptr
{
  u_char family;
  u_char prefixlen;
  uintptr_t prefix __attribute__ ((aligned (8)));
};

/* L2VPN IP-VRF prefix structure. */
struct prefix_macip
{
  u_char family;
  u_char prefixlen;
  struct ipvrfaddr prefix PREFIX_GCC_ALIGN_ATTRIBUTES;
};

/* helper to get type safety/avoid casts on calls
 * (w/o this, functions accepting all prefix types need casts on the caller
 * side, which strips type safety since the cast will accept any pointer
 * type.)
 */
union prefix46ptr
{
  struct prefix *p;
  struct prefix_ipv4 *p4;
  struct prefix_ipv6 *p6;
  struct prefix_macip *pm;
} __attribute__ ((transparent_union));

union prefix46constptr
{
  const struct prefix *p;
  const struct prefix_ipv4 *p4;
  const struct prefix_ipv6 *p6;
  const struct prefix_macip *pm;
} __attribute__ ((transparent_union));


typedef u_int32_t as_t;

struct rd_as
{
  u_int16_t type;
  as_t as;
  u_int32_t val;
};

struct rd_ip
{
  u_int16_t type;
  struct in_addr ip;
  u_int16_t val;
};

/* value of first byte of ESI */
#define ESI_TYPE_ARBITRARY 0 /* */
#define ESI_TYPE_LACP      1 /* <> */
#define ESI_TYPE_BRIDGE    2 /* <Root bridge Mac-6B>:<Root Br Priority-2B>:00 */
#define ESI_TYPE_MAC       3 /* <Syst Mac Add-6B>:<Local Discriminator Value-3B> */
#define ESI_TYPE_ROUTER    4 /* <RouterId-4B>:<Local Discriminator Value-4B> */
#define ESI_TYPE_AS        5 /* <AS-4B>:<Local Discriminator Value-4B> */
#define MAX_ESI {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}
#define ESI_LEN 10

#define MAX_ET 0xffffffff
u_long eth_tag_id;

struct eth_segment_id
{
  u_char val[ESI_LEN];
};

#define MAC_LEN 6

union gw_addr {
  struct in_addr ipv4;
#ifdef HAVE_IPV6
  struct in6_addr ipv6;
#endif /* HAVE_IPV6 */
};

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif /* INET_ADDRSTRLEN */

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif /* INET6_ADDRSTRLEN */

#ifndef INET6_BUFSIZ
#define INET6_BUFSIZ 51
#endif /* INET6_BUFSIZ */

/* [1a:2b:3c:4d:5e:6f/48][32.210.222.0/32] => ETH + Ethtag ID : 83 bytes */
#ifndef L2VPN_BUFSIZ
#define L2VPN_BUFSIZ 51+32
#endif /* L2VPN_BUFSIZ */

/* Maximum prefix string length (L2VPN) */
#define PREFIX_STRLEN 51+32

#define RD_TYPE_AS      0
#define RD_TYPE_IP      1
#define RD_TYPE_AS4     2
#define RD_TYPE_EOI	0xff00

/* Maximum route distinguisher string length */
#define RD_ADDRSTRLEN  28

/* Max bit/byte length of IPv4 address. */
#define IPV4_MAX_BYTELEN    4
#define IPV4_MAX_BITLEN    32
#define IPV4_MAX_PREFIXLEN 32
#define IPV4_ADDR_CMP(D,S)   memcmp ((D), (S), IPV4_MAX_BYTELEN)
#define IPV4_ADDR_SAME(D,S)  (memcmp ((D), (S), IPV4_MAX_BYTELEN) == 0)
#define IPV4_ADDR_COPY(D,S)  memcpy ((D), (S), IPV4_MAX_BYTELEN)

#define IPV4_NET0(a)    ((((u_int32_t) (a)) & 0xff000000) == 0x00000000)
#define IPV4_NET127(a)  ((((u_int32_t) (a)) & 0xff000000) == 0x7f000000)
#define IPV4_LINKLOCAL(a) ((((u_int32_t) (a)) & 0xffff0000) == 0xa9fe0000)
#define IPV4_CLASS_DE(a)  ((((u_int32_t) (a)) & 0xe0000000) == 0xe0000000)

/* Max bit/byte length of IPv6 address. */
#define IPV6_MAX_BYTELEN    16
#define IPV6_MAX_BITLEN    128
#define IPV6_MAX_PREFIXLEN 128
#define IPV6_ADDR_CMP(D,S)   memcmp ((D), (S), IPV6_MAX_BYTELEN)
#define IPV6_ADDR_SAME(D,S)  (memcmp ((D), (S), IPV6_MAX_BYTELEN) == 0)
#define IPV6_ADDR_COPY(D,S)  memcpy ((D), (S), IPV6_MAX_BYTELEN)

/* Max bit/byte length of l2vpn address. */
#define L2VPN_PREFIX_ETHTAGLEN (8 * sizeof(u_int32_t))
#define L2VPN_PREFIX_MACADDRLEN (8 * sizeof (u_int8_t) + 8 * sizeof(struct ethaddr))
#define L2VPN_PREFIX_IPV4LEN (8 * sizeof (u_int8_t) + IPV4_MAX_BITLEN)
#define L2VPN_PREFIX_IPV6LEN (8 * sizeof (u_int8_t) + IPV6_MAX_BITLEN)
#define L2VPN_PREFIX_AD (8 * sizeof (struct eth_segment_id) + L2VPN_PREFIX_ETHTAGLEN)
#define L2VPN_MAX_BYTELEN    28
#define L2VPN_MAX_BITLEN    (   L2VPN_PREFIX_ETHTAGLEN \
                              + L2VPN_PREFIX_MACADDRLEN \
                              + L2VPN_PREFIX_IPV6LEN)
#define L2VPN_MAX_PREFIXLEN    L2VPN_MAX_BITLEN
#define L2VPN_PREFIX_IPLEN(p)  ((p)->u.prefix_macip.ip_len)
#define L2VPN_PREFIX_HAS_IPV4(p)  ((p)->u.prefix_macip.ip_len == IPV4_MAX_PREFIXLEN)
#define L2VPN_PREFIX_HAS_IPV6(p)  ((p)->u.prefix_macip.ip_len == IPV6_MAX_PREFIXLEN)
#define L2VPN_PREFIX_HAS_NOIP(p)  ((p)->u.prefix_macip.ip_len == 0)

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* Prefix's family member. */
#define PREFIX_FAMILY(p)  ((p)->family)
#define PREFIX_IS_L2VPN(p)  ((p)->family == AF_L2VPN)
#define PREFIX_IS_L2VPN_AD(p)  ((p)->family == AF_L2VPN && !(p)->u.prefix_macip.mac_len)

/* glibc defines s6_addr32 to __in6_u.__u6_addr32 if __USE_{MISC || GNU} */
#ifndef s6_addr32
#if defined(SUNOS_5)
/* Some SunOS define s6_addr32 only to kernel */
#define s6_addr32 _S6_un._S6_u32
#else
#define s6_addr32 __u6_addr.__u6_addr32
#endif /* SUNOS_5 */
#endif /*s6_addr32*/

/* Prototypes. */
extern int str2family(const char *);
extern int afi2family (afi_t);
extern afi_t family2afi (int);
extern const char *safi2str(safi_t safi);

/* Check bit of the prefix. */
extern unsigned int prefix_bit (const u_char *prefix, const u_char prefixlen);
extern unsigned int prefix6_bit (const struct in6_addr *prefix, const u_char prefixlen);

extern struct prefix *prefix_new (void);
extern void prefix_free (struct prefix *);
extern const char *prefix_family_str (const struct prefix *);
extern int prefix_blen (const struct prefix *);
extern int str2prefix (const char *, struct prefix *);
extern const char *prefix2str (union prefix46constptr, char *, int);
extern int prefix_match (const struct prefix *, const struct prefix *);
extern int prefix_same (const struct prefix *, const struct prefix *);
extern int prefix_cmp (const struct prefix *, const struct prefix *);
extern int prefix_common_bits (const struct prefix *, const struct prefix *);
extern void prefix_copy (struct prefix *dest, const struct prefix *src);
extern void apply_mask (struct prefix *);

extern struct prefix *sockunion2prefix (const union sockunion *dest,
                                        const union sockunion *mask);
extern struct prefix *sockunion2hostprefix (const union sockunion *, struct prefix *p);
extern void prefix2sockunion (const struct prefix *, union sockunion *);

extern struct prefix_ipv4 *prefix_ipv4_new (void);
extern void prefix_ipv4_free (struct prefix_ipv4 *);
extern int str2prefix_ipv4 (const char *, struct prefix_ipv4 *);
extern void apply_mask_ipv4 (struct prefix_ipv4 *);

#define PREFIX_COPY_IPV4(DST, SRC)	\
	*((struct prefix_ipv4 *)(DST)) = *((const struct prefix_ipv4 *)(SRC));

extern int prefix_ipv4_any (const struct prefix_ipv4 *);
extern void apply_classful_mask_ipv4 (struct prefix_ipv4 *);

extern u_char ip_masklen (struct in_addr);
extern void masklen2ip (const int, struct in_addr *);
/* returns the network portion of the host address */
extern in_addr_t ipv4_network_addr (in_addr_t hostaddr, int masklen);
/* given the address of a host on a network and the network mask length,
 * calculate the broadcast address for that network;
 * special treatment for /31: returns the address of the other host
 * on the network by flipping the host bit */
extern in_addr_t ipv4_broadcast_addr (in_addr_t hostaddr, int masklen);

extern int netmask_str2prefix_str (const char *, const char *, char *);

#ifdef HAVE_IPV6
extern struct prefix_ipv6 *prefix_ipv6_new (void);
extern void prefix_ipv6_free (struct prefix_ipv6 *);
extern int str2prefix_ipv6 (const char *, struct prefix_ipv6 *);
extern void apply_mask_ipv6 (struct prefix_ipv6 *);

#define PREFIX_COPY_IPV6(DST, SRC)	\
	*((struct prefix_ipv6 *)(DST)) = *((const struct prefix_ipv6 *)(SRC));

extern int ip6_masklen (struct in6_addr);
extern void masklen2ip6 (const int, struct in6_addr *);

extern void str2in6_addr (const char *, struct in6_addr *);
extern const char *inet6_ntoa (struct in6_addr);

#endif /* HAVE_IPV6 */

extern int all_digit (const char *);

static inline int ipv4_martian (struct in_addr *addr)
{
  in_addr_t ip = addr->s_addr;

  if (IPV4_NET0(ip) || IPV4_NET127(ip) || IPV4_CLASS_DE(ip)) {
    return 1;
  }
  return 0;
}

extern u_int16_t decode_rd_type (u_char *pnt);
extern void decode_rd_as (u_char *pnt, struct rd_as *rd_as);
extern void decode_rd_as4 (u_char *pnt, struct rd_as *rd_as);
extern void decode_rd_ip (u_char *pnt, struct rd_ip *rd_ip);
extern char *prefix_rd2str (struct prefix_rd *prd, char *buf, size_t size);
extern int prefix_str2rd (const char *buf, struct prefix_rd *prd);
extern int prefix_rd_cmp(struct prefix_rd *p1, struct prefix_rd *p2);
extern int str2esi (const char *str, struct eth_segment_id *id);
extern int str2mac (const char *str, char *mac);
extern char *esi2str (struct eth_segment_id *id);
extern char *mac2str (char *mac);
extern char *ecom_mac2str(char *ecom_mac);

#endif /* _ZEBRA_PREFIX_H */
