/*
 * BFDD - bfd_packet.h   
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

#ifndef _QUAGGA_BFD_PACKET_H
#define _QUAGGA_BFD_PACKET_H

/*
   Diagnostic (Diag)

  0 -- No Diagnostic
  1 -- Control Detection Time Expired
  2 -- Echo Function Failed
  3 -- Neighbor Signaled Session Down
  4 -- Forwarding Plane Reset
  5 -- Path Down
  6 -- Concatenated Path Down
  7 -- Administratively Down
  8 -- Reverse Concatenated Path Down
  9-31 -- Reserved for future use

*/

#define BFD_DIAG_NODIAG            0
#define BFD_DIAG_TIMEEXPIRED       1
#define BFD_DIAG_ECHOFAILED        2
#define BFD_DIAG_SESSIONDOWN       3
#define BFD_DIAG_FWDRESET          4
#define BFD_DIAG_PATHDOWN          5
#define BFD_DIAG_CONCATPATHDOWN    6
#define BFD_DIAG_ADMINDOWN         7
#define BFD_DIAG_REVCONCATPATHDOWN 8

#define BFD_PROTOCOL_VERSION       1

#define BFD_STATE_ADMINDOWN        0
#define BFD_STATE_DOWN             1
#define BFD_STATE_INIT             2
#define BFD_STATE_UP               3

#define BFD_DFT_MULTI              3

#define BFD_PACKET_SIZE_NOAUTH     24
#define BFD_PACKET_SIZE_AUTH       26
#define BFD_PACKET_SIZE_MAX BFD_PACKET_SIZE_AUTH

/*
                Generic BFD Control Packet Format

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       My Discriminator                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Your Discriminator                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Desired Min TX Interval                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                   Required Min RX Interval                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 Required Min Echo RX Interval                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 An optional Authentication Section may be present:

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Auth Type   |   Auth Len    |    Authentication Data...     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct bfd_packet
{
#if (BYTE_ORDER == LITTLE_ENDIAN)
  uint8_t diag:5;
  uint8_t vers:3;

  uint8_t m:1;
  uint8_t d:1;
  uint8_t a:1;
  uint8_t c:1;
  uint8_t f:1;
  uint8_t p:1;
  uint8_t sta:2;
#elif (BYTE_ORDER == BIG_ENDIAN)
  uint8_t vers:3;
  uint8_t diag:5;

  uint8_t sta:2;
  uint8_t p:1;
  uint8_t f:1;
  uint8_t c:1;
  uint8_t a:1;
  uint8_t d:1;
  uint8_t m:1;
#endif
  uint8_t multiplier;
  uint8_t length;
  uint32_t mydisc;
  uint32_t yourdisc;

#define BFD_RREQMINRX_DFT       1
#define BFD_LDESMINTX_DFT       1000000
  uint32_t desmintx;

#define BFD_LREQMINRX_DFT       250000
  uint32_t reqminrx;
#define BFD_REQMINECHORX_DFT 0
  uint32_t reqminechorx;

#define BFD_AUTH_NOAUTH         0
#define BFD_AUTH_SIMPLE         1
#define BFD_AUTH_KEYMD5         2
#define BFD_AUTH_MKEYMD5        3
#define BFD_AUTH_KEYSHA1        4
#define BFD_AUTH_MKEYSHA1       5
  uint8_t authtype;
  uint8_t authlen;
  uint16_t authdata;
};

union bfd_buf
{
  struct bfd_packet bfd_packet;
  char buf[BFD_PACKET_SIZE_MAX];
};

/* unit conversion */
#define MSEC(T) ((T)/1000)	/* USEC->MSEC */
#define USEC(T) ((T)*1000)	/* MSEC->USEC */

#define BFD_TXINT(NEIGHP) (((NEIGHP)->txint)/1000)
#define BFD_DTIME(NEIGHP) (((NEIGHP)->dtime)/1000)

/* Jitter
   "The periodic transmission of BFD Control packets SHOULD be jittered
   by up to 25%, that is, the interval SHOULD be reduced by a random
   value of 0 to 25%, in order to avoid self-synchronization.  Thus, the
   average interval between packets may be up to 12.5% less than that
   negotiated.

   If bfd.DetectMult is equal to 1, the interval between transmitted BFD
   Control packets MUST be no more than 90% of the negotiated
   transmission interval, and MUST be no less than 75% of the negotiated
   transmission interval.  This is to ensure that, on the remote system,
   the calculated DetectTime does not pass prior to the receipt of the
   next BFD Control packet." */

/* Generates a percentage (p) jitter from the given timer (t) */
#define bfd_timer_jitter(t,p) \
        (1 + (uint32_t) (((t)*(p)) * (rand() / (RAND_MAX + 1.0))))
/* Generates a value in range 75% - 100% of t */
#define bfd_jtimer_mult_isnot1(t) ((t) - bfd_timer_jitter((t),0.25))
/* Generates a random value in range ~75% - 90% of t */
#define bfd_jtimer_mult_is1(t) \
       ((uint32_t)((double)((t)*0.90)) - bfd_timer_jitter(((t)*0.90),0.16))


int bfd_pkt_recv (union sockunion *loc, union sockunion *rem,
		  struct bfd_packet *bp, unsigned int ifindex, int ttl,
		  int len);
int bfd_pkt_xmit (struct thread *thread);

#endif /* _QUAGGA_BFD_PACKET_H */
