/*
 * derived from GPLv2+ sources
 */
#ifndef CAPN_C4C948A17D3B2250
#define CAPN_C4C948A17D3B2250


#include "zebra.h"
#include "bgpd.h"
#include "bgp_mpath.h"
afi_t qcapn_AfiSafiKey_get_afi(capn_ptr p);
safi_t qcapn_AfiSafiKey_get_safi(capn_ptr p);
capn_ptr qcapn_new_AfiSafiKey(struct capn_segment *s);
afi_t qcapn_AfiKey_get_afi(capn_ptr p);
capn_ptr qcapn_new_AfiKey(struct capn_segment *s);
void qcapn_VRFTableIter_read(struct prefix *s, capn_ptr p);
void qcapn_VRFTableIter_write(struct prefix *s, capn_ptr p);
void qcapn_VRFTableIter_set(struct prefix *s, capn_ptr p);
capn_ptr qcapn_new_VRFTableIter(struct capn_segment *s);
void qcapn_BGP_read(struct bgp *s, capn_ptr p);
void qcapn_BGP_write(const struct bgp *s, capn_ptr p);
void qcapn_BGP_set(struct bgp *s, capn_ptr p);
as_t qcapn_BGP_get_as(capn_ptr p);
capn_ptr qcapn_new_BGP(struct capn_segment *s);
void qcapn_BGPAfiSafi_read(struct bgp *s, capn_ptr p, afi_t afi, safi_t safi);
void qcapn_BGPAfiSafi_write(const struct bgp *s, capn_ptr p, afi_t afi, safi_t safi);
void qcapn_BGPAfiSafi_set(struct bgp *s, capn_ptr p, afi_t afi, safi_t safi);
capn_ptr qcapn_new_BGPAfiSafi(struct capn_segment *s);
void qcapn_BGPPeer_read(struct peer *s, capn_ptr p);
void qcapn_BGPPeer_write(const struct peer *s, capn_ptr p);
void qcapn_BGPPeer_set(struct peer *s, capn_ptr p);
as_t qcapn_BGPPeer_get_as(capn_ptr p);
const char * qcapn_BGPPeer_get_host(capn_ptr p);
capn_ptr qcapn_new_BGPPeer(struct capn_segment *s);
capn_ptr qcapn_new_BGPPeerStatus(struct capn_segment *s);
void qcapn_BGPPeerStatus_write(const struct peer *s, capn_ptr p);
void qcapn_BGPPeerAfiSafi_read(struct peer *s, capn_ptr p, afi_t afi, safi_t safi);
void qcapn_BGPPeerAfiSafi_write(const struct peer *s, capn_ptr p, afi_t afi, safi_t safi);
void qcapn_BGPPeerAfiSafi_set(struct peer *s, capn_ptr p, afi_t afi, safi_t safi);
capn_ptr qcapn_new_BGPPeerAfiSafi(struct capn_segment *s);
void qcapn_BGPVRF_read(struct bgp_vrf *s, capn_ptr p);
void qcapn_BGPVRF_write(const struct bgp_vrf *s, capn_ptr p);
void qcapn_BGPVRF_set(struct bgp_vrf *s, capn_ptr p);
struct prefix_rd qcapn_BGPVRF_get_outbound_rd(capn_ptr p);
uint8_t qcapn_BGPVRF_get_layer_type(capn_ptr p);
uint32_t qcapn_BGPVRF_get_mpath(capn_ptr p);
capn_ptr qcapn_new_BGPVRF(struct capn_segment *s);
void qcapn_BGPVRFRoute_read(struct bgp_api_route *s, capn_ptr p);
void qcapn_BGPVRFRoute_write(const struct bgp_api_route *s, capn_ptr p);
void qcapn_BGPVRFRoute_set(struct bgp_api_route *s, capn_ptr p);
capn_ptr qcapn_new_BGPVRFRoute(struct capn_segment *s, uint8_t extend_by);
void qcapn_BGPEventVRFRoute_read(struct bgp_event_vrf *s, capn_ptr p);
void qcapn_BGPEventVRFRoute_write(const struct bgp_event_vrf *s, capn_ptr p);
void qcapn_BGPEventVRFRoute_set(struct bgp_event_vrf *s, capn_ptr p);
capn_ptr qcapn_new_BGPEventVRFRoute(struct capn_segment *s);
void qcapn_BGPEventShut_read(struct bgp_event_shut *s, capn_ptr p);
void qcapn_BGPEventShut_write(const struct bgp_event_shut *s, capn_ptr p);
void qcapn_BGPEventShut_set(struct bgp_event_shut *s, capn_ptr p);
capn_ptr qcapn_new_BGPEventShut(struct capn_segment *s);
capn_ptr qcapn_new_BGPVRFInfoIter(struct capn_segment *s);
void qcapn_BGPVRFInfoIter_write(const unsigned long s, capn_ptr p, int offset);
void qcapn_BGPVRFInfoIter_read(unsigned long *s, capn_ptr p, int offset);
void qcapn_prefix_macip_read(capn_ptr p, struct prefix *pfx, uint8_t *index);
void qcapn_prefix_macip_write(capn_ptr p, const struct prefix *pfx, uint8_t *index);
void qcapn_prefix_imethtag_write(capn_ptr p, const struct prefix *pfx, uint8_t *index);
void qcapn_prefix_imethtag_read(capn_ptr p, struct prefix *pfx, uint8_t *index);
void qcapn_prefix_ipv4ipv6_write (capn_ptr p, const struct prefix *pfx, uint8_t index);
void qcapn_prefix_ipv4ipv6_read(capn_ptr p, struct prefix *pfx, uint8_t index);

#define  CAPN_BGPVRF_ROUTE_DEF_SIZE  12
#endif /* CAPN_C4C948A17D3B2250 */
