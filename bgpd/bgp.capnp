#
# Copyright (c) 2016  David Lamparter, for NetDEF, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

@0xc4c948a17d3b2250;

using import "../capnp/codegen.capnp".Cflag;
using import "../capnp/codegen.capnp".IPv4;

using import "../capnp/codegen.capnp".ctype;
using import "../capnp/codegen.capnp".cflag;
using import "../capnp/codegen.capnp".cheader;
using import "../capnp/codegen.capnp".cgen;
using import "../capnp/codegen.capnp".csetter;
using import "../capnp/codegen.capnp".cgetfield;
using import "../capnp/codegen.capnp".cgennaked;
using import "../capnp/codegen.capnp".carraykey;

struct AfiSafiKey $cgennaked $cgetfield {
	afi			 @0 :UInt8 $ctype("afi_t");
	safi			 @1 :UInt8 $ctype("safi_t");
}

struct BGP $ctype("struct bgp") $cgen {
	as			 @0 :UInt32;
	name			 @1 :Text;

	routerIdStatic		 @2 :IPv4;

	cfAlwaysCompareMed	 @3 :Bool $cflag(field = "flags", value = "BGP_FLAG_ALWAYS_COMPARE_MED");
	cfDeterministicMed	 @4 :Bool $cflag(field = "flags", value = "BGP_FLAG_DETERMINISTIC_MED");
	cfMedMissingAsWorst	 @5 :Bool $cflag(field = "flags", value = "BGP_FLAG_MED_MISSING_AS_WORST");
	cfMedConfed		 @6 :Bool $cflag(field = "flags", value = "BGP_FLAG_MED_CONFED");
	cfNoDefaultIPv4		 @7 :Bool $cflag(field = "flags", value = "BGP_FLAG_NO_DEFAULT_IPV4");
	cfNoClientToClient	 @8 :Bool $cflag(field = "flags", value = "BGP_FLAG_NO_CLIENT_TO_CLIENT");
	cfEnforceFirstAS	 @9 :Bool $cflag(field = "flags", value = "BGP_FLAG_ENFORCE_FIRST_AS");
	cfCompareRouterID	@10 :Bool $cflag(field = "flags", value = "BGP_FLAG_COMPARE_ROUTER_ID");
	cfAspathIgnore		@11 :Bool $cflag(field = "flags", value = "BGP_FLAG_ASPATH_IGNORE");
	cfImportCheck		@12 :Bool $cflag(field = "flags", value = "BGP_FLAG_IMPORT_CHECK");
	cfNoFastExtFailover	@13 :Bool $cflag(field = "flags", value = "BGP_FLAG_NO_FAST_EXT_FAILOVER");
	cfLogNeighborChanges	@14 :Bool $cflag(field = "flags", value = "BGP_FLAG_LOG_NEIGHBOR_CHANGES");
	cfGracefulRestart	@15 :Bool $cflag(field = "flags", value = "BGP_FLAG_GRACEFUL_RESTART");
	cfAspathConfed		@16 :Bool $cflag(field = "flags", value = "BGP_FLAG_ASPATH_CONFED");
	cfAspathMpathRelax	@17 :Bool $cflag(field = "flags", value = "BGP_FLAG_ASPATH_MULTIPATH_RELAX");

	distanceEBGP		@18 :UInt8;
	distanceIBGP		@19 :UInt8;
	distanceLocal		@20 :UInt8;

	defaultLocalPref	@21 :UInt32;
	defaultHoldtime		@22 :UInt32;
	defaultKeepalive	@23 :UInt32;

	restartTime		@24 :UInt32;
	stalepathTime		@25 :UInt32;
}

struct BGPAfiSafi $ctype("struct bgp") $cgen $carraykey("AfiSafiKey") {
	cfDampening		 @0 :Bool $cflag(field = "af_flags", value = "BGP_CONFIG_DAMPENING");
}

struct BGPPeerKey $ctype("struct peer") $cgen $cgetfield {
	as			 @0 :UInt32;
	host			 @1 :Text;
}

struct BGPPeer $ctype("struct peer") $cgen $csetter("peer_%%_set") {
	localAs			 @0 :UInt32;

	desc			 @1 :Text $csetter("peer_description_set");
	port			 @2 :UInt16;
	weight			 @3 :UInt32;
	holdtime		 @4 :UInt32;

	cfPassive		 @5 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_PASSIVE");
	cfShutdown		 @6 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_SHUTDOWN");
	cfDontCapability	 @7 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_DONT_CAPABILITY");
	cfOverrideCapability	 @8 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_OVERRIDE_CAPABILITY");
	cfStrictCapMatch	 @9 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_STRICT_CAP_MATCH");
	cfDynamicCapability	@10 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_DYNAMIC_CAPABILITY");
	cfDisableConnectedCheck	@11 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_DISABLE_CONNECTED_CHECK");
	cfLocalAsNoPrepend	@12 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_LOCAL_AS_NO_PREPEND");
	cfLocalAsReplaceAs	@13 :Bool $cflag(field = "flags", setter = "peer_flag_set", value = "PEER_FLAG_LOCAL_AS_REPLACE_AS");
}

struct BGPPeerAfiSafi $ctype("struct peer") $cgen $carraykey("AfiSafiKey") {
	afc			 @0 :Bool;
	
	cfSendCommunity		 @1 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_SEND_COMMUNITY");
	cfSendExtCommunity	 @2 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_SEND_EXT_COMMUNITY");
	cfNexthopSelf		 @3 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_NEXTHOP_SELF");
	cfReflectorClient	 @4 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_REFLECTOR_CLIENT");
	cfRServerClient		 @5 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_RSERVER_CLIENT");
	cfSoftReconfig		 @6 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_SOFT_RECONFIG");
	cfAsPathUnchanged	 @7 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_AS_PATH_UNCHANGED");
	cfNexthopUnchanged	 @8 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_NEXTHOP_UNCHANGED");
	cfMedUnchanged		 @9 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_MED_UNCHANGED");
	cfDefaultOriginate	@10 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_DEFAULT_ORIGINATE");
	cfRemovePrivateAs	@11 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_REMOVE_PRIVATE_AS");
	cfAllowAsIn		@12 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_ALLOWAS_IN");
	cfOrfPrefixSM		@13 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_ORF_PREFIX_SM");
	cfOrfPrefixRM		@14 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_ORF_PREFIX_RM");
	cfMaxPrefix		@15 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_MAX_PREFIX");
	cfMaxPrefixWarn		@16 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_MAX_PREFIX_WARNING");
	cfNexthopLocalUnchanged	@17 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED");
	cfNexthopSelfAll	@18 :Bool $cflag(field = "af_flags", value = "PEER_FLAG_NEXTHOP_SELF_ALL");

	allowAsIn		@19 :Int8;
}

