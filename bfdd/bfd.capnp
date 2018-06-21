#
# Copyright (C) 2018 6WIND
#

@0xc4c948a17d3b2251;

using import "../capnp/codegen.capnp".ctype;
using import "../capnp/codegen.capnp".cgen;
using import "../capnp/codegen.capnp".csetwrite;

struct BFD $ctype("struct bfd") $cgen
{
	configDataVersion	 @0 :UInt8 $csetwrite;
	failureThreshold	 @1 :UInt8 $csetwrite;
	multihop		 @2 :UInt8 $csetwrite;
	rxInterval		 @3 :UInt32 $csetwrite;
	txInterval		 @4 :UInt32 $csetwrite;
	debounceDown		 @5 :UInt32 $csetwrite;
	debounceUp		 @6 :UInt32 $csetwrite;

	logFile			 @7 :Text;
	logLevel		 @8 :Text;
}
