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

@0xc7bbe66a583460d4;

struct QZCNodeInfoReq {
	nid		@0 :UInt64;
}

struct QZCNodeInfoRep {
	nid		@0 :UInt64;
	tid		@1 :UInt64;
}

struct QZCWKNResolveReq {
	wid		@0 :UInt64;
}

struct QZCWKNResolveRep {
	wid		@0 :UInt64;
	nid		@1 :UInt64;
}

struct QZCGet {
	nid		@0 :UInt64;
	elem		@1 :UInt64;
        datatype        @2 :UInt64;
        data            @3 :AnyPointer;
}

struct QZCCreateReq {
	parentnid	@0 :UInt64;
	parentelem	@1 :UInt64;
	datatype	@2 :UInt64;
	data		@3 :AnyPointer;
}

struct QZCCreateRep {
	newnid		@0 :UInt64;
}

struct QZCRequest {
	union {
		ping		@0 :Void;
		nodeinforeq	@1 :QZCNodeInfoReq;
		wknresolve	@2 :QZCWKNResolveReq;
		get		@3 :QZCGet;
		create		@4 :QZCCreateReq;
	}
}

struct QZCReply {
	error @0 :Bool;
	union {
		pong		@1 :Void;
		nodeinforep	@2 :QZCNodeInfoRep;
		wknresolve	@3 :QZCWKNResolveRep;
		get		@4 :QZCGet;
		create		@5 :QZCCreateRep;
	}
}

struct QZCNodeList @0x9bb91c45a95a581d {
	nodes			@0 :List(UInt64);
}

