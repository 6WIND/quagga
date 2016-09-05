## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib \
		-I$(top_srcdir)/lib/c-capnproto @ZEROMQ_CFLAGS@
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libbgp.a libbgpcapnp.a
sbin_PROGRAMS = bgpd
bin_PROGRAMS = bgp_btoa

libbgp_a_SOURCES = \
	bgp_memory.c \
	bgpd.c bgp_fsm.c bgp_aspath.c bgp_community.c bgp_attr.c \
	bgp_debug.c bgp_route.c bgp_zebra.c bgp_open.c bgp_routemap.c \
	bgp_packet.c bgp_network.c bgp_filter.c bgp_regex.c bgp_clist.c \
	bgp_dump.c bgp_snmp.c bgp_mplsvpn.c bgp_evpn.c bgp_nexthop.c \
	bgp_damp.c bgp_table.c bgp_advertise.c bgp_vty.c bgp_mpath.c \
	bgp_encap.c bgp_encap_tlv.c bgp_zmq.c

libbgpcapnp_a_SOURCES = bgp.libbcapnp.c
libbgpcapnp_a_CPPFLAGS = $(AM_CPPFLAGS)

noinst_HEADERS = \
	bgp_memory.h \
	bgp_aspath.h bgp_attr.h bgp_community.h bgp_debug.h bgp_fsm.h \
	bgp_network.h bgp_open.h bgp_packet.h bgp_regex.h bgp_route.h \
	bgpd.h bgp_filter.h bgp_clist.h bgp_dump.h bgp_zebra.h \
	bgp_mplsvpn.h bgp_nexthop.h bgp_damp.h bgp_table.h \
	bgp_advertise.h bgp_snmp.h bgp_vty.h bgp_mpath.h \
	bgp_encap.h bgp_encap_tlv.h bgp_encap_types.h bgp_evpn.h

bgpd_SOURCES = bgp_main.c
bgpd_LDADD = libbgp.a ../lib/libzebra.la @LIBCAP@ @LIBM@ @ZEROMQ_LIBS@

bgp_btoa_SOURCES = bgp_btoa.c
bgp_btoa_LDADD = libbgp.a ../lib/libzebra.la @LIBCAP@ @LIBM@ @ZEROMQ_LIBS@

examplesdir = $(exampledir)
dist_examples_DATA = bgpd.conf.sample bgpd.conf.sample2 bgpd.conf.sample3

EXTRA_DIST = BGP4-MIB.txt

EXTRA_DIST += bgpd.ndef.i bgpd.ndef.hi bgp.bcapnp.c bgp.bcapnp.h
libbgp_a_SOURCES += bgp.bcapnp.c bgp.libbcapnp.c
