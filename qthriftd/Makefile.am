## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib @THRIFT_CFLAGS@ @GLIB2_CFLAGS@ @GOBJECT2_CFLAGS@

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libqthrift.a
sbin_PROGRAMS = qthriftd

libqthrift_a_SOURCES = \
	qthriftd.c qthrift_vpnservice.c qthrift_network.c \
	bgp_configurator.c bgp_updater.c vpnservice_types.c qthrift_memory.c \
	qthrift_debug.c qthrift_vty.c qthrift_bgp_configurator.c qthrift_bgp_updater.c

noinst_HEADERS = \
	bgp_configurator.h bgp_updater.h vpnservice_types.h

qthriftd_SOURCES = \
	qthrift_main.c $(libqthrift_a_SOURCES)

qthriftd_LDADD = ../lib/libzebra.la -lm @THRIFT_LIBS@ @GLIB2_LIBS@ @GOBJECT2_LIBS@ -lpthread

examplesdir = $(exampledir)
dist_examples_DATA = 

EXTRA_DIST = 

