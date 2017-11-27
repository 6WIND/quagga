## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

noinst_LIBRARIES = libbfd.a
sbin_PROGRAMS = bfdd

libbfd_a_SOURCES = \
	bfdd.c bfd_debug.c bfd_fsm.c bfd_interface.c bfd_net.c \
        bfd_packet.c bfd_zebra.c

noinst_HEADERS = \
	bfdd.h bfd_debug.h bfd_fsm.h bfd_interface.h bfd_net.h \
        bfd_packet.h bfd_zebra.h

bfdd_SOURCES = \
	bfd_main.c $(libbfd_a_SOURCES)

bfdd_LDADD = ../lib/libzebra.la @LIBCAP@

examplesdir = $(exampledir)
dist_examples_DATA = bfdd.conf.sample

