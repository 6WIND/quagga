AUTOMAKE_OPTIONS    = dejagnu
DEJATOOL = libzebra

SUBDIRS = \
	bgpd.tests \
	libzebra.tests

EXTRA_DIST = \
	config/unix.exp \
	lib/bgpd.exp \
	lib/libzebra.exp \
	global-conf.exp \
	testcommands.in \
	testcommands.refout \
	testcli.in \
	testcli.refout

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib -I$(top_srcdir)/lib/c-capnproto
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\" @ZEROMQ_CFLAGS@

if BGPD
TESTS_BGPD = aspathtest testbgpcap ecommtest testbgpmpattr testbgpmpath
DEJATOOL += bgpd
else
TESTS_BGPD =
endif

check_PROGRAMS = testsig testsegv testbuffer testmemory heavy heavywq heavythread \
		testprivs teststream testchecksum tabletest testnexthopiter \
		testcommands test-timer-correctness test-timer-performance \
		testcli \
		$(TESTS_BGPD)

if HAVE_ZEROMQ
check_PROGRAMS += test_zmq_event
endif

../vtysh/vtysh_cmd.c:
	$(MAKE) -C ../vtysh vtysh_cmd.c

test-commands-defun.c: ../vtysh/vtysh_cmd.c
	sed \
		-e 's/"vtysh\.h"/"tests.h"/' \
		-e 's/vtysh_init_cmd/test_init_cmd/' \
		-e 's/VTYSH_[A-Z][A-Z_0-9]*/0/g' \
		< ../vtysh/vtysh_cmd.c \
		> test-commands-defun.c

BUILT_SOURCES = test-commands-defun.c
noinst_HEADERS = prng.h tests.h common-cli.h

testcli_SOURCES = test-cli.c common-cli.c
testsig_SOURCES = test-sig.c
testsegv_SOURCES = test-segv.c
testbuffer_SOURCES = test-buffer.c
testmemory_SOURCES = test-memory.c
testprivs_SOURCES = test-privs.c
teststream_SOURCES = test-stream.c
heavy_SOURCES = heavy.c main.c
heavywq_SOURCES = heavy-wq.c main.c
heavythread_SOURCES = heavy-thread.c main.c
aspathtest_SOURCES = aspath_test.c
testbgpcap_SOURCES = bgp_capability_test.c
ecommtest_SOURCES = ecommunity_test.c
testbgpmpattr_SOURCES =  bgp_mp_attr_test.c
testchecksum_SOURCES = test-checksum.c
testbgpmpath_SOURCES = bgp_mpath_test.c
tabletest_SOURCES = table_test.c
testnexthopiter_SOURCES = test-nexthop-iter.c prng.c
testcommands_SOURCES = test-commands-defun.c test-commands.c prng.c
test_timer_correctness_SOURCES = test-timer-correctness.c prng.c
test_timer_performance_SOURCES = test-timer-performance.c prng.c
test_zmq_event_SOURCES = test-zmq-event.c common-cli.c

testcli_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
testsig_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
testsegv_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
testbuffer_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
testmemory_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
testprivs_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
teststream_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
heavy_LDADD = ../lib/libzebra.la @LIBCAP@ -lm @ZEROMQ_LIBS@
heavywq_LDADD = ../lib/libzebra.la @LIBCAP@ -lm @ZEROMQ_LIBS@
heavythread_LDADD = ../lib/libzebra.la @LIBCAP@ -lm @ZEROMQ_LIBS@
aspathtest_LDADD = ../bgpd/libbgp.a ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@ -lm
testbgpcap_LDADD = ../bgpd/libbgp.a ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@ -lm
ecommtest_LDADD = ../bgpd/libbgp.a ../lib/libzebra.la @LIBCAP@ -lm @ZEROMQ_LIBS@ 
testbgpmpattr_LDADD = ../bgpd/libbgp.a ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@ -lm
testchecksum_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@ 
testbgpmpath_LDADD = ../bgpd/libbgp.a ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@ -lm
tabletest_LDADD = ../lib/libzebra.la @LIBCAP@ -lm @ZEROMQ_LIBS@
testnexthopiter_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
testcommands_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
test_timer_correctness_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
test_timer_performance_LDADD = ../lib/libzebra.la @LIBCAP@ @ZEROMQ_LIBS@
test_zmq_event_LDADD = ../lib/libzebra.la @LIBCAP@ $(ZEROMQ_LIBS)
