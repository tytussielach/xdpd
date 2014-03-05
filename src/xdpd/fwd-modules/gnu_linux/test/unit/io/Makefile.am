MAINTAINERCLEANFILES = Makefile.in

test_datapacket_storage_SOURCES= $(top_srcdir)/src/io/datapacket_storage.cc\
	test_datapacket_storage.cc

test_performance_classifier_SOURCES= test_performance_classifier.cc \
	mockup_operations.cc \
	pipeline_packet_mockup.c\
	platform_hooks_of1x_mockup.cc \
	$(top_srcdir)/src/pipeline-imp/memory.c \
	$(top_srcdir)/src/pipeline-imp/pthread_lock.c \
	$(top_srcdir)/src/pipeline-imp/atomic_operations.c \
	$(top_srcdir)/src/pipeline-imp/timing.c \
	$(top_srcdir)/src/io/bufferpool.cc \
	$(top_srcdir)/src/io/datapacketx86.cc \
	$(top_srcdir)/src/io/datapacket_storage.cc \
	$(top_srcdir)/src/io/packet_classifiers/c_pktclassifier/c_pktclassifier.c

test_datapacket_storage_LDADD= -lrofl -lcppunit -lpthread

test_performance_classifier_CXXFLAGS= -O3 -pg
test_performance_classifier_CFLAGS= -O3 -pg
test_performance_classifier_LDADD= -lrofl -lcppunit -lpthread -lrofl_pipeline

check_PROGRAMS = test_datapacket_storage test_performance_classifier
TESTS = test_datapacket_storage test_performance_classifier
