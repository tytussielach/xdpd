MAINTAINERCLEANFILES = Makefile.in

test_datapacket_storage_SOURCES= $(top_srcdir)/src/io/datapacket_storage.cc\
	test_datapacket_storage.cc

test_performance_classifier_SOURCES= test_performance_classifier.cc \
	mockup_operations.cc \
	$(top_srcdir)/src/io/packet_classifiers/c_pktclassifier/c_pktclassifier.c

test_datapacket_storage_LDADD= -lrofl -lcppunit -lpthread

test_performance_classifier_LDADD= -lrofl -lcppunit -lpthread

check_PROGRAMS = test_datapacket_storage test_performance_classifier
TESTS = test_datapacket_storage test_performance_classifier
