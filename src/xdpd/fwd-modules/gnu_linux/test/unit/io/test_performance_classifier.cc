/**
* This is a test that should measure the performance of 
* the classifier being used
*/
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/TestCase.h>
#include <cppunit/extensions/HelperMacros.h>

#include <rofl.h>
#include <rofl/datapath/pipeline/common/datapacket.h>

#include "time_utils.h"

#include "io/packet_classifiers/pktclassifier.h"
//#ifdef C_PKTCLASSIFIER
#include "io/packet_classifiers/c_pktclassifier/c_pktclassifier.h"
//#else
	//#include "io/packet_classifiers/cpp_pktclassifier/cpp_pktclassifier.h"
//#endif

#define NUM_OF_ITERATONS 500
//#define PACKET_STRING {0x00,0x1a,0x64,0x11,0xf2,0x6d,0x3c,0x97,0x0e,0x5f,0xbb,0x67,0x08,0x00,0x45,0x00,0x00,0x34,0x62,0x07,0x40,0x00,0x40,0x06,0xf3,
//0x85,0xac,0x10,0xfa,0x8b,0xbc,0xa5,0x81,0xf5,0xd1,0xae,0x00,0x50,0xac,0x4d,0xfc,0x9e,0x9b,0x16,0x9f,0x73,0x80,0x10,0x01,0x3a,0xe5,0x5d,0x00,0x00,0x01,
//0x01,0x08,0x0a,0x00,0x1a,0x5d,0xfa,0x5c,0xc6,0x6d,0x63}
#define SIZE 66
uint8_t packet[2] = { 0x00,0x22 };

class PerfClassifierTestCase : public CppUnit::TestFixture{
	CPPUNIT_TEST_SUITE(PerfClassifierTestCase);
	CPPUNIT_TEST(test_basic);
	CPPUNIT_TEST_SUITE_END();
	
	void test_basic(void);

	struct classify_state* clas_state;
	
public:
	void setUp(void);
	void tearDown(void);
};

void PerfClassifierTestCase::setUp(){
	//init classifier
	clas_state = (struct classify_state*) malloc(sizeof(struct classify_state));
	memset(clas_state,0,sizeof(struct classify_state));
	clas_state->matches=(packet_matches_t*) malloc(sizeof(packet_matches_t));
}

void PerfClassifierTestCase::tearDown(){
	free(clas_state->matches);
	free(clas_state);
}

void PerfClassifierTestCase::test_basic(){
	
	uint64_t tics, accumulated_time;
	uint32_t average_tics;
	
	int i;

	for(i=0; i<NUM_OF_ITERATONS; i++){

		tics = rdtsc();
		
		classify_packet(clas_state,packet,SIZE,1,0);
		
		accumulated_time += rdtsc() - tics;

	}
	
	average_tics = accumulated_time / NUM_OF_ITERATONS;
	
	fprintf(stderr, "num_of_iterations %u Average cycles: %u\n",NUM_OF_ITERATONS, average_tics);
}

/*
* Test MAIN
*/
int main( int argc, char* argv[] )
{
	CppUnit::TextUi::TestRunner runner;
	runner.addTest(PerfClassifierTestCase::suite()); // Add the top suite to the test runner
	runner.setOutputter(
			new CppUnit::CompilerOutputter(&runner.result(), std::cerr));

	// Run the test and don't wait a key if post build check.
	bool wasSuccessful = runner.run( "" );
	
	std::cerr<<"************** Test finished ************"<<std::endl;

	// Return error code 1 if the one of test failed.
	return wasSuccessful ? 0 : 1;
}
