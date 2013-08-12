/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef PACKETCLASSIFIER_H
#define PACKETCLASSIFIER_H

#include <bitset>
#include <inttypes.h>
#include <sys/types.h>

#include <rofl.h>
#include <rofl/datapath/pipeline/common/datapacket.h>
#include <rofl/common/protocols/fetherframe.h>
#include <rofl/common/protocols/fvlanframe.h>
#include <rofl/common/protocols/fmplsframe.h>
#include <rofl/common/protocols/farpv4frame.h>
#include <rofl/common/protocols/fipv4frame.h>
#include <rofl/common/protocols/ficmpv4frame.h>
#include <rofl/common/protocols/fudpframe.h>
#include <rofl/common/protocols/ftcpframe.h>
#include <rofl/common/protocols/fsctpframe.h>
#include <rofl/common/protocols/fpppoeframe.h>
#include <rofl/common/protocols/fpppframe.h>
#include <rofl/common/protocols/fgtpuframe.h>
#include <rofl/datapath/pipeline/platform/memory.h>
//#include <rofl/datapath/pipeline/util/rofl_pipeline_utils.h>
#include <rofl/common/utils/c_logger.h>

/**
* @file packetclassifier.h
* @author Marc Sune<marc.sune (at) bisdn.de>
* @author Andreas Koepsel<andreas.koepsel (at) bisdn.de>
*
* @brief Pure abstract packet classifier class.
*
* All the packet classifiers associated with datapacketx86
* should be compliant with this interface.
*
*/

//fwd declarations (avoid circular dependencies)
class datapacketx86;

//Instead of defininig virtual (pure virtual) functions, just
//abort on calling abstract methods
#define PKT_CLASSIFIER_UNIMPLEMENTED_METHOD()\
	do{\
		fprintf(stderr,"PKT_CLASSIFIER: unimplemented method by pkt_classifier provider. Aborting...\n");\
		exit(-1);\
	}while(0) 


class packetclassifier{

public:
	//Constructor&destructor
	packetclassifier(datapacketx86* pkt_ref):pkt(pkt_ref){}; 
	virtual ~packetclassifier(){}; 

	/*
	* Main classification methods. 
	*/
	/*virtual*/ inline void classify(void){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline void classify_reset(void){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};

	/*
	* header access
	*/

	/*virtual*/ inline rofl::fetherframe* ether(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fvlanframe* vlan(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fmplsframe* mpls(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::farpv4frame* arpv4(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fipv4frame* ipv4(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::ficmpv4frame* icmpv4(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fudpframe* udp(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::ftcpframe* tcp(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fsctpframe* sctp(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fpppoeframe* pppoe(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fpppframe* ppp(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fgtpuframe* gtp(int idx = 0) const{
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};

	/*
	 * pop operations
	 */
	/*virtual*/ inline void pop_vlan(void){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline void pop_mpls(uint16_t ether_type){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline void pop_pppoe(uint16_t ether_type){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};

	/*
	 * push operations
	 */
	/*virtual*/ inline rofl::fvlanframe* push_vlan(uint16_t ether_type){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fmplsframe* push_mpls(uint16_t ether_type){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	/*virtual*/ inline rofl::fpppoeframe* push_pppoe(uint16_t ether_type){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	
	/*
	* dump
	*/
	/*virtual*/ inline void dump(void){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};

	/** returns length of packet starting at 'fframe' from up to including fframe 'to'
	 *
	 */
	/*virtual*/ inline size_t
	get_pkt_len(
			rofl::fframe *from = (rofl::fframe*)0,
			rofl::fframe   *to = (rofl::fframe*)0){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};


protected:

	//Datapacket reference
	datapacketx86* pkt;

	/*
	* Wrappers for pkt push and pop so that we can use friendship in derived classes
	*/
	inline rofl_result_t pkt_push(unsigned int num_of_bytes, unsigned int offset=0){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	inline rofl_result_t pkt_pop(unsigned int num_of_bytes, unsigned int offset=0){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	inline rofl_result_t pkt_push(uint8_t* push_point, unsigned int num_of_bytes){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};
	inline rofl_result_t pkt_pop(uint8_t* pop_point, unsigned int num_of_bytes){
		PKT_CLASSIFIER_UNIMPLEMENTED_METHOD();
	};

};

#if 0
#include "../datapacketx86.h"

/*
* Implementation of the (necessary?) wrappers 
*/
rofl_result_t packetclassifier::pkt_push(unsigned int num_of_bytes, unsigned int offset){
	return pkt->push(num_of_bytes,offset);
}
rofl_result_t packetclassifier::pkt_pop(unsigned int num_of_bytes, unsigned int offset){
	return pkt->pop(num_of_bytes,offset);
}
rofl_result_t packetclassifier::pkt_push(uint8_t* push_point, unsigned int num_of_bytes){
	return pkt->push(push_point,num_of_bytes);
}
rofl_result_t packetclassifier::pkt_pop(uint8_t* pop_point, unsigned int num_of_bytes){ 
	return pkt->pop(pop_point,num_of_bytes);
}
#endif

#endif /* PACKETCLASSIFIER_H_ */
