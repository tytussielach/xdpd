/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _CLASSIFIER_MONOHDR_H_
#define _CLASSIFIER_MONOHDR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <rofl/datapath/pipeline/common/datapacket.h>
#include "../pktclassifier.h"

#include "./headers/cpc_arpv4.h"
#include "./headers/cpc_ethernet.h"
#include "./headers/cpc_gtpu.h"
#include "./headers/cpc_icmpv4.h"
#include "./headers/cpc_icmpv6_opt.h"
#include "./headers/cpc_icmpv6.h"
#include "./headers/cpc_ipv4.h"
#include "./headers/cpc_ipv6.h"
#include "./headers/cpc_mpls.h"
#include "./headers/cpc_ppp.h"
#include "./headers/cpc_pppoe.h"
#include "./headers/cpc_tcp.h"
#include "./headers/cpc_udp.h"
#include "./headers/cpc_vlan.h"

/**
* @file classifier_monohdr.h
* @author Victor Alvarez<victor.alvarez (at) bisdn.de>
*
* @brief Interface for the C classifiers with only one Header per type
*/

//Header type
enum header_type{
	HEADER_TYPE_ETHER = 0,
	HEADER_TYPE_VLAN = 1,
	HEADER_TYPE_MPLS = 2,
	HEADER_TYPE_ARPV4 = 3,
	HEADER_TYPE_IPV4 = 4,
	HEADER_TYPE_ICMPV4 = 5,
	HEADER_TYPE_IPV6 = 6,
	HEADER_TYPE_ICMPV6 = 7,
	HEADER_TYPE_ICMPV6_OPT_LLADDR_SOURCE = 8,
	HEADER_TYPE_ICMPV6_OPT_LLADDR_TARGET = 9,
	HEADER_TYPE_ICMPV6_OPT_PREFIX_INFO = 10,
	HEADER_TYPE_UDP = 11,
	HEADER_TYPE_TCP = 12,
	HEADER_TYPE_SCTP = 13,
	HEADER_TYPE_PPPOE = 14,
	HEADER_TYPE_PPP = 15,
	HEADER_TYPE_GTP = 16,

	//Must be the last one
	HEADER_TYPE_MAX
};

ROFL_BEGIN_DECLS

//Header container
typedef struct header_container{

	//Presence of header
	//bool present;
	
	//Header pointer
	void* frame;
	size_t length;
	
	//NOTE not used:
	enum header_type type;
	//Pseudo-linked list pointers (short-cuts)
	//struct header_container* prev;
	//struct header_container* next;
}header_container_t;

typedef struct classify_state{
	//Real container
	header_container_t headers[HEADER_TYPE_MAX];
	
	unsigned int total_headers;
	
	//vector of index of headers
	int mapper[HEADER_TYPE_MAX];
	
	//Flag to know if it is classified
	bool is_classified;

	//Inner most (last) ethertype
	uint16_t eth_type;

	//Pre-parsed packet matches
	packet_matches_t* matches; 
}classify_state_t;


//NOTE all the getters could be simplified into one now that there is only one per type.
// idx is also not used. Anyhow we will keep the interface for now

inline static 
void* __get_hdr(classify_state_t* clas_state, enum header_type type){
	header_container_t *hdr;
	int pos = clas_state->mapper[type];
	
	if(pos >= (int)clas_state->total_headers)
		return NULL;
	
	hdr = &(clas_state->headers[pos]);
	
	if(hdr->type != type )
		return NULL;
	
	return hdr->frame;
}

//inline function implementations
inline static 
void* get_ether_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_ETHER);
}

inline static
void* get_vlan_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_VLAN);
}

inline static
void* get_mpls_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_MPLS);
}

inline static
void* get_arpv4_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_ARPV4);
}

inline static
void* get_ipv4_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_IPV4);
}

inline static
void* get_icmpv4_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_ICMPV4);
}

inline static
void* get_ipv6_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_IPV6);
}

inline static
void* get_icmpv6_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_ICMPV6);
}

inline static
void* get_icmpv6_opt_lladr_source_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_ICMPV6_OPT_LLADDR_SOURCE);
}

inline static
void* get_icmpv6_opt_lladr_target_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_ICMPV6_OPT_LLADDR_TARGET);
}

inline static
void* get_icmpv6_opt_prefix_info_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_ICMPV6_OPT_PREFIX_INFO);
}

inline static
void* get_udp_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_UDP);
}

inline static
void* get_tcp_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_TCP);
}

inline static
void* get_pppoe_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_PPPOE);
}

inline static
void* get_ppp_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_PPP);
}

inline static
void* get_gtpu_hdr(classify_state_t* clas_state, int idx){
	return __get_hdr(clas_state,HEADER_TYPE_GTP);
}

ROFL_END_DECLS

#endif //_CLASSIFIER_MONOHDR_H_
