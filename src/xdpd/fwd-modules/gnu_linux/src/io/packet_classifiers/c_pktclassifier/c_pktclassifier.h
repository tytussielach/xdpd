/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _C_PKTCLASSIFIER_H_
#define _C_PKTCLASSIFIER_H_

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
* @file cpc_pktclassifier.h
* @author Victor Alvarez<victor.alvarez (at) bisdn.de>
*
* @brief Interface for the C classifiers
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
	HEADER_TYPE_ICMPV6_OPT = 8,	
	HEADER_TYPE_UDP = 9,	
	HEADER_TYPE_TCP = 10,	
	HEADER_TYPE_SCTP = 11,	
	HEADER_TYPE_PPPOE = 12,	
	HEADER_TYPE_PPP = 13,	
	HEADER_TYPE_GTP = 14,

	//Must be the last one
	HEADER_TYPE_MAX
};


// Constants
//Maximum header occurrences per type
#define MAX_ETHER_FRAMES 2
#define MAX_VLAN_FRAMES 4
#define MAX_MPLS_FRAMES 16
#define MAX_ARPV4_FRAMES 1
#define MAX_IPV4_FRAMES 2
#define MAX_ICMPV4_FRAMES 2
#define MAX_IPV6_FRAMES 2
#define MAX_ICMPV6_FRAMES 1
#define MAX_ICMPV6_OPT_FRAMES 3
#define MAX_UDP_FRAMES 2
#define MAX_TCP_FRAMES 2
#define MAX_SCTP_FRAMES 2
#define MAX_PPPOE_FRAMES 1
#define MAX_PPP_FRAMES 1
#define MAX_GTP_FRAMES 1

//Total maximum header occurrences
#define MAX_HEADERS MAX_ETHER_FRAMES + \
						MAX_VLAN_FRAMES + \
						MAX_MPLS_FRAMES + \
						MAX_ARPV4_FRAMES + \
						MAX_IPV4_FRAMES + \
						MAX_ICMPV4_FRAMES + \
						MAX_IPV6_FRAMES + \
						MAX_ICMPV6_FRAMES + \
						MAX_ICMPV6_OPT_FRAMES + \
						MAX_UDP_FRAMES + \
						MAX_TCP_FRAMES + \
						MAX_SCTP_FRAMES + \
						MAX_PPPOE_FRAMES + \
						MAX_PPP_FRAMES + \
						MAX_GTP_FRAMES


//Relative positions within the array;
//Very first frame always
#define FIRST_ETHER_FRAME_POS 0
#define FIRST_VLAN_FRAME_POS FIRST_ETHER_FRAME_POS+MAX_ETHER_FRAMES
#define FIRST_MPLS_FRAME_POS FIRST_VLAN_FRAME_POS+MAX_VLAN_FRAMES
#define FIRST_ARPV4_FRAME_POS FIRST_MPLS_FRAME_POS+MAX_MPLS_FRAMES
#define FIRST_IPV4_FRAME_POS FIRST_ARPV4_FRAME_POS+MAX_ARPV4_FRAMES
#define FIRST_ICMPV4_FRAME_POS FIRST_IPV4_FRAME_POS+MAX_IPV4_FRAMES
#define FIRST_IPV6_FRAME_POS FIRST_ICMPV4_FRAME_POS+MAX_ICMPV4_FRAMES
#define FIRST_ICMPV6_FRAME_POS FIRST_IPV6_FRAME_POS+MAX_IPV6_FRAMES
#define FIRST_ICMPV6_OPT_FRAME_POS FIRST_ICMPV6_FRAME_POS+MAX_ICMPV6_FRAMES
#define FIRST_UDP_FRAME_POS FIRST_ICMPV6_OPT_FRAME_POS+MAX_ICMPV6_OPT_FRAMES
#define FIRST_TCP_FRAME_POS FIRST_UDP_FRAME_POS+MAX_UDP_FRAMES
#define FIRST_SCTP_FRAME_POS FIRST_TCP_FRAME_POS+MAX_TCP_FRAMES
#define FIRST_PPPOE_FRAME_POS FIRST_SCTP_FRAME_POS+MAX_SCTP_FRAMES
#define FIRST_PPP_FRAME_POS FIRST_PPPOE_FRAME_POS+MAX_PPPOE_FRAMES
#define FIRST_GTP_FRAME_POS FIRST_PPP_FRAME_POS+MAX_PPP_FRAMES

#define OFFSET_ICMPV6_OPT_LLADDR_SOURCE 0
#define OFFSET_ICMPV6_OPT_LLADDR_TARGET 1
#define OFFSET_ICMPV6_OPT_PREFIX_INFO 2

//Just to be on the safe side of life
//assert( (FIRST_PPP_FRAME_POS + MAX_PPP_FRAMES) == MAX_HEADERS);

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
	header_container_t headers[MAX_HEADERS];
	
	//Counters
	unsigned int num_of_headers[HEADER_TYPE_MAX];
	unsigned int total_headers;
	
	//vector of index of headers
	int mapper[MAX_HEADERS];
	
	//Flag to know if it is classified
	bool is_classified;

	//Inner most (last) ethertype
	uint16_t eth_type;

	//Pre-parsed packet matches
	packet_matches_t* matches; 
}classify_state_t;


//inline function implementations
inline static 
void* get_ether_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_ETHER];
	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_ETHER_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_ETHER_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_ETHER)
		return clas_state->headers[pos].frame;	
	return NULL;
}

inline static
void* get_vlan_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_VLAN];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_VLAN_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_VLAN_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if (pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_VLAN)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_mpls_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_MPLS];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_MPLS_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_MPLS_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_MPLS)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_arpv4_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_ARPV4];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_ARPV4_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_ARPV4_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_ARPV4)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_ipv4_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_IPV4];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most const
		mapper_pos = FIRST_IPV4_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_IPV4_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_IPV4)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_icmpv4_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_ICMPV4];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_ICMPV4_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_ICMPV4_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_ICMPV4)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_ipv6_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_IPV6];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_IPV6_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_IPV6_FRAME_POS + idx;

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_IPV6)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_icmpv6_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_ICMPV6];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_ICMPV6_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_ICMPV6_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_ICMPV6)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_icmpv6_opt_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_ICMPV6_OPT];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_ICMPV6_OPT_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_ICMPV6_OPT_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_ICMPV6_OPT)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_icmpv6_opt_lladr_source_hdr(classify_state_t* clas_state, int idx){
	//only one option of this kind is allowed
	unsigned int pos;

	pos = clas_state->mapper[FIRST_ICMPV6_OPT_FRAME_POS + OFFSET_ICMPV6_OPT_LLADDR_SOURCE];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_ICMPV6_OPT)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_icmpv6_opt_lladr_target_hdr(classify_state_t* clas_state, int idx){
	//only one option of this kind is allowed
	unsigned int pos;

	pos = clas_state->mapper[FIRST_ICMPV6_OPT_FRAME_POS + OFFSET_ICMPV6_OPT_LLADDR_TARGET];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_ICMPV6_OPT)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_icmpv6_opt_prefix_info_hdr(classify_state_t* clas_state, int idx){
	//only one option of this kind is allowed
	unsigned int pos;

	pos = clas_state->mapper[FIRST_ICMPV6_OPT_FRAME_POS + OFFSET_ICMPV6_OPT_PREFIX_INFO];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_ICMPV6_OPT)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_udp_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_UDP];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_UDP_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_UDP_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_UDP)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_tcp_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_TCP];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_TCP_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_TCP_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_TCP)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_pppoe_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_PPPOE];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_PPPOE_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_PPPOE_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_PPPOE)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_ppp_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_PPP];	

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_PPP_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_PPP_FRAME_POS + idx;	

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_PPP)
		return clas_state->headers[pos].frame;
	return NULL;
}

inline static
void* get_gtpu_hdr(classify_state_t* clas_state, int idx){
	unsigned int pos, mapper_pos, num_of_headers = clas_state->num_of_headers[HEADER_TYPE_GTP];

	if(idx > (int)num_of_headers)
		return NULL;

	if(idx < 0) //Inner most
		mapper_pos = FIRST_GTP_FRAME_POS + num_of_headers - 1;
	else
		mapper_pos = FIRST_GTP_FRAME_POS + idx;

	pos = clas_state->mapper[mapper_pos];
	//Return the index
	if( pos < clas_state->total_headers && clas_state->headers[pos].type == HEADER_TYPE_GTP)
		return clas_state->headers[pos].frame;
	return NULL;
}

ROFL_END_DECLS

#endif //_C_PKTCLASSIFIER_H_
