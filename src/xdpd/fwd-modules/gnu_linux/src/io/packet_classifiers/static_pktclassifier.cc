#include "static_pktclassifier.h"
#include <rofl/common/utils/c_logger.h>
#include "../datapacketx86.h"


//Constructor&destructor
static_pktclassifier::static_pktclassifier(datapacketx86* pkt_ref) :
	packetclassifier(pkt_ref)
{
	unsigned int i;

	classify_reset();	
	
	/*
	* Initialize fframes
	*/
	
	//Ether
	for(i=0;i<MAX_ETHER_FRAMES;i++){
		headers[FIRST_ETHER_FRAME_POS+i].frame = new rofl::fetherframe(NULL, 0);		
		headers[FIRST_ETHER_FRAME_POS+i].type = HEADER_TYPE_ETHER;
	}
	//vlan
	for(i=0;i<MAX_VLAN_FRAMES;i++){
		headers[FIRST_VLAN_FRAME_POS+i].frame = new rofl::fvlanframe(NULL, 0);		
		headers[FIRST_VLAN_FRAME_POS+i].type = HEADER_TYPE_VLAN;
	}
	//mpls
	for(i=0;i<MAX_MPLS_FRAMES;i++){
		headers[FIRST_MPLS_FRAME_POS+i].frame = new rofl::fmplsframe(NULL, 0);		
		headers[FIRST_MPLS_FRAME_POS+i].type = HEADER_TYPE_MPLS;
	}
	//arpv4
	for(i=0;i<MAX_ARPV4_FRAMES;i++){
		headers[FIRST_ARPV4_FRAME_POS+i].frame = new rofl::farpv4frame(NULL, 0);		
		headers[FIRST_ARPV4_FRAME_POS+i].type = HEADER_TYPE_ARPV4;
	}
	//ipv4
	for(i=0;i<MAX_IPV4_FRAMES;i++){
		headers[FIRST_IPV4_FRAME_POS+i].frame = new rofl::fipv4frame(NULL, 0);		
		headers[FIRST_IPV4_FRAME_POS+i].type = HEADER_TYPE_IPV4;
	}
	//icmpv4
	for(i=0;i<MAX_ICMPV4_FRAMES;i++){
		headers[FIRST_ICMPV4_FRAME_POS+i].frame = new rofl::ficmpv4frame(NULL, 0);		
		headers[FIRST_ICMPV4_FRAME_POS+i].type = HEADER_TYPE_ICMPV4;
	}
	//udp
	for(i=0;i<MAX_UDP_FRAMES;i++){
		headers[FIRST_UDP_FRAME_POS+i].frame = new rofl::fudpframe(NULL, 0);		
		headers[FIRST_UDP_FRAME_POS+i].type = HEADER_TYPE_UDP;
	}
	//tcp
	for(i=0;i<MAX_TCP_FRAMES;i++){
		headers[FIRST_TCP_FRAME_POS+i].frame = new rofl::ftcpframe(NULL, 0);		
		headers[FIRST_TCP_FRAME_POS+i].type = HEADER_TYPE_TCP;
	}
	//sctp
	for(i=0;i<MAX_SCTP_FRAMES;i++){
		headers[FIRST_SCTP_FRAME_POS+i].frame = new rofl::fsctpframe(NULL, 0);		
		headers[FIRST_SCTP_FRAME_POS+i].type = HEADER_TYPE_SCTP;
	}
	//pppoe
	for(i=0;i<MAX_PPPOE_FRAMES;i++){
		headers[FIRST_PPPOE_FRAME_POS+i].frame = new rofl::fpppoeframe(NULL, 0);		
		headers[FIRST_PPPOE_FRAME_POS+i].type = HEADER_TYPE_PPPOE;
	}

	//ppp
	for(i=0;i<MAX_PPP_FRAMES;i++){
		headers[FIRST_PPP_FRAME_POS+i].frame = new rofl::fpppframe(NULL, 0);		
		headers[FIRST_PPP_FRAME_POS+i].type = HEADER_TYPE_PPP;
	}
	//gtp
	for (i=0;i<MAX_GTP_FRAMES;i++){
		headers[FIRST_GTP_FRAME_POS+i].frame = new rofl::fgtpuframe(NULL, 0);
		headers[FIRST_GTP_FRAME_POS+i].type = HEADER_TYPE_GTP;
	}

	//Add more here...
}

static_pktclassifier::~static_pktclassifier(){
	
	for(unsigned i=0; i<MAX_HEADERS; i++){
		if(headers[i].frame)
			delete headers[i].frame;		
	}

}



