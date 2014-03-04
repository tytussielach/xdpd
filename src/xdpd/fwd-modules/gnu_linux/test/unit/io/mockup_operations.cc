//push pop get_buffer_length
#include <rofl.h>
#include <rofl/datapath/pipeline/common/datapacket.h>
#include "io/packet_classifiers/packet_operations.h"

rofl_result_t pkt_push(datapacket_t* pkt, uint8_t* push_point, unsigned int offset, unsigned int num_of_bytes){
	return ROFL_SUCCESS;
}

rofl_result_t pkt_pop(datapacket_t* pkt, uint8_t* pop_point, unsigned int offset, unsigned int num_of_bytes){
	return ROFL_SUCCESS;
}

size_t get_buffer_length(datapacket_t* pkt){
	//return ((xdpd::gnu_linux::datapacketx86*)pkt->platform_state)->get_buffer_length();
	return 0;
}
