#include "datapacketx86.h"

//Include here the classifier you want to use
#include "packet_classifiers/rofl_pktclassifier.h"
#include "packet_classifiers/static_pktclassifier.h"

/*
 * x86 datapacket related methods
 */

//Change this if you want to use another classifier
//typedef rofl_pktclassifier pktclassifier;
typedef static_pktclassifier pktclassifier;

//Constructor
datapacketx86::datapacketx86() :
	 buffer_id(0),
	 internal_buffer_id(0),
	 lsw(0),
	 in_port(0),
	 in_phy_port(0),
	 output_queue(0),
	 ipv4_recalc_checksum(false),
	 tcp_recalc_checksum(false),
	 udp_recalc_checksum(false),
	 icmpv4_recalc_checksum(false),
	 pktin_table_id(0),
	 pktin_reason(0),
	 headers(new pktclassifier(this)),
	 buffering_status(X86_DATAPACKET_BUFFER_IS_EMPTY)
{

}



datapacketx86::~datapacketx86()
{
	delete headers;
}





void
datapacketx86::destroy(void)
{
	headers->classify_reset();

	if (X86_DATAPACKET_BUFFERED_IN_USER_SPACE == get_buffering_status()){
#ifndef NDEBUG
		// not really necessary, but makes debugging a little bit easier
		platform_memset(slot.iov_base, 0x00, slot.iov_len);
#endif

		slot.iov_base 	= 0;
		slot.iov_len 	= 0;
		buffer.iov_base = 0;
		buffer.iov_len 	= 0;

		buffering_status = X86_DATAPACKET_BUFFER_IS_EMPTY;
	}
}




//Transfer copy to user-space
rofl_result_t datapacketx86::transfer_to_user_space(){

	switch (get_buffering_status()){

		case X86_DATAPACKET_BUFFERED_IN_NIC: {
			slot.iov_base 	= user_space_buffer;
			slot.iov_len	= sizeof(user_space_buffer);
#ifndef NDEBUG
			// not really necessary, but makes debugging a little bit easier
			platform_memset(slot.iov_base, 0x00, slot.iov_len);
#endif
			// safety check for buffer.iov_len <= FRAME_SIZE_BYTES was done in datapacketx86::init() already
			platform_memcpy((uint8_t*)slot.iov_base + PRE_GUARD_BYTES, buffer.iov_base, buffer.iov_len);

			buffer.iov_base = (uint8_t*)slot.iov_base + PRE_GUARD_BYTES;
			// buffer.iov_len stays as it is
			
			// set buffering flag
			buffering_status = X86_DATAPACKET_BUFFERED_IN_USER_SPACE;
			
			//Re-classify 
			//TODO: use offsets instead of fixed pointers for frames to avoid re-classification here
			headers->classify();
			
			//Copy done
		} return ROFL_SUCCESS;

		case X86_DATAPACKET_BUFFERED_IN_USER_SPACE: {
		}return ROFL_SUCCESS;
		
		case X86_DATAPACKET_BUFFER_IS_EMPTY: // packet is un-initialized
		default: {
		} return ROFL_FAILURE; // do nothing
	}
}


