/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DATAPACKETX86_H
#define DATAPACKETX86_H 

#include <bitset>
#include <inttypes.h>
#include <sys/types.h>
#include <rofl.h>
#include <rofl/datapath/pipeline/openflow/of_switch.h>

#include "packet_classifiers/packetclassifier.h"

/**
* @file datapacketx86.h
* @author Andreas Koepsel<andreas.koepsel (at) bisdn.de>
* @author Marc Sune<marc.sune (at) bisdn.de>
* @author Tobias Jungel<tobias.jungel (at) bisdn.de>
* @author Victor Alvarez<victor.alvarez (at) bisdn.de>
*
* @brief Data packet abstraction for an x86 (GNU/Linux)
*
*/

/* Auxiliary state for x86 datapacket*/
//buffering status
typedef enum{
	X86_DATAPACKET_BUFFER_IS_EMPTY,
	X86_DATAPACKET_BUFFERED_IN_NIC,
	X86_DATAPACKET_BUFFERED_IN_USER_SPACE
}x86buffering_status_t;

class datapacketx86{

public:
	
	//Constructor&destructor
	datapacketx86();
	~datapacketx86();

	//General data of the packet
	uint64_t buffer_id;		//Unique "non-reusable" buffer id
	uint64_t internal_buffer_id;	//IO subsystem buffer ID

	//Incomming packet information
	of_switch_t* lsw;
	uint32_t in_port;
	uint32_t in_phy_port;
	
	//Output queue
	uint32_t output_queue;

	//Checksum flags
	bool ipv4_recalc_checksum;
	bool tcp_recalc_checksum;
	bool udp_recalc_checksum;
	bool icmpv4_recalc_checksum;

	//Temporary store for pkt_in information
	uint8_t pktin_table_id;
	of_packet_in_reason_t pktin_reason;	

public: // methods

	//Initialize the already constructed object
	inline rofl_result_t init(uint8_t* buf, size_t buflen, of_switch_t* sw, uint32_t in_port, uint32_t in_phy_port = 0, bool classify=true, bool copy_packet_to_internal_buffer = true);

	//Destroy object. This is NOT a destructor nor releases memory, but resets fields
	void destroy(void);

	/*
	* Return pointer to the buffer, regardless of where is right now (NIC or USER_SPACE). For memory on USER_SPACE returns pointer to the FIRST packet bytes.
	*/
	inline uint8_t* get_buffer(){ return (uint8_t*)buffer.iov_base; }
	inline size_t get_buffer_length(){ return buffer.iov_len; }
	inline x86buffering_status_t get_buffering_status(){ return buffering_status; }

	//Transfer buffer to user-space
	rofl_result_t transfer_to_user_space(void);

	//Header packet classification	
	friend class packetclassifier;
	packetclassifier* headers;
	

	//Other	
	friend std::ostream& operator<<(std::ostream& os, datapacketx86& pack);
	inline void dump(void) {
		headers->dump();
	}

private:
	//HOST buffer size
	static const unsigned int PRE_GUARD_BYTES  = 256;
	static const unsigned int FRAME_SIZE_BYTES = 9000;
	static const unsigned int POST_GUARD_BYTES = 64;

	/*
	* Pointer to buffer, either on NIC or on USER_SPACE pointer. It ALWAYS points to the first byte of the packet.
	*/
	struct iovec buffer;

	/*
	 * real memory area
	 * => in user space, this contains the above buffer including head and tail space
	 * => in NIC space, it is set to 0
	 */
	struct iovec slot;

	//FIXME: NIC buffer info MISSING

	//User space buffer	
	uint8_t user_space_buffer[PRE_GUARD_BYTES+FRAME_SIZE_BYTES+POST_GUARD_BYTES];

	//Status of this buffer
	x86buffering_status_t buffering_status;

	/**
	 * utility function to set the correct buffer location
	 * @param location
	 */
	inline void init_internal_buffer_location_defaults(x86buffering_status_t location, uint8_t* buf, size_t buflen);
	//Add more stuff here...

	
	/*
	* Push&pop raw operations. To be used ONLY by classifiers
	*/
	inline rofl_result_t push(unsigned int num_of_bytes, unsigned int offset = 0);
	inline rofl_result_t pop(unsigned int num_of_bytes, unsigned int offset = 0);

	inline rofl_result_t push(uint8_t* push_point, unsigned int num_of_bytes);
	inline rofl_result_t pop(uint8_t* pop_point, unsigned int num_of_bytes);

};

/*
* Inline functions
*/ 

//Init
rofl_result_t
datapacketx86::init(
		uint8_t* buf, size_t buflen,
		of_switch_t* sw,
		uint32_t in_port,
		uint32_t in_phy_port,
		bool classify, 
		bool copy_packet_to_internal_buffer)
{
	// do this sanity check here, as someone may request later a transfer to user space,
	// so make sure we have enough space for doing this later
	if (buflen > FRAME_SIZE_BYTES){
		return ROFL_FAILURE;
	}
#if 0
	// if buffer is NULL we initialize to local buffer and do not copy anything
	if (NULL == buf) {
		init_internal_buffer_location_defaults(X86_DATAPACKET_BUFFERED_IN_USER_SPACE, NULL, buflen);
		return ROFL_SUCCESS;
	}
#endif

	if( copy_packet_to_internal_buffer) {

		init_internal_buffer_location_defaults(X86_DATAPACKET_BUFFERED_IN_USER_SPACE, NULL, buflen);

		if(buf)
			platform_memcpy(buffer.iov_base, buf, buflen);
	}else{
		if(!buf)
			return ROFL_FAILURE;

		init_internal_buffer_location_defaults(X86_DATAPACKET_BUFFERED_IN_NIC, buf, buflen);
	}

	//Fill in
	this->lsw = sw;
	this->in_port = in_port;
	this->in_phy_port = in_phy_port;
	//this->eth_type 		= 0;

	this->output_queue = 0;

	//Classify the packet
	if(classify)
		headers->classify();

	return ROFL_SUCCESS;
}


void
datapacketx86::init_internal_buffer_location_defaults(
		x86buffering_status_t location, uint8_t* buf, size_t buflen)
{
	switch (location) {

		case X86_DATAPACKET_BUFFERED_IN_NIC:
			slot.iov_base = 0;
			slot.iov_len = 0;

			buffer.iov_base = buf;
			buffer.iov_len = buflen;
			buffering_status = X86_DATAPACKET_BUFFERED_IN_NIC;
			break;

		case X86_DATAPACKET_BUFFERED_IN_USER_SPACE:
			slot.iov_base = user_space_buffer;
			slot.iov_len = sizeof(user_space_buffer);
#ifndef NDEBUG
			// not really necessary, but makes debugging a little bit easier
			platform_memset(slot.iov_base, 0x00, slot.iov_len);
#endif
			buffer.iov_base = user_space_buffer + PRE_GUARD_BYTES;
			buffer.iov_len = buflen; // set to requested length
			buffering_status = X86_DATAPACKET_BUFFERED_IN_USER_SPACE;
			break;

		case X86_DATAPACKET_BUFFER_IS_EMPTY:
		default:
			// todo ?
			break;
	}
}



/*
 * Push&pop operations
 */
rofl_result_t
datapacketx86::push(
		unsigned int offset,
		unsigned int num_of_bytes)
{
	//If not already transfer to user space
	if(X86_DATAPACKET_BUFFERED_IN_NIC == buffering_status){
		transfer_to_user_space();
	}
	
	if (offset > buffer.iov_len){
		return ROFL_FAILURE;
	}

	size_t free_space_head = (uint8_t*)buffer.iov_base - (uint8_t*)slot.iov_base;
	size_t free_space_tail = slot.iov_len - (free_space_head + buffer.iov_len);

	/*
	 * this is the safe sanity check for both head and tail space
	 */
	if (num_of_bytes > (free_space_head + free_space_tail)){
		return ROFL_FAILURE;
	}

	/*
	 * implicit assumption: we only have pre-guard-bytes and move forward and backward at the head of the packet
	 */
	if (num_of_bytes > free_space_head){
		return ROFL_FAILURE;
	}

	// move header num_of_bytes backward
	platform_memmove((uint8_t*)buffer.iov_base - num_of_bytes, buffer.iov_base, offset);
#ifndef NDEBUG
	// initialize new pushed memory area with 0x00
	platform_memset((uint8_t*)buffer.iov_base - num_of_bytes + offset, 0x00, num_of_bytes);
#endif

	buffer.iov_base = (uint8_t*)buffer.iov_base - num_of_bytes;
	buffer.iov_len += num_of_bytes;


	return ROFL_SUCCESS;
}



rofl_result_t
datapacketx86::pop(
		unsigned int offset,
		unsigned int num_of_bytes)
{
	//Check boundaries
	//FIXME

	//If not already transfer to user space
	if(X86_DATAPACKET_BUFFERED_IN_NIC == buffering_status){
		transfer_to_user_space();
	}

	// sanity check: start of area to be deleted must not be before start of buffer
	if (offset > buffer.iov_len){
		return ROFL_FAILURE;
	}

	// sanity check: end of area to be deleted must not be behind end of buffer
	if ((offset + num_of_bytes) > buffer.iov_len){
		return ROFL_FAILURE;
	}

	// move first bytes backward
	platform_memmove((uint8_t*)buffer.iov_base + num_of_bytes, buffer.iov_base, offset);

#ifndef NDEBUG
	// set now unused bytes to 0x00 for easier debugging
	platform_memset(buffer.iov_base, 0x00, num_of_bytes);
#endif

	buffer.iov_base = (uint8_t*)buffer.iov_base + num_of_bytes;
	buffer.iov_len -= num_of_bytes;

	// re-parse_ether() here? yes, we have to, but what about the costs?

	return ROFL_SUCCESS;
}



//Push&pop operations
rofl_result_t
datapacketx86::push(
		uint8_t* push_point,
		unsigned int num_of_bytes)
{
	//If not already transfer to user space
	if(X86_DATAPACKET_BUFFERED_IN_NIC == buffering_status){
		transfer_to_user_space();
	}
	
	if (push_point < buffer.iov_base){
		return ROFL_FAILURE;
	}

	if (((uint8_t*)push_point + num_of_bytes) > ((uint8_t*)buffer.iov_base + buffer.iov_len)){
		return ROFL_FAILURE;
	}

	//size_t offset = ((uint8_t*)buffer.iov_base - push_point);
	size_t offset = (push_point - (uint8_t*)buffer.iov_base);

	return push(offset, num_of_bytes);
}



rofl_result_t
datapacketx86::pop(
		uint8_t* pop_point,
		unsigned int num_of_bytes)
{
	if (pop_point < buffer.iov_base){
		return ROFL_FAILURE;
	}

	if (((uint8_t*)pop_point + num_of_bytes) > ((uint8_t*)buffer.iov_base + buffer.iov_len)){
		return ROFL_FAILURE;
	}

	//size_t offset = ((uint8_t*)buffer.iov_base - pop_point);
	size_t offset = ((uint8_t*)buffer.iov_base - pop_point);

	return pop(offset, num_of_bytes);
}



#endif /* DATAPACKETX86_H_ */
