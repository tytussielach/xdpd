/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef IOPORTV2_MMAP_H
#define IOPORTV2_MMAP_H 

#include <string>

#include <rofl.h>
#include <rofl/datapath/pipeline/common/datapacket.h>
#include <rofl/datapath/pipeline/switch_port.h>
#include <rofl/common/cmacaddr.h>

#include "../ioport.h"
#include "mmap_rx.h"
#include "mmap_tx.h"
#include "../../datapacketx86.h"
#include "../../bufferpool.h"

/**
* @file ioport_mmapv2.h
* @author Tobias Jungel<tobias.jungel (at) bisdn.de>
* @author Andreas Koepsel<andreas.koepsel (at) bisdn.de>
* @author Marc Sune<marc.sune (at) bisdn.de>
*
* @brief GNU/Linux interface access via Memory Mapped
* region (MMAP) using PF_PACKET TX/RX rings 
*/

class ioport_mmapv2 : public ioport{


public:
	//ioport_mmapv2
	ioport_mmapv2(
			/*int port_no,*/
			switch_port_t* of_ps,
			int block_size = IO_IFACE_MMAP_BLOCK_SIZE,
			int n_blocks = IO_IFACE_MMAP_BLOCKS,
			int frame_size = IO_IFACE_MMAP_FRAME_SIZE,
			unsigned int num_queues = IO_IFACE_NUM_QUEUES);

	/*virtual*/
	~ioport_mmapv2();

	//Enque packet for transmission(blocking)
	/*virtual*/ inline void enqueue_packet(datapacket_t* pkt, unsigned int q_id);


	//Non-blocking read and write
	/*virtual*/ inline datapacket_t* read(void);

	/*virtual*/ inline unsigned int write(unsigned int q_id, unsigned int num_of_buckets);

	// Get read fds. Return -1 if do not exist
	inline /*virtual*/ int
	get_read_fd(void){
		if(rx)
			return rx->get_fd();
		return -1;
	};

	// Get write fds. Return -1 if do not exist
	inline /*virtual*/ int get_write_fd(void){
		return notify_pipe[READ];
	};

	unsigned int get_port_no() {
		/* FIXME: probably a check whether of_port_state is not null in the constructor will suffice*/
		if(of_port_state)
			return of_port_state->of_port_num;
		else
			return 0;
	}


	/**
	 * Sets the port administratively up. This MUST change the of_port_state appropiately
	 */
	/*virtual*/ rofl_result_t enable(void);

	/**
	 * Sets the port administratively down. This MUST change the of_port_state appropiately
	 */
	/*virtual*/ rofl_result_t disable(void);

protected:

private:
	
	//Minimum frame size (ethernet header size)
	static const unsigned int MIN_PKT_LEN=14;
	
	//mmap internals
	mmap_rx* rx;
	mmap_tx* tx;

	//parameters for regenerating tx/rx
	int block_size;
	int n_blocks;
	int frame_size;

	/* todo move to parent? */
	cmacaddr hwaddr;
	
	//Pipe used to
	int notify_pipe[2];
	
	//Pipe extremes
	static const unsigned int READ=0;
	static const unsigned int WRITE=1;

	inline void fill_vlan_pkt(struct tpacket2_hdr *hdr, datapacketx86 *pkt_x86);
	inline void fill_tx_slot(struct tpacket2_hdr *hdr, datapacketx86 *packet);
	inline void empty_pipe(void);
};


//Read and write methods over port
void ioport_mmapv2::enqueue_packet(datapacket_t* pkt, unsigned int q_id){

	//Whatever
	const char c='a';
	int ret;
	unsigned int len;
	
	datapacketx86* pkt_x86 = (datapacketx86*) pkt->platform_state;
	len = pkt_x86->get_buffer_length();

	if ( likely(of_port_state->up) && 
		likely(of_port_state->forward_packets) &&
		likely(len >= MIN_PKT_LEN) ) {

		//Safe check for q_id
		if( unlikely(q_id >= get_num_of_queues()) ){
			ROFL_DEBUG("[mmap:%s] Packet(%p) trying to be enqueued in an invalid q_id: %u\n",  of_port_state->name, pkt, q_id);
			q_id = 0;
			bufferpool::release_buffer(pkt);
			assert(0);
		}
	
		//Store on queue and exit. This is NOT copying it to the mmap buffer
		if(output_queues[q_id].non_blocking_write(pkt) != ROFL_SUCCESS){
			ROFL_DEBUG("[mmap:%s] Packet(%p) dropped. Congestion in output queue: %d\n",  of_port_state->name, pkt, q_id);
			//Drop packet
			bufferpool::release_buffer(pkt);
			return;
		}

		ROFL_DEBUG_VERBOSE("[mmap:%s] Packet(%p) enqueued, buffer size: %d\n",  of_port_state->name, pkt, output_queues[q_id].size());
	
		//TODO: make it happen only if thread is really sleeping...
		ret = ::write(notify_pipe[WRITE],&c,sizeof(c));
		(void)ret; // todo use the value
	} else {
		if(len < MIN_PKT_LEN){
			ROFL_ERR("[mmap:%s] ERROR: attempt to send invalid packet size for packet(%p) scheduled for queue %u. Packet size: %u\n", of_port_state->name, pkt, q_id, len);
			assert(0);
		}else{
			ROFL_DEBUG_VERBOSE("[mmap:%s] dropped packet(%p) scheduled for queue %u\n", of_port_state->name, pkt, q_id);
		}

		//Drop packet
		bufferpool::release_buffer(pkt);
	}

}

void ioport_mmapv2::empty_pipe(){
	//Whatever
	char c;
	int ret;

	//Just take the byte from the pipe	
	ret = ::read(notify_pipe[READ],&c,sizeof(c));
	(void)ret; // todo use the value
}

void ioport_mmapv2::fill_vlan_pkt(struct tpacket2_hdr *hdr, datapacketx86 *pkt_x86){

	//Initialize pktx86
	pkt_x86->init(NULL, hdr->tp_len + sizeof(struct fvlanframe::vlan_hdr_t), of_port_state->attached_sw, get_port_no(), 0, false); //Init but don't classify

	// write ethernet header
	memcpy(pkt_x86->get_buffer(), (uint8_t*)hdr + hdr->tp_mac, sizeof(struct fetherframe::eth_hdr_t));

	// set dl_type to vlan
	if( htobe16(ETH_P_8021Q) == ((struct fetherframe::eth_hdr_t*)((uint8_t*)hdr + hdr->tp_mac))->dl_type ) {
		((struct fetherframe::eth_hdr_t*)pkt_x86->get_buffer())->dl_type = htobe16(ETH_P_8021Q); // tdoo maybe this should be ETH_P_8021AD
	}else{
		((struct fetherframe::eth_hdr_t*)pkt_x86->get_buffer())->dl_type = htobe16(ETH_P_8021Q);
	}

	// write vlan
	struct fvlanframe::vlan_hdr_t* vlanptr =
			(struct fvlanframe::vlan_hdr_t*) (pkt_x86->get_buffer()
			+ sizeof(struct fetherframe::eth_hdr_t));
	vlanptr->byte0 =  (hdr->tp_vlan_tci >> 8);
	vlanptr->byte1 = hdr->tp_vlan_tci & 0x00ff;
	vlanptr->dl_type = ((struct fetherframe::eth_hdr_t*)((uint8_t*)hdr + hdr->tp_mac))->dl_type;

	// write payload
	memcpy(pkt_x86->get_buffer() + sizeof(struct fetherframe::eth_hdr_t) + sizeof(struct fvlanframe::vlan_hdr_t),
	(uint8_t*)hdr + hdr->tp_mac + sizeof(struct fetherframe::eth_hdr_t), 
	hdr->tp_len - sizeof(struct fetherframe::eth_hdr_t));

	//And classify
	pkt_x86->headers->classify();
}
	
// handle read
datapacket_t* ioport_mmapv2::read(){

	struct tpacket2_hdr *hdr;
	struct sockaddr_ll *sll;
	datapacket_t *pkt;
	datapacketx86 *pkt_x86;
	cmacaddr eth_src;

	//Check if we really have to read
	if(unlikely(!of_port_state->up) || unlikely(of_port_state->drop_received) || unlikely(!rx))
		return NULL;

next:
	//Empty reading pipe
	empty_pipe();

	//Retrieve a packet	
 	hdr = rx->read_packet();

	//No packets available
	if (!hdr)
		return NULL;

	//Sanity check 
	if ( unlikely(hdr->tp_mac + hdr->tp_snaplen > rx->get_tpacket_req()->tp_frame_size) ) {
		ROFL_DEBUG_VERBOSE("[mmap:%s] sanity check during read mmap failed\n",of_port_state->name);
		//Increment error statistics
		switch_port_stats_inc_lockless(of_port_state,0,0,0,0,1,0);

		//Return packet to kernel in the RX ring		
		rx->return_packet(hdr);
		return NULL;
	}

	//Check if it is an ongoing frame from TX
	sll = (struct sockaddr_ll*)((uint8_t*)hdr + TPACKET_ALIGN(sizeof(struct tpacket_hdr)));
	if (PACKET_OUTGOING == sll->sll_pkttype) {
		/*ROFL_DEBUG_VERBOSE("cioport(%s)::handle_revent() outgoing "
					"frame rcvd in slot i:%d, ignoring\n", of_port_state->name, rx->rpos);*/

		//Return packet to kernel in the RX ring		
		rx->return_packet(hdr);
		goto next;
	}
	
	//Discard frames generated by the switch OS
	eth_src = cmacaddr(((struct fetherframe::eth_hdr_t*)((uint8_t*)hdr + hdr->tp_mac))->dl_src, OFP_ETH_ALEN); //TODO: convert this into a uint64 comparison
	if (hwaddr == eth_src) {
		/*ROFL_DEBUG_VERBOSE("cioport(%s)::handle_revent() outgoing "
		"frame rcvd in slot i:%d, src-mac == own-mac, ignoring\n", of_port_state->name, rx->rpos);*/

		//Return packet to kernel in the RX ring		
		rx->return_packet(hdr);
		goto next;
	}

	//Retrieve buffer from pool: this is a non-blocking call
	pkt = bufferpool::get_free_buffer(false);

	//Handle no free buffer
	if(unlikely(!pkt)) {
		//Increment error statistics and drop
		switch_port_stats_inc_lockless(of_port_state,0,0,0,0,1,0);
		rx->return_packet(hdr);
		return NULL;
	}
			
	pkt_x86 = (datapacketx86*) pkt->platform_state;

	//Fill packet
	if(hdr->tp_vlan_tci != 0){
		//There is a VLAN
		fill_vlan_pkt(hdr, pkt_x86);	
	}else{
		// no vlan tag present
		pkt_x86->init((uint8_t*)hdr + hdr->tp_mac, hdr->tp_len, of_port_state->attached_sw, get_port_no());
	}

	//Return packet to kernel in the RX ring		
	rx->return_packet(hdr);

	//Increment statistics&return
	switch_port_stats_inc_lockless(of_port_state, 1, 0, hdr->tp_len, 0, 0, 0);	
	
	return pkt;


}

void ioport_mmapv2::fill_tx_slot(struct tpacket2_hdr *hdr, datapacketx86 *packet){

	uint8_t *data = ((uint8_t *) hdr) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
	memcpy(data, packet->get_buffer(), packet->get_buffer_length());

#if 0
	ROFL_DEBUG_VERBOSE("%s(): datapacketx86 %p to tpacket_hdr %p\n"
			"	data = %p\n,"
			"	with content:\n", __FUNCTION__, packet, hdr, data);
	packet->dump();
#endif
	hdr->tp_len = packet->get_buffer_length();
	hdr->tp_snaplen = packet->get_buffer_length();
	hdr->tp_status = TP_STATUS_SEND_REQUEST;

}

unsigned int ioport_mmapv2::write(unsigned int q_id, unsigned int num_of_buckets){

	struct tpacket2_hdr *hdr;
	datapacket_t* pkt;
	datapacketx86* pkt_x86;
	unsigned int cnt = 0;
	int tx_bytes_local = 0;

	circular_queue<datapacket_t, IO_IFACE_RING_SLOTS>* queue = &output_queues[q_id];

	if ( unlikely(tx == NULL) ) {
		return num_of_buckets;
	}

	// read available packets from incoming buffer
	for ( ; 0 < num_of_buckets; --num_of_buckets ) {

		
		//Check
		if(queue->size() == 0){
			ROFL_DEBUG_VERBOSE("[mmap:%s] no packet left in output_queue %u left, %u buckets left\n",
					of_port_state->name,
					q_id,
					num_of_buckets);
			break;
		}

		//Retrieve an empty slot in the TX ring
		hdr = tx->get_free_slot();

		//Skip, TX is full
		if(!hdr)
			break;
		
		//Retrieve the buffer
		pkt = queue->non_blocking_read();
		
		if(!pkt){
			ROFL_ERR("[mmap:%s] A packet has been discarted due to race condition on the output queue. Are you really running the I/O subsystem with a single thread? output_queue %u left, %u buckets left\n",
				of_port_state->name,
				q_id,
				num_of_buckets);
		
			assert(0);
			break;
		}
	
		pkt_x86 = (datapacketx86*) pkt->platform_state;
		
		// todo check the right size
		fill_tx_slot(hdr, pkt_x86);
		
		//Return buffer to the pool
		bufferpool::release_buffer(pkt);

		// todo statistics
		tx_bytes_local += hdr->tp_len;
		cnt++;
	}
	
	//Increment stats and return
	if (cnt) {
		ROFL_DEBUG_VERBOSE("[mmap:%s] schedule %u packet(s) to be send\n", __FUNCTION__, cnt);

		// send packets in TX
		if(tx->send() != ROFL_SUCCESS){
			ROFL_DEBUG("[mmap:%s] packet(%p) put in the MMAP region\n", of_port_state->name ,pkt);
			assert(0);
			switch_port_stats_inc_lockless(of_port_state, 0, 0, 0, 0, 0, cnt);	
			port_queue_stats_inc_lockless(&of_port_state->queues[q_id], 0, 0, cnt);	
		}

		//Increment statistics
		switch_port_stats_inc_lockless(of_port_state, 0, cnt, 0, tx_bytes_local, 0, 0);	
		port_queue_stats_inc_lockless(&of_port_state->queues[q_id], cnt, tx_bytes_local, 0);	
	}

	// return not used buckets
	return num_of_buckets;
}


#endif /* IOPORTV2_MMAP_H_ */
