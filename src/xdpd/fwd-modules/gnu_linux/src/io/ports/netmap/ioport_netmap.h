/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef IOPORT_NETMAP_H
#define IOPORT_NETMAP_H 

#include <unistd.h>
#include <rofl.h>
#include <rofl/datapath/pipeline/common/datapacket.h>
#include <rofl/datapath/pipeline/switch_port.h>
#include "../ioport.h" 
#include "../../datapacketx86.h" 

#ifndef IFNAMSIZ
#include <net/if.h>
#endif

#include <net/netmap.h>
#include <net/netmap_user.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>


namespace xdpd {
namespace gnu_linux {

/**
* @brief Simple netmap of a port, used for testing purposes only.
* 
* It opens two files, on for input and another for output.
*/
class ioport_netmap : public ioport{

public:
	//ioport_netmap
	ioport_netmap(switch_port_t* of_ps, unsigned int num_queues=NETMAP_DEFAULT_NUM_OF_QUEUES);
	virtual ~ioport_netmap();
	 
	//Enque packet for transmission (blocking)
	virtual void enqueue_packet(datapacket_t* pkt, unsigned int q_id);

	//Non-blocking read and write
	virtual datapacket_t* read(void);
	virtual unsigned int write(unsigned int q_id, unsigned int num_of_buckets);

	//Get read&write fds. Return -1 if do not exist
	inline virtual int get_read_fd(void){return fd;}; 
	inline virtual int get_write_fd(void){return -1;};

	inline unsigned int get_queue_size(unsigned int id){
		return (id < num_of_queues)? slotsize[id]: 0;
	};

	//Get buffer status
	//virtual circular_queue_state_t get_input_queue_state(void); 
	//virtual circular_queue_state_t get_output_queue_state(unsigned int q_id=0);

	virtual rofl_result_t 
	disable();

	virtual rofl_result_t
	enable();

protected:
	virtual void flush_ring();
	//Queues
	static const unsigned int NETMAP_DEFAULT_NUM_OF_QUEUES=8; 

	//netmap interface handler
	struct netmap_if *nifp;

	int nr_tx_rings;
	int nr_rx_rings;

	//netmap mmap area
	static struct netmap_d *mem;
	// size
	uint64_t memsize;
	//pollfds
	int fd;

	int slotsize[NETMAP_DEFAULT_NUM_OF_QUEUES];

};

}// namespace xdpd::gnu_linux 
}// namespace xdpd


#endif /* IOPORT_NETMAP_H_ */
