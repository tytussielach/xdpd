#include "ioport_netmap.h"
#include <iostream>
#include <rofl/common/utils/c_logger.h>
#include "../../bufferpool.h"
#include <fcntl.h>

#include <net/if.h>

using namespace xdpd::gnu_linux;

struct netmap_d *ioport_netmap::mem = NULL;

//Constructor and destructor
ioport_netmap::ioport_netmap(switch_port_t* of_ps, unsigned int num_queues):ioport(of_ps,num_queues){
	int ret;

	if (!strcmp(of_port_state->name, "lo"))
		throw "Don't register for loopback";

	//ROFL_INFO("netmap: %s trying to open with netmap\n", of_port_state->name);
	fd = open("/dev/netmap", O_RDWR);
	if (fd == -1) {
		throw "Check kernel module";
	}

	struct nmreq req;
	bzero(&req,sizeof(nmreq));
	req.nr_version = NETMAP_API;

	strcpy(req.nr_name, of_port_state->name);
	ret = ioctl(fd, NIOCGINFO, &req);
	if (unlikely(ret == -1)) {
		close(fd);
		throw "Unable to get information about netmap interface";
	}

	ROFL_INFO("%s has txr %d txd %d rxr %d rxd %d \n", of_port_state->name,
			req.nr_tx_rings, req.nr_tx_slots,
			req.nr_rx_rings, req.nr_rx_slots);

	num_of_queues=req.nr_tx_rings;
	for(unsigned int i=0;i<num_of_queues;i++) {
		slotsize[i]=req.nr_tx_slots;
	}

	close(fd);
	
	ROFL_INFO("netmap: %s can use netmap\n", of_port_state->name);
}

ioport_netmap::~ioport_netmap(){
}

//Read and write methods over port
void ioport_netmap::enqueue_packet(datapacket_t* pkt, unsigned int q_id){
	unsigned int cur;
	datapacketx86* pkt_x86;

	if (num_of_queues < q_id) {
		//ROFL_DEBUG("We don't have %d queue\n",q_id);
		return; 
	}

	struct netmap_ring *ring;
	ring = NETMAP_TXRING(nifp, q_id);
	cur = ring->cur;
	
	if(!pkt) {
		ROFL_DEBUG("pkt is null\n");
		return;
	}

	pkt_x86 = (datapacketx86*)pkt->platform_state;
	//(void)pkt_x86;

	struct netmap_slot *slot = &ring->slot[cur];
	//char *buf;
	//buf = NETMAP_BUF(ring, slot->buf_idx);
	//pkt_copy(pkt_x86->get_buffer(),buf,pkt_x86->get_buffer_length());
	slot->flags=0;
	//slot->flags |= NS_INDIRECT;
	//slot->ptr = (uint64_t)(pkt_x86->get_buffer());
	slot->buf_idx = NETMAP_BUF_IDX(ring, (char *) pkt_x86->get_buffer());
	slot->flags |= NS_BUF_CHANGED;	
	slot->len = pkt_x86->get_buffer_length();

	ROFL_DEBUG("Sending %p buf_idx:%d\n", pkt_x86->get_buffer(), slot->buf_idx);

	//ROFL_INFO("Sent pkt id:%p of size %d\n", pkt_x86, slot->len);
	//ROFL_INFO("Sent pkt id:%p of size %d\n", pkt_x86, slot->len);
	cur = NETMAP_RING_NEXT(ring, cur);

	//ROFL_DEBUG_VERBOSE("Getting buffer with id:%d. Putting it into the wire\n", pkt_x86->buffer_id);

	//Free buffer
	bufferpool::release_buffer(pkt);
	
	ring->avail--;
	ring->cur = cur;
	//ROFL_INFO("Sent %d out of %d\n", i,num_of_buckets);
	int ret;
	ret = ioctl(fd,NIOCTXSYNC, NULL);
	if(unlikely(ret == -1))
		ROFL_DEBUG_VERBOSE("Netmap sync problem\n");

	return;
}

void ioport_netmap::flush_ring() {
	struct pollfd x[1];
	int ret;
	x[0].fd = fd;
	x[0].events = (POLLIN);

	poll(x,1,1000);

	struct netmap_ring *ring;
	ring = NETMAP_RXRING(nifp, 0);
	while(ring->avail > 0) {
		ring->cur = NETMAP_RING_NEXT(ring, ring->cur);
		ring->avail--;
	}
	ret = ioctl(fd,NIOCTXSYNC|NIOCRXSYNC, NULL);
	if( unlikely(ret == -1) )
		ROFL_DEBUG_VERBOSE("Netmap sync problem\n");
	return;
}

datapacket_t* ioport_netmap::read(){

	datapacket_t* pkt;
	datapacketx86* pkt_x86;
	unsigned int cur;
	char *buf;

	struct netmap_ring *ring;

	ring = NETMAP_RXRING(nifp, 0);
	ROFL_DEBUG("Ring Avail: %"PRIu32"\n", ring->avail);

	if (ring->avail == 0) {
		//assert(0);
		return NULL;
	}

	//Allocate free buffer
	pkt = bufferpool::get_free_buffer(false);
	if(!pkt) {
		ROFL_DEBUG("Buffer Problem\n");
		assert(0);
	}
	pkt_x86 = ((datapacketx86*)pkt->platform_state);

	cur = ring->cur;
	struct netmap_slot *slot = &ring->slot[cur];

	buf = NETMAP_BUF(ring, slot->buf_idx);

	pkt_x86->init((uint8_t*)buf, slot->len, of_port_state->attached_sw, of_port_state->of_port_num,0,true,false);

	//ROFL_DEBUG_VERBOSE("Got pkt %d of size %d ==> %p\n", slot->buf_idx, slot->len, pkt_x86->get_buffer());

	ring->cur = NETMAP_RING_NEXT(ring, cur);
	ring->avail-- ;

	ROFL_DEBUG_VERBOSE("Filled buffer with id:%d. Sending to process.\n", slot->buf_idx);

	if(ioctl(fd,NIOCRXSYNC, NULL) == -1)
		ROFL_DEBUG_VERBOSE("Netmap sync problem\n");
	return pkt;
}

unsigned int ioport_netmap::write(unsigned int q_id, unsigned int num_of_buckets){
	return 0;
}

rofl_result_t ioport_netmap::disable(){
	struct ifreq ifr;
	int sd;

	munmap(mem,memsize);
	close(fd);
	
	if (( sd = socket(AF_PACKET, SOCK_RAW, 0)) <0 ) {
		return ROFL_FAILURE;
	}

	bzero(&ifr,sizeof(struct ifreq));
	strcpy(ifr.ifr_name, of_port_state->name);

	if (ioctl(sd, SIOCGIFFLAGS, &ifr) < 0) {
		close(sd);
		return ROFL_FAILURE;
	}

	if(IFF_UP & ifr.ifr_flags) {
		ifr.ifr_flags &= ~IFF_UP;
	}
	if(IFF_PROMISC & ifr.ifr_flags) {
		ifr.ifr_flags &= ~IFF_PROMISC;
	}

	if (ioctl(sd, SIOCSIFFLAGS, &ifr) <0) {
		close(sd);
		return ROFL_FAILURE;
	}

	of_port_state->up = true;
	close(sd);
	
	int ret;
	ret = ioctl(fd, NIOCUNREGIF, NULL);
	if (unlikely(ret == -1)) {
		close(fd);
	}


	//Close NETMAP
	close(fd);

	return ROFL_SUCCESS;
}

rofl_result_t ioport_netmap::enable(){
	struct ifreq ifr;
	int sd;
	if (( sd = socket(AF_PACKET, SOCK_RAW, 0)) <0 ) {
		return ROFL_FAILURE;
	}

	bzero(&ifr,sizeof(struct ifreq));
	strcpy(ifr.ifr_name, of_port_state->name);

	if (ioctl(sd, SIOCGIFFLAGS, &ifr) < 0) {
		close(sd);
		return ROFL_FAILURE;
	}
	if(!(IFF_UP & ifr.ifr_flags)) {
		ifr.ifr_flags |= IFF_UP;
		ifr.ifr_flags |= IFF_PROMISC;
	}
	
	pthread_rwlock_wrlock(&rwlock);
	
	if (ioctl(sd, SIOCSIFFLAGS, &ifr) <0) {
		close(sd);
		return ROFL_FAILURE;
	}

	pthread_rwlock_unlock(&rwlock);	
	close(sd);
	
	fd = open("/dev/netmap", O_RDWR);
	if (unlikely(fd == -1)) {
		ROFL_INFO("Check kernel module");
	}

	struct nmreq req;
	bzero(&req,sizeof(nmreq));
	req.nr_version = NETMAP_API;
	req.nr_ringid = NETMAP_HW_RING;
	req.nr_ringid |= NETMAP_NO_TX_POLL;

	strcpy(req.nr_name, of_port_state->name);
	int ret;
	ret = ioctl(fd, NIOCREGIF, &req);
	if (unlikely(ret == -1)) {
		close(fd);
		ROFL_INFO("Unable to register\n");
	}

	if( mem == NULL) {
		mem = (struct netmap_d *) mmap(0, req.nr_memsize, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		ROFL_INFO("memsize is %d MB\n", req.nr_memsize>>20);
		bzero(mem,sizeof(req.nr_memsize));
		if ( mem == MAP_FAILED ) {
			ROFL_INFO("MMAP Failed\n");
		}
	}
	nifp = NETMAP_IF(mem, req.nr_offset);
	
	of_port_state->up = true;
	
	flush_ring();
	return ROFL_SUCCESS;
}
