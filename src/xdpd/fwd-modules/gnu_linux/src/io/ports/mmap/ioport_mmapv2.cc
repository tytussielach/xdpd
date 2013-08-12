#include "ioport_mmapv2.h"
#include "../../bufferpool.h"
#include "../../datapacketx86.h"
#include "../../../util/likely.h"

#include <linux/ethtool.h>
#include <rofl/common/utils/c_logger.h>
#include <rofl/common/protocols/fetherframe.h>
#include <rofl/common/protocols/fvlanframe.h>

using namespace rofl;

//Constructor and destructor
ioport_mmapv2::ioport_mmapv2(
		/*int port_no,*/
		switch_port_t* of_ps,
		int block_size,
		int n_blocks,
		int frame_size,
		unsigned int num_queues) :
			ioport(of_ps, num_queues),
			rx(NULL),
			tx(NULL),
			block_size(block_size),
			n_blocks(n_blocks),
			frame_size(frame_size),	
			hwaddr(of_ps->hwaddr, OFP_ETH_ALEN)
{
	int rc;

	//Open pipe for output signaling on enqueue	
	rc = pipe(notify_pipe);
	(void)rc; // todo use the value

	//Set non-blocking read/write in the pipe
	for(unsigned int i=0;i<2;i++){
		int flags = fcntl(notify_pipe[i], F_GETFL, 0);	///get current file status flags
		flags |= O_NONBLOCK;				//turn off blocking flag
		fcntl(notify_pipe[i], F_SETFL, flags);		//set up non-blocking read
	}

}


ioport_mmapv2::~ioport_mmapv2()
{
	if(rx)
		delete rx;
	if(tx)
		delete tx;
	
	close(notify_pipe[READ]);
	close(notify_pipe[WRITE]);
}

/*
*
* Enable and disable port routines
*
*/
rofl_result_t ioport_mmapv2::enable() {
	
	struct ifreq ifr;
	int sd, rc;
        struct ethtool_value eval;

	ROFL_DEBUG("[mmap:%s] Trying to enable port\n",of_port_state->name);
	
	if ((sd = socket(AF_PACKET, SOCK_RAW, 0)) < 0){
		return ROFL_FAILURE;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, of_port_state->name);

	if ((rc = ioctl(sd, SIOCGIFINDEX, &ifr)) < 0){
		return ROFL_FAILURE;
	}

	/*
	* Make sure we are disabling Receive Offload from the NIC.
	* This screws up the MMAP
	*/

	//First retrieve the current gro setup, so that we can gently
	//inform the user we are going to disable (and not set it back)
	eval.cmd = ETHTOOL_GGRO;
	ifr.ifr_data = (caddr_t)&eval;
	eval.data = 0;//Make valgrind happy

	if (ioctl(sd, SIOCETHTOOL, &ifr) < 0) {
		ROFL_WARN("[mmap:%s] Unable to detect if the Generic Receive Offload (GRO) feature on the NIC is enabled or not. Please make sure it is disabled using ethtool or similar...\n", of_port_state->name);
		
	}else{
		//Show nice messages in debug mode
		if(eval.data == 0){
			ROFL_DEBUG("[mmap:%s] GRO already disabled.\n", of_port_state->name);
		}else{
			//Do it
			eval.cmd = ETHTOOL_SGRO;
			eval.data = 0;
			ifr.ifr_data = (caddr_t)&eval;
			
			if (ioctl(sd, SIOCETHTOOL, &ifr) < 0) {
				ROFL_ERR("[mmap:%s] Could not disable Generic Receive Offload feature on the NIC. This can be potentially dangeros...be advised!\n",  of_port_state->name);
			}else{
				ROFL_DEBUG("[mmap:%s] GRO successfully disabled.\n", of_port_state->name);
			}

		}
	}
	
	//Recover flags
	if ((rc = ioctl(sd, SIOCGIFFLAGS, &ifr)) < 0){ 
		close(sd);
		return ROFL_FAILURE;
	}

	// enable promiscous mode
	memset((void*)&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, of_port_state->name, sizeof(ifr.ifr_name));
	
	if ((rc = ioctl(sd, SIOCGIFFLAGS, &ifr)) < 0){
		close(sd);
		return ROFL_FAILURE;
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if ((rc = ioctl(sd, SIOCSIFFLAGS, &ifr)) < 0){
		close(sd);
		return ROFL_FAILURE;
	}
	
	//Check if is up or not
	if (IFF_UP & ifr.ifr_flags){
		
		//Already up.. Silently skip
		close(sd);

		//If tx/rx lines are not created create them
		if(!rx){	
			ROFL_DEBUG_VERBOSE("[mmap:%s] generating a new mmap_rx for RX\n",of_port_state->name);
			rx = new mmap_rx(std::string(of_port_state->name), 2 * block_size, n_blocks, frame_size);
		}
		if(!tx){
			ROFL_DEBUG_VERBOSE("[mmap:%s] generating a new mmap_tx for TX\n",of_port_state->name);
			tx = new mmap_tx(std::string(of_port_state->name), block_size, n_blocks, frame_size);
		}

		of_port_state->up = true;
		return ROFL_SUCCESS;
	}

	ifr.ifr_flags |= IFF_UP;
	if ((rc = ioctl(sd, SIOCSIFFLAGS, &ifr)) < 0){
		close(sd);
		return ROFL_FAILURE;
	}

	//If tx/rx lines are not created create them
	if(!rx){	
		ROFL_DEBUG_VERBOSE("[mmap:%s] generating a new mmap_rx for RX\n",of_port_state->name);
		rx = new mmap_rx(std::string(of_port_state->name), 2 * block_size, n_blocks, frame_size);
	}
	if(!tx){
		ROFL_DEBUG_VERBOSE("[mmap:%s] generating a new mmap_tx for TX\n",of_port_state->name);
		tx = new mmap_tx(std::string(of_port_state->name), block_size, n_blocks, frame_size);
	}

	// todo recheck?
	// todo check link state IFF_RUNNING
	of_port_state->up = true;

	close(sd);
	return ROFL_SUCCESS;
}

rofl_result_t ioport_mmapv2::disable() {
	
	struct ifreq ifr;
	int sd, rc;

	ROFL_DEBUG_VERBOSE("[mmap:%s] Trying to disable port\n",of_port_state->name);

	if ((sd = socket(AF_PACKET, SOCK_RAW, 0)) < 0) {
		return ROFL_FAILURE;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, of_port_state->name);

	if ((rc = ioctl(sd, SIOCGIFINDEX, &ifr)) < 0) {
		return ROFL_FAILURE;
	}

	if ((rc = ioctl(sd, SIOCGIFFLAGS, &ifr)) < 0) {
		close(sd);
		return ROFL_FAILURE;
	}

	//If rx/tx exist, delete them
	if(rx){
		ROFL_DEBUG_VERBOSE("[mmap:%s] destroying mmap_int for RX\n",of_port_state->name);
		delete rx;
		rx = NULL;
	}
	if(tx){
		ROFL_DEBUG_VERBOSE("[mmap:%s] destroying mmap_int for TX\n",of_port_state->name);
		delete tx;
		tx = NULL;
	}

	if ( !(IFF_UP & ifr.ifr_flags) ) {
		close(sd);
		//Already down.. Silently skip
		return ROFL_SUCCESS;
	}

	ifr.ifr_flags &= ~IFF_UP;

	if ((rc = ioctl(sd, SIOCSIFFLAGS, &ifr)) < 0) {
		close(sd);
		return ROFL_FAILURE;
	}

	// todo recheck?
	// todo check link state IFF_RUNNING
	of_port_state->up = false;

	close(sd);

	return ROFL_SUCCESS;
}
