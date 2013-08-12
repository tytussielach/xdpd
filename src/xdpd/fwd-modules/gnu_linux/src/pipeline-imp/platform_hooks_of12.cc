/*
 * platform_hooks_of12.c
 *
 *  Created on: Feb 7, 2013
 *      Author: tobi
 */

#include <assert.h>
#include <rofl/datapath/pipeline/openflow/openflow12/of12_async_events_hooks.h>
#include <rofl/datapath/pipeline/openflow/openflow12/of12_switch.h>
#include <rofl/datapath/pipeline/openflow/openflow12/pipeline/of12_flow_table.h>
#include <rofl/datapath/afa/openflow/openflow12/of12_cmm.h>
#include <rofl/common/utils/c_logger.h>

#include "../config.h"
#include "../io/bufferpool.h"
#include "../io/datapacketx86.h"
#include "../io/datapacket_storage.h"
#include "../processing/ls_internal_state.h"
#include "../io/pktin_dispatcher.h"


#define DATAPACKET_STORE_EXPIRATION_TIME 180
#define DATAPACKET_STORE_MAX_BUFFERS bufferpool::RESERVED_SLOTS/2 

/*
* Hooks for configuration of the switch
*/
rofl_result_t platform_post_init_of12_switch(of12_switch_t* sw){
	//Set OF12 flow table 
	unsigned int i;
	of12_flow_table_t* table;

	table = sw->pipeline->tables; 
	
	for(i=0;i<sw->pipeline->num_of_tables;++i){
		//Set appropiate flags
		table->default_action = OF12_TABLE_MISS_CONTROLLER;
	}
	
	//Create GNU/Linux FWD_Module additional state (platform state)
	struct logical_switch_internals* ls_int = (struct logical_switch_internals*)calloc(1, sizeof(struct logical_switch_internals));

	//Create input queues
	for(i=0;i<PROCESSING_THREADS_PER_LSI;i++){
		ls_int->input_queues[i] = new circular_queue<datapacket_t, PROCESSING_INPUT_QUEUE_SLOTS>();
	}

	ls_int->pkt_in_queue = new circular_queue<datapacket_t, PROCESSING_PKT_IN_QUEUE_SLOTS>();
	ls_int->storage = new datapacket_storage( IO_PKT_IN_STORAGE_MAX_BUF, IO_PKT_IN_STORAGE_EXPIRATION_S); // todo make this value configurable

	sw->platform_state = (of_switch_platform_state_t*)ls_int;

	//Set number of buffers
	sw->pipeline->num_of_buffers = IO_PKT_IN_STORAGE_MAX_BUF;

	return ROFL_SUCCESS;
}

rofl_result_t platform_pre_destroy_of12_switch(of12_switch_t* sw){
	
	unsigned int i;

	struct logical_switch_internals* ls_int =  (struct logical_switch_internals*)sw->platform_state;
	
	//delete ring buffers and storage (delete switch platform state)
	for(i=0;i<PROCESSING_THREADS_PER_LSI;i++){
		delete ls_int->input_queues[i]; 
	}
	delete ls_int->pkt_in_queue;
	delete ls_int->storage;
	free(sw->platform_state);
	
	return ROFL_SUCCESS;
}


//Async notifications

/*
* Packet in
*/

void platform_of12_packet_in(const of12_switch_t* sw, uint8_t table_id, datapacket_t* pkt, of_packet_in_reason_t reason)
{
	datapacketx86* pkt_x86;
	struct logical_switch_internals* ls_state = (struct logical_switch_internals*)sw->platform_state;

	assert(OF_VERSION_12 == sw->of_ver);

	ROFL_DEBUG("Enqueuing PKT_IN event for packet(%p) in switch: %s\n",pkt,sw->name);

	//Recover platform state
	pkt_x86 = (datapacketx86*)pkt->platform_state;
	
	//Recover platform state and fill it so that state can be recovered afterwards
	pkt_x86 = (datapacketx86*)pkt->platform_state;
	pkt_x86->pktin_table_id = table_id;
	pkt_x86->pktin_reason = reason;
		
	//Enqueue
	if( ls_state->pkt_in_queue->non_blocking_write(pkt) == ROFL_SUCCESS ){
		//Notify
		notify_packet_in();
	}else{
		ROFL_DEBUG("PKT_IN for packet(%p) could not be sent for sw:%s (PKT_IN queue full). Dropping..\n",pkt,sw->name);
		//Return to the bufferpool
		bufferpool::release_buffer(pkt);
	}
}

//Flow removed
void platform_of12_notify_flow_removed(const of12_switch_t* sw, 	
						of12_flow_remove_reason_t reason, 
						of12_flow_entry_t* removed_flow_entry){

	cmm_process_of12_flow_removed(sw, (uint8_t)reason, removed_flow_entry);

}


void plaftorm_of12_add_entry_hook(of12_flow_entry_t* new_entry){

}

void platform_of12_modify_entry_hook(of12_flow_entry_t* old_entry, of12_flow_entry_t* mod, int reset_count){

}

void platform_of12_remove_entry_hook(of12_flow_entry_t* entry){

}

void
platform_of12_update_stats_hook(of12_flow_entry_t* entry)
{

}
