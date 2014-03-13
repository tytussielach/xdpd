#include "classifier_monohdr.h"
#include <stdlib.h>
#include <string.h>
#include <rofl/common/utils/c_logger.h>
#include "../packet_operations.h"
#include "../../../config.h"

void parse_ethernet(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_vlan(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_mpls(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_pppoe(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_ppp(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_arpv4(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_ipv4(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_icmpv4(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_ipv6(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_icmpv6(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_tcp(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_udp(classify_state_t* clas_state, uint8_t *data, size_t datalen);
void parse_gtp(classify_state_t* clas_state, uint8_t *data, size_t datalen);


/// Classify part
classify_state_t* init_classifier(datapacket_t*const  pkt){

	classify_state_t* classifier = malloc(sizeof(classify_state_t));
	memset(classifier,0,sizeof(classify_state_t));

	assert(pkt != NULL);
	classifier->matches = &pkt->matches;

	return classifier;
}
void destroy_classifier(classify_state_t* clas_state){
	free(clas_state);
}

void classify_packet(classify_state_t* clas_state, uint8_t* data, size_t len, uint32_t port_in, uint32_t phy_port_in){
	if(clas_state->is_classified)
		reset_classifier(clas_state);
	parse_ethernet(clas_state, data, len);
	clas_state->is_classified = true;
	
	//Fill in the matches
	//clas_state->matches->pkt_size_bytes = len;
	//clas_state->matches->port_in = port_in;
	//clas_state->matches->phy_port_in = phy_port_in;
}

void reset_classifier(classify_state_t* clas_state){
	//packet_matches_t* matches = clas_state->matches;
	//if(likely(matches != NULL))
		//memset(clas_state->matches,0,sizeof(packet_matches_t));
	
	clas_state->total_headers = 0;
	clas_state->is_classified = false;
}

void parse_ethernet(classify_state_t* clas_state, uint8_t *data, size_t datalen){

	if (unlikely(datalen < sizeof(cpc_eth_hdr_t))){return;}
	
	int total_headers = clas_state->total_headers;

	//Data pointer	
	cpc_eth_hdr_t* ether = (cpc_eth_hdr_t *)data;

	//Set frame
	clas_state->headers[total_headers].frame = ether;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_ETHER;
	//update mapper & counters
	clas_state->mapper[HEADER_TYPE_ETHER] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	if( is_llc_frame(ether) ){
		data += sizeof(cpc_eth_llc_hdr_t);
		datalen -= sizeof(cpc_eth_llc_hdr_t);
	}else{
		data += sizeof(cpc_eth_hdr_t);
		datalen -= sizeof(cpc_eth_hdr_t);
	}

	clas_state->eth_type = get_ether_type(ether);

	//Initialize eth packet matches
	//clas_state->matches->eth_type = get_ether_type(ether); //This MUST be here
	//clas_state->matches->eth_src = get_ether_dl_src(ether);
	//clas_state->matches->eth_dst = get_ether_dl_dst(ether);

	switch (clas_state->eth_type) {
		case VLAN_CTAG_ETHER:
		case VLAN_STAG_ETHER:
		case VLAN_ITAG_ETHER:
			{
				parse_vlan(clas_state, data, datalen);
			}
			break;
		case MPLS_ETHER:
		case MPLS_ETHER_UPSTREAM:
			{
				parse_mpls(clas_state, data, datalen);
			}
			break;
		case PPPOE_ETHER_DISCOVERY:
		case PPPOE_ETHER_SESSION:
			{
				parse_pppoe(clas_state, data, datalen);
			}
			break;
		case ARPV4_ETHER:
			{
				parse_arpv4(clas_state, data, datalen);
			}
			break;
		case IPV4_ETHER:
			{
				parse_ipv4(clas_state, data, datalen);
			}
			break;
		case IPV6_ETHER:
			{
				parse_ipv6(clas_state, data,datalen);
			}
			break;
		default:
			{
				
			}
			break;
	}


}

void parse_vlan(classify_state_t* clas_state, uint8_t *data, size_t datalen){

	if (unlikely(datalen < sizeof(cpc_vlan_hdr_t))) { return; }

	int total_headers = clas_state->total_headers;
	
	//Data pointer	
	cpc_vlan_hdr_t* vlan = (cpc_vlan_hdr_t *)data;

	//Set frame
	clas_state->headers[total_headers].frame = vlan;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_VLAN;
	//upload mapper & counters
	clas_state->mapper[HEADER_TYPE_VLAN] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_vlan_hdr_t);
	datalen -= sizeof(cpc_vlan_hdr_t);

	clas_state->eth_type = get_vlan_type(vlan);

	switch (clas_state->eth_type) {
		case VLAN_CTAG_ETHER:
		case VLAN_STAG_ETHER:
		case VLAN_ITAG_ETHER:
			{
				parse_vlan(clas_state, data, datalen);
			}
			break;
		case MPLS_ETHER:
		case MPLS_ETHER_UPSTREAM:
			{
				parse_mpls(clas_state, data, datalen);
			}
			break;
		case PPPOE_ETHER_DISCOVERY:
		case PPPOE_ETHER_SESSION:
			{
				parse_pppoe(clas_state, data, datalen);
			}
			break;
		case ARPV4_ETHER:
			{
				parse_arpv4(clas_state, data, datalen);
			}
			break;
		case IPV4_ETHER:
			{
				parse_ipv4(clas_state, data, datalen);
			}
			break;
		default:
			{

			}
			break;
	}

	//Initialize vlan packet matches
	//clas_state->matches->has_vlan = true;
	//clas_state->matches->eth_type = get_vlan_type(vlan);
	//clas_state->matches->vlan_vid = get_vlan_id(vlan);
	//clas_state->matches->vlan_pcp = get_vlan_pcp(vlan);
}

void parse_mpls(classify_state_t* clas_state, uint8_t *data, size_t datalen){
	
	if (unlikely(datalen < sizeof(cpc_mpls_hdr_t))) { return; }

	int total_headers = clas_state->total_headers;
	
	cpc_mpls_hdr_t* mpls = (cpc_mpls_hdr_t*)data;
	
	//Set frame
	clas_state->headers[total_headers].frame = mpls;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_MPLS;
	//update mapper & counters
	clas_state->mapper[HEADER_TYPE_MPLS] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_mpls_hdr_t);
	datalen -= sizeof(cpc_mpls_hdr_t);

	if (! get_mpls_bos(mpls)){

		parse_mpls(clas_state,data, datalen);

	}else{
		
		//TODO: We could be trying to guess if payload is IPv4/v6 and continue parsing...
	}

	//Initialize mpls packet matches
	//clas_state->matches->mpls_bos = get_mpls_bos(mpls);
	//clas_state->matches->mpls_label = get_mpls_label(mpls); 
	//clas_state->matches->mpls_tc = get_mpls_tc(mpls); 
}
void parse_pppoe(classify_state_t* clas_state, uint8_t *data, size_t datalen){

	if (unlikely(datalen < sizeof(cpc_pppoe_hdr_t))) { return; }

	int total_headers = clas_state->total_headers;
	
	cpc_pppoe_hdr_t* pppoe = (cpc_pppoe_hdr_t*)data;

	//Set frame
	clas_state->headers[total_headers].frame = pppoe;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_PPPOE;
	//Update mapper & counters
	clas_state->mapper[HEADER_TYPE_PPPOE] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;
	
	
	switch (clas_state->eth_type) {
		case PPPOE_ETHER_DISCOVERY:
			{
				datalen -= sizeof(cpc_pppoe_hdr_t);
#if 0
//TODO?
				uint16_t pppoe_len = get_pppoe_length(pppoe) > datalen ? datalen : get_pppoe_length(pppoe);

				/*
				 * parse any pppoe service tags
				 */
				pppoe->unpack(data, sizeof(cpc_pppoe_hdr_t) + pppoe_len);


				/*
				 * any remaining bytes after the pppoe tags => padding?
				 */
				if (datalen > pppoe->tags.length())
				{
					//TODO?: Continue parsing??	
				}
#endif
			}
			break;
		case PPPOE_ETHER_SESSION:
			{
				//Increment pointers and decrement remaining payload size
				data += sizeof(cpc_pppoe_hdr_t);
				datalen -= sizeof(cpc_pppoe_hdr_t);

				parse_ppp(clas_state,data, datalen);
			}
			break;
		default:
			{
				// log error?
			}
			break;
	}

	//Initialize pppoe packet matches
	//clas_state->matches->pppoe_code = get_pppoe_code(pppoe);
	//clas_state->matches->pppoe_type = get_pppoe_type(pppoe);
	//clas_state->matches->pppoe_sid = get_pppoe_sessid(pppoe);
	//version?
}

void parse_ppp(classify_state_t* clas_state, uint8_t *data, size_t datalen){
	
	if (unlikely(datalen < sizeof(cpc_ppp_hdr_t))) { return; }

	int total_headers = clas_state->total_headers; 
	cpc_ppp_hdr_t* ppp = (cpc_ppp_hdr_t*)data;
	
	//Set frame
	clas_state->headers[total_headers].frame = ppp; 
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_PPP;
	//update mapper & counters
	clas_state->mapper[HEADER_TYPE_PPP] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	switch (get_ppp_prot(ppp)) {
		case PPP_PROT_IPV4:
			{
				//Increment pointers and decrement remaining payload size
				data += sizeof(cpc_ppp_hdr_t);
				datalen -= sizeof(cpc_ppp_hdr_t);

				parse_ipv4(clas_state, data, datalen);
			}
			break;
		default:
			{
				//TODO? ppp->unpack(data, datalen);
			}
			break;
	}

	//Initialize ppp packet matches
	//clas_state->matches->ppp_proto = get_ppp_prot(ppp);
}

void parse_arpv4(classify_state_t* clas_state, uint8_t *data, size_t datalen){
	
	if (unlikely(datalen < sizeof(cpc_arpv4_hdr_t))) { return; }
	
	int total_headers = clas_state->total_headers;
	
	cpc_arpv4_hdr_t* arpv4 = (cpc_arpv4_hdr_t*)data;

	//Set frame
	
	clas_state->headers[total_headers].frame = arpv4;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_ARPV4;
	//Update mapper & counters
	clas_state->mapper[HEADER_TYPE_ARPV4] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_arpv4_hdr_t);
	datalen -= sizeof(cpc_arpv4_hdr_t);

	if (datalen > 0){
		//TODO: something?
	}

	//Initialize arpv4 packet matches
	//clas_state->matches->arp_opcode = get_arpv4_opcode(arpv4);
	//clas_state->matches->arp_sha =  get_arpv4_dl_src(arpv4);
	//clas_state->matches->arp_spa =  get_arpv4_ip_src(arpv4);
	//clas_state->matches->arp_tha =  get_arpv4_dl_dst(arpv4);
	//clas_state->matches->arp_tpa =  get_arpv4_ip_dst(arpv4);
}

void parse_ipv4(classify_state_t* clas_state, uint8_t *data, size_t datalen){
	if (unlikely(datalen < sizeof(cpc_ipv4_hdr_t))) { return; }
	
	int total_headers = clas_state->total_headers;
	
	//Set reference
	cpc_ipv4_hdr_t *ipv4 = (cpc_ipv4_hdr_t*)data; 

	//Set frame
	clas_state->headers[total_headers].frame = ipv4;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_IPV4;
	//Update mapper & counters
	clas_state->mapper[HEADER_TYPE_IPV4] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_ipv4_hdr_t);
	datalen -= sizeof(cpc_ipv4_hdr_t);

	if (has_ipv4_MF_bit_set(ipv4)){
		// TODO: fragment handling

		return;
	}

	// FIXME: IP header with options


	switch (get_ipv4_proto(ipv4)) {
		case IPV4_IP_PROTO:
			{
				parse_ipv4(clas_state, data, datalen);
			}
			break;
		case ICMPV4_IP_PROTO:
			{
				parse_icmpv4(clas_state, data, datalen);
			}
			break;
		case UDP_IP_PROTO:
			{
				parse_udp(clas_state, data, datalen);
			}
			break;
		case TCP_IP_PROTO:
			{
				parse_tcp(clas_state, data, datalen);
			}
			break;
#if 0
		case SCTP_IP_PROTO:
			{
				parse_sctp(clas_state, data, datalen);
			}
			break;
#endif
		default:
			{
			
			}
			break;
	}

	//Initialize ipv4 packet matches
	//clas_state->matches->ip_proto = get_ipv4_proto(ipv4);
	//clas_state->matches->ip_dscp = get_ipv4_dscp(ipv4);
	//clas_state->matches->ip_ecn = get_ipv4_ecn(ipv4);
	//clas_state->matches->ipv4_src = get_ipv4_src(ipv4);
	//clas_state->matches->ipv4_dst = get_ipv4_dst(ipv4);
}

void parse_icmpv4(classify_state_t* clas_state, uint8_t *data, size_t datalen){

	if (unlikely(datalen < sizeof(cpc_icmpv4_hdr_t))) { return; }

	int total_headers = clas_state->total_headers;
	
	//Set reference
	cpc_icmpv4_hdr_t *icmpv4 = (cpc_icmpv4_hdr_t*)data; 

	//Set frame
	clas_state->headers[total_headers].frame = icmpv4; 
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_ICMPV4;
	//Update mapper & counters
	clas_state->mapper[HEADER_TYPE_ICMPV4] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Set reference

	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_icmpv4_hdr_t);
	datalen -= sizeof(cpc_icmpv4_hdr_t);


	if (datalen > 0){
		//TODO: something?	
	}

	//Initialize ipv4 packet matches
	//clas_state->matches->icmpv4_code = get_icmpv4_code(icmpv4);
	//clas_state->matches->icmpv4_type = get_icmpv4_type(icmpv4);
}

void parse_ipv6(classify_state_t* clas_state, uint8_t *data, size_t datalen){
	
	if(unlikely(datalen < sizeof(cpc_ipv6_hdr_t))) { return; }
	
	int total_headers = clas_state->total_headers;
	
	//Set reference
	cpc_ipv6_hdr_t *ipv6 = (cpc_ipv6_hdr_t*)data; 

	//Set frame
	clas_state->headers[total_headers].frame = ipv6;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_IPV6;
	//update mapper & counters
	clas_state->mapper[HEADER_TYPE_IPV6] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_ipv6_hdr_t);
	datalen -= sizeof(cpc_ipv6_hdr_t);

	// FIXME: IP header with options

	switch (get_ipv6_next_header(ipv6)) {
		case IPV4_IP_PROTO:
			{
				parse_ipv4(clas_state, data, datalen);
			}
			break;
		case ICMPV4_IP_PROTO:
			{
				parse_icmpv4(clas_state, data, datalen);
			}
			break;
		case IPV6_IP_PROTO:
			{
				parse_ipv6(clas_state, data, datalen);
			}
			break;
		case ICMPV6_IP_PROTO:
			{
				parse_icmpv6(clas_state, data, datalen);
			}
			break;
		case UDP_IP_PROTO:
			{
				parse_udp(clas_state, data, datalen);
			}
			break;
		case TCP_IP_PROTO:
			{
				parse_tcp(clas_state, data, datalen);
			}
			break;
#if 0
		case SCTP_IP_PROTO:
			{
				parse_sctp(data, datalen);
			}
			break;
#endif
		default:
			{
			
			}
			break;
	}

	//Initialize ipv6 packet matches
	//clas_state->matches->ip_proto = get_ipv6_next_header(ipv6);
	//clas_state->matches->ip_dscp = get_ipv6_dscp(ipv6);
	//clas_state->matches->ip_ecn = get_ipv6_ecn(ipv6);
	//clas_state->matches->ipv6_src = get_ipv6_src(ipv6);
	//clas_state->matches->ipv6_dst = get_ipv6_dst(ipv6);
	//clas_state->matches->ipv6_flabel = get_ipv6_flow_label(ipv6);
}

void parse_icmpv6_opts(classify_state_t* clas_state, uint8_t *data, size_t datalen){
	if (unlikely(datalen < sizeof(cpc_icmpv6_option_hdr_t))) { return; }
	/*So far we only parse optionsICMPV6_OPT_LLADDR_TARGET, ICMPV6_OPT_LLADDR_SOURCE and ICMPV6_OPT_PREFIX_INFO*/
	
	int total_headers = clas_state->total_headers;
	
	cpc_icmpv6_option_hdr_t* icmpv6_opt = (cpc_icmpv6_option_hdr_t*)data;
	
	//Set frame
	clas_state->headers[total_headers].frame = icmpv6_opt;
	clas_state->headers[total_headers].length = datalen;
	
	//we asume here that there is only one option for each type
	switch(icmpv6_opt->type){
		case ICMPV6_OPT_LLADDR_SOURCE:
			clas_state->headers[total_headers].type = HEADER_TYPE_ICMPV6_OPT_LLADDR_SOURCE;
			clas_state->mapper[HEADER_TYPE_ICMPV6_OPT_LLADDR_SOURCE] = clas_state->total_headers;
			
			data += sizeof(struct cpc_icmpv6_lla_option);		//update data pointer
			datalen -= sizeof(struct cpc_icmpv6_lla_option);	//decrement data length
			
			//clas_state->matches->ipv6_nd_sll = get_icmpv6_ll_saddr( (struct cpc_icmpv6_lla_option *)icmpv6_opt ); //init matches

			break;
		case ICMPV6_OPT_LLADDR_TARGET:
			clas_state->headers[total_headers].type = HEADER_TYPE_ICMPV6_OPT_LLADDR_TARGET;
			clas_state->mapper[HEADER_TYPE_ICMPV6_OPT_LLADDR_TARGET] = clas_state->total_headers;
			
			data += sizeof(struct cpc_icmpv6_lla_option);		 //update pointers
			datalen -= sizeof(struct cpc_icmpv6_lla_option);	//decrement data length
			
			//clas_state->matches->ipv6_nd_tll = get_icmpv6_ll_taddr( (struct cpc_icmpv6_lla_option *)icmpv6_opt ); //init matches

			break;
		case ICMPV6_OPT_PREFIX_INFO:
			clas_state->headers[total_headers].type = HEADER_TYPE_ICMPV6_OPT_PREFIX_INFO;
			clas_state->mapper[HEADER_TYPE_ICMPV6_OPT_PREFIX_INFO] = clas_state->total_headers;
			
			data += sizeof(struct cpc_icmpv6_prefix_info);		 //update pointers
			datalen -= sizeof(struct cpc_icmpv6_prefix_info);	//decrement data length

			get_icmpv6_pfx_on_link_flag( (struct cpc_icmpv6_prefix_info *)icmpv6_opt ); //init matches
			get_icmpv6_pfx_aac_flag( (struct cpc_icmpv6_prefix_info *)icmpv6_opt );

			break;
	}
	//update counters
	clas_state->total_headers = total_headers+1;

	if (datalen > 0){
		parse_icmpv6_opts(clas_state, data, datalen);
	}
}

void parse_icmpv6(classify_state_t* clas_state, uint8_t *data, size_t datalen){

	if (unlikely(datalen < sizeof(cpc_icmpv6_hdr_t))) { return; }

	int total_headers = clas_state->total_headers;
	
	cpc_icmpv6_hdr_t* icmpv6 = (cpc_icmpv6_hdr_t*)data;
	
	//Set frame
	clas_state->headers[total_headers].frame = icmpv6;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_ICMPV6;
	//update mapper & counters
	clas_state->mapper[HEADER_TYPE_ICMPV6] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Initialize icmpv6 packet matches
	//clas_state->matches->icmpv6_code = get_icmpv6_code(icmpv6);
	//clas_state->matches->icmpv6_type = get_icmpv6_type(icmpv6);
	//clas_state->matches->ipv6_nd_target = get_icmpv6_neighbor_taddr(icmpv6);
	
	//Increment pointers and decrement remaining payload size (depending on type)
	switch(clas_state->matches->icmpv6_type){
		case ICMPV6_TYPE_ROUTER_SOLICATION:
			data += sizeof(struct cpc_icmpv6_router_solicitation_hdr);
			datalen -= sizeof(struct cpc_icmpv6_router_solicitation_hdr);
			break;
		case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
			data += sizeof(struct cpc_icmpv6_router_advertisement_hdr);
			datalen -= sizeof(struct cpc_icmpv6_router_advertisement_hdr);
			break;
		case ICMPV6_TYPE_NEIGHBOR_SOLICITATION:
			data += sizeof(struct cpc_icmpv6_neighbor_solicitation_hdr);
			datalen -= sizeof(struct cpc_icmpv6_neighbor_solicitation_hdr);
			break;
		case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
			data += sizeof(struct cpc_icmpv6_neighbor_advertisement_hdr);
			datalen -= sizeof(struct cpc_icmpv6_neighbor_advertisement_hdr);
			break;
		case ICMPV6_TYPE_REDIRECT_MESSAGE:
			data += sizeof(struct cpc_icmpv6_redirect_hdr);
			datalen -= sizeof(struct cpc_icmpv6_redirect_hdr);
			break;
		default:
			//Here we have a not supported type
			// for example errors, which we are not parsing.
			data += sizeof(cpc_icmpv6_hdr_t);
			datalen -= sizeof(cpc_icmpv6_hdr_t);
			return;
			break;
	}

	if (datalen > 0){
		parse_icmpv6_opts(clas_state,data,datalen);
	}
}

void parse_tcp(classify_state_t* clas_state, uint8_t *data, size_t datalen){
	if (unlikely(datalen < sizeof(cpc_tcp_hdr_t))) { return; }

	int total_headers = clas_state->total_headers;
	
	cpc_tcp_hdr_t* tcp = (cpc_tcp_hdr_t*)data;
	
	//Set frame
	clas_state->headers[total_headers].frame = tcp;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_TCP;
	//update mapper & counters
	clas_state->mapper[HEADER_TYPE_TCP] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_tcp_hdr_t);
	datalen -= sizeof(cpc_tcp_hdr_t);

	if (datalen > 0){
		//TODO: something 
	}
	
	//Initialize tcp packet matches
	//clas_state->matches->tcp_src = get_tcp_sport(tcp);
	//clas_state->matches->tcp_dst = get_tcp_dport(tcp);
}

void parse_udp(classify_state_t* clas_state, uint8_t *data, size_t datalen){

	if (unlikely(datalen < sizeof(cpc_udp_hdr_t))) { return; }

	int total_headers = clas_state->total_headers;
	
	cpc_udp_hdr_t *udp = (cpc_udp_hdr_t*)data; 
	
	//Set frame
	clas_state->headers[total_headers].frame = udp;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_UDP;
	//update mapper & counters
	clas_state->mapper[HEADER_TYPE_UDP] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Set reference
	
	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_udp_hdr_t);
	datalen -= sizeof(cpc_udp_hdr_t);

	if (datalen > 0){
		switch (get_udp_dport(udp)) {
		case GTPU_UDP_PORT: {
			parse_gtp(clas_state, data, datalen);
		} break;
		default: {
			//TODO: something
		} break;
		}
	}

	//Initialize udp packet matches
	//clas_state->matches->udp_src = get_udp_sport(udp);
	//clas_state->matches->udp_dst = get_udp_dport(udp);
}

void parse_gtp(classify_state_t* clas_state, uint8_t *data, size_t datalen){

	if (unlikely(datalen < sizeof(cpc_gtphu_t))) { return; }

	int total_headers = clas_state->total_headers;
	
	cpc_gtphu_t *gtp = (cpc_gtphu_t*)data; 
		
	//Set frame
	clas_state->headers[total_headers].frame = gtp;
	clas_state->headers[total_headers].length = datalen;
	clas_state->headers[total_headers].type = HEADER_TYPE_GTP;
	//update mapper & counters
	clas_state->mapper[HEADER_TYPE_GTP] = clas_state->total_headers;
	clas_state->total_headers = total_headers+1;

	//Increment pointers and decrement remaining payload size
	data += sizeof(cpc_gtphu_t);
	datalen -= sizeof(cpc_gtphu_t);

	if (datalen > 0){
		//TODO: something
	}

	//Initialize udp packet matches
	//clas_state->matches->gtp_msg_type = get_gtpu_msg_type(gtp);
	//clas_state->matches->gtp_teid = get_gtpu_teid(gtp);
}

void pop_vlan(datapacket_t* pkt, classify_state_t* clas_state){
	//cpc_eth_hdr_t* ether_header;
#error "push and pop do not work"
	int pos = clas_state->mapper[HEADER_TYPE_VLAN];
	// outermost vlan tag, if any, following immediately the initial ethernet header
	if( pos >= clas_state->total_headers || clas_state->headers[pos].type != HEADER_TYPE_VLAN )
		return;

	//Take header out from packet
	pkt_pop(pkt, NULL,/*offset=*/sizeof(cpc_eth_hdr_t), sizeof(cpc_vlan_hdr_t));

	//re-classify packet
	classify_packet_wrapper(pkt, clas_state);

}
void pop_mpls(datapacket_t* pkt, classify_state_t* clas_state, uint16_t ether_type){
	// outermost mpls tag, if any, following immediately the initial ethernet header

	int pos = clas_state->mapper[HEADER_TYPE_MPLS];
	if ( pos >= clas_state->total_headers || clas_state->headers[pos].type != HEADER_TYPE_MPLS )
		return;
	
	cpc_mpls_hdr_t* mpls = (cpc_mpls_hdr_t*) clas_state->headers[pos].frame;
	
	if (!mpls)
		return;
	
	pkt_pop(pkt, NULL,/*offset=*/sizeof(cpc_eth_hdr_t), sizeof(cpc_mpls_hdr_t));
	
	//re-classify packet
	classify_packet_wrapper(pkt, clas_state);

}
void pop_pppoe(datapacket_t* pkt, classify_state_t* clas_state, uint16_t ether_type){
	cpc_eth_hdr_t* ether_header;
	
	int pos = clas_state->mapper[HEADER_TYPE_PPPOE];
	// outermost mpls tag, if any, following immediately the initial ethernet header
	if( pos >= clas_state->total_headers || clas_state->headers[pos].type == HEADER_TYPE_PPPOE)
		return;

	//Recover the ether(0)
	ether_header = get_ether_hdr(clas_state,0);

	switch (get_ether_type(ether_header)) {
		case PPPOE_ETHER_DISCOVERY:
		{
			pkt_pop(pkt, NULL,/*offset=*/sizeof(cpc_eth_hdr_t), sizeof(cpc_pppoe_hdr_t));
			if (get_pppoe_hdr(clas_state, 0)) {
				//re-classify packet
				classify_packet_wrapper(pkt, clas_state);
			}
		}
			break;

		case PPPOE_ETHER_SESSION:
		{
			pkt_pop(pkt, NULL,/*offset=*/sizeof(cpc_eth_hdr_t),sizeof(cpc_pppoe_hdr_t) + sizeof(cpc_ppp_hdr_t));
			if ( get_pppoe_hdr(clas_state, 0) || get_ppp_hdr(clas_state, 0) ){
				//re-classify packet
				classify_packet_wrapper(pkt, clas_state);
			}
		}
		break;
	}
}

void pop_gtp(datapacket_t* pkt, classify_state_t* clas_state, uint16_t ether_type){
	// assumption: UDP -> GTP
	
	int pos_ipv4 = clas_state->mapper[HEADER_TYPE_IPV4];
	int pos_udp = clas_state->mapper[HEADER_TYPE_UDP];
	int pos_gtp = clas_state->mapper[HEADER_TYPE_GTP];

	// an ip header must be present
	if( pos_ipv4 >= clas_state->total_headers || (clas_state->headers[pos_ipv4].type != HEADER_TYPE_IPV4) )
		return;

	// a udp header must be present
	if( pos_udp >= clas_state->total_headers || (clas_state->headers[pos_udp].type != HEADER_TYPE_UDP) )
		return;

	// a gtp header must be present
	if( pos_gtp >= clas_state->total_headers || clas_state->headers[pos_gtp].type != HEADER_TYPE_GTP)
		return;


	// determine effective length of GTP header
	size_t pop_length = sizeof(cpc_ipv4_hdr_t) + sizeof(cpc_udp_hdr_t);

	//Remove bytes from packet
	pkt_pop(pkt, get_ipv4_hdr(clas_state, 0), 0, pop_length);

	//re-classify packet
	classify_packet_wrapper(pkt, clas_state);

}

void* push_vlan(datapacket_t* pkt, classify_state_t* clas_state, uint16_t ether_type){

	if ( NULL == get_ether_hdr(clas_state, 0) ){
		return NULL;
	}

	/*
	 * this invalidates ether(0), as it shifts ether(0) to the left
	 */
	if (pkt_push(pkt, NULL, sizeof(cpc_eth_hdr_t), sizeof(cpc_vlan_hdr_t)) == ROFL_FAILURE){
		// TODO: log error
		return 0;
	}

	//re-classify packet
	classify_packet_wrapper(pkt, clas_state);
	
	return get_vlan_hdr(clas_state,0);
}

void* push_mpls(datapacket_t* pkt, classify_state_t* clas_state, uint16_t ether_type){
	void* ether_header;

	//WARNING check for MAX MPLS TAGS??
	
	if(!clas_state->is_classified || NULL == get_ether_hdr(clas_state, 0)){
		assert(0);	//classify(clas_state);
		return NULL;
	}
	//Recover the ether(0)
	ether_header = get_ether_hdr(clas_state, 0);
	
	/*
	 * this invalidates ether(0), as it shifts ether(0) to the left
	 */
	if (pkt_push(pkt, (void*)(ether_header + sizeof(cpc_eth_hdr_t)),0 , sizeof(cpc_mpls_hdr_t)) == ROFL_FAILURE){
		// TODO: log error
		return 0;
	}

	//re-classify packet
	classify_packet_wrapper(pkt, clas_state);

	return get_mpls_hdr(clas_state,0);
}

void* push_pppoe(datapacket_t* pkt, classify_state_t* clas_state, uint16_t ether_type){
	void* ether_header;

	if(!clas_state->is_classified || NULL == get_ether_hdr(clas_state, 0)){
		assert(0);	//classify(clas_state);
		return NULL;
	}
	
	if (get_pppoe_hdr(clas_state, 0)){
		// TODO: log error => pppoe tag already exists
		return NULL;
	}

	//Recover the ether(0)
	ether_header = get_ether_hdr(clas_state, 0);

	switch (ether_type) {
		case PPPOE_ETHER_SESSION:
		{
			unsigned int bytes_to_insert = sizeof(cpc_pppoe_hdr_t) + sizeof(cpc_ppp_hdr_t);

			/*
			 * this invalidates ether(0), as it shifts ether(0) to the left
			 */
			if (pkt_push(pkt, NULL, sizeof(cpc_eth_hdr_t), bytes_to_insert) == ROFL_FAILURE){
				// TODO: log error
				return NULL;
			}

			//re-classify packet
			classify_packet_wrapper(pkt, clas_state);
		}
			break;

		case PPPOE_ETHER_DISCOVERY:
		{
			unsigned int bytes_to_insert = sizeof(cpc_pppoe_hdr_t);

			/*
			 * this invalidates ether(0), as it shifts ether(0) to the left
			 */
			if (pkt_push(pkt, (void*)(ether_header+sizeof(cpc_eth_hdr_t)),0, bytes_to_insert) == ROFL_FAILURE){
				// TODO: log error
				return NULL;
			}

			//re-classify packet
			classify_packet_wrapper(pkt, clas_state);
		}
			break;
	}

	return NULL;
}

void* push_gtp(datapacket_t* pkt, classify_state_t* clas_state, uint16_t ether_type){
	return NULL;
}

void dump_pkt_classifier(classify_state_t* clas_state){
	//TODO ROFL_DEBUG(FWD_MOD_NAME" [c_pktclassifier] datapacketx86(%p) soframe: %p framelen: %zu\n", this, pkt->get_buffer(), pkt->get_buffer_length());
	ROFL_DEBUG(FWD_MOD_NAME" [c_pktclassifier] Dump packet state(%p) TODO!!\n",clas_state);
}

size_t get_pkt_len(datapacket_t* pkt, classify_state_t* clas_state, void *from, void *to){

	unsigned int total_length = get_buffer_length(pkt);
	void* eth = get_ether_hdr(clas_state, 0);

	if(!from)
		return total_length;

	if(!to)
		return (size_t)(total_length - (from - eth));

	return (size_t)(to - from);
}

