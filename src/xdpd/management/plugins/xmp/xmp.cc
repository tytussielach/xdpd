/*
 * xmp.cc
 *
 *  Created on: 11.01.2014
 *      Author: andreas
 */

#include "xmp.h"

using namespace rofl; 
using namespace xdpd::mgmt::protocol;



xmp::xmp() :
		socket(NULL)
{
	socket = rofl::csocket::csocket_factory(rofl::csocket::SOCKET_TYPE_PLAIN, this);

	socket_params = rofl::csocket::get_default_params(rofl::csocket::SOCKET_TYPE_PLAIN);

	socket_params.set_param(rofl::csocket::PARAM_KEY_LOCAL_HOSTNAME).set_string(MGMT_PORT_UDP_ADDR);
	socket_params.set_param(rofl::csocket::PARAM_KEY_LOCAL_PORT).set_string(MGMT_PORT_UDP_PORT);
	socket_params.set_param(rofl::csocket::PARAM_KEY_DOMAIN).set_string("inet");
	socket_params.set_param(rofl::csocket::PARAM_KEY_TYPE).set_string("dgram");
	socket_params.set_param(rofl::csocket::PARAM_KEY_PROTOCOL).set_string("udp");
}


xmp::~xmp()
{

}



void
xmp::init()
{
	rofl::logging::error << "[xdpd][plugin][xmp] initializing ..." << std::endl;
	socket->listen(socket_params);
}



void
xmp::handle_timeout(
		int opaque, void *data)
{
	switch (opaque) {
	default:
		;;
	}
}


void
xmp::handle_read(
		csocket& socket)
{
	cmemory mem(128);

	int nbytes = socket.recv(mem.somem(), mem.memlen());

	if (nbytes == 0) {
		// socket closed
		rofl::logging::error << "[xdpd][plugin][xmp] reading xmp socket failed, errno:"
				<< errno << " (" << strerror(errno) << ")" << std::endl;
		return;
	} else if (nbytes < 0) {
		rofl::logging::error << "[xdpd][plugin][xmp] reading xmp socket failed, errno:"
				<< errno << " (" << strerror(errno) << ")" << std::endl;
		return;
	}

	if ((unsigned int)nbytes < sizeof(struct xmp_header_t)) {
		rofl::logging::error << "[xdpd][plugin][xmp] short packet rcvd, rc:" << nbytes << std::endl;
		return;
	}

	struct xmp_header_t *hdr = (struct xmp_header_t*)mem.somem();
	cxmpmsg msg(mem.somem(), nbytes);

	switch (hdr->type) {
	case XMPT_REQUEST: {
		handle_request(msg);
	} break;
	case XMPT_REPLY:
	case XMPT_NOTIFICATION:
	default: {
		rofl::logging::error << "[xdpd][plugin][xmp] unknown message rcvd" << std::endl;
	};
	}
}


void
xmp::handle_request(
		cxmpmsg& msg)
{
	rofl::logging::error << "[xdpd][plugin][xmp] rcvd message:" << std::endl << msg;

	if (not msg.get_xmpies().has_ie_command()) {
		rofl::logging::error << "[xdpd][plugin][xmp] rcvd xmp request without -COMMAND- IE, dropping message." << std::endl;
		return;
	}

	switch (msg.get_xmpies().get_ie_command().get_command()) {
	case XMPIEMCT_PORT_ATTACH: {
		handle_port_attach(msg);
	} break;
	case XMPIEMCT_PORT_DETACH: {
		handle_port_detach(msg);
	} break;
	case XMPIEMCT_PORT_ENABLE: {
		handle_port_enable(msg);
	} break;
	case XMPIEMCT_PORT_DISABLE: {
		handle_port_disable(msg);
	} break;
	case XMPIEMCT_NONE:
	default: {
		rofl::logging::error << "[xdpd][plugin][xmp] rcvd xmp request with unknown command:"
				<< (int)msg.get_xmpies().get_ie_command().get_command() << ", dropping message." << std::endl;
		return;
	};
	}
}


void
xmp::handle_port_attach(
		cxmpmsg& msg)
{
	std::string portname;
	uint64_t dpid = 0;

	try {
		if (not msg.get_xmpies().has_ie_portname()) {
			rofl::logging::error << "[xdpd][plugin][xmp] rcvd xmp Port-Attach request without -PORTNAME- IE, dropping message." << std::endl;
			return;
		}

		if (not msg.get_xmpies().has_ie_dpid()) {
			rofl::logging::error << "[xdpd][plugin][xmp] rcvd xmp Port-Attach request without -DPID- IE, dropping message." << std::endl;
			return;
		}

		portname = msg.get_xmpies().get_ie_portname().get_portname();
		dpid = msg.get_xmpies().get_ie_dpid().get_dpid();

		unsigned int of_port_num = 0;
		port_manager::attach_port_to_switch(dpid, portname, &of_port_num);
		rofl::logging::error << "[xdpd][plugin][xmp] attached port:" << portname
				<< " to dpid:" << (unsigned long long)dpid << " "
				<< " port-no:" << of_port_num << std::endl;

	} catch(eOfSmDoesNotExist& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] attaching port:" << portname
				<< " to dpid:" << (unsigned long long)dpid << " failed, LSI does not exist" << std::endl;

	} catch(ePmInvalidPort& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] attaching port:" << portname
				<< " to dpid:" << (unsigned long long)dpid << " failed (ePmInvalidPort)" << std::endl;

	} catch(ePmUnknownError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] attaching port:" << portname
				<< " from dpid:" << (unsigned long long)dpid << " failed (ePmUnknownError)" << std::endl;

	} catch(eOfSmGeneralError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] attaching port:" << portname
				<< " to dpid:" << (unsigned long long)dpid << " failed (eOfSmGeneralError)" << std::endl;

	} catch (...) {
		rofl::logging::error << "[xdpd][plugin][xmp] attaching port:" << portname
				<< " to dpid:" << (unsigned long long)dpid << " failed" << std::endl;

	}
}


void
xmp::handle_port_detach(
		cxmpmsg& msg)
{
	std::string portname;
	uint64_t dpid = 0;

	try {
		if (not msg.get_xmpies().has_ie_portname()) {
			rofl::logging::error << "[xdpd][plugin][xmp] rcvd xmp Port-Detach request without -PORTNAME- IE, dropping message." << std::endl;
			return;
		}

		if (not msg.get_xmpies().has_ie_dpid()) {
			rofl::logging::error << "[xdpd][plugin][xmp] rcvd xmp Port-Detach request without -DPID- IE, dropping message." << std::endl;
			return;
		}

		portname = msg.get_xmpies().get_ie_portname().get_portname();
		dpid = msg.get_xmpies().get_ie_dpid().get_dpid();

		port_manager::detach_port_from_switch(dpid, portname);
		rofl::logging::error << "[xdpd][plugin][xmp] detached port:" << portname
				<< " from dpid:" << (unsigned long long)dpid << std::endl;

	} catch(eOfSmDoesNotExist& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] detaching port:" << portname
				<< " from dpid:" << (unsigned long long)dpid << " failed, LSI does not exist (eOfSmDoesNotExist)" << std::endl;

	} catch(ePmInvalidPort& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] detaching port:" << portname
				<< " from dpid:" << (unsigned long long)dpid << " failed, port does not exist (ePmInvalidPort)" << std::endl;

	} catch(ePmPortNotAttachedError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] detaching port:" << portname
				<< " from dpid:" << (unsigned long long)dpid << " failed, port does not exist (ePmPortNotAttachedError)" << std::endl;

	} catch(ePmUnknownError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] detaching port:" << portname
				<< " from dpid:" << (unsigned long long)dpid << " failed, port does not exist (ePmUnknownError)" << std::endl;

	} catch(eOfSmGeneralError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] detaching port:" << portname
				<< " from dpid:" << (unsigned long long)dpid << " failed (eOfSmGeneralError)" << std::endl;

	} catch (...) {
		rofl::logging::error << "[xdpd][plugin][xmp] detaching port:" << portname
				<< " from dpid:" << (unsigned long long)dpid << " failed." << std::endl;

	}
}


void
xmp::handle_port_enable(
		cxmpmsg& msg)
{
	std::string portname;

	try {
		if (not msg.get_xmpies().has_ie_portname()) {
			rofl::logging::error << "[xdpd][plugin][xmp] rcvd xmp Port-Bring-Up request without -PORTNAME- IE, dropping message." << std::endl;
			return;
		}

		portname = msg.get_xmpies().get_ie_portname().get_portname();

		port_manager::bring_up(portname);
		rofl::logging::error << "[xdpd][plugin][xmp] brought port:" << portname <<" up"<< std::endl;

	} catch(ePmInvalidPort& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] bringing port:" << portname << " up failed (ePmInvalidPort)" << std::endl;

	} catch(ePmUnknownError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] bringing port:" << portname << " up failed (ePmUnknownError)" << std::endl;

	} catch(eOfSmGeneralError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] bringing port:" << portname << " up failed (eOfSmGeneralError)" << std::endl;

	} catch (...) {
		rofl::logging::error << "[xdpd][plugin][xmp] bringing port:" << portname << " up failed" << std::endl;

	}
}


void
xmp::handle_port_disable(
		cxmpmsg& msg)
{
	std::string portname;

	try {
		if (not msg.get_xmpies().has_ie_portname()) {
			rofl::logging::error << "[xdpd][plugin][xmp] rcvd xmp Port-Bring-Down request without -PORTNAME- IE, dropping message." << std::endl;
			return;
		}

		portname = msg.get_xmpies().get_ie_portname().get_portname();

		port_manager::bring_down(portname);
		rofl::logging::error << "[xdpd][plugin][xmp] brought port:" << portname <<" down"<< std::endl;

	} catch(ePmInvalidPort& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] bringing port:" << portname << " down failed (ePmInvalidPort)" << std::endl;

	} catch(ePmUnknownError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] bringing port:" << portname << " down failed (ePmUnknownError)" << std::endl;

	} catch(eOfSmGeneralError& e) {
		rofl::logging::error << "[xdpd][plugin][xmp] bringing port:" << portname << " down failed (eOfSmGeneralError)" << std::endl;

	} catch (...) {
		rofl::logging::error << "[xdpd][plugin][xmp] bringing port:" << portname << " down failed" << std::endl;

	}
}



