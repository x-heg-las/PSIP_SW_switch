#include "Port.h"
#include <tins/tins.h>
#include "Filter.h"
#include <tins/pdu.h>
#include <thread>
#include <iostream>
#include <vector>
#include <pcap.h>
#include <QMetaType>
#include <mutex>
#include <utility>
#include <unordered_map>
#include <regex>

#define ONLY_IN 2
#define ONLY_OUT 4
#define DONT_RESEND 8
#define RESEND 16
#define WAITING 8

using namespace std;
using namespace Tins;
std::vector<Port> Interfaces::ports;
std::vector<Port> ports_global;
// casovac je inicializovany na 30 sekund
int cam_timer = 30;
std::unordered_map<int, int> reset_flag;
std::unordered_map<int, Port> global_ports;
std::unordered_map<int, int> active_interfaces;
CamTable global_cam;

mutex cam_mutex;
mutex stat_mutex;
mutex intf_mutex;


bool authorize(pdu_info packet, Port port, int direction);

void gui_updater(Interfaces* iface) {

	while (1) {
		std::this_thread::sleep_for(1s);
		iface->update_table(global_cam);

	}
}

void cam_clean(Interfaces* iface) {
	std::lock_guard<std::mutex> lock(cam_mutex);
	CamTable::iterator record;
	for (record = global_cam.begin(); record != global_cam.end() && global_cam.size() > 0;) {
		if (chrono::duration<double>(chrono::system_clock::now() - record->second.second ).count() > cam_timer) {
			record = global_cam.erase(record);
			iface->update_table(global_cam);
		}
		else
			record++;
	}
		

}

bool find_http(std::string payload) {

	if (payload.find("HTTP/1.1") != std::string::npos) {
		return true;
	}

	return false;
}


Packet deencapsulate(Packet packet, NetworkInterface iface) {

	PDU* link_layer = packet.pdu()->release_inner_pdu();

	if (packet.pdu()->matches_flag(PDU::ETHERNET_II)) {
		EthernetII* e = packet.pdu()->find_pdu<EthernetII>();
		EthernetII newFrame(e->dst_addr(), iface.hw_address());
		newFrame.payload_type(e->payload_type());
		newFrame.inner_pdu(link_layer);

		return newFrame;

	}

	return EthernetII();
}


void startSniffing(Port& port, Interfaces *interf) {
	try
	{
		int this_port_id = port.getPortId();
		NetworkInterface adapter(IPv4Address(port.getInterfaceAddr().c_str()));
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_pkthdr* head = new pcap_pkthdr;
		const u_char* packet = new  u_char[2300];
		auto timer = std::chrono::steady_clock::now();
		auto keepalive = std::chrono::steady_clock::now();;
///////////////		
		TCPStreamFollower follower;

		while (true) {
	
			//aktualizovanie

			if (reset_flag[this_port_id]) {
				std::lock_guard<std::mutex> lock(stat_mutex);
				global_ports[port.getPortId()].reset_statistics();
				reset_flag[this_port_id] = 0;
			}
			
		
			//Packet recieved = sniffer.next_packet();
			packet = pcap_next(port.handle, head);
			//Packet packet_to_send;	
			
			
			
			//kontrola ci rozhranie prijalo ramec poslednych 6 sekund
			if ((std::chrono::duration<double>(std::chrono::steady_clock::now() - timer).count()) > WAITING) {
				std::lock_guard<std::mutex> lock(cam_mutex);
				interf->reset_cam(global_ports[port.getPortId()]);
				std::lock_guard<mutex> lockint(intf_mutex);
				active_interfaces[port.getPortId()] = 0;
			}
			else {
				std::lock_guard<mutex> lock(intf_mutex);
				active_interfaces[port.getPortId()] = 1;
			}

			cam_clean(interf);
			if (packet){

				
				
				timer = std::chrono::steady_clock::now();
				pdu_info packet_info = Filter::build_info(packet, head->len);

				if (!authorize(packet_info, port, IN)) {
					packet = NULL;
					continue;
				}


				//pridanie zaznamu do CAM
				interf->insert_mac(packet_info, port);
				//odoslanie na port/y
				
				Port* handler_to_send_from = interf->find_mac(packet_info);
				int resend = 0;
				if (handler_to_send_from != nullptr) {
					
					char* temp = new char[2000];
					memcpy(temp, packet, head->len);
					std::string temp_s(temp, head->len);
					EthernetII* eth = new EthernetII(packet, head->len);
					
					
					//aby neposielal na rovnaky port
					bool filtered = true;
					if (handler_to_send_from->getPortId() == port.getPortId()) 
						resend = DONT_RESEND;
					else {
						resend = 0;


						bool filtered = authorize(packet_info, global_ports[handler_to_send_from->getPortId()], OUT);
						
						// ak je premenna filtered true tak odosle packet
						if (filtered) {
							//poslem na vybrany interface
							pcap_sendpacket(handler_to_send_from->handle, packet, head->len);
						}
						else if (resend == 0) {
							resend = ONLY_IN;
						}

							
						
					}
					
					
					

					if (eth->payload_type() <= 1500) {
						Dot3* dot = new Dot3(packet, head->len);
						global_ports[port.getPortId()].updateStats(dot, global_ports[handler_to_send_from->getPortId()], temp_s, resend);
						interf->update_statistics(global_ports[port.getPortId()], global_ports[handler_to_send_from->getPortId()]);
						delete dot;
					}
					else {
						global_ports[port.getPortId()].updateStats(eth, global_ports[handler_to_send_from->getPortId()], temp_s, resend);
						//signal pre GUI
						interf->update_statistics(global_ports[port.getPortId()], global_ports[handler_to_send_from->getPortId()]);
					}
					delete eth;
					delete[]temp;
					
				}
				else {
					for (auto& a : Interfaces::ports) {
						NetworkInterface iface_to_send_from(IPv4Address(a.getInterfaceAddr().c_str()));
						PacketSender sender;
						int direction = 0;
						if (iface_to_send_from.name().compare(adapter.name())) {
							
							char* temp = new char[2000];
							memcpy(temp, packet, head->len);
							std::string temp_s(temp, head->len);

							EthernetII* eth = new EthernetII(packet, head->len);

							bool filtered = true;
							

							if (eth->payload_type() <= 1500) {
								Dot3* dot = new Dot3(packet, head->len);
								if (dot->dst_addr() == HWAddress< 6 >("01:00:0c:cc:cc:cc")) {
									
									delete []temp;
									delete dot;
									delete eth;
									break;
								}else
									delete dot;
								
							}
							else {
								filtered = authorize(packet_info, global_ports[a.getPortId()], OUT);

								if (filtered) {
									pcap_sendpacket(a.handle, packet, head->len);
									direction = 0;
								}
								else {
									direction = ONLY_IN;
								}
								

							}
							
							if (eth->payload_type() <= 1500) {
								Dot3* dot = new Dot3(packet, head->len);
								global_ports[port.getPortId()].updateStats(dot, global_ports[a.getPortId()], temp_s, direction);
								interf->update_statistics(global_ports[port.getPortId()], global_ports[a.getPortId()]);
								delete dot;
							}
							else {
								global_ports[port.getPortId()].updateStats(eth, global_ports[a.getPortId()], temp_s, direction);
								//signal pre GUI
								interf->update_statistics(global_ports[port.getPortId()], global_ports[a.getPortId()]);
							}
							delete eth;
							delete[]temp;
						}
					}
				}
				//aktualizovanie , signal pre GUI pre CAM
				interf->update_table(global_cam);
				packet = NULL;
			}
		}


	}
	catch (const std::exception&)
	{

		std::cerr << "Chyba pri portoch";
		return ;
	}
	
}

int Interfaces::initiatePort(Port port, Interfaces *interf)
{

	if (!global_ports.size()) {
		std::thread updater(gui_updater, interf);
		updater.detach();
	}


	{
		std::lock_guard<std::mutex> lock(stat_mutex);
		reset_flag[port.getPortId()] = 0;
		global_ports[port.getPortId()] = port;
	}
	{
		std::lock_guard<std::mutex> lock(intf_mutex);
		active_interfaces[port.getPortId()] = 1;
	}
	
	qRegisterMetaType<CamTable>("CamTable");
	qRegisterMetaType<Port>("Port");
	qRegisterMetaType<std::string>("std::string");
	qRegisterMetaType<pdu_info>("Filter::pdu_info");

	try
	{
		
		//Start sniffing on adapter
		std::thread sniff(startSniffing, port, interf);
		
		sniff.detach();
	}
	catch (const std::exception&)
	{
		return -1;
	}
	

	Interfaces::ports.push_back(port);
	
	return 0;
}

std::unordered_map<Tins::PDU::PDUType, int>& Port::getInStats()
{
	return IN_STAT;
}

std::unordered_map<Tins::PDU::PDUType, int>& Port::getOutStats()
{
	return OUT_STAT;
}



void Port::updateStats(PDU* pdu, Port& out_port, std::string payload, int resend)
{
	std::lock_guard<std::mutex> lock(stat_mutex);
	PDU* packet = pdu;
	while (packet) {
		if (resend != ONLY_OUT) {
			if (packet->pdu_type() == PDU::PDUType::TCP) {

				Tins::TCP* tcp = packet->find_pdu<Tins::TCP>();
				if (tcp->dport() == 80 || tcp->sport() == 80) {
					
					port80_in++;
					if (resend != DONT_RESEND)
						port80_out++;


					if (find_http(payload)) {
						http_in++;
						if (resend != DONT_RESEND )
							global_ports[out_port.getPortId()].http_out++;
					}
				}
			}

			if (IN_STAT.find(packet->pdu_type()) != IN_STAT.end()) {
				IN_STAT[packet->pdu_type()] ++;
			}
			else
				IN_STAT[packet->pdu_type()] = 1;
		}

		if(resend != ONLY_IN )
		{
			std::lock_guard<std::mutex> lock(intf_mutex);
			if (active_interfaces[out_port.getPortId()] && resend != DONT_RESEND) {
				auto OUT_STAT = global_ports[out_port.getPortId()].getOutStats();

				if (OUT_STAT.find(packet->pdu_type()) != OUT_STAT.end()) {
					global_ports[out_port.getPortId()].OUT_STAT[packet->pdu_type()] ++;
				}
				else {
					global_ports[out_port.getPortId()].OUT_STAT[packet->pdu_type()] = 1;
				}
			}
		}
		packet = packet->release_inner_pdu();
	}

	delete packet;
}


void Interfaces::insert_mac(pdu_info packet_info, Port recieving_port)
{
		
	if (global_cam.find(packet_info.src_mac) == global_cam.end()) {
		std::lock_guard<std::mutex> guard(cam_mutex);
		global_cam[packet_info.src_mac] = std::make_pair(recieving_port, std::chrono::system_clock::now());
	}
	else {
		std::lock_guard<std::mutex> guard(cam_mutex);
		if (global_cam[packet_info.src_mac].first.getPortId() != recieving_port.getPortId()) {
			global_cam[packet_info.src_mac].first = recieving_port;
		}
		global_cam[packet_info.src_mac].second = std::chrono::system_clock::now();
	}

}

Port* Interfaces::find_mac(pdu_info packet_info)
{
	//broadcast
	if(packet_info.dst_mac.is_broadcast()){
		return nullptr;
	}

	//unicast
	if (global_cam.find(packet_info.dst_mac) != global_cam.end()) {
		return &global_cam[packet_info.dst_mac].first;
	}
	
	return nullptr;
}

void Interfaces::request_update_cam()
{
	std::lock_guard<std::mutex> lock(cam_mutex);
	global_cam.clear();
}

void Interfaces::reset_statistics()
{
	std::lock_guard<std::mutex> lock(stat_mutex);
	for (auto& port : global_ports) {
		port.second.reset_statistics();
		
	}
	for (auto &id : reset_flag) {
		id.second = 1;
	}
}

void Interfaces::reset_cam(Port port)
{
	int portId = port.getPortId();
	CamTable::iterator record;
	for (record = global_cam.begin(); record != global_cam.end() && global_cam.size() > 0;) {
		if (record->second.first.getPortId() == portId) {
			record = global_cam.erase(record);
						
		}
		else
			record++;
	}
	update_table(global_cam);
}

void Interfaces::reset_cam_all()
{
	std::lock_guard<std::mutex> lock(cam_mutex);
	global_cam.clear();
	update_table(global_cam);
}

int Interfaces::get_timeout() {
	return cam_timer;
}

void Interfaces::set_timeout(int time) {
	cam_timer = time;
}

void Interfaces::assignFilter(pdu_info filter, std::string interface) {
	int id = -1;
	for (auto port : global_ports) {
		if (! port.second.getInterfaceName().compare(interface)) {
			id = port.second.getPortId();
			break;
		}
	}

	if(id > 0)
		global_ports[id].addFilter(filter);


}

void Interfaces::deleteFilter(int id) {
	//std::lock_guard<std::mutex> lock(stat_mutex);

	for (auto port : global_ports) {
		int filterIndex = 0;

		for (pdu_info filter : port.second.getFilters())
		{
			if (filter.id == id) {
				global_ports[port.second.getPortId()].removeFilter(filterIndex);
				return;
			}
			filterIndex++;

		}
	}
}


void Port::addFilter(pdu_info filter) {
	filters.push_back(filter);
}




bool authorize(pdu_info packet, Port port, int direction) {

	std::vector<pdu_info> filters;
	{
	//	std::lock_guard<std::mutex> lock(stat_mutex);
		filters = global_ports[port.getPortId()].getFilters();
	}

	
	for (pdu_info filter : filters) {
		bool permision = filter.permit;
		short check = 0;
		Tins::IP::address_type anyIP = Tins::IP::address_type("0.0.0.0");
		Tins::HWAddress<6> anyMAC = Tins::HWAddress<6>(0);

		if (filter.direction == direction) {

			if (filter.src_mac == anyMAC || filter.src_mac_set) {
				if (filter.src_mac == anyMAC || filter.src_mac == packet.src_mac) {
					check |= 1;
				}
				else {
					if (filter.permit == false)
						continue;
					return false;
				}
			}
			if (filter.dst_mac == anyMAC || filter.dst_mac_set) {
				if (filter.dst_mac == anyMAC || filter.dst_mac == packet.dst_mac) {
					check |= 1;
				}
				else {
					if (filter.permit == false)
						continue;
					return false;
				}
			}
			if (filter.src_ip_set) {
				if (filter.src_ip == anyIP || filter.src_ip == packet.src_ip)
					check |= 1;
				else {
					if (filter.permit == false)
						continue;
					return false;
				}
					
			}
			if (filter.dst_ip_set)
				if (filter.dst_ip == anyIP || filter.dst_ip == packet.dst_ip)
					check |= 1;
				else {
					if (filter.permit == false)
						continue;
					return false;
				}
					
			
			if (filter.protocol_L3 != NO && filter.protocol_L3 != icmp) {
				if (filter.protocol_L3 == ANY || filter.protocol_L3 == packet.protocol_L3)
					check |= 1;
				else
				{
					if (filter.permit == false)
						continue;
					return false;
				}
					
			}
			else if (filter.protocol_L3 == icmp ) {
				if (filter.icmpType != NO && packet.protocol_L3 == icmp) {
					if (filter.icmpType == ANY || filter.icmpType == packet.icmpType)
						check |= 1;
					else
					{
						if (filter.permit == false)
							continue;
						return false;
					}
				}
				else
				{
					if (filter.permit == false)
						continue;
					return false;
				}
			}
			


			if (filter.src_port != NO)
				if (filter.src_port == ANY || filter.src_port == packet.src_port)
					check |= 1;
				else
				{
					if (filter.permit == false)
						continue;
					return false;
				}

			if (filter.dst_port != NO)
				if (filter.dst_port == ANY || filter.dst_port == packet.dst_port)
					check |= 1;
				else
				{
					if (filter.permit == false)
						continue;
					return false;
				}
		}

		if (check == 1)
			return permision;

			
	
	}


	return true;
}