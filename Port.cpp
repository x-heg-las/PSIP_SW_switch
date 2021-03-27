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


using namespace std;
using namespace Tins;
std::vector<Port> Interfaces::ports;
std::vector<Port> ports_global;
std::unordered_map<int, int> reset_flag;
std::unordered_map<int, Port> global_ports;

mutex cam_mutex;
mutex stat_mutex;

bool find_http(std::string payload) {

	/*std::regex request_regex("([\\w]+) ([^ ]+).+\r\nHost: ([\\d\\w\\.-]+)\r\n");
	std::regex response_regex("HTTP/*");*/

	if (payload.find("HTTP/1.1") != std::string::npos) {
		return true;
	}

	//if (std::regex_match(load.begin(), load.end(), response_regex) ||
	//	std::regex_match(load.begin(), load.end(), request_regex))
	//	return true;

	/*for (int i = 0; i < len; i++) {
		if (std::regex_match(payload+i, payload + len-i, response_regex) ||
			std::regex_match(payload+i, payload + len-i, request_regex))
			return true;
	}*/

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
//
//bool handle(PDU& packet, NetworkInterface iface) {
//
//	Packet packet_to_send;
//	if (packet.matches_flag(PDU::ETHERNET_II)) {
//		packet_to_send = deencapsulate(packet, iface);
//		PacketSender sender;
//
//		for (auto& a : Interfaces::ports) {
//			NetworkInterface iface_to_send_from(IPv4Address(a.getInterfaceAddr().c_str()));
//
//			if(iface_to_send_from.name() != iface.name())
//				sender.send(*packet_to_send.pdu(), iface_to_send_from);
//		}
//
//	}
//
//	
//}

void startSniffing(Port& port, Interfaces *interf) {
	try
	{
		int this_port_id = port.getPortId();
		NetworkInterface adapter(IPv4Address(port.getInterfaceAddr().c_str()));
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_pkthdr* head = new pcap_pkthdr;
		const u_char* packet = new  u_char[2300];
	
///////////////		
		TCPStreamFollower follower;

		while (true) {
			//aktualizovanie

			if (reset_flag[this_port_id]) {
				std::lock_guard<std::mutex> lock(stat_mutex);
				port.reset_statistics();
				
				reset_flag[this_port_id] = 0;
			}
		
			//Packet recieved = sniffer.next_packet();
			packet = pcap_next(port.handle, head);
			//Packet packet_to_send;			
			
			if (packet){

				Filter::pdu_info packet_info = Filter::build_info(packet, head->len);
				//pridanie zaznamu do CAM
				interf->insert_mac(packet_info, port);
				//odoslanie na port/y
				Port* handler_to_send_from = interf->find_mac(packet_info);
				
				if (handler_to_send_from != nullptr) {
					//poslem na vybrany interface

					pcap_sendpacket(handler_to_send_from->handle, packet, head->len);
					char* temp = new char[2000];
					memcpy(temp, packet, head->len);
					std::string temp_s(temp, head->len);

					EthernetII* eth = new EthernetII(packet, head->len);

					port.updateStats(eth, global_ports[handler_to_send_from->getPortId()], temp_s);
					//signal pre GUI

					interf->update_statistics(port, global_ports[handler_to_send_from->getPortId()]);
					delete eth;
					
				}
				else {
					for (auto& a : Interfaces::ports) {
						NetworkInterface iface_to_send_from(IPv4Address(a.getInterfaceAddr().c_str()));
						PacketSender sender;

						if (iface_to_send_from.name().compare(adapter.name())) {

							pcap_sendpacket(a.handle, packet, head->len);

							//TODO ::  Pozor toto funguje len ak su 2 porty !!! oprav 
							//berie len ethernetII ramce

							char* temp = new char[2000];
							memcpy(temp, packet, head->len);
							std::string temp_s(temp, head->len);

							EthernetII* eth = new EthernetII(packet, head->len);

							port.updateStats(eth, global_ports[a.getPortId()], temp_s);
							//signal pre GUI

							interf->update_statistics(port, global_ports[a.getPortId()]);
							delete eth;
						}
					}
				}
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
	{
		std::lock_guard<std::mutex> lock(stat_mutex);
		reset_flag[port.getPortId()] = 0;
		global_ports[port.getPortId()] = port;
	}
	
	qRegisterMetaType<Port>("Port");
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



void Port::updateStats(PDU* pdu,Port& out_port, std::string payload)
{
	std::lock_guard<std::mutex> lock(stat_mutex);
	PDU* packet = pdu;
	while (packet) {

		if (packet->pdu_type() == PDU::PDUType::TCP) {

			Tins::TCP *tcp = packet->find_pdu<Tins::TCP>();
			if (tcp->dport() == 80 || tcp->sport() == 80) {
				if (find_http(payload)) {
					http_in++;
					out_port.http_out++;
				}
			}
		}

		if (IN_STAT.find(packet->pdu_type()) != IN_STAT.end()) {
			IN_STAT[packet->pdu_type()] ++;
		}
		else
			IN_STAT[packet->pdu_type()] = 1;
			
		auto OUT_STAT = out_port.getOutStats();
		
		if (OUT_STAT.find(packet->pdu_type()) != OUT_STAT.end()) {
			out_port.OUT_STAT[packet->pdu_type()] ++;
		}
		else {
			out_port.OUT_STAT[packet->pdu_type()] = 1;                                                 
		}

		packet = packet->release_inner_pdu();
	}

	delete packet;
}


void Interfaces::insert_mac(Filter::pdu_info packet_info, Port recieving_port)
{
		
	if (CAM_TABLE.find(packet_info.src_mac) == CAM_TABLE.end()) {
		std::lock_guard<std::mutex> guard(cam_mutex);
		CAM_TABLE[packet_info.src_mac] = std::make_pair(recieving_port, std::chrono::system_clock::now());
	}

}

Port* Interfaces::find_mac(Filter::pdu_info packet_info)
{
	//broadcast
	if(packet_info.dst_mac.is_broadcast()){
		return nullptr;
	}

	//unicast
	if (CAM_TABLE.find(packet_info.dst_mac) != CAM_TABLE.end()) {
		return &CAM_TABLE[packet_info.dst_mac].first;
	}
	
	return nullptr;
}

void Interfaces::request_update_cam()
{
	std::lock_guard<std::mutex> lock(cam_mutex);
	CAM_TABLE.clear();
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


