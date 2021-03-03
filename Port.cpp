#include "Port.h"
#include <tins/tins.h>
#include <tins/pdu.h>
#include <thread>
#include <iostream>
#include <vector>
#include <pcap.h>
#include <QMetaType>
#include <regex>


using namespace Tins;
std::vector<Port> Interfaces::ports;


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
		NetworkInterface adapter(IPv4Address(port.getInterfaceAddr().c_str()));
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_pkthdr* head = new pcap_pkthdr;
		const u_char* packet = new  u_char[2300];
	
///////////////		
		TCPStreamFollower follower;

		while (true) {

			//Packet recieved = sniffer.next_packet();
			packet = pcap_next(port.handle, head);
			//Packet packet_to_send;
			
			
			if (packet){
				
				//zatial rozosiela na vsetky ostatne porty !!!!
				for (auto& a : Interfaces::ports) {
					NetworkInterface iface_to_send_from(IPv4Address(a.getInterfaceAddr().c_str()));
					PacketSender sender;
					
					if (iface_to_send_from.name().compare(adapter.name())) {
				
						pcap_sendpacket(a.handle ,packet, head->len);
	
						//TODO ::  Pozor toto funguje len ak su 2 porty !!! oprav 
						//berie len ethernetII ramce
						
						char* temp = new char[2000];
						memcpy(temp, packet, head->len);
						std::string temp_s(temp, head->len);

						EthernetII *eth = new EthernetII(packet, head->len);
						
						port.updateStats(eth, a, temp_s);
						//signal pre GUI
						
						interf->update_statistics(port, a);
						delete eth;
						
						
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

