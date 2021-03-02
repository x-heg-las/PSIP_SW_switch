#include "Port.h"
#include <tins/tins.h>
#include <tins/pdu.h>
#include <thread>
#include <vector>
#include <pcap.h>
#include <QMetaType>


using namespace Tins;
std::vector<Port> Interfaces::ports;

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

void startSniffing(Port port, Interfaces *interf) {
	try
	{

		SnifferConfiguration configuration;
		configuration.set_promisc_mode(true);
		configuration.set_immediate_mode(true);
		configuration.set_direction(PCAP_D_IN);
		//configuration.set_filter("(not ether src 02:00:4C:4F:4f:50) and (not ether proto 0x9000)");

		NetworkInterface adapter(IPv4Address(port.getInterfaceAddr().c_str()));
		Sniffer sniffer(adapter.name(), configuration);

		while (true) {

			Packet recieved = sniffer.next_packet();

			Packet packet_to_send;
			if (recieved.pdu()->matches_flag(PDU::ETHERNET_II)) {
				//toto vymaz
				packet_to_send = deencapsulate(recieved, adapter);
				PacketSender sender;
				//zatial rozosiela na vsetky ostatne porty !!!!
				for (auto& a : Interfaces::ports) {
					NetworkInterface iface_to_send_from(IPv4Address(a.getInterfaceAddr().c_str()));

					if (iface_to_send_from.name() != adapter.name()) {
						sender.send(*packet_to_send.pdu(), iface_to_send_from);
						
						// Pozor toto funguje len ak su 2 porty !!! oprav
						port.updateStats(packet_to_send.pdu(), a);


						//signal pre GUI
						interf->update_statistics(port, a);
					}
				}

			}
		}


	}
	catch (const std::exception&)
	{
		return;
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

std::unordered_map<Tins::PDU::PDUType, int> Port::getInStats()
{
	return IN_STAT;
}

std::unordered_map<Tins::PDU::PDUType, int> Port::getOutStats()
{
	return OUT_STAT;
}

void Port::updateStats(PDU* pdu,Port out_port)
{
	PDU* packet = pdu;
	while (packet) {

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