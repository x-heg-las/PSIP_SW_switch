#include "Port.h"
#include <tins/tins.h>
#include <tins/pdu.h>
#include <thread>
#include <vector>
#include <pcap.h>

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

void startSniffing(Port port) {
	try
	{

		SnifferConfiguration configuration;
		configuration.set_promisc_mode(true);
		configuration.set_immediate_mode(true);
		configuration.set_direction(PCAP_D_IN);
		configuration.set_filter("(not ether src 02:00:4C:4F:4f:50) and (not ether proto 0x9000)");

		NetworkInterface adapter(IPv4Address(port.getInterfaceAddr().c_str()));
		Sniffer sniffer(adapter.name(), configuration);

		while (true) {

			Packet recieved = sniffer.next_packet();

			Packet packet_to_send;
			if (recieved.pdu()->matches_flag(PDU::ETHERNET_II)) {
				packet_to_send = deencapsulate(recieved, adapter);
				PacketSender sender;
				//zatial rozosiela na vsetky ostatne porty !!!!
				for (auto& a : Interfaces::ports) {
					NetworkInterface iface_to_send_from(IPv4Address(a.getInterfaceAddr().c_str()));

					if (iface_to_send_from.name() != adapter.name())
						sender.send(*packet_to_send.pdu(), iface_to_send_from);
				}

			}
		}


	}
	catch (const std::exception&)
	{
		return;
	}
	
}

int Interfaces::initiatePort(Port port)
{

	try
	{
		
		//Start sniffing on adapter
		std::thread sniff(startSniffing, port);
		
		sniff.detach();
	}
	catch (const std::exception&)
	{
		return -1;
	}
    
	Interfaces::ports.push_back(port);
	
	return 0;
}

