#include "Port.h"
#include <tins/tins.h>
#include <tins/pdu.h>
#include <thread>
#include <iostream>
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
		NetworkInterface adapter(IPv4Address(port.getInterfaceAddr().c_str()));
		char errbuf[PCAP_ERRBUF_SIZE];
		/*SnifferConfiguration configuration;
		configuration.set_promisc_mode(true);
		configuration.set_immediate_mode(true);
		configuration.set_direction(PCAP_D_IN);
		
		configuration.set_filter(" (not ip src 9.0.0.10) and (not ether proto 0x9000)");

		pcap_if_t* indt;
		
		pcap_findalldevs(&indt, errbuf);
		

		
		std::string name = adapter.name();
		Sniffer sniffer(adapter.name(), configuration);
		sniffer.set_direction(PCAP_D_IN);*/
/////////////////

		//pcap_if_t* devices;
		//struct bpf_program fp;
		//pcap_findalldevs(&devices, errbuf);

		//pcap_if* d = devices;
		//while (devices) {
		//	d = devices;
		//	std::string device_name(d->name);
		//	if (device_name.find(adapter.name()) != std::string::npos) {
		//		break;
		//	}
		//	d = nullptr;
		//	devices = devices->next;
		//}


		//pcap_t* handle = pcap_open(d->name, // name of the device
		//	65536,     // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
		//	PCAP_OPENFLAG_PROMISCUOUS , //flags
		//	1,      // read timeout
		//	NULL,	//auth
		//	errbuf     // error buffer
		//);

		//pcap_compile(handle, &fp, "(not ip dst 239.255.255.250) and (not ether proto 0x9000)", 1, 0xffffff);
		//
		//pcap_t* t;
		pcap_pkthdr* head = new pcap_pkthdr;
		const u_char* packet = new const u_char[2300];
	
///////////////		
		while (true) {

			//Packet recieved = sniffer.next_packet();
			packet = pcap_next(port.handle, head);
			//Packet packet_to_send;
			
			
			if (packet){//raw.->matches_flag(PDU::ETHERNET_II)) {
				//toto vymaz
				//packet_to_send = deencapsulate(recieved, adapter);
				
				//zatial rozosiela na vsetky ostatne porty !!!!
				for (auto& a : Interfaces::ports) {
					NetworkInterface iface_to_send_from(IPv4Address(a.getInterfaceAddr().c_str()));
					PacketSender sender;
					
					if (iface_to_send_from.name().compare(adapter.name())) {
						//sender.default_interface(iface_to_send_from.name());
						//sender.send(*packet_to_send.pdu());

						//pcap_findalldevs(&devices, errbuf);

						//while (devices) {
						//	d = devices;
						//	std::string device_names(d->name);
						//	if (device_names.find(iface_to_send_from.name()) != std::string::npos) {
						//		break;
						//	}
						//	d = nullptr;
						//	devices = devices->next;
						//}

						//pcap_t* handles = pcap_open(d->name, // name of the device
						//	65536,     // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
						//	PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL, //flags
						//	1,      // read timeout
						//	NULL,	//auth
						//	errbuf     // error buffer
						//);

						pcap_sendpacket(a.handle ,packet, head->len);
						

						//pcap_close(handles);
						// Pozor toto funguje len ak su 2 porty !!! oprav
						if (*(unsigned short*)(packet + 12) <= 1536) {
							
							EthernetII eth(packet, head->len);
							port.updateStats(eth.inner_pdu(), a);

							//signal pre GUI
							interf->update_statistics(port, a);
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

