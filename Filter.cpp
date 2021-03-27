#include "Filter.h"
#include <pcap.h>
#include <tins/tins.h>

using namespace Tins;
Filter::pdu_info Filter::build_info(const u_char* packet, int len)
{	
	struct pdu_info packet_detail;
	if (packet) {
		
		EthernetII* eth = new EthernetII(packet, len);
		PDU* pdu = eth;
		while (pdu) {
			//TODO:: asi nebude potrebny while 
			if (pdu->pdu_type() == PDU::PDUType::ETHERNET_II) {
				Tins::EthernetII* eth = pdu->find_pdu<Tins::EthernetII>();
				packet_detail.src_mac = eth->src_addr();
				packet_detail.dst_mac = eth->dst_addr();
				packet_detail.ethertype = eth->payload_type();
			}

			if (pdu->pdu_type() == PDU::PDUType::IP) {
				IP* ip = pdu->find_pdu<IP>();
				packet_detail.src_ip = ip->src_addr();
				packet_detail.dst_ip = ip->dst_addr();
				packet_detail.protocol_L3 = ip->protocol();
			}

			if (pdu->pdu_type() == PDU::PDUType::UDP) {
				UDP* ip = pdu->find_pdu<UDP>();
				packet_detail.src_port = ip->sport();
				packet_detail.dst_port = ip->dport();
			}

			if (pdu->pdu_type() == PDU::PDUType::TCP) {
				TCP* ip = pdu->find_pdu<TCP>();
				packet_detail.src_port = ip->sport();
				packet_detail.dst_port = ip->dport();
			}

			pdu = pdu->inner_pdu();
		}
	
	}
	return packet_detail;
}
