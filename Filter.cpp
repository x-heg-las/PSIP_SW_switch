#include "Filter.h"
#include <pcap.h>
#include <tins/tins.h>

using namespace Tins;
pdu_info Filter::build_info(const u_char* packet, int len)
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

			if (pdu->pdu_type() == PDU::PDUType::ICMP) {
				ICMP* icmpm = pdu->find_pdu<ICMP>();
				packet_detail.icmpType = icmpm->type();
			}

			pdu = pdu->inner_pdu();
		}
	
	}
	return packet_detail;
}

bool Filter::verify(pdu_info packet, pdu_info filter)
{

	//struct pdu_info {
	//	Tins::HWAddress<6> src_mac;
	//	Tins::HWAddress<6> dst_mac;
	//	uint16_t ethertype = -1;
	//	///
	//	Tins::IP::address_type src_ip;
	//	Tins::IP::address_type dst_ip;
	//	uint8_t protocol_L3 = -1;
	//	///
	//	int protovol_app = -1;
	//	short dst_port = -1;
	//	short src_port = -1;
	//};



	if ((packet.src_mac == filter.src_mac || filter.src_mac_set) &&
		(packet.dst_mac == filter.dst_mac || filter.dst_mac_set) &&
		
		(packet.src_ip == filter.src_ip || filter.src_ip_set) &&
		(packet.dst_ip == filter.dst_ip || filter.dst_ip_set) &&
		(packet.dst_port == filter.dst_port || filter.dst_port == ANY) &&
		(packet.src_port == filter.src_port || filter.src_port == ANY) &&
		(packet.protocol_L3 == filter.protocol_L3 || filter.protocol_L3 == ANY)) {

		return filter.permit;

	}
	return filter.permit;
	
}

pdu_info Filter::create_filter(bool src_mac_set, Tins::HWAddress<6> src_mac, bool dst_mac_set, 
	Tins::HWAddress<6> dst_mac, bool src_ip_set, Tins::IP::address_type src_ip, 
	bool dst_ip_set, Tins::IP::address_type dst_ip, short protocol_L3,
	int dst_port, int src_port, bool permit, char direction)

{
	struct pdu_info newFilter;
	newFilter.src_ip_set = src_ip_set;
	newFilter.src_mac_set = src_mac_set;
	newFilter.src_mac = src_mac;
	newFilter.dst_mac_set = dst_mac_set;
	newFilter.dst_mac = dst_mac;
	
	newFilter.src_ip_set = src_ip_set;
	newFilter.src_ip = src_ip;
	newFilter.dst_ip_set = dst_ip;
	newFilter.protocol_L3 = protocol_L3;
	
	newFilter.dst_port = dst_port;
	newFilter.src_port = src_port;
	newFilter.permit = permit;
	newFilter.direction = direction;



	return newFilter;
}
