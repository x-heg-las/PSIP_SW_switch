#pragma once
#include <pcap.h>
#include <tins/tins.h>
class Filter
{
public:

	struct pdu_info {
		Tins::HWAddress<6> src_mac;
		Tins::HWAddress<6> dst_mac;
		uint16_t ethertype=-1;
		///
		Tins::IP::address_type src_ip;
		Tins::IP::address_type dst_ip;
		uint8_t protocol_L3=-1;
		///
		int protovol_app=-1;
		short dst_port=-1;
		short src_port=-1;
	};


	void checkFilter(struct pdu_info);
	void createPduInfo(char* data);
	static pdu_info build_info(const u_char* packet, int len);

};

