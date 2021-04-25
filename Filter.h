#pragma once
#include <pcap.h>
#include <tins/tins.h>

#define IN 1
#define OUT 2
#define ANY -1
#define NO -2
#define icmp 1

struct pdu_info {

	bool src_mac_set = false;
	Tins::HWAddress<6> src_mac = Tins::HWAddress<6>("ff:ff:ff:ff:ff:ff");
	bool dst_mac_set = false;
	Tins::HWAddress<6> dst_mac = Tins::HWAddress<6>("ff:ff:ff:ff:ff:ff");
	///
	bool src_ip_set = false;
	int icmpType = NO;
	Tins::IP::address_type src_ip = Tins::IP::address_type("0.0.0.0");
	bool dst_ip_set = false;
	Tins::IP::address_type dst_ip = Tins::IP::address_type("0.0.0.0");
	short protocol_L3 = NO;
	///
	int dst_port = NO;
	int src_port = NO;
	bool permit = false;
	char direction = 0;
	int id = -1;
};

class Filter
{
public:

	

	


	void checkFilter(struct pdu_info);
	void createPduInfo(char* data);
	static pdu_info build_info(const u_char* packet, int len);
	bool verify(struct pdu_info packet, struct pdu_info filter);
	struct pdu_info create_filter(bool src_mac_set,
		Tins::HWAddress<6> src_mac,
		bool dst_mac_set,
		Tins::HWAddress<6> dst_mac,
		bool src_ip_set,
		Tins::IP::address_type src_ip,
		bool dst_ip_set,
		Tins::IP::address_type dst_ip,
		short protocol_L3,
		int dst_port,
		int src_port,
		bool permit,
		char direction);

};

