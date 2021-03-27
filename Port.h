#pragma once
#include <unordered_map>
#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <utility>
#include "Filter.h"
#include <tins/tins.h>
#include <QObject>


using namespace Tins;
using namespace std;

class Port 
{
	

public:	

	enum Protocols{
		EthernetII, HTTP, IP, ICMP, TCP, UDP, ARP
	};

	Port() {};

	Port(std::string interface_, int id) {
		port_id = id;
		
		http_in = http_out = 0;
		interface = interface_;
		std::wstring name = NetworkInterface(IPv4Address(interface_)).friendly_name();
		interfaceName = std::string(name.begin(), name.end());

		char errbuf[PCAP_ERRBUF_SIZE];

		pcap_if_t* devices;
		struct bpf_program fp;
		pcap_findalldevs(&devices, errbuf);

		pcap_if* d = devices;
		while (devices) {
			d = devices;
			std::string device_name(d->name);
			if (device_name.find(NetworkInterface(IPv4Address(interface_)).name()) != std::string::npos) {
				break;
			}
			d = nullptr;
			devices = devices->next;
		}
		bpf_program* bf = new bpf_program;

		pcap_t* handle_ = pcap_open(d->name, // name of the device
			65536,     // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
			PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL, //flags
			1,      // read timeout
			NULL,	//auth
			errbuf     // error buffer
		);
		//pcap_compile(handle_, &fp, "(not ip dst 239.255.255.250) and (not ether proto 0x9000)", 1, 0xffffff);
		handle = handle_;
		pcap_compile(handle_, bf, "not ip src 10.0.0.12 and not ip src 9.0.0.10", 1, 1) ;
		pcap_setfilter(handle_, bf);
		
	}

	std::string getInterfaceAddr() {
		return interface;
		
	}

	int getPortId() {
		return port_id;
	}

	std::string getInterfaceName() {
		return interfaceName;
	}

	void reset_statistics() {
		http_in = http_out = 0;
		IN_STAT.clear();
		OUT_STAT.clear();
	
	}
	std::unordered_map<Tins::PDU::PDUType, int>& getInStats();
	std::unordered_map<Tins::PDU::PDUType, int>& getOutStats();
	void updateStats(PDU* pdu, Port& out_port, std::string payload);

	int http_in;
	int http_out;
	
	pcap_t* handle;
private:
	
	int port_id;
	std::string interface, interfaceName;
	std::unordered_map<Tins::PDU::PDUType, int> IN_STAT;
	std::unordered_map<Tins::PDU::PDUType, int> OUT_STAT;
};


class Interfaces : public QObject {
	Q_OBJECT

	public:

	
		explicit Interfaces(QObject* parent = 0) : QObject(parent) {}

		static std::vector<Port> ports;
		static int initiatePort(Port port, Interfaces *interf);
		void update_statistics( Port& port_in, Port & port_out) { emit request_update_statistics(port_in, port_out); }

		 std::unordered_map<Tins::HWAddress<6>, std::pair<Port, std::chrono::time_point<chrono::system_clock>>> CAM_TABLE;
		 void insert_mac(Filter::pdu_info packet_info, Port port);
		 Port* find_mac(Filter::pdu_info packet_info);
		 void reset_statistics();
		 void reset_cam();
		 void request_update_cam();

signals: 
	    void request_update_statistics(Port, Port);
		
	


};