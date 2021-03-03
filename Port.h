#pragma once
#include <unordered_map>
#include <string>
#include <vector>

#include <tins/tins.h>
#include <QObject>

using namespace Tins;

class Port 
{
	

public:	

	enum Protocols{
		EthernetII, HTTP, IP, ICMP, TCP, UDP, ARP
	};

	Port() {};

	Port(std::string interface_) {
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


		pcap_t* handle_ = pcap_open(d->name, // name of the device
			65536,     // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
			PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL, //flags
			1,      // read timeout
			NULL,	//auth
			errbuf     // error buffer
		);
		//pcap_compile(handle_, &fp, "(not ip dst 239.255.255.250) and (not ether proto 0x9000)", 1, 0xffffff);
		handle = handle_;
	}

	std::string getInterfaceAddr() {
		return interface;
		
	}

	std::string getInterfaceName() {
		return interfaceName;
	}
	std::unordered_map<Tins::PDU::PDUType, int> getInStats();
	std::unordered_map<Tins::PDU::PDUType, int> getOutStats();
	void updateStats(PDU* pdu, Port out_port);

	pcap_t* handle;
private:
	
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

signals: 
	    void request_update_statistics(Port, Port);


};