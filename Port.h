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