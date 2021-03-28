#include "Port.h"
#include <tins/tins.h>
#include "Filter.h"
#include <tins/pdu.h>
#include <thread>
#include <iostream>
#include <vector>
#include <pcap.h>
#include <QMetaType>
#include <mutex>
#include <utility>
#include <unordered_map>
#include <regex>


using namespace std;
using namespace Tins;
std::vector<Port> Interfaces::ports;
std::vector<Port> ports_global;
// casovac je inicializovany na 30 sekund
int cam_timer = 30;
std::unordered_map<int, int> reset_flag;
std::unordered_map<int, Port> global_ports;
std::unordered_map<int, int> active_interfaces;
CamTable global_cam;

mutex cam_mutex;
mutex stat_mutex;
mutex intf_mutex;

void gui_updater(Interfaces* iface) {

	while (1) {
		std::this_thread::sleep_for(1s);
		iface->update_table(global_cam);

	}
}

void cam_clean(Interfaces* iface) {
	std::lock_guard<std::mutex> lock(cam_mutex);
	CamTable::iterator record;
	for (record = global_cam.begin(); record != global_cam.end() && global_cam.size() > 0;) {
		if (chrono::duration<double>(chrono::system_clock::now() - record->second.second ).count() > cam_timer) {
			record = global_cam.erase(record);
			iface->update_table(global_cam);
		}
		else
			record++;
	}
		

}

bool find_http(std::string payload) {

	if (payload.find("HTTP/1.1") != std::string::npos) {
		return true;
	}

	return false;
}


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


void startSniffing(Port& port, Interfaces *interf) {
	try
	{
		int this_port_id = port.getPortId();
		NetworkInterface adapter(IPv4Address(port.getInterfaceAddr().c_str()));
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_pkthdr* head = new pcap_pkthdr;
		const u_char* packet = new  u_char[2300];
		auto timer = std::chrono::steady_clock::now();
///////////////		
		TCPStreamFollower follower;

		while (true) {
			//aktualizovanie

			if (reset_flag[this_port_id]) {
				std::lock_guard<std::mutex> lock(stat_mutex);
				port.reset_statistics();
				reset_flag[this_port_id] = 0;
			}
			
		
			//Packet recieved = sniffer.next_packet();
			packet = pcap_next(port.handle, head);
			//Packet packet_to_send;	
			
			
			//kontrola ci rozhranie prijalo ramec poslednych 6 sekund
			if ((std::chrono::duration<double>(std::chrono::steady_clock::now() - timer).count()) > 7) {
				std::lock_guard<std::mutex> lock(cam_mutex);
				interf->reset_cam(port);
				std::lock_guard<mutex> lockint(intf_mutex);
				active_interfaces[port.getPortId()] = 0;
			}
			else {
				std::lock_guard<mutex> lock(intf_mutex);
				active_interfaces[port.getPortId()] = 1;
			}

			cam_clean(interf);
			if (packet){

				
				timer = std::chrono::steady_clock::now();
				Filter::pdu_info packet_info = Filter::build_info(packet, head->len);
				//pridanie zaznamu do CAM
				interf->insert_mac(packet_info, port);
				//odoslanie na port/y
				
				Port* handler_to_send_from = interf->find_mac(packet_info);
			
				if (handler_to_send_from != nullptr) {
					//poslem na vybrany interface

					pcap_sendpacket(handler_to_send_from->handle, packet, head->len);
					char* temp = new char[2000];
					memcpy(temp, packet, head->len);
					std::string temp_s(temp, head->len);

					EthernetII* eth = new EthernetII(packet, head->len);
					if (eth->payload_type() <= 1500) {
						Dot3* dot = new Dot3(packet, head->len);
						port.updateStats(dot, global_ports[handler_to_send_from->getPortId()], temp_s);
						interf->update_statistics(port, global_ports[handler_to_send_from->getPortId()]);
						delete dot;
					}
					else {
						port.updateStats(eth, global_ports[handler_to_send_from->getPortId()], temp_s);
						//signal pre GUI
						interf->update_statistics(port, global_ports[handler_to_send_from->getPortId()]);
					}
					delete eth;
					delete[]temp;
					
				}
				else {
					for (auto& a : Interfaces::ports) {
						NetworkInterface iface_to_send_from(IPv4Address(a.getInterfaceAddr().c_str()));
						PacketSender sender;

						if (iface_to_send_from.name().compare(adapter.name())) {

							pcap_sendpacket(a.handle, packet, head->len);

							//TODO ::  Pozor toto funguje len ak su 2 porty !!! oprav 
						

							char* temp = new char[2000];
							memcpy(temp, packet, head->len);
							std::string temp_s(temp, head->len);

							EthernetII* eth = new EthernetII(packet, head->len);
							if (eth->payload_type() <= 1500) {
								Dot3* dot = new Dot3(packet, head->len);
								port.updateStats(dot, global_ports[a.getPortId()], temp_s);
								interf->update_statistics(port, global_ports[a.getPortId()]);
								delete dot;
							}
							else {
								port.updateStats(eth, global_ports[a.getPortId()], temp_s);
								//signal pre GUI
								interf->update_statistics(port, global_ports[a.getPortId()]);
							}
							delete eth;
							delete[]temp;
						}
					}
				}
				//aktualizovanie , signal pre GUI pre CAM
				interf->update_table(global_cam);
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

	if (!global_ports.size()) {
		std::thread updater(gui_updater, interf);
		updater.detach();
	}


	{
		std::lock_guard<std::mutex> lock(stat_mutex);
		reset_flag[port.getPortId()] = 0;
		global_ports[port.getPortId()] = port;
	}
	{
		std::lock_guard<std::mutex> lock(intf_mutex);
		active_interfaces[port.getPortId()] = 1;
	}
	
	qRegisterMetaType<CamTable>("CamTable");
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

std::unordered_map<Tins::PDU::PDUType, int>& Port::getInStats()
{
	return IN_STAT;
}

std::unordered_map<Tins::PDU::PDUType, int>& Port::getOutStats()
{
	return OUT_STAT;
}



void Port::updateStats(PDU* pdu,Port& out_port, std::string payload)
{
	std::lock_guard<std::mutex> lock(stat_mutex);
	PDU* packet = pdu;
	while (packet) {

		if (packet->pdu_type() == PDU::PDUType::TCP) {

			Tins::TCP *tcp = packet->find_pdu<Tins::TCP>();
			if (tcp->dport() == 80 || tcp->sport() == 80) {
				if (find_http(payload)) {
					http_in++;
					out_port.http_out++;
				}
			}
		}

		if (IN_STAT.find(packet->pdu_type()) != IN_STAT.end()) {
			IN_STAT[packet->pdu_type()] ++;
		}
		else
			IN_STAT[packet->pdu_type()] = 1;
		{
			std::lock_guard<std::mutex> lock(intf_mutex);
			if (active_interfaces[out_port.getPortId()]) {
				auto OUT_STAT = out_port.getOutStats();

				if (OUT_STAT.find(packet->pdu_type()) != OUT_STAT.end()) {
					out_port.OUT_STAT[packet->pdu_type()] ++;
				}
				else {
					out_port.OUT_STAT[packet->pdu_type()] = 1;
				}
			}
		}
		packet = packet->release_inner_pdu();
	}

	delete packet;
}


void Interfaces::insert_mac(Filter::pdu_info packet_info, Port recieving_port)
{
		
	if (global_cam.find(packet_info.src_mac) == global_cam.end()) {
		std::lock_guard<std::mutex> guard(cam_mutex);
		global_cam[packet_info.src_mac] = std::make_pair(recieving_port, std::chrono::system_clock::now());
	}
	else {
		std::lock_guard<std::mutex> guard(cam_mutex);
		global_cam[packet_info.src_mac].second = std::chrono::system_clock::now();
	}

}

Port* Interfaces::find_mac(Filter::pdu_info packet_info)
{
	//broadcast
	if(packet_info.dst_mac.is_broadcast()){
		return nullptr;
	}

	//unicast
	if (global_cam.find(packet_info.dst_mac) != global_cam.end()) {
		return &global_cam[packet_info.dst_mac].first;
	}
	
	return nullptr;
}

void Interfaces::request_update_cam()
{
	std::lock_guard<std::mutex> lock(cam_mutex);
	global_cam.clear();
}

void Interfaces::reset_statistics()
{
	std::lock_guard<std::mutex> lock(stat_mutex);
	for (auto& port : global_ports) {
		port.second.reset_statistics();
		
	}
	for (auto &id : reset_flag) {
		id.second = 1;
	}
}

void Interfaces::reset_cam(Port port)
{
	int portId = port.getPortId();
	CamTable::iterator record;
	for (record = global_cam.begin(); record != global_cam.end() && global_cam.size() > 0;) {
		if (record->second.first.getPortId() == portId) {
			record = global_cam.erase(record);
						
		}
		else
			record++;
	}
	update_table(global_cam);
}

void Interfaces::reset_cam_all()
{
	std::lock_guard<std::mutex> lock(cam_mutex);
	global_cam.clear();
	update_table(global_cam);
}

int Interfaces::get_timeout() {
	return cam_timer;
}


