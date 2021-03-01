#pragma once
#include <unordered_map>
#include <string>
#include <vector>
#include <tins/tins.h>

using namespace Tins;

class Port
{
private:
	std::string interface;
public:	
	Port() {};

	Port(std::string interface_) {
		interface = interface_;
	}

	std::string getInterfaceAddr() {
		return interface;
	}

};


class Interfaces {
	public:	
		static std::vector<Port> ports;
		static int initiatePort(Port port);



};