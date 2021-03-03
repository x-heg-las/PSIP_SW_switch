#include "sw_switch.h"
#include <QtWidgets/QApplication>
#include <tins/tins.h>
#include <pcap.h>


int main(int argc, char *argv[])
{
    SetDllDirectory(L"C:/Windows/System32/Npcap/" );
    QApplication a(argc, argv);
    SW_switch w;
    //w.initialize();
    w.show();
    return a.exec();

    //NetworkInterface nab(IPv4Address("9.0.0.10"));
    //char errbuf[PCAP_ERRBUF_SIZE];
    //pcap_if_t* devices;
    //pcap_if_t* devicesl;
    //std::string na(nab.name());
    //pcap_findalldevs(&devices,errbuf);
    //devicesl = devices;
    //pcap_if* d;
    //d = devices;
    //while (d) {
    //    std::string nam(d->name);
    //    if (nab.name().find(nam)) {
    //        break;
    //    }
    //    d = devices->next;
    // }
    //NetworkInterface nabs(IPv4Address("9.0.0.12"));
    //pcap_if* ds;
    //std::string ns(nabs.name());
    //devices = devicesl;
    //while (ds) {
    //    ds = devices;
    //    std::string nams(ds->name);
    //    if (nams.find(nabs.name()) != std::string::npos) {
    //        break;
    //    }
    //    devices = devices->next;
    //}

    //pcap_t* handles = pcap_open(ds->name, // name of the device
    //    65536,     // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
    //    PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL, //flags
    //    1,      // read timeout
    //    NULL,	//auth
    //    errbuf     // error buffer
    //);

    //pcap_t* handle = pcap_open(d->name, // name of the device
    //    65536,     // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
    //    PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL, //flags
    //    1,      // read timeout
    //    NULL,	//auth
    //    errbuf     // error buffer
    //);

    //pcap_t* t;
    //pcap_pkthdr *head = new pcap_pkthdr;
    //const u_char *packet = new const u_char[2300];
    //while (1) {
    //    packet = pcap_next(handle, head);
    //    pcap_sendpacket(handles, packet, 128);
    //}

    //return 0;
}
