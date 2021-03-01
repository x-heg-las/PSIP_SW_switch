#include "sw_switch.h"
#include "Port.h"
#include <tins/tins.h>
#include <iostream>
#include <string>
#include <QtPlugin>
#include <pcap.h>
#include <thread>
#include <tins/pdu.h>
#include <qtabwidget.h>
#include <QTableWidgetItem>



//Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin);
using namespace Tins;

SW_switch::SW_switch(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
   
}

void *SW_switch::initialize() {
   
    interfaces.initiatePort(Port("9.0.0.10"));
    interfaces.initiatePort(Port("9.0.0.12"));
   
    return NULL;
}

void SW_switch::update_stats(PDU *pdu)  {
    




    ui.port_1->setItem(1,0,new QTableWidgetItem("ahij"));
    ui.port_1->viewport()->update();

}



