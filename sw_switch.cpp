#include "sw_switch.h"
#include "Port.h"
#include "camview.h"
#include <tins/tins.h>
#include <iostream>
#include <string>
#include <QtPlugin>
#include <pcap.h>
#include <thread>
#include <tins/pdu.h>
#include <qtabwidget.h>
#include <QPushButton>
#include <QTableWidgetItem>
#include <QThread>
#include <mutex>
#include <QMenu>
#include <QAction>

using namespace Tins;


SW_switch::SW_switch(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    cam = new CamView;
    QThread* thread = new QThread(this);
    interfaces = new Interfaces();
    interfaces->moveToThread(thread);
    QPushButton* clearStats = ui.clearStats;

    //Ports in switch
    Port port_1("9.0.0.10", 1);
    Port port_2("10.0.0.12", 2);

    interfaces->initiatePort(port_1, interfaces);
    interfaces->initiatePort(port_2, interfaces);

    //NetworkInterface(IPv4Address(port_1)).friendly_name()
    ui.port_1_label->setText(port_1.getInterfaceName().c_str());
    ui.port_2_label->setText(port_2.getInterfaceName().c_str());

    connect(ui.actionCAM, &QAction::triggered, this, &SW_switch::open_cam);
    connect(clearStats, &QPushButton::clicked, this, &SW_switch::reset_stats);
    connect(interfaces, SIGNAL(request_update_statistics(Port, Port)), this, SLOT(set_status(Port, Port )));
    connect(thread, SIGNAL(destroyed()), interfaces, SLOT(deleteLater()));
}

void SW_switch::set_cam() {
    
}


void SW_switch::set_status(Port port_in, Port  port_out) {
    // ROWS: 1. EthernetII, 2. ARP, 3. IP, 4. TCP, 5. UDP, 6. HTTP, 7. ICMP
    // COLS: 0. IN, 1. OUT 

    QTableWidget* in_stream = nullptr;
    QTableWidget* out_stream = nullptr;

    if ((port_in.getInterfaceName()).compare(ui.port_1_label->text().toLocal8Bit().constData())) {
        in_stream = ui.port_1;
        out_stream = ui.port_2;
    }
    else {
        in_stream = ui.port_2;
        out_stream = ui.port_1;
    }

    //IN
    auto in_values = port_in.getInStats();
    in_stream->setItem(0,0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::ETHERNET_II])));
    in_stream->setItem(1,0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::ARP])));
    in_stream->setItem(2,0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::IP])));
    in_stream->setItem(3,0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::TCP])));
    in_stream->setItem(4,0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::UDP])));
    in_stream->setItem(5,0, new QTableWidgetItem(QString::number(port_in.http_in)));
    in_stream->setItem(6,0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::ICMP])));

    //OUT
    auto out_values = port_out.getOutStats();
    out_stream->setItem(0, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ETHERNET_II])));
    out_stream->setItem(1, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ARP])));
    out_stream->setItem(2, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::IP])));
    out_stream->setItem(3, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::TCP])));
    out_stream->setItem(4, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::UDP])));
    out_stream->setItem(5, 1, new QTableWidgetItem(QString::number(port_out.http_out)));
    out_stream->setItem(6, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ICMP])));

}

void SW_switch::reset_stats()
{
    interfaces->reset_statistics();
    for (auto port : interfaces->ports) {

        QTableWidget* stream = nullptr;
  
        if ((port.getInterfaceName()).compare(ui.port_1_label->text().toLocal8Bit().constData()))
            stream = ui.port_1;
        else
            stream = ui.port_2;
           


        //IN
        auto in_values = port.getInStats();
        stream->setItem(0, 0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::ETHERNET_II])));
        stream->setItem(1, 0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::ARP])));
        stream->setItem(2, 0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::IP])));
        stream->setItem(3, 0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::TCP])));
        stream->setItem(4, 0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::UDP])));
        stream->setItem(5, 0, new QTableWidgetItem(QString::number(port.http_in)));
        stream->setItem(6, 0, new QTableWidgetItem(QString::number(in_values[PDU::PDUType::ICMP])));

        //OUT
        auto out_values = port.getOutStats();
        stream->setItem(0, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ETHERNET_II])));
        stream->setItem(1, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ARP])));
        stream->setItem(2, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::IP])));
        stream->setItem(3, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::TCP])));
        stream->setItem(4, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::UDP])));
        stream->setItem(5, 1, new QTableWidgetItem(QString::number(port.http_out)));
        stream->setItem(6, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ICMP])));


    }
}

void SW_switch::open_cam() {   
    cam->show();
}
