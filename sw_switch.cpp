#include "sw_switch.h"
#include "Port.h"
#include "camview.h"
#include <tins/tins.h>
#include <iostream>
#include <string>
#include <QtPlugin>
#include <pcap.h>
#include <thread>
#include "Filter.h"
#include <tins/pdu.h>
#include <qtabwidget.h>
#include <QPushButton>
#include <QTableWidgetItem>
#include <QThread>
#include <mutex>
#include <QMenu>
#include <QAction>

using namespace Tins;

int SW_switch::filter_id = 0;

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
    ui.port->addItem(port_1.getInterfaceName().c_str());
    ui.port_2_label->setText(port_2.getInterfaceName().c_str());
    ui.port->addItem(port_2.getInterfaceName().c_str());
    ui.timeout->setText(QString::number(interfaces->get_timeout()));

    connect(ui.btnAddFilter, &QPushButton::clicked, this, &SW_switch::addFilter);
    connect(ui.submitTime, &QPushButton::clicked, this, &SW_switch::changeTimeout);
    connect(ui.actionCAM, &QAction::triggered, this, &SW_switch::open_cam);
    connect(ui.clearCamTable, &QPushButton::clicked, this, &SW_switch::reset_cam);
    connect(clearStats, &QPushButton::clicked, this, &SW_switch::reset_stats);
    connect(interfaces, SIGNAL(request_table_update(CamTable)), this, SLOT(set_cam(CamTable)));
    connect(interfaces, SIGNAL(request_update_statistics(Port, Port)), this, SLOT(set_status(Port, Port )));
    connect(thread, SIGNAL(destroyed()), interfaces, SLOT(deleteLater()));
    connect(ui.removeFilter, &QPushButton::clicked, this, &SW_switch::removeFilter);
}

void SW_switch::set_cam(CamTable content) {
    QTableWidget* camTable = ui.camTable;
    camTable->clear();
    int counter = 0;
    for (auto row : content) {
        int id = row.second.first.getPortId();
        camTable->setItem(counter, 0, new QTableWidgetItem(QString(row.second.first.getInterfaceName().c_str())));
        std::string mac = row.first.to_string().c_str();
        camTable->setItem(counter, 1, new QTableWidgetItem(QString(row.first.to_string().c_str())));
        double timestamp = (double)interfaces->get_timeout() + std::chrono::duration<double>(row.second.second - std::chrono::system_clock::now()).count();
        camTable->setItem(counter, 2, new QTableWidgetItem(QString::number((int) timestamp)));
        counter++;
    }
}

void SW_switch::changeTimeout()
{
    bool ok = false; 
    int time = ui.timerEdit->text().toInt(&ok, 10);
    if (ok) {
        interfaces->set_timeout(time);
        ui.timeout->setText(QString::number(time));
    }
    ui.timerEdit->setText("");
}

void SW_switch::addFilter()
{
    Tins::IP::address_type anyip = Tins::IP::address_type("0.0.0.0");
    Tins::HWAddress<6> anymac = Tins::HWAddress<6>(0);
    struct pdu_info filter;
    bool ok = false;
    std::string portID = ui.port->currentText().toLocal8Bit().constData();
    std::string permision = ui.type->currentText().toLocal8Bit().constData();
    std::string dst_mac = ui.dstMac->currentText().toLocal8Bit().constData();
    std::string src_mac = ui.srcMac->currentText().toLocal8Bit().constData();
    std::string srcIp = ui.srcIP->currentText().toLocal8Bit().constData();
    std::string dstIp = ui.dstIP->currentText().toLocal8Bit().constData();
    std::string direct = ui.direction->currentText().toLocal8Bit().constData();
    std::string icmpType = ui.icmpType->currentText().toLocal8Bit().constData();


    bool permision_b = false;

    if (!permision.compare("PERMIT"))
        filter.permit = true;
    else
        filter.permit = false;


        //addresses
    if (dst_mac.compare("ANY") && dst_mac.compare("-")) {
        filter.dst_mac = Tins::HWAddress<6>(dst_mac.c_str());
        filter.dst_mac_set = true;
    }
    else  if (!dst_mac.compare("ANY"))
            filter.dst_mac = anymac;
       

    if (src_mac.compare("ANY") && src_mac.compare("-")) {
        filter.src_mac = Tins::HWAddress<6>(src_mac.c_str());
        filter.src_mac_set = true;
    }
    else if(!src_mac.compare("ANY"))
        filter.src_mac = anymac;
        
    if (srcIp.compare("ANY") && srcIp.compare("-")) {
        filter.src_ip = Tins::IPv4Address(srcIp.c_str());
        filter.src_ip_set = true;
    }
    else if (!srcIp.compare("ANY"))
        filter.src_ip = anyip;

    if (dstIp.compare("ANY") && dstIp.compare("-")) {
        filter.dst_ip = Tins::IPv4Address(dstIp.c_str());
        filter.dst_ip_set = true;
    }
    else if(!dstIp.compare("ANY"))
        filter.dst_ip = anyip;
        
    int direction = 0;
    if (!((std::string)ui.direction->currentText().toLocal8Bit().constData()).compare("IN")) {
        filter.direction = IN;
    }
    else {
        filter.direction = OUT;
    }

    //transport protocol
    int ipProto = ui.transportProto->currentText().toInt(&ok, 10);
    std::string protocol = ui.transportProto->currentText().toLocal8Bit().constData();

    if (!ok && !((std::string)ui.transportProto->currentText().toLocal8Bit().constData()).compare("ANY"))
        filter.protocol_L3 = ANY;
    else if (!ok && !((std::string)ui.transportProto->currentText().toLocal8Bit().constData()).compare("-"))
        filter.protocol_L3 = NO;
    else {
        if (!protocol.compare("UDP"))
            filter.protocol_L3 = 17;
        if (!protocol.compare("TCP"))
            filter.protocol_L3 = 6;

        if (!protocol.compare("ICMP")) {
            filter.protocol_L3 = icmp;
            if (!icmpType.compare("REQUEST")) {
                filter.icmpType = 8;
            }else if (!icmpType.compare("REPLY")) {
                filter.icmpType = 0;
            }
            else if (!icmpType.compare("ANY")) {
                filter.icmpType = ANY;
            }
        }
    }

    //dst port
    int dstPort = ui.dstPort->currentText().toInt(&ok, 10);
    std::string dstport = ui.dstPort->currentText().toLocal8Bit().constData();
        
    if (!ok && !((std::string)ui.dstPort->currentText().toLocal8Bit().constData()).compare("ANY"))
        filter.dst_port = ANY;
    else if (!ok && !((std::string)ui.dstPort->currentText().toLocal8Bit().constData()).compare("-"))
        filter.dst_port = NO;
    else
        filter.dst_port = dstPort;
        
    //src port
    int srcPort = ui.srcPort->currentText().toInt(&ok, 10);
    std::string srcport = ui.srcPort->currentText().toLocal8Bit().constData();

    if (!ok && !((std::string)ui.srcPort->currentText().toLocal8Bit().constData()).compare("ANY"))
        filter.src_port = ANY;
    else if (!ok && !((std::string)ui.srcPort->currentText().toLocal8Bit().constData()).compare("-"))
        filter.src_port = NO;
    else            
        filter.src_port = srcPort;

    int rows = ui.filters->rowCount();
    ui.filters->insertRow(rows);

    ui.filters->setItem(rows,0, new QTableWidgetItem(QString::fromStdString(permision)));
    ui.filters->setItem(rows,1, new QTableWidgetItem(QString::fromStdString(portID)));
    ui.filters->setItem(rows,2, new QTableWidgetItem(QString::fromStdString(direct)));
    ui.filters->setItem(rows,3, new QTableWidgetItem(QString::fromStdString(src_mac)));
    ui.filters->setItem(rows,4, new QTableWidgetItem(QString::fromStdString(srcIp)));
    ui.filters->setItem(rows,5, new QTableWidgetItem(QString::fromStdString(dst_mac)));
    ui.filters->setItem(rows,6, new QTableWidgetItem(QString::fromStdString(dstIp)));
    ui.filters->setItem(rows,7, new QTableWidgetItem(QString::fromStdString(protocol)));
    ui.filters->setItem(rows,8, new QTableWidgetItem(QString::fromStdString(srcport)));
    ui.filters->setItem(rows,9, new QTableWidgetItem(QString::fromStdString(dstport)));
    ui.filters->setItem(rows, 10, new QTableWidgetItem(QString::fromStdString(dstport)));
    ui.filters->setItem(rows,11, new QTableWidgetItem(QString::number(filter_id)));

    filter.id = filter_id++;

    interfaces->assignFilter(filter, portID);

}

void SW_switch::removeFilter()
{
    int id = -1;
    int row = -1;
    if(ui.filters->selectionModel()->selectedRows().size() > 0)
         row = (int) ui.filters->selectionModel()->selectedRows().at(0).row();
    
    qDebug() << row;
    
    if (row >= 0) {
        id = (int) ui.filters->item(row, 11)->text().toInt();
    }
    
    if (id >= 0) {
        interfaces->deleteFilter(id);
        ui.filters->removeRow(row);
    }

}


void SW_switch::set_status(Port port_in, Port  port_out) {
    // ROWS: 1. EthernetII, 2. ARP, 3. IP, 4. TCP, 5. UDP, 6. HTTP, 7. ICMP
    // COLS: 0. IN, 1. OUT 

    QTableWidget* in_stream = nullptr;
    QTableWidget* out_stream = nullptr;

    if ((port_in.getInterfaceName()).compare(ui.port_1_label->text().toLocal8Bit().constData())) {
        if (port_in.getPortId() == port_out.getPortId()) {
            in_stream = out_stream = ui.port_1;
        }
        else {
            in_stream = ui.port_1;
            out_stream = ui.port_2;
        }
    }
    else {
        if (port_in.getPortId() == port_out.getPortId()) {
            in_stream = out_stream = ui.port_2;
        }
        else {
            in_stream = ui.port_2;
            out_stream = ui.port_1;
        }
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
    in_stream->setItem(7,0, new QTableWidgetItem(QString::number(port_in.port80_in)));

    //OUT
    auto out_values = port_out.getOutStats();
    out_stream->setItem(0, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ETHERNET_II])));
    out_stream->setItem(1, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ARP])));
    out_stream->setItem(2, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::IP])));
    out_stream->setItem(3, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::TCP])));
    out_stream->setItem(4, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::UDP])));
    out_stream->setItem(5, 1, new QTableWidgetItem(QString::number(port_out.http_out)));
    out_stream->setItem(6, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ICMP])));
    out_stream->setItem(7, 1, new QTableWidgetItem(QString::number(port_out.port80_out)));

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
        stream->setItem(7, 0, new QTableWidgetItem(QString::number(port.port80_in)));

        //OUT
        auto out_values = port.getOutStats();
        stream->setItem(0, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ETHERNET_II])));
        stream->setItem(1, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ARP])));
        stream->setItem(2, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::IP])));
        stream->setItem(3, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::TCP])));
        stream->setItem(4, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::UDP])));
        stream->setItem(5, 1, new QTableWidgetItem(QString::number(port.http_out)));
        stream->setItem(6, 1, new QTableWidgetItem(QString::number(out_values[PDU::PDUType::ICMP])));
        stream->setItem(7, 1, new QTableWidgetItem(QString::number(port.port80_out)));

    }
}

void SW_switch::reset_cam()
{
    interfaces->reset_cam_all();
}

void SW_switch::open_cam() {   
    cam->show();
}
