#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_sw_switch.h"
#include <string>
#include <tins/tins.h>
#include "camview.h"
#include "Filter.h"
#include "Port.h"
#include <qtablewidget.h>
#include <pcap.h>




class SW_switch : public QMainWindow
{
    Q_OBJECT
   
public:
    SW_switch(QWidget *parent = Q_NULLPTR);
    void* initialize();
    Interfaces* interfaces;
    CamView* cam;
   
public slots:
    void open_cam();
    void set_status(Port port_in, Port port_out);
    void reset_stats();
    void reset_cam();
    void set_cam(CamTable content);


private:
    Ui::SW_switchClass ui;

    
};
