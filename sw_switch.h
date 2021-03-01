#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_sw_switch.h"
#include <string>
#include <tins/tins.h>
#include "Port.h"
#include <qtablewidget.h>

class SW_switch : public QMainWindow
{
    Q_OBJECT

public:
    SW_switch(QWidget *parent = Q_NULLPTR);
    void* initialize();
    Interfaces interfaces;

public slots:
    void set_status(PDU* pdu, NetworkInterface iface);
signals:
    void update_stats(PDU* pdu, NetworkInterface iface);

private:
    Ui::SW_switchClass ui;

    
};
