#include "sw_switch.h"
#include <QtWidgets/QApplication>
#include <tins/tins.h>
#include <pcap.h>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    SW_switch w;
    w.initialize();
    w.show();
    return a.exec();
}
