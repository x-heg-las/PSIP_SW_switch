#include "sw_switch.h"
#include <QtWidgets/QApplication>
#include <tins/tins.h>
#include <pcap.h>


int main(int argc, char *argv[])
{
    SetDllDirectory(L"C:/Windows/System32/Npcap/" );
    QApplication a(argc, argv);
    SW_switch w;
    w.show();
    return a.exec();


}
