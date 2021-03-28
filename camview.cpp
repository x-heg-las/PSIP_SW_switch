#include "camview.h"
#include <QTableWidgetItem>
#include <QThread>
#include <QtPlugin>

CamView::CamView(QWidget *parent)
	: QWidget(parent)
{
	ui.setupUi(this);
	QThread* thread = new QThread(this);



}

CamView::~CamView()
{
}
