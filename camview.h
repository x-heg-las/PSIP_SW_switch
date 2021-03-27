#pragma once

#include <QWidget>
#include "ui_camview.h"

class CamView : public QWidget
{
	Q_OBJECT

public:
	CamView(QWidget *parent = Q_NULLPTR);
	~CamView();

private:
	Ui::CamView ui;
};
