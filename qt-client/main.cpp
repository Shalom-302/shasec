#include <QApplication>
#include "MainWindow.h"

// Dark "security console" theme (NanoCore-style dashboard aesthetic): dark
// panels, subtle borders, a blue accent. Pure styling — applied app-wide.
static const char* kDarkTheme = R"qss(
* { font-family: "Segoe UI", "Inter", sans-serif; font-size: 13px; }
QWidget { background: #1b1d24; color: #d6dae2; }
QMainWindow { background: #15161c; }

#HeaderBar {
    background: #11121a; border-bottom: 1px solid #2c2f3a;
}
#HeaderTitle { color: #f2f4f8; font-size: 17px; font-weight: 700; padding: 10px 14px; }
#HeaderTitle #Accent { color: #4aa3ff; }

QGroupBox {
    background: #23252e; border: 1px solid #2f323d; border-radius: 8px;
    margin-top: 14px; padding: 10px;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 12px; padding: 0 6px;
    color: #8b93a6; font-weight: 600; text-transform: uppercase; font-size: 11px;
}

QLineEdit, QComboBox {
    background: #15161c; border: 1px solid #343845; border-radius: 6px;
    padding: 6px 8px; color: #e6e9ef; selection-background-color: #4aa3ff;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #4aa3ff; }
QComboBox::drop-down { border: none; width: 18px; }
QComboBox QAbstractItemView {
    background: #23252e; border: 1px solid #343845; selection-background-color: #4aa3ff;
}

QPushButton {
    background: #2b2e39; border: 1px solid #3a3e4c; border-radius: 6px;
    padding: 7px 14px; color: #e6e9ef; font-weight: 600;
}
QPushButton:hover { background: #343846; border-color: #4aa3ff; }
QPushButton:pressed { background: #1f2129; }
QPushButton:disabled { color: #5a6072; background: #21232b; border-color: #2c2f3a; }
QPushButton#Primary { background: #2563eb; border-color: #2563eb; color: #ffffff; }
QPushButton#Primary:hover { background: #1d4fd7; }

QCheckBox { spacing: 6px; }
QCheckBox::indicator {
    width: 16px; height: 16px; border-radius: 4px;
    border: 1px solid #3a3e4c; background: #15161c;
}
QCheckBox::indicator:checked { background: #4aa3ff; border-color: #4aa3ff; }

QTabWidget::pane { border: 1px solid #2f323d; border-radius: 8px; top: -1px; }
QTabBar::tab {
    background: #1b1d24; color: #8b93a6; padding: 8px 16px;
    border: 1px solid #2f323d; border-bottom: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
}
QTabBar::tab:selected { background: #23252e; color: #f2f4f8; }

QTableWidget {
    background: #1b1d24; alternate-background-color: #20222b;
    gridline-color: #2a2d37; border: none; selection-background-color: #2a3550;
    selection-color: #ffffff;
}
QHeaderView::section {
    background: #15161c; color: #8b93a6; padding: 7px; border: none;
    border-right: 1px solid #2a2d37; border-bottom: 1px solid #2a2d37;
    font-weight: 600; text-transform: uppercase; font-size: 11px;
}
QTableWidget::item { padding: 4px 6px; }

QStatusBar { background: #11121a; color: #8b93a6; border-top: 1px solid #2c2f3a; }
QScrollBar:vertical { background: #15161c; width: 11px; margin: 0; }
QScrollBar::handle:vertical { background: #3a3e4c; border-radius: 5px; min-height: 24px; }
QScrollBar::handle:vertical:hover { background: #4aa3ff; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }

/* Sidebar navigation */
QListWidget#Sidebar {
    background: #11121a; border: none; border-right: 1px solid #2c2f3a;
    outline: 0; padding-top: 8px; font-size: 14px;
}
QListWidget#Sidebar::item {
    padding: 11px 14px; color: #9aa3b5; border-left: 3px solid transparent;
}
QListWidget#Sidebar::item:hover { background: #1a1c25; color: #d6dae2; }
QListWidget#Sidebar::item:selected {
    background: #1d2030; color: #ffffff; border-left: 3px solid #f5c542;
}

/* Dashboard stat cards */
QFrame#Card { background: #23252e; border: 1px solid #2f323d; border-radius: 10px; }
QLabel#CardValue { font-size: 30px; font-weight: 700; color: #4aa3ff; }
QLabel#CardTitle { font-size: 11px; color: #8b93a6; }

/* Page padding */
QStackedWidget > QWidget { background: #15161c; }
QStackedWidget QLabel { background: transparent; }

/* "How it works" guide banner */
QLabel#Guide {
    background: #1d2433; border: 1px solid #2f3a52; border-left: 3px solid #f5c542;
    border-radius: 8px; padding: 10px 14px; color: #c7d0e0; font-size: 12px;
}
)qss";

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("SHASEC Console");
    app.setStyleSheet(QString::fromUtf8(kDarkTheme));

    MainWindow w;
    w.resize(1040, 760);
    w.show();
    return app.exec();
}
