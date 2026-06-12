#pragma once

#include <QMainWindow>
#include <QJsonArray>

class ApiClient;
class QLineEdit;
class QComboBox;
class QCheckBox;
class QPushButton;
class QLabel;
class QTableWidget;
class QTabWidget;
class QTimer;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onConnectClicked();
    void onRegisterClicked();
    void onScanClicked();
    void onReportClicked();

private:
    QWidget* buildConnectionBar();
    QWidget* buildScanBar();
    QWidget* buildResults();
    void fillFindings(const QJsonArray& findings);
    void fillExploits(const QJsonArray& exploits);
    void setConnected(bool connected);

    ApiClient* m_api;

    QLineEdit* m_baseUrl;
    QLineEdit* m_email;
    QLineEdit* m_password;
    QLabel*    m_connStatus;

    QLineEdit* m_scanUrl;
    QComboBox* m_type;
    QCheckBox* m_active;
    QLineEdit* m_authToken;
    QPushButton* m_scanBtn;
    QLabel*    m_scanStatus;

    QTabWidget*   m_tabs;
    QTableWidget* m_findings;
    QTableWidget* m_exploits;

    QComboBox*   m_reportFmt;
    QPushButton* m_reportBtn;
    QLabel*      m_reportLink;
    QString      m_reportUrl;

    QTimer* m_poll;
    int     m_currentScan = -1;
};
