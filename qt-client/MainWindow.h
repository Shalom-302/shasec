#pragma once

#include <QMainWindow>
#include <QJsonArray>
#include <QHash>

class ApiClient;
class QListWidget;
class QStackedWidget;
class QLineEdit;
class QComboBox;
class QCheckBox;
class QPushButton;
class QLabel;
class QTableWidget;
class QTabWidget;
class QTimer;

// SHASEC desktop console — sidebar (Dashboard / Cibles / Scans / Rapports /
// Réglages) + stacked pages, dark theme. Drives the SHASEC REST API.
class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private:
    QWidget* buildSidebar();
    QWidget* buildDashboard();
    QWidget* buildTargets();
    QWidget* buildScans();
    QWidget* buildReports();
    QWidget* buildSettings();

    void refreshData();
    void fillScans(const QJsonArray& scans);
    void fillTargets(const QJsonArray& targets);
    void fillFindings(const QJsonArray& findings);
    void fillExploits(const QJsonArray& exploits);
    void selectScan(int id, const QString& label);
    void setConnected(bool connected);

    ApiClient* m_api;
    QListWidget* m_sidebar;
    QStackedWidget* m_stack;

    // Compte / connexion
    QLineEdit* m_email;
    QLineEdit* m_password;
    QLabel*    m_connStatus;

    // Dashboard
    QLabel* m_cardScans;
    QLabel* m_cardTargets;
    QLabel* m_cardFindings;
    QLabel* m_cardProofs;
    QTableWidget* m_recent;

    // Cibles
    QTableWidget* m_targetsTable;

    // Scans
    QLineEdit*   m_scanUrl;
    QComboBox*   m_type;
    QCheckBox*   m_active;
    QLineEdit*   m_authToken;
    QPushButton* m_scanBtn;
    QTableWidget* m_scansTable;
    QTabWidget*  m_detailTabs;
    QTableWidget* m_findings;
    QTableWidget* m_exploits;
    QLabel*      m_scanStatus;

    // Rapports
    QLabel*      m_reportScan;
    QComboBox*   m_reportFmt;
    QPushButton* m_reportGen;
    QPushButton* m_reportDl;
    QLabel*      m_reportInfo;

    QTimer* m_poll;
    int     m_currentScan = -1;
    QHash<int, QString> m_targetUrl;   // target_id -> url
    QHash<int, QString> m_targetType;  // target_id -> type
    QJsonArray m_findingsData;         // raw findings (for the detail dialog)
    QJsonArray m_exploitsData;         // raw exploits (for the detail dialog)
};
