#include "MainWindow.h"
#include "ApiClient.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_api(new ApiClient(this))
    , m_poll(new QTimer(this))
{
    setWindowTitle(QStringLiteral("SHASEC — client d'audit"));

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setSpacing(10);

    // Console header
    auto* header = new QWidget(central);
    header->setObjectName(QStringLiteral("HeaderBar"));
    auto* hl = new QHBoxLayout(header);
    auto* title = new QLabel(QStringLiteral(
        "🛡  <b style='color:#4aa3ff'>SHA</b>SEC"
        "  <span style='color:#8b93a6;font-weight:400'>— Security Audit Console</span>"), header);
    title->setObjectName(QStringLiteral("HeaderTitle"));
    hl->addWidget(title);
    hl->addStretch();
    root->addWidget(header);

    root->addWidget(buildConnectionBar());
    root->addWidget(buildScanBar());
    root->addWidget(buildResults(), 1);
    setCentralWidget(central);

    statusBar()->showMessage(QStringLiteral("Prêt — connecte-toi pour lancer un audit."));
    setConnected(false);

    m_poll->setInterval(4000);
    connect(m_poll, &QTimer::timeout, this, [this]() {
        if (m_currentScan > 0)
            m_api->getScan(m_currentScan);
    });

    // --- wire the API client ---
    connect(m_api, &ApiClient::loggedIn, this, [this](const QString& email) {
        m_connStatus->setText(QStringLiteral("✅ Connecté : %1").arg(email));
        setConnected(true);
    });
    connect(m_api, &ApiClient::registered, this, [this](const QString& email) {
        m_connStatus->setText(QStringLiteral("Compte créé (%1) — connexion…").arg(email));
        m_api->login(m_email->text(), m_password->text());
    });
    connect(m_api, &ApiClient::scanCreated, this, [this](int id, const QString& status) {
        m_currentScan = id;
        m_findings->setRowCount(0);
        m_exploits->setRowCount(0);
        m_reportLink->clear();
        m_scanStatus->setText(QStringLiteral("Scan #%1 : %2…").arg(id).arg(status));
        m_poll->start();
    });
    connect(m_api, &ApiClient::scanStatus, this, [this](int id, const QString& status) {
        m_scanStatus->setText(QStringLiteral("Scan #%1 : %2").arg(id).arg(status));
        if (status == QStringLiteral("completed") || status == QStringLiteral("failed")) {
            m_poll->stop();
            m_scanBtn->setEnabled(true);
            m_reportBtn->setEnabled(status == QStringLiteral("completed"));
            m_api->getFindings(id);
            m_api->getExploits(id);
        }
    });
    connect(m_api, &ApiClient::findingsReady, this, &MainWindow::fillFindings);
    connect(m_api, &ApiClient::exploitsReady, this, &MainWindow::fillExploits);
    connect(m_api, &ApiClient::reportReady, this, [this](const QString& location) {
        m_reportUrl = location;
        m_reportLink->setText(QStringLiteral("Rapport : %1").arg(location));
    });
    connect(m_api, &ApiClient::error, this, [this](const QString& msg) {
        m_poll->stop();
        m_scanBtn->setEnabled(true);
        m_scanStatus->setText(QStringLiteral("⚠️ %1").arg(msg));
    });
}

QWidget* MainWindow::buildConnectionBar()
{
    auto* box = new QGroupBox(QStringLiteral("Connexion"), this);
    auto* l = new QHBoxLayout(box);

    m_baseUrl = new QLineEdit(QStringLiteral("https://shasec.kortexai.dev"), box);
    m_baseUrl->setPlaceholderText(QStringLiteral("URL de l'API"));
    m_email = new QLineEdit(box);
    m_email->setPlaceholderText(QStringLiteral("email"));
    m_password = new QLineEdit(box);
    m_password->setPlaceholderText(QStringLiteral("mot de passe"));
    m_password->setEchoMode(QLineEdit::Password);

    auto* registerBtn = new QPushButton(QStringLiteral("Créer un compte"), box);
    auto* connectBtn = new QPushButton(QStringLiteral("Se connecter"), box);
    connectBtn->setObjectName(QStringLiteral("Primary"));
    m_connStatus = new QLabel(QStringLiteral("Non connecté"), box);

    l->addWidget(new QLabel(QStringLiteral("API:")));
    l->addWidget(m_baseUrl, 2);
    l->addWidget(m_email, 1);
    l->addWidget(m_password, 1);
    l->addWidget(registerBtn);
    l->addWidget(connectBtn);
    l->addWidget(m_connStatus, 1);

    connect(connectBtn, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
    connect(registerBtn, &QPushButton::clicked, this, &MainWindow::onRegisterClicked);
    return box;
}

QWidget* MainWindow::buildScanBar()
{
    auto* box = new QGroupBox(QStringLiteral("Nouveau scan"), this);
    auto* l = new QHBoxLayout(box);

    m_scanUrl = new QLineEdit(box);
    m_scanUrl->setPlaceholderText(QStringLiteral("https://cible.exemple.com"));
    m_type = new QComboBox(box);
    m_type->addItems({"api", "website", "graphql", "host"});
    m_active = new QCheckBox(QStringLiteral("Exploitation active"), box);
    m_authToken = new QLineEdit(box);
    m_authToken->setPlaceholderText(QStringLiteral("JWT cible (optionnel, pour JWT/BFLA)"));
    m_scanBtn = new QPushButton(QStringLiteral("Lancer le scan"), box);
    m_scanBtn->setObjectName(QStringLiteral("Primary"));
    m_scanStatus = new QLabel(box);

    l->addWidget(new QLabel(QStringLiteral("Cible:")));
    l->addWidget(m_scanUrl, 2);
    l->addWidget(m_type);
    l->addWidget(m_active);
    l->addWidget(m_authToken, 1);
    l->addWidget(m_scanBtn);

    connect(m_scanBtn, &QPushButton::clicked, this, &MainWindow::onScanClicked);

    auto* wrap = new QWidget(this);
    auto* v = new QVBoxLayout(wrap);
    v->setContentsMargins(0, 0, 0, 0);
    v->addWidget(box);
    v->addWidget(m_scanStatus);
    return wrap;
}

QWidget* MainWindow::buildResults()
{
    m_tabs = new QTabWidget(this);

    m_findings = new QTableWidget(0, 4, this);
    m_findings->setHorizontalHeaderLabels({"Sévérité", "Titre", "Scanner", "Description"});
    m_findings->horizontalHeader()->setStretchLastSection(true);
    m_findings->setEditTriggers(QAbstractItemView::NoEditTriggers);

    m_exploits = new QTableWidget(0, 6, this);
    m_exploits->setHorizontalHeaderLabels({"Sévérité", "Confirmé", "Catégorie", "Module", "Titre", "Impact"});
    m_exploits->horizontalHeader()->setStretchLastSection(true);
    m_exploits->setEditTriggers(QAbstractItemView::NoEditTriggers);

    m_tabs->addTab(m_findings, QStringLiteral("Findings"));
    m_tabs->addTab(m_exploits, QStringLiteral("Preuves d'exploitation"));

    // Report bar
    auto* reportBox = new QGroupBox(QStringLiteral("Rapport"), this);
    auto* rl = new QHBoxLayout(reportBox);
    m_reportFmt = new QComboBox(reportBox);
    m_reportFmt->addItems({"pdf", "html", "markdown", "json"});
    m_reportBtn = new QPushButton(QStringLiteral("Générer"), reportBox);
    m_reportBtn->setObjectName(QStringLiteral("Primary"));
    auto* openBtn = new QPushButton(QStringLiteral("Ouvrir"), reportBox);
    m_reportLink = new QLabel(reportBox);
    m_reportLink->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rl->addWidget(new QLabel(QStringLiteral("Format:")));
    rl->addWidget(m_reportFmt);
    rl->addWidget(m_reportBtn);
    rl->addWidget(openBtn);
    rl->addWidget(m_reportLink, 1);

    connect(m_reportBtn, &QPushButton::clicked, this, &MainWindow::onReportClicked);
    connect(openBtn, &QPushButton::clicked, this, [this]() {
        if (!m_reportUrl.isEmpty())
            QDesktopServices::openUrl(QUrl(m_reportUrl));
    });

    auto* wrap = new QWidget(this);
    auto* v = new QVBoxLayout(wrap);
    v->setContentsMargins(0, 0, 0, 0);
    v->addWidget(m_tabs, 1);
    v->addWidget(reportBox);
    return wrap;
}

void MainWindow::setConnected(bool connected)
{
    m_scanBtn->setEnabled(connected);
    m_reportBtn->setEnabled(false);
}

void MainWindow::onConnectClicked()
{
    m_api->setBaseUrl(m_baseUrl->text());
    m_connStatus->setText(QStringLiteral("Connexion…"));
    m_api->login(m_email->text(), m_password->text());
}

void MainWindow::onRegisterClicked()
{
    m_api->setBaseUrl(m_baseUrl->text());
    m_connStatus->setText(QStringLiteral("Création du compte…"));
    m_api->registerUser(m_email->text(), m_password->text());
}

void MainWindow::onScanClicked()
{
    if (m_scanUrl->text().trimmed().isEmpty()) {
        m_scanStatus->setText(QStringLiteral("⚠️ Renseigne une URL cible"));
        return;
    }
    m_scanBtn->setEnabled(false);
    m_scanStatus->setText(QStringLiteral("Création du scan…"));
    m_api->quickScan(m_scanUrl->text().trimmed(), m_type->currentText(),
                     m_active->isChecked(), m_authToken->text().trimmed());
}

void MainWindow::onReportClicked()
{
    if (m_currentScan > 0)
        m_api->generateReport(m_currentScan, m_reportFmt->currentText());
}

static QTableWidgetItem* item(const QString& text)
{
    return new QTableWidgetItem(text);
}

void MainWindow::fillFindings(const QJsonArray& findings)
{
    m_findings->setRowCount(0);
    for (const auto& v : findings) {
        const QJsonObject f = v.toObject();
        const int row = m_findings->rowCount();
        m_findings->insertRow(row);
        m_findings->setItem(row, 0, item(f.value("severity").toString()));
        m_findings->setItem(row, 1, item(f.value("title").toString()));
        m_findings->setItem(row, 2, item(f.value("plugin").toString()));
        m_findings->setItem(row, 3, item(f.value("description").toString()));
    }
    m_tabs->setTabText(0, QStringLiteral("Findings (%1)").arg(findings.size()));
}

void MainWindow::fillExploits(const QJsonArray& exploits)
{
    m_exploits->setRowCount(0);
    for (const auto& v : exploits) {
        const QJsonObject e = v.toObject();
        const int row = m_exploits->rowCount();
        m_exploits->insertRow(row);
        m_exploits->setItem(row, 0, item(e.value("severity").toString()));
        m_exploits->setItem(row, 1, item(e.value("confirmed").toBool() ? QStringLiteral("✔") : QString()));
        m_exploits->setItem(row, 2, item(e.value("category").toString()));
        m_exploits->setItem(row, 3, item(e.value("module").toString()));
        m_exploits->setItem(row, 4, item(e.value("title").toString()));
        m_exploits->setItem(row, 5, item(e.value("impact").toString()));
    }
    m_tabs->setTabText(1, QStringLiteral("Preuves (%1)").arg(exploits.size()));
}
