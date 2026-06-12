#include "MainWindow.h"
#include "ApiClient.h"

#include <QAbstractItemView>
#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextBrowser>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

static QWidget* statCard(const QString& title, QLabel*& valueOut)
{
    auto* card = new QFrame;
    card->setObjectName(QStringLiteral("Card"));
    auto* v = new QVBoxLayout(card);
    valueOut = new QLabel(QStringLiteral("—"));
    valueOut->setObjectName(QStringLiteral("CardValue"));
    auto* t = new QLabel(title);
    t->setObjectName(QStringLiteral("CardTitle"));
    v->addWidget(valueOut);
    v->addWidget(t);
    return card;
}

static QTableWidget* makeTable(const QStringList& headers)
{
    auto* t = new QTableWidget(0, headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->horizontalHeader()->setStretchLastSection(true);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->verticalHeader()->setVisible(false);
    return t;
}

static QString severityMeaning(const QString& s)
{
    if (s == QStringLiteral("critical")) return QStringLiteral("🔴 Critique — exploitable, impact majeur. Priorité absolue.");
    if (s == QStringLiteral("high")) return QStringLiteral("🔴 Élevé — risque important, à corriger vite.");
    if (s == QStringLiteral("medium")) return QStringLiteral("🟠 Moyen — à corriger.");
    if (s == QStringLiteral("low")) return QStringLiteral("🔵 Faible — durcissement / hygiène.");
    return QStringLiteral("⚪ Info — informatif, pas une faille en soi.");
}

static QString esc(const QString& s) { return s.toHtmlEscaped(); }

static void showDetailDialog(QWidget* parent, const QString& title, const QString& html)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(title);
    dlg.resize(660, 480);
    auto* v = new QVBoxLayout(&dlg);
    auto* br = new QTextBrowser(&dlg);
    br->setOpenExternalLinks(true);
    br->setHtml(html);
    v->addWidget(br);
    auto* close = new QPushButton(QStringLiteral("Fermer"), &dlg);
    QObject::connect(close, &QPushButton::clicked, &dlg, &QDialog::accept);
    v->addWidget(close, 0, Qt::AlignRight);
    dlg.exec();
}

static void showFindingDetail(QWidget* parent, const QJsonObject& f)
{
    QString h = QStringLiteral("<h3>%1</h3>").arg(esc(f.value(QStringLiteral("title")).toString()));
    h += QStringLiteral("<p><b>Sévérité :</b> %1</p>").arg(severityMeaning(f.value(QStringLiteral("severity")).toString()));
    h += QStringLiteral("<p><b>Détecté par :</b> %1</p>").arg(esc(f.value(QStringLiteral("plugin")).toString()));
    const QString d = f.value(QStringLiteral("description")).toString();
    if (!d.isEmpty()) h += QStringLiteral("<p><b>Ce que c'est :</b><br>%1</p>").arg(esc(d));
    const QString ev = f.value(QStringLiteral("evidence")).toString();
    if (!ev.isEmpty()) h += QStringLiteral("<p><b>Preuve :</b><br><code>%1</code></p>").arg(esc(ev));
    const QString rec = f.value(QStringLiteral("recommendation")).toString();
    if (!rec.isEmpty()) h += QStringLiteral("<p><b>✅ Comment corriger :</b><br>%1</p>").arg(esc(rec));
    showDetailDialog(parent, QStringLiteral("Détail du finding"), h);
}

static void showExploitDetail(QWidget* parent, const QJsonObject& e)
{
    QString h = QStringLiteral("<h3>%1</h3>").arg(esc(e.value(QStringLiteral("title")).toString()));
    h += QStringLiteral("<p><b>Sévérité :</b> %1</p>").arg(severityMeaning(e.value(QStringLiteral("severity")).toString()));
    h += QStringLiteral("<p><b>Statut :</b> %1</p>").arg(
        e.value(QStringLiteral("confirmed")).toBool()
            ? QStringLiteral("✔ <span style='color:#15803d'>CONFIRMÉ</span> — faille prouvée")
            : QStringLiteral("non confirmé — à vérifier à l'œil"));
    h += QStringLiteral("<p><b>Type :</b> %1 · module %2</p>")
             .arg(esc(e.value(QStringLiteral("category")).toString()), esc(e.value(QStringLiteral("module")).toString()));
    const QString imp = e.value(QStringLiteral("impact")).toString();
    if (!imp.isEmpty()) h += QStringLiteral("<p><b>Impact :</b><br>%1</p>").arg(esc(imp));
    const QString req = e.value(QStringLiteral("request")).toString();
    if (!req.isEmpty())
        h += QStringLiteral("<p><b>Requête envoyée :</b></p><pre style='background:#0f1626;color:#cdd6e4;padding:8px;border-radius:6px'>%1</pre>").arg(esc(req));
    const QString resp = e.value(QStringLiteral("response")).toString();
    if (!resp.isEmpty())
        h += QStringLiteral("<p><b>Réponse (la preuve) :</b></p><pre style='background:#0f1626;color:#cdd6e4;padding:8px;border-radius:6px'>%1</pre>").arg(esc(resp));
    showDetailDialog(parent, QStringLiteral("Détail de la preuve"), h);
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , m_api(new ApiClient(this))
    , m_poll(new QTimer(this))
{
    setWindowTitle(QStringLiteral("SHASEC — Security Audit Console"));

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

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

    auto* bodyW = new QWidget(central);
    auto* body = new QHBoxLayout(bodyW);
    body->setContentsMargins(0, 0, 0, 0);
    body->setSpacing(0);
    body->addWidget(buildSidebar());
    m_stack = new QStackedWidget(bodyW);
    m_stack->addWidget(buildDashboard());  // 0
    m_stack->addWidget(buildTargets());    // 1
    m_stack->addWidget(buildScans());      // 2
    m_stack->addWidget(buildReports());    // 3
    m_stack->addWidget(buildSettings());   // 4
    body->addWidget(m_stack, 1);
    root->addWidget(bodyW, 1);
    setCentralWidget(central);

    connect(m_sidebar, &QListWidget::currentRowChanged, m_stack, &QStackedWidget::setCurrentIndex);

#ifdef SHASEC_HAS_WEBSOCKETS
    m_poll->setInterval(15000);  // WebSocket is primary; this poll is just a backstop
#else
    m_poll->setInterval(4000);   // no WebSockets module — polling is the live mechanism
#endif
    connect(m_poll, &QTimer::timeout, this, [this]() {
        if (m_currentScan > 0)
            m_api->getScan(m_currentScan);
    });

    connect(m_api, &ApiClient::loggedIn, this, [this](const QString& e) {
        m_connStatus->setText(QStringLiteral("✅ Connecté : %1").arg(e));
        setConnected(true);
        statusBar()->showMessage(QStringLiteral("Connecté — %1").arg(e));
        m_sidebar->setCurrentRow(0);
        refreshData();
    });
    connect(m_api, &ApiClient::registered, this, [this](const QString&) {
        statusBar()->showMessage(QStringLiteral("Compte créé — connexion…"));
        m_api->login(m_email->text(), m_password->text());
    });
    connect(m_api, &ApiClient::targetsReady, this, [this](const QJsonArray& a) {
        fillTargets(a);
        m_api->getScans();
    });
    connect(m_api, &ApiClient::scansReady, this, &MainWindow::fillScans);
    connect(m_api, &ApiClient::scanCreated, this, [this](int id, const QString& s) {
        m_currentScan = id;
        m_scanStatus->setText(QStringLiteral("Scan #%1 : %2…").arg(id).arg(s));
        statusBar()->showMessage(QStringLiteral("Scan #%1 lancé").arg(id));
        m_api->openScanSocket(id);  // live progress
        m_poll->start();            // backstop
    });
    connect(m_api, &ApiClient::progress, this, [this](int id, const QString& event, const QString& msg) {
        if (id != m_currentScan)
            return;
        m_scanStatus->setText(QStringLiteral("Scan #%1 · %2  %3").arg(id).arg(event).arg(msg));
        statusBar()->showMessage(QStringLiteral("%1 — %2").arg(event, msg));
    });
    connect(m_api, &ApiClient::scanStatus, this, [this](int id, const QString& s) {
        m_scanStatus->setText(QStringLiteral("Scan #%1 : %2").arg(id).arg(s));
        if (s == QStringLiteral("completed") || s == QStringLiteral("failed")) {
            m_poll->stop();
            m_scanBtn->setEnabled(true);
            refreshData();
            selectScan(id, QStringLiteral("scan #%1").arg(id));
        }
    });
    connect(m_api, &ApiClient::findingsReady, this, &MainWindow::fillFindings);
    connect(m_api, &ApiClient::exploitsReady, this, &MainWindow::fillExploits);
    connect(m_api, &ApiClient::targetAuthorized, this, [this]() { refreshData(); });
    connect(m_api, &ApiClient::analysisReady, this, [this](const QJsonObject& a) {
        if (a.isEmpty()) {
            QMessageBox::information(this, QStringLiteral("Analyse IA"),
                QStringLiteral("Pas d'analyse IA pour ce scan (clé DeepSeek absente, ou scan sans IA)."));
            return;
        }
        QMessageBox box(this);
        box.setWindowTitle(QStringLiteral("Analyse IA — DeepSeek"));
        box.setIcon(QMessageBox::Information);
        box.setText(QStringLiteral("Score : %1/100  (%2)\n\n%3")
                        .arg(a.value(QStringLiteral("score")).toInt())
                        .arg(a.value(QStringLiteral("provider")).toString())
                        .arg(a.value(QStringLiteral("summary")).toString()));
        box.setDetailedText(QStringLiteral("— IMPACTS —\n%1\n\n— RECOMMANDATIONS —\n%2")
                                .arg(a.value(QStringLiteral("impacts")).toString())
                                .arg(a.value(QStringLiteral("recommendations")).toString()));
        box.exec();
    });
    connect(m_api, &ApiClient::scanCancelled, this, [this]() {
        statusBar()->showMessage(QStringLiteral("Scan annulé"));
        refreshData();
    });
    connect(m_api, &ApiClient::scanDeleted, this, [this]() {
        statusBar()->showMessage(QStringLiteral("Scan supprimé"));
        m_findings->setRowCount(0);
        m_exploits->setRowCount(0);
        refreshData();
    });
    connect(m_api, &ApiClient::targetDeleted, this, [this]() {
        statusBar()->showMessage(QStringLiteral("Cible supprimée"));
        refreshData();
    });
    connect(m_api, &ApiClient::reportReady, this, [this](const QString& loc) {
        m_reportInfo->setText(QStringLiteral("Stocké : %1").arg(loc));
    });
    connect(m_api, &ApiClient::reportDownloaded, this, [this](const QByteArray& data, const QString& fn) {
        const QString path = QDir::temp().filePath(fn);
        QFile f(path);
        if (f.open(QIODevice::WriteOnly)) {
            f.write(data);
            f.close();
            m_reportInfo->setText(QStringLiteral("Téléchargé : %1").arg(path));
            QDesktopServices::openUrl(QUrl::fromLocalFile(path));
        } else {
            m_reportInfo->setText(QStringLiteral("Impossible d'écrire %1").arg(path));
        }
    });
    connect(m_api, &ApiClient::error, this, [this](const QString& m) {
        m_poll->stop();
        m_scanBtn->setEnabled(true);
        m_connStatus->setText(QStringLiteral("⚠️ %1").arg(m));
        m_scanStatus->setText(QStringLiteral("⚠️ %1").arg(m));
        statusBar()->showMessage(QStringLiteral("⚠️ %1").arg(m));
    });

    setConnected(false);
    m_sidebar->setCurrentRow(4);  // start on Compte — connect first
    statusBar()->showMessage(QStringLiteral("Connecte-toi pour démarrer."));
}

QWidget* MainWindow::buildSidebar()
{
    m_sidebar = new QListWidget(this);
    m_sidebar->setObjectName(QStringLiteral("Sidebar"));
    m_sidebar->setFixedWidth(196);
    m_sidebar->addItem(QStringLiteral("  📊   Dashboard"));
    m_sidebar->addItem(QStringLiteral("  🎯   Cibles"));
    m_sidebar->addItem(QStringLiteral("  🛰   Scans"));
    m_sidebar->addItem(QStringLiteral("  📄   Rapports"));
    m_sidebar->addItem(QStringLiteral("  👤   Compte"));
    return m_sidebar;
}

QWidget* MainWindow::buildDashboard()
{
    auto* page = new QWidget(this);
    auto* v = new QVBoxLayout(page);
    v->addWidget(new QLabel(QStringLiteral("<h2 style='color:#f2f4f8'>Dashboard</h2>")));

    auto* guide = new QLabel(QStringLiteral(
        "<b>Comment ça marche :</b>&nbsp; ①&nbsp;Onglet <b>Scans</b> → URL + type, coche "
        "<i>Exploitation active</i> pour les preuves, clique <b>Lancer</b>.&nbsp;&nbsp; "
        "②&nbsp;Clique un scan → <b>Findings</b> &amp; <b>Preuves</b> (clic-droit = rapport, "
        "analyse IA, relancer, supprimer).&nbsp;&nbsp; ③&nbsp;Onglet <b>Rapports</b> → "
        "<b>Télécharger &amp; ouvrir</b> le PDF."));
    guide->setObjectName(QStringLiteral("Guide"));
    guide->setWordWrap(true);
    v->addWidget(guide);

    auto* cards = new QHBoxLayout();
    cards->addWidget(statCard(QStringLiteral("Scans"), m_cardScans));
    cards->addWidget(statCard(QStringLiteral("Cibles"), m_cardTargets));
    cards->addWidget(statCard(QStringLiteral("Findings (sélection)"), m_cardFindings));
    cards->addWidget(statCard(QStringLiteral("Preuves (sélection)"), m_cardProofs));
    v->addLayout(cards);

    v->addWidget(new QLabel(QStringLiteral("<b>Scans récents</b>")));
    m_recent = makeTable({"#", "Cible", "Type", "Statut"});
    v->addWidget(m_recent, 1);
    return page;
}

QWidget* MainWindow::buildTargets()
{
    auto* page = new QWidget(this);
    auto* v = new QVBoxLayout(page);
    v->addWidget(new QLabel(QStringLiteral("<h2 style='color:#f2f4f8'>Cibles</h2>")));
    auto* hint = new QLabel(QStringLiteral(
        "Les API / sites que tu audites. <b>Clic-droit</b> sur une ligne : nouveau scan, "
        "autoriser/révoquer, supprimer."));
    hint->setStyleSheet(QStringLiteral("color:#8b93a6"));
    hint->setWordWrap(true);
    v->addWidget(hint);
    m_targetsTable = makeTable({"#", "Nom", "URL", "Type", "Autorisée"});
    v->addWidget(m_targetsTable, 1);

    m_targetsTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_targetsTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        QTableWidgetItem* it = m_targetsTable->itemAt(pos);
        if (!it)
            return;
        const int row = it->row();
        const int id = m_targetsTable->item(row, 0)->data(Qt::UserRole).toInt();
        if (id <= 0)
            return;
        const QString url = m_targetsTable->item(row, 2)->text();
        const QString type = m_targetsTable->item(row, 3)->text();
        const bool authorized = m_targetsTable->item(row, 4)->text() == QStringLiteral("✔");

        QMenu menu(this);
        QAction* aScan = menu.addAction(QStringLiteral("🛰  Nouveau scan sur cette cible"));
        QAction* aAuth = menu.addAction(authorized ? QStringLiteral("🔒  Révoquer l'autorisation")
                                                    : QStringLiteral("✅  Autoriser"));
        menu.addSeparator();
        QAction* aDel = menu.addAction(QStringLiteral("🗑  Supprimer la cible"));

        QAction* chosen = menu.exec(m_targetsTable->viewport()->mapToGlobal(pos));
        if (chosen == aScan) {
            m_scanUrl->setText(url);
            const int idx = m_type->findText(type);
            if (idx >= 0)
                m_type->setCurrentIndex(idx);
            m_sidebar->setCurrentRow(2);  // Scans
        } else if (chosen == aAuth) {
            m_api->authorizeTarget(id, !authorized);
        } else if (chosen == aDel) {
            if (QMessageBox::question(this, QStringLiteral("Supprimer"),
                    QStringLiteral("Supprimer la cible « %1 » ?").arg(url)) == QMessageBox::Yes)
                m_api->deleteTarget(id);
        }
    });
    return page;
}

QWidget* MainWindow::buildScans()
{
    auto* page = new QWidget(this);
    auto* v = new QVBoxLayout(page);
    v->addWidget(new QLabel(QStringLiteral("<h2 style='color:#f2f4f8'>Scans</h2>")));
    auto* shint = new QLabel(QStringLiteral(
        "URL d'une cible <b>autorisée</b> + type ; coche <i>Exploitation active</i> pour les preuves. "
        "<b>Clique</b> un scan = détails ; <b>clic-droit</b> = rapport / IA / relancer / supprimer."));
    shint->setStyleSheet(QStringLiteral("color:#8b93a6"));
    shint->setWordWrap(true);
    v->addWidget(shint);

    auto* box = new QGroupBox(QStringLiteral("Nouveau scan"), page);
    auto* hb = new QHBoxLayout(box);
    m_scanUrl = new QLineEdit(box);
    m_scanUrl->setPlaceholderText(QStringLiteral("https://cible.exemple.com"));
    m_type = new QComboBox(box);
    m_type->addItems({"api", "website", "graphql", "host"});
    m_active = new QCheckBox(QStringLiteral("Exploitation active"), box);
    m_authToken = new QLineEdit(box);
    m_authToken->setPlaceholderText(QStringLiteral("JWT cible (optionnel)"));
    m_scanBtn = new QPushButton(QStringLiteral("Lancer"), box);
    m_scanBtn->setObjectName(QStringLiteral("Primary"));
    hb->addWidget(m_scanUrl, 2);
    hb->addWidget(m_type);
    hb->addWidget(m_active);
    hb->addWidget(m_authToken, 1);
    hb->addWidget(m_scanBtn);
    v->addWidget(box);

    m_scansTable = makeTable({"#", "Cible", "Type", "Statut", "Démarré", "Exploit"});
    v->addWidget(m_scansTable, 1);
    m_scanStatus = new QLabel(page);
    v->addWidget(m_scanStatus);

    auto* legend = new QLabel(QStringLiteral(
        "<b>Findings</b> = problèmes potentiels repérés · <b>Preuves</b> = failles réellement "
        "exploitées. <b>Double-clique</b> une ligne → cause + preuve + comment corriger."));
    legend->setStyleSheet(QStringLiteral("color:#8b93a6"));
    legend->setWordWrap(true);
    v->addWidget(legend);

    m_detailTabs = new QTabWidget(page);
    m_findings = makeTable({"Sévérité", "Titre", "Scanner", "Description"});
    m_exploits = makeTable({"Sévérité", "Confirmé", "Catégorie", "Module", "Titre", "Impact"});
    m_detailTabs->addTab(m_findings, QStringLiteral("Findings (problèmes)"));
    m_detailTabs->addTab(m_exploits, QStringLiteral("Preuves (failles prouvées)"));
    v->addWidget(m_detailTabs, 1);

    connect(m_findings, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* it) {
        const int r = it->row();
        if (r >= 0 && r < m_findingsData.size())
            showFindingDetail(this, m_findingsData.at(r).toObject());
    });
    connect(m_exploits, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* it) {
        const int r = it->row();
        if (r >= 0 && r < m_exploitsData.size())
            showExploitDetail(this, m_exploitsData.at(r).toObject());
    });

    connect(m_scanBtn, &QPushButton::clicked, this, [this]() {
        if (m_scanUrl->text().trimmed().isEmpty()) {
            m_scanStatus->setText(QStringLiteral("⚠️ Renseigne une URL cible"));
            return;
        }
        m_scanBtn->setEnabled(false);
        m_scanStatus->setText(QStringLiteral("Création du scan…"));
        m_api->quickScan(m_scanUrl->text().trimmed(), m_type->currentText(),
                         m_active->isChecked(), m_authToken->text().trimmed());
    });
    connect(m_scansTable, &QTableWidget::itemSelectionChanged, this, [this]() {
        const auto sel = m_scansTable->selectedItems();
        if (sel.isEmpty())
            return;
        const int row = sel.first()->row();
        const int id = m_scansTable->item(row, 0)->data(Qt::UserRole).toInt();
        if (id > 0)
            selectScan(id, m_scansTable->item(row, 1)->text());
    });

    // Right-click context menu (admin-style actions on a scan)
    m_scansTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_scansTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        QTableWidgetItem* it = m_scansTable->itemAt(pos);
        if (!it)
            return;
        const int row = it->row();
        const int id = m_scansTable->item(row, 0)->data(Qt::UserRole).toInt();
        if (id <= 0)
            return;
        const QString url = m_scansTable->item(row, 1)->text();
        const QString type = m_scansTable->item(row, 2)->text();
        const QString status = m_scansTable->item(row, 3)->text();

        QMenu menu(this);
        QAction* aDetails = menu.addAction(QStringLiteral("🔎  Voir détails (findings/preuves)"));
        QAction* aReport = menu.addAction(QStringLiteral("📄  Générer le rapport"));
        QAction* aAI = menu.addAction(QStringLiteral("🤖  Voir l'analyse IA"));
        menu.addSeparator();
        QAction* aRecon = menu.addAction(QStringLiteral("↻  Relancer (recon)"));
        QAction* aExploit = menu.addAction(QStringLiteral("⚔  Relancer (exploitation active)"));
        menu.addSeparator();
        QAction* aCancel = menu.addAction(QStringLiteral("✖  Annuler le scan"));
        aCancel->setEnabled(status == QStringLiteral("running") || status == QStringLiteral("pending"));
        QAction* aDelete = menu.addAction(QStringLiteral("🗑  Supprimer le scan"));

        QAction* chosen = menu.exec(m_scansTable->viewport()->mapToGlobal(pos));
        if (chosen == aDetails) {
            selectScan(id, url);
        } else if (chosen == aReport) {
            selectScan(id, url);
            m_sidebar->setCurrentRow(3);  // Rapports
        } else if (chosen == aAI) {
            m_api->getAnalysis(id);
        } else if (chosen == aRecon) {
            m_api->quickScan(url, type, false);
        } else if (chosen == aExploit) {
            m_api->quickScan(url, type, true);
        } else if (chosen == aCancel) {
            m_api->cancelScan(id);
        } else if (chosen == aDelete) {
            if (QMessageBox::question(this, QStringLiteral("Supprimer"),
                    QStringLiteral("Supprimer le scan #%1 et ses résultats ?").arg(id)) == QMessageBox::Yes)
                m_api->deleteScan(id);
        }
    });
    return page;
}

QWidget* MainWindow::buildReports()
{
    auto* page = new QWidget(this);
    auto* v = new QVBoxLayout(page);
    v->addWidget(new QLabel(QStringLiteral("<h2 style='color:#f2f4f8'>Rapports</h2>")));
    auto* rhint = new QLabel(QStringLiteral(
        "Sélectionne d'abord un scan (onglet Scans), puis <b>Télécharger &amp; ouvrir</b> "
        "(PDF recommandé)."));
    rhint->setStyleSheet(QStringLiteral("color:#8b93a6"));
    rhint->setWordWrap(true);
    v->addWidget(rhint);

    auto* box = new QGroupBox(QStringLiteral("Générer / télécharger"), page);
    auto* hb = new QHBoxLayout(box);
    m_reportScan = new QLabel(QStringLiteral("Aucun scan sélectionné"), box);
    m_reportFmt = new QComboBox(box);
    m_reportFmt->addItems({"pdf", "html", "markdown", "json"});
    m_reportGen = new QPushButton(QStringLiteral("Générer (stocker)"), box);
    m_reportDl = new QPushButton(QStringLiteral("Télécharger & ouvrir"), box);
    m_reportDl->setObjectName(QStringLiteral("Primary"));
    hb->addWidget(m_reportScan, 1);
    hb->addWidget(new QLabel(QStringLiteral("Format:")));
    hb->addWidget(m_reportFmt);
    hb->addWidget(m_reportGen);
    hb->addWidget(m_reportDl);
    v->addWidget(box);

    m_reportInfo = new QLabel(page);
    m_reportInfo->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_reportInfo->setWordWrap(true);
    v->addWidget(m_reportInfo);
    v->addStretch();

    connect(m_reportGen, &QPushButton::clicked, this, [this]() {
        if (m_currentScan > 0) {
            m_reportInfo->setText(QStringLiteral("Génération…"));
            m_api->generateReport(m_currentScan, m_reportFmt->currentText());
        }
    });
    connect(m_reportDl, &QPushButton::clicked, this, [this]() {
        if (m_currentScan > 0) {
            m_reportInfo->setText(QStringLiteral("Téléchargement…"));
            m_api->downloadReport(m_currentScan, m_reportFmt->currentText());
        }
    });
    return page;
}

QWidget* MainWindow::buildSettings()
{
    auto* page = new QWidget(this);
    auto* v = new QVBoxLayout(page);
    v->addWidget(new QLabel(QStringLiteral("<h2 style='color:#f2f4f8'>Compte</h2>")));

    auto* box = new QGroupBox(QStringLiteral("Connexion"), page);
    auto* form = new QVBoxLayout(box);
    m_email = new QLineEdit(box);
    m_email->setPlaceholderText(QStringLiteral("email"));
    m_password = new QLineEdit(box);
    m_password->setPlaceholderText(QStringLiteral("mot de passe"));
    m_password->setEchoMode(QLineEdit::Password);

    auto* regBtn = new QPushButton(QStringLiteral("Créer un compte"), box);
    auto* connBtn = new QPushButton(QStringLiteral("Se connecter"), box);
    connBtn->setObjectName(QStringLiteral("Primary"));
    auto* row3 = new QHBoxLayout();
    row3->addWidget(regBtn);
    row3->addWidget(connBtn);
    row3->addStretch();
    m_connStatus = new QLabel(QStringLiteral("Non connecté"), box);

    form->addWidget(m_email);
    form->addWidget(m_password);
    form->addLayout(row3);
    form->addWidget(m_connStatus);
    v->addWidget(box);
    v->addStretch();

    // Pressing Enter in either field logs in.
    connect(m_password, &QLineEdit::returnPressed, connBtn, &QPushButton::click);

    connect(connBtn, &QPushButton::clicked, this, [this]() {
        m_connStatus->setText(QStringLiteral("Connexion…"));
        m_api->login(m_email->text(), m_password->text());
    });
    connect(regBtn, &QPushButton::clicked, this, [this]() {
        m_connStatus->setText(QStringLiteral("Création du compte…"));
        m_api->registerUser(m_email->text(), m_password->text());
    });
    return page;
}

void MainWindow::setConnected(bool connected)
{
    m_scanBtn->setEnabled(connected);
    m_reportGen->setEnabled(false);
    m_reportDl->setEnabled(false);
}

void MainWindow::refreshData()
{
    if (m_api->isAuthenticated())
        m_api->getTargets();  // -> targetsReady -> getScans
}

void MainWindow::selectScan(int id, const QString& label)
{
    m_currentScan = id;
    m_reportScan->setText(QStringLiteral("Scan #%1 — %2").arg(id).arg(label));
    m_reportGen->setEnabled(true);
    m_reportDl->setEnabled(true);
    m_api->getFindings(id);
    m_api->getExploits(id);
}

void MainWindow::fillTargets(const QJsonArray& targets)
{
    m_targetUrl.clear();
    m_targetType.clear();
    m_targetsTable->setRowCount(0);
    for (const auto& v : targets) {
        const QJsonObject t = v.toObject();
        const int id = t.value(QStringLiteral("id")).toInt();
        m_targetUrl[id] = t.value(QStringLiteral("url")).toString();
        m_targetType[id] = t.value(QStringLiteral("type")).toString();
        const int r = m_targetsTable->rowCount();
        m_targetsTable->insertRow(r);
        auto* idItem = new QTableWidgetItem(QString::number(id));
        idItem->setData(Qt::UserRole, id);
        m_targetsTable->setItem(r, 0, idItem);
        m_targetsTable->setItem(r, 1, new QTableWidgetItem(t.value(QStringLiteral("name")).toString()));
        m_targetsTable->setItem(r, 2, new QTableWidgetItem(t.value(QStringLiteral("url")).toString()));
        m_targetsTable->setItem(r, 3, new QTableWidgetItem(t.value(QStringLiteral("type")).toString()));
        m_targetsTable->setItem(r, 4, new QTableWidgetItem(
            t.value(QStringLiteral("is_authorized")).toBool() ? QStringLiteral("✔") : QStringLiteral("—")));
    }
    m_cardTargets->setText(QString::number(targets.size()));
}

void MainWindow::fillScans(const QJsonArray& scans)
{
    m_scansTable->setRowCount(0);
    m_recent->setRowCount(0);
    int shown = 0;
    for (const auto& v : scans) {
        const QJsonObject s = v.toObject();
        const int id = s.value(QStringLiteral("id")).toInt();
        const int tid = s.value(QStringLiteral("target_id")).toInt();
        const QString url = m_targetUrl.value(tid, QStringLiteral("cible #%1").arg(tid));
        const QString type = m_targetType.value(tid, QStringLiteral("—"));
        const QString status = s.value(QStringLiteral("status")).toString();
        const QString started = s.value(QStringLiteral("started_at")).toString().left(19).replace('T', ' ');
        const bool exploit = s.value(QStringLiteral("allow_active_exploitation")).toBool();

        const int r = m_scansTable->rowCount();
        m_scansTable->insertRow(r);
        auto* idItem = new QTableWidgetItem(QString::number(id));
        idItem->setData(Qt::UserRole, id);
        m_scansTable->setItem(r, 0, idItem);
        m_scansTable->setItem(r, 1, new QTableWidgetItem(url));
        m_scansTable->setItem(r, 2, new QTableWidgetItem(type));
        m_scansTable->setItem(r, 3, new QTableWidgetItem(status));
        m_scansTable->setItem(r, 4, new QTableWidgetItem(started));
        m_scansTable->setItem(r, 5, new QTableWidgetItem(exploit ? QStringLiteral("⚔") : QStringLiteral("—")));

        if (shown < 8) {
            const int rr = m_recent->rowCount();
            m_recent->insertRow(rr);
            m_recent->setItem(rr, 0, new QTableWidgetItem(QString::number(id)));
            m_recent->setItem(rr, 1, new QTableWidgetItem(url));
            m_recent->setItem(rr, 2, new QTableWidgetItem(type));
            m_recent->setItem(rr, 3, new QTableWidgetItem(status));
            ++shown;
        }
    }
    m_cardScans->setText(QString::number(scans.size()));
}

void MainWindow::fillFindings(const QJsonArray& findings)
{
    m_findingsData = findings;
    m_findings->setRowCount(0);
    for (const auto& v : findings) {
        const QJsonObject f = v.toObject();
        const int r = m_findings->rowCount();
        m_findings->insertRow(r);
        m_findings->setItem(r, 0, new QTableWidgetItem(f.value(QStringLiteral("severity")).toString()));
        m_findings->setItem(r, 1, new QTableWidgetItem(f.value(QStringLiteral("title")).toString()));
        m_findings->setItem(r, 2, new QTableWidgetItem(f.value(QStringLiteral("plugin")).toString()));
        m_findings->setItem(r, 3, new QTableWidgetItem(f.value(QStringLiteral("description")).toString()));
    }
    m_detailTabs->setTabText(0, QStringLiteral("Findings (%1)").arg(findings.size()));
    m_cardFindings->setText(QString::number(findings.size()));
}

void MainWindow::fillExploits(const QJsonArray& exploits)
{
    m_exploitsData = exploits;
    m_exploits->setRowCount(0);
    int confirmed = 0;
    for (const auto& v : exploits) {
        const QJsonObject e = v.toObject();
        if (e.value(QStringLiteral("confirmed")).toBool())
            ++confirmed;
        const int r = m_exploits->rowCount();
        m_exploits->insertRow(r);
        m_exploits->setItem(r, 0, new QTableWidgetItem(e.value(QStringLiteral("severity")).toString()));
        m_exploits->setItem(r, 1, new QTableWidgetItem(
            e.value(QStringLiteral("confirmed")).toBool() ? QStringLiteral("✔") : QString()));
        m_exploits->setItem(r, 2, new QTableWidgetItem(e.value(QStringLiteral("category")).toString()));
        m_exploits->setItem(r, 3, new QTableWidgetItem(e.value(QStringLiteral("module")).toString()));
        m_exploits->setItem(r, 4, new QTableWidgetItem(e.value(QStringLiteral("title")).toString()));
        m_exploits->setItem(r, 5, new QTableWidgetItem(e.value(QStringLiteral("impact")).toString()));
    }
    m_detailTabs->setTabText(1, QStringLiteral("Preuves (%1)").arg(exploits.size()));
    m_cardProofs->setText(QString::number(confirmed));
}
