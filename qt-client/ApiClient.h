#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <functional>

class QNetworkReply;

// Thin REST client for the SHASEC API. Wraps the {code,msg,data} envelope and
// Bearer auth. Each call emits a typed signal on success or error() on failure.
class ApiClient : public QObject
{
    Q_OBJECT
public:
    explicit ApiClient(QObject* parent = nullptr);

    void setBaseUrl(const QString& url);
    QString baseUrl() const { return m_baseUrl; }
    bool isAuthenticated() const { return !m_token.isEmpty(); }

    void login(const QString& email, const QString& password);
    void registerUser(const QString& email, const QString& password);

    void getScans();
    void getTargets();
    void quickScan(const QString& url, const QString& type, bool activeExploit,
                   const QString& authToken = QString());
    void getScan(int id);
    void getFindings(int id);
    void getExploits(int id);
    void getAnalysis(int id);
    void cancelScan(int id);
    void deleteScan(int id);
    void authorizeTarget(int id, bool authorized);
    void deleteTarget(int id);

    void generateReport(int id, const QString& format);
    void downloadReport(int id, const QString& format);

signals:
    void loggedIn(const QString& email);
    void registered(const QString& email);
    void scansReady(const QJsonArray& scans);
    void targetsReady(const QJsonArray& targets);
    void scanCreated(int id, const QString& status);
    void scanStatus(int id, const QString& status);
    void findingsReady(const QJsonArray& findings);
    void exploitsReady(const QJsonArray& exploits);
    void analysisReady(const QJsonObject& analysis);
    void scanCancelled();
    void scanDeleted();
    void targetAuthorized();
    void targetDeleted();
    void reportReady(const QString& location);
    void reportDownloaded(const QByteArray& data, const QString& filename);
    void error(const QString& message);

private:
    QNetworkRequest jsonRequest(const QString& path) const;
    void handle(QNetworkReply* reply, const std::function<void(const QJsonValue&)>& onOk);

    QNetworkAccessManager m_nam;
    QString m_baseUrl;
    QString m_token;
};
