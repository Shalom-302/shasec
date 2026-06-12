#pragma once

#include <QObject>
#include <QString>
#include <QJsonArray>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <functional>

class QNetworkReply;

// Thin REST client for the SHASEC API. Wraps the {code,msg,data} response
// envelope and the Bearer-token auth. Each call emits a typed signal on success
// or error() on failure.
class ApiClient : public QObject
{
    Q_OBJECT
public:
    explicit ApiClient(QObject* parent = nullptr);

    void setBaseUrl(const QString& url);
    bool isAuthenticated() const { return !m_token.isEmpty(); }

    void login(const QString& email, const QString& password);
    void registerUser(const QString& email, const QString& password);
    void quickScan(const QString& url, const QString& type, bool activeExploit,
                   const QString& authToken = QString());
    void getScan(int id);
    void getFindings(int id);
    void getExploits(int id);
    void generateReport(int id, const QString& format);

signals:
    void loggedIn(const QString& email);
    void registered(const QString& email);
    void scanCreated(int id, const QString& status);
    void scanStatus(int id, const QString& status);
    void findingsReady(const QJsonArray& findings);
    void exploitsReady(const QJsonArray& exploits);
    void reportReady(const QString& location);
    void error(const QString& message);

private:
    QNetworkRequest jsonRequest(const QString& path) const;
    void handle(QNetworkReply* reply, const std::function<void(const QJsonValue&)>& onOk);

    QNetworkAccessManager m_nam;
    QString m_baseUrl;   // e.g. https://shasec.kortexai.dev/api/v1
    QString m_token;     // Bearer JWT
};
