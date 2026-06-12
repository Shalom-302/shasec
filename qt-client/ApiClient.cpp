#include "ApiClient.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QUrl>

ApiClient::ApiClient(QObject* parent)
    : QObject(parent)
{
    m_baseUrl = QStringLiteral("http://localhost:8000/api/v1");
}

void ApiClient::setBaseUrl(const QString& url)
{
    QString u = url.trimmed();
    while (u.endsWith('/'))
        u.chop(1);
    // Accept either the host root or a full /api/v1 base.
    if (!u.endsWith(QStringLiteral("/api/v1")))
        u += QStringLiteral("/api/v1");
    m_baseUrl = u;
}

QNetworkRequest ApiClient::jsonRequest(const QString& path) const
{
    QNetworkRequest req{QUrl(m_baseUrl + path)};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    if (!m_token.isEmpty())
        req.setRawHeader("Authorization", QByteArray("Bearer ") + m_token.toUtf8());
    return req;
}

void ApiClient::handle(QNetworkReply* reply, const std::function<void(const QJsonValue&)>& onOk)
{
    reply->deleteLater();
    const QByteArray body = reply->readAll();
    const int httpCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(body, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        emit error(reply->error() != QNetworkReply::NoError
                       ? reply->errorString()
                       : QStringLiteral("Réponse invalide du serveur"));
        return;
    }

    const QJsonObject obj = doc.object();
    const int code = obj.value(QStringLiteral("code")).toInt(httpCode);
    if (code != 200) {
        emit error(obj.value(QStringLiteral("msg")).toString(
            QStringLiteral("Erreur %1").arg(code)));
        return;
    }
    onOk(obj.value(QStringLiteral("data")));
}

void ApiClient::login(const QString& email, const QString& password)
{
    QJsonObject payload{{"email", email}, {"password", password}};
    QNetworkReply* reply = m_nam.post(jsonRequest(QStringLiteral("/auth/login")),
                                      QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply, email]() {
        handle(reply, [this, email](const QJsonValue& data) {
            m_token = data.toObject().value(QStringLiteral("access_token")).toString();
            if (m_token.isEmpty())
                emit error(QStringLiteral("Pas de token dans la réponse"));
            else
                emit loggedIn(email);
        });
    });
}

void ApiClient::registerUser(const QString& email, const QString& password)
{
    QJsonObject payload{{"email", email}, {"password", password}};
    QNetworkReply* reply = m_nam.post(jsonRequest(QStringLiteral("/auth/register")),
                                      QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply, email]() {
        handle(reply, [this, email](const QJsonValue&) { emit registered(email); });
    });
}

void ApiClient::quickScan(const QString& url, const QString& type, bool activeExploit,
                          const QString& authToken)
{
    QJsonObject payload{
        {"url", url},
        {"type", type},
        {"allow_active_exploitation", activeExploit},
    };
    if (!authToken.isEmpty())
        payload.insert(QStringLiteral("auth_token"), authToken);

    QNetworkReply* reply = m_nam.post(jsonRequest(QStringLiteral("/scans/quick")),
                                      QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue& data) {
            const QJsonObject o = data.toObject();
            emit scanCreated(o.value(QStringLiteral("id")).toInt(),
                             o.value(QStringLiteral("status")).toString());
        });
    });
}

void ApiClient::getScan(int id)
{
    QNetworkReply* reply = m_nam.get(jsonRequest(QStringLiteral("/scans/%1").arg(id)));
    connect(reply, &QNetworkReply::finished, this, [this, reply, id]() {
        handle(reply, [this, id](const QJsonValue& data) {
            emit scanStatus(id, data.toObject().value(QStringLiteral("status")).toString());
        });
    });
}

void ApiClient::getFindings(int id)
{
    QNetworkReply* reply = m_nam.get(jsonRequest(QStringLiteral("/scans/%1/findings").arg(id)));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue& data) { emit findingsReady(data.toArray()); });
    });
}

void ApiClient::getExploits(int id)
{
    QNetworkReply* reply = m_nam.get(jsonRequest(QStringLiteral("/scans/%1/exploits").arg(id)));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue& data) { emit exploitsReady(data.toArray()); });
    });
}

void ApiClient::generateReport(int id, const QString& format)
{
    const QString path = QStringLiteral("/scans/%1/report?format=%2&lang=fr").arg(id).arg(format);
    QNetworkReply* reply = m_nam.post(jsonRequest(path), QByteArray());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue& data) {
            emit reportReady(data.toObject().value(QStringLiteral("location")).toString());
        });
    });
}
