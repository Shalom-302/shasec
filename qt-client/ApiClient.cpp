#include "ApiClient.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QUrl>

ApiClient::ApiClient(QObject* parent)
    : QObject(parent)
{
    m_baseUrl = QStringLiteral("https://shasec.kortexai.dev/api/v1");
}

void ApiClient::setBaseUrl(const QString& url)
{
    QString u = url.trimmed();
    while (u.endsWith('/'))
        u.chop(1);
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
        emit error(obj.value(QStringLiteral("msg")).toString(QStringLiteral("Erreur %1").arg(code)));
        return;
    }
    onOk(obj.value(QStringLiteral("data")));
}

// Paginated responses wrap the list under data.items; plain lists come as data.
static QJsonArray itemsOf(const QJsonValue& data)
{
    if (data.isArray())
        return data.toArray();
    return data.toObject().value(QStringLiteral("items")).toArray();
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

void ApiClient::getScans()
{
    QNetworkReply* reply = m_nam.get(jsonRequest(QStringLiteral("/scans/?page=1&size=100")));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue& data) { emit scansReady(itemsOf(data)); });
    });
}

void ApiClient::getTargets()
{
    QNetworkReply* reply = m_nam.get(jsonRequest(QStringLiteral("/targets/?page=1&size=100")));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue& data) { emit targetsReady(itemsOf(data)); });
    });
}

void ApiClient::quickScan(const QString& url, const QString& type, bool activeExploit,
                          const QString& authToken)
{
    QJsonObject payload{
        {"url", url}, {"type", type}, {"allow_active_exploitation", activeExploit}};
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

void ApiClient::getAnalysis(int id)
{
    QNetworkReply* reply = m_nam.get(jsonRequest(QStringLiteral("/scans/%1/analysis").arg(id)));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue& data) { emit analysisReady(data.toObject()); });
    });
}

void ApiClient::cancelScan(int id)
{
    QNetworkReply* reply = m_nam.post(jsonRequest(QStringLiteral("/scans/%1/cancel").arg(id)), QByteArray());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue&) { emit scanCancelled(); });
    });
}

void ApiClient::authorizeTarget(int id, bool authorized)
{
    QJsonObject payload{{"is_authorized", authorized}};
    QNetworkReply* reply = m_nam.post(jsonRequest(QStringLiteral("/targets/%1/authorize").arg(id)),
                                      QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        handle(reply, [this](const QJsonValue&) { emit targetAuthorized(); });
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

void ApiClient::downloadReport(int id, const QString& format)
{
    const QString path = QStringLiteral("/scans/%1/report/download?format=%2&lang=fr").arg(id).arg(format);
    QNetworkReply* reply = m_nam.get(jsonRequest(path));
    connect(reply, &QNetworkReply::finished, this, [this, reply, id, format]() {
        reply->deleteLater();
        const int http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        if (http != 200) {
            const QJsonObject o = QJsonDocument::fromJson(body).object();
            emit error(o.value(QStringLiteral("msg"))
                           .toString(QStringLiteral("Téléchargement échoué (%1)").arg(http)));
            return;
        }
        const QString ext = (format == QStringLiteral("markdown")) ? QStringLiteral("md") : format;
        QString filename = QStringLiteral("shasec_report_scan%1.%2").arg(id).arg(ext);
        const QByteArray cd = reply->rawHeader("Content-Disposition");
        const int idx = cd.indexOf("filename=");
        if (idx >= 0) {
            QString fn = QString::fromUtf8(cd.mid(idx + 9)).remove('"').trimmed();
            if (!fn.isEmpty())
                filename = fn;
        }
        emit reportDownloaded(body, filename);
    });
}
