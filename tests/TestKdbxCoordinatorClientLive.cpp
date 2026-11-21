/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "gui/remote/KdbxCoordinatorClient.h"

#include <QCryptographicHash>
#include <QEventLoop>
#include <QHostAddress>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>
#include <QTimer>
#include <QUrl>
#include <QUuid>
#include <atomic>
#include <functional>

namespace {

/**
 * Test-only HTTP/1.1 fault proxy (mirrors KeySafe KdbxLiveFaultProxy for XC live proofs).
 * Forwards to the real Go coordinator; can truncate GET /file or reject PUT before forward.
 */
class XcLiveFaultProxy : public QObject
{
public:
    enum class GetMode { Normal, TruncateHalf, RejectBeforeForward };
    enum class PutMode { Normal, RejectBeforeForward };

    explicit XcLiveFaultProxy(QString backend, QObject* parent = nullptr)
        : QObject(parent)
        , m_backend(std::move(backend))
    {
        while (m_backend.endsWith(QLatin1Char('/'))) {
            m_backend.chop(1);
        }
        m_server.listen(QHostAddress::LocalHost, 0);
        QObject::connect(&m_server, &QTcpServer::newConnection, this, [this]() {
            while (m_server.hasPendingConnections()) {
                QTcpSocket* socket = m_server.nextPendingConnection();
                socket->setParent(this);
                QObject::connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
                    serve(socket);
                });
                QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            }
        });
    }

    bool isListening() const { return m_server.isListening(); }

    QString url() const
    {
        return QStringLiteral("http://127.0.0.1:%1").arg(m_server.serverPort());
    }

    void setGetInterceptor(std::function<GetMode()> fn) { m_get = std::move(fn); }
    void setPutInterceptor(std::function<PutMode()> fn) { m_put = std::move(fn); }

private:
    static QByteArray readLine(QTcpSocket* socket)
    {
        QByteArray line;
        while (socket->bytesAvailable() > 0 || socket->waitForReadyRead(5000)) {
            char ch = 0;
            if (socket->read(&ch, 1) != 1) {
                break;
            }
            if (ch == '\n') {
                break;
            }
            if (ch != '\r') {
                line.append(ch);
            }
            if (line.size() > 8192) {
                return {};
            }
        }
        return line;
    }

    void respond(QTcpSocket* socket,
                 int status,
                 const QByteArray& body,
                 const QByteArray& etag,
                 bool truncateHalf)
    {
        QByteArray sendBody = body;
        int declared = body.size();
        if (truncateHalf && !body.isEmpty()) {
            sendBody = body.left(body.size() / 2);
            declared = body.size();
        }
        QByteArray headers = "HTTP/1.1 " + QByteArray::number(status) + " Test\r\n"
                             "Content-Length: " + QByteArray::number(declared) + "\r\n"
                             "Connection: close\r\n";
        if (!etag.isEmpty()) {
            headers += "ETag: " + etag + "\r\n";
        }
        headers += "\r\n";
        socket->write(headers);
        socket->write(sendBody);
        socket->flush();
        socket->disconnectFromHost();
    }

    void serve(QTcpSocket* socket)
    {
        if (socket->property("xc_proxy_done").toBool()) {
            return;
        }
        const QByteArray requestLine = readLine(socket);
        const QList<QByteArray> parts = requestLine.split(' ');
        if (parts.size() < 2) {
            socket->disconnectFromHost();
            return;
        }
        const QByteArray method = parts[0];
        const QByteArray path = parts[1];
        QMap<QByteArray, QByteArray> headers;
        while (true) {
            const QByteArray header = readLine(socket);
            if (header.isEmpty()) {
                break;
            }
            const int colon = header.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            headers.insert(header.left(colon).toLower(), header.mid(colon + 1).trimmed());
        }
        const int length = headers.value("content-length").toInt();
        QByteArray body;
        if (length > 0) {
            body.resize(length);
            int got = 0;
            while (got < length) {
                if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(10000)) {
                    break;
                }
                const int n = int(socket->read(body.data() + got, length - got));
                if (n <= 0) {
                    break;
                }
                got += n;
            }
            body.resize(got);
        }

        PutMode putMode = PutMode::Normal;
        if (method == "PUT" && m_put) {
            putMode = m_put();
        }
        if (putMode == PutMode::RejectBeforeForward) {
            respond(socket, 503, {}, {}, false);
            socket->setProperty("xc_proxy_done", true);
            return;
        }

        GetMode getMode = GetMode::Normal;
        if (method == "GET" && path.endsWith("/file") && m_get) {
            getMode = m_get();
        }
        if (getMode == GetMode::RejectBeforeForward) {
            respond(socket, 503, {}, {}, false);
            socket->setProperty("xc_proxy_done", true);
            return;
        }

        QUrl backendUrl(m_backend + QString::fromUtf8(path));
        QNetworkRequest req(backendUrl);
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        for (const char* key : {"Authorization", "X-KDBX-Lease", "If-Match", "Content-Type"}) {
            const QByteArray v = headers.value(QByteArray(key).toLower());
            if (!v.isEmpty()) {
                req.setRawHeader(key, v);
            }
        }

        QNetworkAccessManager nam;
        QNetworkReply* reply = nullptr;
        if (method == "GET") {
            reply = nam.get(req);
        } else if (method == "POST") {
            req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
            reply = nam.post(req, body);
        } else if (method == "PUT") {
            req.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream");
            reply = nam.put(req, body);
        } else if (method == "DELETE") {
            reply = nam.deleteResource(req);
        } else {
            respond(socket, 400, {}, {}, false);
            socket->setProperty("xc_proxy_done", true);
            return;
        }

        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, reply, &QNetworkReply::abort);
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        timeout.start(30000);
        if (!reply->isFinished()) {
            loop.exec();
        }
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray etag = reply->rawHeader("ETag");
        const QByteArray replyBody = reply->readAll();
        reply->deleteLater();

        respond(socket,
                status == 0 ? 502 : status,
                replyBody,
                etag,
                getMode == GetMode::TruncateHalf && status == 200);
        socket->setProperty("xc_proxy_done", true);
    }

    QTcpServer m_server;
    QString m_backend;
    std::function<GetMode()> m_get;
    std::function<PutMode()> m_put;
};

} // namespace

/**
 * Live integration: drives KdbxCoordinatorClient against a running Go kdbx-coordinator.
 *
 * Skips unless KEYSAFE_INTEGRATION_URL is set (same gate as KeySafe JVM integration tests).
 * Requires a bearer token of at least 32 printable ASCII characters. Prefer
 * KEYSAFE_INTEGRATION_TOKEN; if unset, KDBX_COORDINATOR_TOKEN is used (match the Go process).
 *
 * Run headless: QT_QPA_PLATFORM=offscreen
 */
class TestKdbxCoordinatorClientLive : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void roundTripOpaqueCiphertext();
    void reloadTipPublishedByKeySafe();
    void secondClientSeesBusyLease();
    void sameOwnerSuccessivePublishAdvancesTip();
    void externalLeaseRevocationBlocksPublish();
    void staleIfMatchPublishFailsClosed();
    void truncatedDownloadFailsClosedThenRetry();
    void rejectedPublishLeavesTipUnchangedThenRetry();

private:
    static QString integrationUrl();
    static QByteArray integrationToken();
    static QByteArray opaquePayload(int size, int seed);
    static bool revokeLeaseHttp(const QString& dbId, const QByteArray& token, const QByteArray& lease);
};

void TestKdbxCoordinatorClientLive::initTestCase()
{
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")) {
        QSKIP("KEYSAFE_INTEGRATION_URL not set; live coordinator test skipped.");
    }
    if (integrationToken().size() < 32) {
        QSKIP("Set KEYSAFE_INTEGRATION_TOKEN or KDBX_COORDINATOR_TOKEN (>=32 printable ASCII chars).");
    }
}

QString TestKdbxCoordinatorClientLive::integrationUrl()
{
    return QString::fromUtf8(qgetenv("KEYSAFE_INTEGRATION_URL")).trimmed();
}

QByteArray TestKdbxCoordinatorClientLive::integrationToken()
{
    QByteArray t = qgetenv("KEYSAFE_INTEGRATION_TOKEN");
    if (t.isEmpty()) {
        t = qgetenv("KDBX_COORDINATOR_TOKEN");
    }
    return t;
}

QByteArray TestKdbxCoordinatorClientLive::opaquePayload(int size, int seed)
{
    QByteArray ciphertext(size, '\0');
    for (int i = 0; i < ciphertext.size(); ++i) {
        ciphertext[i] = static_cast<char>((i * 17 + seed) & 0xff);
    }
    ciphertext[0] = static_cast<char>(0x03);
    ciphertext[1] = static_cast<char>(0xd9);
    return ciphertext;
}

bool TestKdbxCoordinatorClientLive::revokeLeaseHttp(const QString& dbId,
                                                    const QByteArray& token,
                                                    const QByteArray& lease)
{
    QUrl url(integrationUrl());
    QString path = url.path();
    while (path.endsWith(QLatin1Char('/'))) {
        path.chop(1);
    }
    url.setPath(path + QStringLiteral("/v1/databases/") + dbId + QStringLiteral("/lock"));

    QNetworkAccessManager nam;
    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    req.setRawHeader("Authorization", "Bearer " + token);
    req.setRawHeader("X-KDBX-Lease", lease);
    QNetworkReply* reply = nam.deleteResource(req);
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, reply, &QNetworkReply::abort);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    timeout.start(15000);
    if (!reply->isFinished()) {
        loop.exec();
    }
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    reply->deleteLater();
    return status == 204;
}

void TestKdbxCoordinatorClientLive::roundTripOpaqueCiphertext()
{
    if (!qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_REVERSE")) {
        QSKIP("KEYSAFE_INTEGRATION_REVERSE set; skipping forward round-trip.");
    }
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")) {
        QSKIP("KEYSAFE_INTEGRATION_URL not set");
    }
    const QByteArray token = integrationToken();
    if (token.size() < 32) {
        QSKIP("integration token not configured");
    }

    QString dbId = QString::fromUtf8(qgetenv("KEYSAFE_INTEGRATION_DB_ID")).trimmed();
    if (dbId.isEmpty()) {
        dbId = QStringLiteral("xc_live_") + QUuid::createUuid().toString(QUuid::WithoutBraces);
    }

    KdbxCoordinatorClient client(QUrl(integrationUrl()),
                                 dbId,
                                 token,
                                 QStringLiteral("TestKdbxCoordinatorClientLive"),
                                 this);

    QString err;

    // Empty DB path: acquire with revision "0", download returns 404 / no file.
    QVERIFY2(client.acquire(&err), qPrintable(err));
    QVERIFY(client.hasLease());

    QByteArray downloaded;
    bool exists = false;
    QVERIFY2(client.download(&downloaded, &exists, &err), qPrintable(err));
    QVERIFY(!exists);
    QVERIFY(downloaded.isEmpty());

    // Opaque ciphertext bytes (not a real KDBX — coordinator treats as opaque blob).
    QByteArray ciphertext(2048, '\0');
    if (!qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_DB_ID")) {
        // Deterministic payload for XC→KeySafe bridge proofs.
        for (int i = 0; i < ciphertext.size(); ++i) {
            ciphertext[i] = static_cast<char>((i * 17 + 41) & 0xff);
        }
    } else {
        for (int i = 0; i < ciphertext.size(); ++i) {
            ciphertext[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
        }
    }
    // Ensure non-empty payload rules and stable test comparison.
    ciphertext[0] = static_cast<char>(0x03);
    ciphertext[1] = static_cast<char>(0xd9);

    QVERIFY2(client.publish(ciphertext, &err), qPrintable(err));

    const QByteArray expectedRev =
        QCryptographicHash::hash(ciphertext, QCryptographicHash::Sha256).toHex();
    qInfo("KEYSAFE_BRIDGE_DB_ID=%s", qPrintable(dbId));
    qInfo("KEYSAFE_BRIDGE_SHA256=%s", expectedRev.constData());
    QCOMPARE(client.hasLease(), true);

    downloaded.clear();
    exists = false;
    QVERIFY2(client.download(&downloaded, &exists, &err), qPrintable(err));
    QVERIFY(exists);
    QCOMPARE(downloaded, ciphertext);

    // Revision / ETag contract is enforced inside publish & download via CoordinatorConfigValidation.
    QVERIFY2(client.release(&err), qPrintable(err));
}

void TestKdbxCoordinatorClientLive::reloadTipPublishedByKeySafe()
{
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")
        || qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_REVERSE")) {
        QSKIP("Set KEYSAFE_INTEGRATION_REVERSE=1 after KeySafe published the tip.");
    }
    const QByteArray token = integrationToken();
    if (token.size() < 32) {
        QSKIP("integration token not configured");
    }
    QString dbId = QString::fromUtf8(qgetenv("KEYSAFE_INTEGRATION_DB_ID")).trimmed();
    if (dbId.isEmpty()) {
        QSKIP("KEYSAFE_INTEGRATION_DB_ID required for reverse bridge");
    }
    const QByteArray expectedSha = qgetenv("KEYSAFE_INTEGRATION_EXPECTED_SHA256").trimmed();
    if (expectedSha.size() != 64) {
        QSKIP("KEYSAFE_INTEGRATION_EXPECTED_SHA256 (64 hex) required for reverse bridge");
    }

    KdbxCoordinatorClient client(QUrl(integrationUrl()),
                                 dbId,
                                 token,
                                 QStringLiteral("TestKdbxCoordinatorClientLive-reverse"),
                                 this);
    QString err;
    QVERIFY2(client.acquire(&err), qPrintable(err));
    QByteArray downloaded;
    bool exists = false;
    QVERIFY2(client.download(&downloaded, &exists, &err), qPrintable(err));
    QVERIFY(exists);
    const QByteArray actualSha =
        QCryptographicHash::hash(downloaded, QCryptographicHash::Sha256).toHex();
    QCOMPARE(QString::fromLatin1(actualSha), QString::fromLatin1(expectedSha).toLower());
    QVERIFY2(client.release(&err), qPrintable(err));
}

void TestKdbxCoordinatorClientLive::secondClientSeesBusyLease()
{
    if (!qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_REVERSE")) {
        QSKIP("KEYSAFE_INTEGRATION_REVERSE set; skipping busy-lease probe.");
    }
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")) {
        QSKIP("KEYSAFE_INTEGRATION_URL not set");
    }
    const QByteArray token = integrationToken();
    if (token.size() < 32) {
        QSKIP("integration token not configured");
    }

    const QString dbId =
        QStringLiteral("xc_busy_") + QUuid::createUuid().toString(QUuid::WithoutBraces);

    KdbxCoordinatorClient holder(QUrl(integrationUrl()),
                                 dbId,
                                 token,
                                 QStringLiteral("TestKdbxCoordinatorClientLive-holder"),
                                 this);
    KdbxCoordinatorClient waiter(QUrl(integrationUrl()),
                                 dbId,
                                 token,
                                 QStringLiteral("TestKdbxCoordinatorClientLive-waiter"),
                                 this);
    QString err;
    QVERIFY2(holder.acquire(&err), qPrintable(err));
    QVERIFY(holder.hasLease());
    QVERIFY(!waiter.acquire(&err));
    QVERIFY(waiter.isBusy());
    QVERIFY2(holder.release(&err), qPrintable(err));
    QVERIFY2(waiter.acquire(&err), qPrintable(err));
    QVERIFY(waiter.hasLease());
    QVERIFY2(waiter.release(&err), qPrintable(err));
}

void TestKdbxCoordinatorClientLive::sameOwnerSuccessivePublishAdvancesTip()
{
    if (!qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_REVERSE")) {
        QSKIP("KEYSAFE_INTEGRATION_REVERSE set; skipping successive publish.");
    }
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")) {
        QSKIP("KEYSAFE_INTEGRATION_URL not set");
    }
    const QByteArray token = integrationToken();
    if (token.size() < 32) {
        QSKIP("integration token not configured");
    }

    const QString dbId =
        QStringLiteral("xc_succ_") + QUuid::createUuid().toString(QUuid::WithoutBraces);

    KdbxCoordinatorClient client(QUrl(integrationUrl()),
                                 dbId,
                                 token,
                                 QStringLiteral("TestKdbxCoordinatorClientLive-succ"),
                                 this);
    QString err;
    QVERIFY2(client.acquire(&err), qPrintable(err));

    const QByteArray tip1 = opaquePayload(1024, 7);
    const QByteArray tip2 = opaquePayload(1024, 11);
    QVERIFY(tip1 != tip2);

    QVERIFY2(client.publish(tip1, &err), qPrintable(err));
    QByteArray downloaded;
    bool exists = false;
    QVERIFY2(client.download(&downloaded, &exists, &err), qPrintable(err));
    QVERIFY(exists);
    QCOMPARE(downloaded, tip1);

    QVERIFY2(client.publish(tip2, &err), qPrintable(err));
    downloaded.clear();
    exists = false;
    QVERIFY2(client.download(&downloaded, &exists, &err), qPrintable(err));
    QVERIFY(exists);
    QCOMPARE(downloaded, tip2);
    QCOMPARE(QCryptographicHash::hash(downloaded, QCryptographicHash::Sha256).toHex(),
             QCryptographicHash::hash(tip2, QCryptographicHash::Sha256).toHex());

    QVERIFY2(client.release(&err), qPrintable(err));
}

void TestKdbxCoordinatorClientLive::externalLeaseRevocationBlocksPublish()
{
    if (!qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_REVERSE")) {
        QSKIP("KEYSAFE_INTEGRATION_REVERSE set; skipping lease-revocation probe.");
    }
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")) {
        QSKIP("KEYSAFE_INTEGRATION_URL not set");
    }
    const QByteArray token = integrationToken();
    if (token.size() < 32) {
        QSKIP("integration token not configured");
    }

    const QString dbId =
        QStringLiteral("xc_lloss_") + QUuid::createUuid().toString(QUuid::WithoutBraces);

    KdbxCoordinatorClient oldClient(QUrl(integrationUrl()),
                                    dbId,
                                    token,
                                    QStringLiteral("TestKdbxCoordinatorClientLive-old"),
                                    this);
    QString err;
    QVERIFY2(oldClient.acquire(&err), qPrintable(err));
    QVERIFY(!oldClient.m_lease.isEmpty());

    QSignalSpy lostSpy(&oldClient, &KdbxCoordinatorClient::leaseLost);
    QVERIFY(revokeLeaseHttp(dbId, token, oldClient.m_lease));

    KdbxCoordinatorClient winner(QUrl(integrationUrl()),
                                 dbId,
                                 token,
                                 QStringLiteral("TestKdbxCoordinatorClientLive-new"),
                                 this);
    QVERIFY2(winner.acquire(&err), qPrintable(err));
    const QByteArray tip = opaquePayload(768, 23);
    QVERIFY2(winner.publish(tip, &err), qPrintable(err));

    const QByteArray stale = opaquePayload(768, 29);
    QVERIFY(!oldClient.publish(stale, &err));
    QVERIFY(!oldClient.hasLease());
    QVERIFY(lostSpy.count() >= 1);

    QByteArray downloaded;
    bool exists = false;
    QVERIFY2(winner.download(&downloaded, &exists, &err), qPrintable(err));
    QVERIFY(exists);
    QCOMPARE(downloaded, tip);
    QVERIFY2(winner.release(&err), qPrintable(err));
}

void TestKdbxCoordinatorClientLive::staleIfMatchPublishFailsClosed()
{
    if (!qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_REVERSE")) {
        QSKIP("KEYSAFE_INTEGRATION_REVERSE set; skipping stale If-Match probe.");
    }
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")) {
        QSKIP("KEYSAFE_INTEGRATION_URL not set");
    }
    const QByteArray token = integrationToken();
    if (token.size() < 32) {
        QSKIP("integration token not configured");
    }

    const QString dbId =
        QStringLiteral("xc_412_") + QUuid::createUuid().toString(QUuid::WithoutBraces);

    KdbxCoordinatorClient client(QUrl(integrationUrl()),
                                 dbId,
                                 token,
                                 QStringLiteral("TestKdbxCoordinatorClientLive-412"),
                                 this);
    QString err;
    QVERIFY2(client.acquire(&err), qPrintable(err));
    const QByteArray tip1 = opaquePayload(512, 41);
    QVERIFY2(client.publish(tip1, &err), qPrintable(err));

    // Force a stale If-Match while the lease token is still locally held (friend access).
    client.m_revision = QByteArrayLiteral("0");
    QSignalSpy lostSpy(&client, &KdbxCoordinatorClient::leaseLost);
    const QByteArray tip2 = opaquePayload(512, 43);
    QVERIFY(!client.publish(tip2, &err));
    QVERIFY(!client.hasLease());
    QVERIFY(lostSpy.count() >= 1);
    // invalidate() fails closed locally but does not DELETE the server lease; drop it explicitly.
    QVERIFY2(client.release(&err), qPrintable(err));

    // Tip must remain tip1; a fresh owner loads the last good revision.
    KdbxCoordinatorClient reader(QUrl(integrationUrl()),
                                 dbId,
                                 token,
                                 QStringLiteral("TestKdbxCoordinatorClientLive-412-reader"),
                                 this);
    QVERIFY2(reader.acquire(&err), qPrintable(err));
    QByteArray downloaded;
    bool exists = false;
    QVERIFY2(reader.download(&downloaded, &exists, &err), qPrintable(err));
    QVERIFY(exists);
    QCOMPARE(downloaded, tip1);
    QVERIFY2(reader.release(&err), qPrintable(err));
}

void TestKdbxCoordinatorClientLive::truncatedDownloadFailsClosedThenRetry()
{
    if (!qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_REVERSE")) {
        QSKIP("KEYSAFE_INTEGRATION_REVERSE set; skipping truncated-download probe.");
    }
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")) {
        QSKIP("KEYSAFE_INTEGRATION_URL not set");
    }
    const QByteArray token = integrationToken();
    if (token.size() < 32) {
        QSKIP("integration token not configured");
    }

    const QString dbId =
        QStringLiteral("xc_trunc_") + QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QByteArray tip = opaquePayload(2048, 61);

    {
        KdbxCoordinatorClient publisher(QUrl(integrationUrl()),
                                        dbId,
                                        token,
                                        QStringLiteral("TestKdbxCoordinatorClientLive-trunc-pub"),
                                        this);
        QString err;
        QVERIFY2(publisher.acquire(&err), qPrintable(err));
        QVERIFY2(publisher.publish(tip, &err), qPrintable(err));
        QVERIFY2(publisher.release(&err), qPrintable(err));
    }

    XcLiveFaultProxy proxy(integrationUrl(), this);
    QVERIFY(proxy.isListening());
    std::atomic<int> gets{0};
    proxy.setGetInterceptor([&gets]() {
        if (gets.fetch_add(1) == 0) {
            return XcLiveFaultProxy::GetMode::TruncateHalf;
        }
        return XcLiveFaultProxy::GetMode::Normal;
    });

    {
        KdbxCoordinatorClient broken(QUrl(proxy.url()),
                                     dbId,
                                     token,
                                     QStringLiteral("TestKdbxCoordinatorClientLive-trunc-broken"),
                                     this);
        QString err;
        QVERIFY2(broken.acquire(&err), qPrintable(err));
        QByteArray downloaded;
        bool exists = false;
        QVERIFY(!broken.download(&downloaded, &exists, &err));
        QVERIFY2(broken.release(&err), qPrintable(err));
    }

    {
        KdbxCoordinatorClient retry(QUrl(proxy.url()),
                                    dbId,
                                    token,
                                    QStringLiteral("TestKdbxCoordinatorClientLive-trunc-retry"),
                                    this);
        QString err;
        QVERIFY2(retry.acquire(&err), qPrintable(err));
        QByteArray downloaded;
        bool exists = false;
        QVERIFY2(retry.download(&downloaded, &exists, &err), qPrintable(err));
        QVERIFY(exists);
        QCOMPARE(downloaded, tip);
        QVERIFY2(retry.release(&err), qPrintable(err));
    }
}

void TestKdbxCoordinatorClientLive::rejectedPublishLeavesTipUnchangedThenRetry()
{
    if (!qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_REVERSE")) {
        QSKIP("KEYSAFE_INTEGRATION_REVERSE set; skipping rejected-publish probe.");
    }
    if (qEnvironmentVariableIsEmpty("KEYSAFE_INTEGRATION_URL")) {
        QSKIP("KEYSAFE_INTEGRATION_URL not set");
    }
    const QByteArray token = integrationToken();
    if (token.size() < 32) {
        QSKIP("integration token not configured");
    }

    const QString dbId =
        QStringLiteral("xc_rej_") + QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QByteArray tip1 = opaquePayload(1024, 71);
    const QByteArray tip2 = opaquePayload(1024, 73);

    {
        KdbxCoordinatorClient seed(QUrl(integrationUrl()),
                                   dbId,
                                   token,
                                   QStringLiteral("TestKdbxCoordinatorClientLive-rej-seed"),
                                   this);
        QString err;
        QVERIFY2(seed.acquire(&err), qPrintable(err));
        QVERIFY2(seed.publish(tip1, &err), qPrintable(err));
        QVERIFY2(seed.release(&err), qPrintable(err));
    }

    XcLiveFaultProxy proxy(integrationUrl(), this);
    QVERIFY(proxy.isListening());
    std::atomic<int> puts{0};
    proxy.setPutInterceptor([&puts]() {
        if (puts.fetch_add(1) == 0) {
            return XcLiveFaultProxy::PutMode::RejectBeforeForward;
        }
        return XcLiveFaultProxy::PutMode::Normal;
    });

    {
        KdbxCoordinatorClient writer(QUrl(proxy.url()),
                                     dbId,
                                     token,
                                     QStringLiteral("TestKdbxCoordinatorClientLive-rej-writer"),
                                     this);
        QString err;
        QVERIFY2(writer.acquire(&err), qPrintable(err));
        QVERIFY(!writer.publish(tip2, &err));
        QVERIFY(writer.hasLease());
        QVERIFY2(writer.publish(tip2, &err), qPrintable(err));
        QByteArray downloaded;
        bool exists = false;
        QVERIFY2(writer.download(&downloaded, &exists, &err), qPrintable(err));
        QVERIFY(exists);
        QCOMPARE(downloaded, tip2);
        QVERIFY2(writer.release(&err), qPrintable(err));
    }
}

QTEST_GUILESS_MAIN(TestKdbxCoordinatorClientLive)
#include "TestKdbxCoordinatorClientLive.moc"
