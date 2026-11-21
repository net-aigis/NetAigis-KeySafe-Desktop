/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "gui/remote/CoordinatedRecoveryStore.h"
#include "gui/remote/KdbxCoordinatorClient.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTest>
#include <QUrl>

class TestCoordinatedRecoveryStore : public QObject
{
    Q_OBJECT
private slots:
    void decidePublishConflictAlreadyPublished();
    void retainAndAcknowledgeRoundTrip();
    void offlineReconnectLive_data();
    void offlineReconnectLive();
};

void TestCoordinatedRecoveryStore::decidePublishConflictAlreadyPublished()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QByteArray identity = QByteArrayLiteral("http://127.0.0.1:1") + char(0) + QByteArrayLiteral("db-a");
    const QByteArray tip1 = QByteArrayLiteral("tip-one-ciphertext-aaaa");
    const QByteArray tip2 = QByteArrayLiteral("tip-two-ciphertext-bbbb");
    const QByteArray tip3 = QByteArrayLiteral("tip-three-ciphertext-ccc");
    const QByteArray base = CoordinatedRecoveryStore::sha256Hex(tip1);
    QString error;
    QVERIFY(CoordinatedRecoveryStore::retain(dir.path(), identity, base, tip2, &error));

    CoordinatedRecoveryStore::Pending pending;
    QVERIFY(CoordinatedRecoveryStore::find(dir.path(), identity, &pending, &error));
    QCOMPARE(pending.baseRevision, base);
    QCOMPARE(CoordinatedRecoveryStore::decide(pending, base, &error),
             CoordinatedRecoveryStore::RecoveryAction::Publish);
    QCOMPARE(CoordinatedRecoveryStore::decide(pending, CoordinatedRecoveryStore::sha256Hex(tip2), &error),
             CoordinatedRecoveryStore::RecoveryAction::AlreadyPublished);
    QCOMPARE(CoordinatedRecoveryStore::decide(pending, CoordinatedRecoveryStore::sha256Hex(tip3), &error),
             CoordinatedRecoveryStore::RecoveryAction::Conflict);
}

void TestCoordinatedRecoveryStore::retainAndAcknowledgeRoundTrip()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QByteArray identity = QByteArrayLiteral("http://127.0.0.1:1") + char(0) + QByteArrayLiteral("db-b");
    const QByteArray tip1 = QByteArrayLiteral("ack-base-bytes-xxxxxxxxxxxx");
    const QByteArray tip2 = QByteArrayLiteral("ack-edit-bytes-yyyyyyyyyyyy");
    const QByteArray base = CoordinatedRecoveryStore::sha256Hex(tip1);
    QString error;
    QVERIFY(CoordinatedRecoveryStore::retain(dir.path(), identity, base, tip2, &error));
    const QByteArray confirmed = CoordinatedRecoveryStore::sha256Hex(tip2);
    QVERIFY(CoordinatedRecoveryStore::acknowledge(dir.path(), identity, confirmed, &error));
    CoordinatedRecoveryStore::Pending pending;
    QVERIFY(!CoordinatedRecoveryStore::find(dir.path(), identity, &pending, &error));
    QVERIFY(error.isEmpty());
}

void TestCoordinatedRecoveryStore::offlineReconnectLive_data()
{
    QTest::addColumn<QString>("mode");
    QTest::newRow("publish") << QStringLiteral("publish");
    QTest::newRow("conflict") << QStringLiteral("conflict");
    QTest::newRow("already") << QStringLiteral("already");
}

void TestCoordinatedRecoveryStore::offlineReconnectLive()
{
    const QByteArray urlEnv = qgetenv("KEYSAFE_INTEGRATION_URL");
    const QByteArray tokenEnv = qgetenv("KEYSAFE_INTEGRATION_TOKEN").isEmpty()
                                    ? qgetenv("KDBX_COORDINATOR_TOKEN")
                                    : qgetenv("KEYSAFE_INTEGRATION_TOKEN");
    if (urlEnv.isEmpty() || tokenEnv.size() < 32) {
        QSKIP("KEYSAFE_INTEGRATION_URL and token (≥32) required");
    }
    QFETCH(QString, mode);

    const QString url = QString::fromUtf8(urlEnv);
    const QString token = QString::fromUtf8(tokenEnv);
    const QString dbId = QStringLiteral("xc_offline_%1_%2")
                             .arg(mode, QString::number(QDateTime::currentMSecsSinceEpoch()));
    const QByteArray identity = (url + QChar::Null + dbId).toUtf8();

    const QByteArray tip1 = QByteArrayLiteral("xc-offline-base-") + dbId.toUtf8();
    const QByteArray tip2 = QByteArrayLiteral("xc-offline-local-") + dbId.toUtf8();
    const QByteArray tipRemote = QByteArrayLiteral("xc-offline-remote-") + dbId.toUtf8();
    const QByteArray base = CoordinatedRecoveryStore::sha256Hex(tip1);

    {
        KdbxCoordinatorClient seed(QUrl(url), dbId, token.toUtf8(), QStringLiteral("xc-offline-seed"));
        QString error;
        QVERIFY2(seed.acquire(&error), qPrintable(error));
        QVERIFY2(seed.publish(tip1, &error), qPrintable(error));
        QVERIFY2(seed.release(&error), qPrintable(error));
    }

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    QString error;
    QVERIFY(CoordinatedRecoveryStore::retain(dir.path(), identity, base, tip2, &error));

    if (mode == QLatin1String("conflict")) {
        KdbxCoordinatorClient peer(QUrl(url), dbId, token.toUtf8(), QStringLiteral("xc-offline-peer"));
        QVERIFY2(peer.acquire(&error), qPrintable(error));
        QVERIFY2(peer.publish(tipRemote, &error), qPrintable(error));
        QVERIFY2(peer.release(&error), qPrintable(error));
    } else if (mode == QLatin1String("already")) {
        KdbxCoordinatorClient writer(QUrl(url), dbId, token.toUtf8(), QStringLiteral("xc-offline-writer"));
        QVERIFY2(writer.acquire(&error), qPrintable(error));
        QVERIFY2(writer.publish(tip2, &error), qPrintable(error));
        QVERIFY2(writer.release(&error), qPrintable(error));
    }

    KdbxCoordinatorClient editor(QUrl(url), dbId, token.toUtf8(), QStringLiteral("xc-offline-reconnect"));
    QVERIFY2(editor.acquire(&error), qPrintable(error));
    QByteArray remote;
    bool exists = false;
    QVERIFY2(editor.download(&remote, &exists, &error), qPrintable(error));
    QVERIFY(exists);
    const QByteArray remoteRevision = CoordinatedRecoveryStore::sha256Hex(remote);

    CoordinatedRecoveryStore::Pending pending;
    QVERIFY(CoordinatedRecoveryStore::find(dir.path(), identity, &pending, &error));
    const auto action = CoordinatedRecoveryStore::decide(pending, remoteRevision, &error);

    if (mode == QLatin1String("publish")) {
        QCOMPARE(action, CoordinatedRecoveryStore::RecoveryAction::Publish);
        QVERIFY2(editor.publish(tip2, &error), qPrintable(error));
        QVERIFY(CoordinatedRecoveryStore::acknowledge(
            dir.path(), identity, CoordinatedRecoveryStore::sha256Hex(tip2), &error));
    } else if (mode == QLatin1String("conflict")) {
        QCOMPARE(action, CoordinatedRecoveryStore::RecoveryAction::Conflict);
        QVERIFY(QFile::exists(pending.filePath));
        QCOMPARE(remote, tipRemote);
    } else {
        QCOMPARE(action, CoordinatedRecoveryStore::RecoveryAction::AlreadyPublished);
        QVERIFY(CoordinatedRecoveryStore::acknowledge(dir.path(), identity, remoteRevision, &error));
    }
}

QTEST_GUILESS_MAIN(TestCoordinatedRecoveryStore)
#include "TestCoordinatedRecoveryStore.moc"
