/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "CoordinatedRecoveryStore.h"

#include "CoordinatorByteLimits.h"
#include "CoordinatorConfigValidation.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QStandardPaths>
#include <QUuid>

namespace CoordinatedRecoveryStore {
namespace {

QByteArray identityPrefix(const QByteArray& identity)
{
    return QByteArrayLiteral("coordinated-kdbx-") + sha256Hex(identity) + QByteArrayLiteral("-");
}

bool isValidRevision(const QByteArray& revision)
{
    return CoordinatorConfigValidation::isValidRevision(revision);
}

QByteArray fileSha256Hex(const QString& path, QString* error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = QStringLiteral("Cannot read recovery file");
        }
        return {};
    }
    if (file.size() > CoordinatorByteLimits::MaxKdbxBytes) {
        if (error) {
            *error = QStringLiteral("Pending KDBX exceeds permitted size");
        }
        return {};
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 total = 0;
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(8192);
        if (chunk.isEmpty() && !file.atEnd()) {
            if (error) {
                *error = QStringLiteral("Cannot read recovery file");
            }
            return {};
        }
        total += chunk.size();
        if (total > CoordinatorByteLimits::MaxKdbxBytes) {
            if (error) {
                *error = QStringLiteral("Pending KDBX exceeds permitted size");
            }
            return {};
        }
        hash.addData(chunk);
    }
    return hash.result().toHex();
}

} // namespace

QByteArray sha256Hex(const QByteArray& bytes)
{
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
}

bool canReplace(const QByteArray& previousBase,
                const QByteArray& previousContentHash,
                const QByteArray& newBase)
{
    return previousBase == newBase || previousContentHash == newBase;
}

QString recoveryDirectory()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)
           + QStringLiteral("/coordinated-recovery");
}

bool find(const QString& directory, const QByteArray& identity, Pending* out, QString* error)
{
    if (!out) {
        if (error) {
            *error = QStringLiteral("Pending output required");
        }
        return false;
    }
    QDir dir(directory);
    if (!dir.exists()) {
        return false;
    }
    if (QFile::exists(dir.filePath(QStringLiteral("coordinated-kdbx-pending.kdbx")))) {
        if (error) {
            *error = QStringLiteral(
                "An older unsynchronized KDBX recovery file exists. Preserve and recover it manually.");
        }
        return false;
    }
    const QByteArray prefix = identityPrefix(identity);
    const QStringList entries = dir.entryList(QDir::Files);
    QStringList matches;
    for (const QString& name : entries) {
        const QByteArray utf8 = name.toUtf8();
        if (utf8.startsWith(prefix) && utf8.endsWith(".stage")) {
            if (error) {
                *error = QStringLiteral("Incomplete recovery staging file exists; preserve for manual recovery");
            }
            return false;
        }
        if (utf8.startsWith(prefix) && utf8.endsWith("-pending.kdbx")) {
            matches.append(name);
        }
    }
    if (matches.size() > 1) {
        if (error) {
            *error = QStringLiteral("Multiple recovery revisions exist; manual recovery required");
        }
        return false;
    }
    if (matches.isEmpty()) {
        return false;
    }
    const QString name = matches.front();
    QByteArray revision = name.toUtf8();
    revision.remove(0, prefix.size());
    revision.chop(QByteArrayLiteral("-pending.kdbx").size());
    if (!isValidRevision(revision)) {
        if (error) {
            *error = QStringLiteral("Invalid recovery metadata; manual recovery required");
        }
        return false;
    }
    out->filePath = dir.filePath(name);
    out->baseRevision = revision;
    return true;
}

bool retain(const QString& directory,
            const QByteArray& identity,
            const QByteArray& baseRevision,
            const QByteArray& encryptedDatabase,
            QString* error)
{
    if (!isValidRevision(baseRevision)) {
        if (error) {
            *error = QStringLiteral("Invalid base revision");
        }
        return false;
    }
    if (!CoordinatorConfigValidation::isAcceptableKdbxPayload(encryptedDatabase.size())) {
        if (error) {
            *error = QStringLiteral("Refusing empty or oversized recovery database");
        }
        return false;
    }
    if (!QDir().mkpath(directory)) {
        if (error) {
            *error = QStringLiteral("Cannot create recovery directory");
        }
        return false;
    }

    Pending previous;
    QString findError;
    const bool hasPrevious = find(directory, identity, &previous, &findError);
    if (!findError.isEmpty()) {
        if (error) {
            *error = findError;
        }
        return false;
    }
    if (hasPrevious) {
        const QByteArray previousHash = fileSha256Hex(previous.filePath, error);
        if (previousHash.isEmpty()) {
            return false;
        }
        if (!canReplace(previous.baseRevision, previousHash, baseRevision)) {
            if (error) {
                *error = QStringLiteral("Existing recovery revision has an unrelated base; manual recovery required");
            }
            return false;
        }
    }

    const QByteArray prefix = identityPrefix(identity);
    const QString destinationName = QString::fromUtf8(prefix + baseRevision + QByteArrayLiteral("-pending.kdbx"));
    const QString destination = QDir(directory).filePath(destinationName);
    const QString staged = QDir(directory).filePath(
        QString::fromUtf8(prefix + baseRevision + QByteArrayLiteral("-") + QUuid::createUuid().toByteArray(QUuid::WithoutBraces)
                          + QByteArrayLiteral(".stage")));

    QFile stageFile(staged);
    if (!stageFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) {
            *error = QStringLiteral("Cannot write recovery staging file");
        }
        return false;
    }
    if (stageFile.write(encryptedDatabase) != encryptedDatabase.size() || !stageFile.flush()) {
        stageFile.close();
        QFile::remove(staged);
        if (error) {
            *error = QStringLiteral("Could not persist recovery staging file");
        }
        return false;
    }
    stageFile.close();

    // Atomic replace when destination exists (same base); otherwise rename into place.
    if (QFile::exists(destination)) {
        if (!QFile::remove(destination)) {
            QFile::remove(staged);
            if (error) {
                *error = QStringLiteral("Could not replace previous recovery copy");
            }
            return false;
        }
    }
    if (!QFile::rename(staged, destination)) {
        QFile::remove(staged);
        if (error) {
            *error = QStringLiteral("Could not atomically retain KDBX recovery copy");
        }
        return false;
    }

    if (hasPrevious && previous.filePath != destination) {
        if (!QFile::remove(previous.filePath)) {
            if (error) {
                *error = QStringLiteral("New recovery copy is durable, but old revision could not be removed");
            }
            return false;
        }
    }
    return true;
}

RecoveryAction decide(const Pending& pending, const QByteArray& remoteRevision, QString* error)
{
    if (!isValidRevision(remoteRevision)) {
        if (error) {
            *error = QStringLiteral("Invalid remote revision");
        }
        return RecoveryAction::Conflict;
    }
    const QByteArray localRevision = fileSha256Hex(pending.filePath, error);
    if (localRevision.isEmpty()) {
        return RecoveryAction::Conflict;
    }
    if (localRevision == remoteRevision) {
        return RecoveryAction::AlreadyPublished;
    }
    if (pending.baseRevision == remoteRevision) {
        return RecoveryAction::Publish;
    }
    return RecoveryAction::Conflict;
}

bool acknowledge(const QString& directory,
                 const QByteArray& identity,
                 const QByteArray& expectedContentHash,
                 QString* error)
{
    Pending pending;
    if (!find(directory, identity, &pending, error)) {
        if (error && error->isEmpty()) {
            *error = QStringLiteral("Recovery copy missing");
        }
        return false;
    }
    if (!isValidRevision(expectedContentHash)) {
        if (error) {
            *error = QStringLiteral("Invalid acknowledgement hash");
        }
        return false;
    }
    const QByteArray actual = fileSha256Hex(pending.filePath, error);
    if (actual.isEmpty()) {
        return false;
    }
    if (actual != expectedContentHash) {
        if (error) {
            *error = QStringLiteral("Recovery copy changed; refusing to delete it");
        }
        return false;
    }
    if (!QFile::remove(pending.filePath)) {
        if (error) {
            *error = QStringLiteral("Remote save succeeded, but recovery copy could not be removed");
        }
        return false;
    }
    Q_UNUSED(directory);
    return true;
}

bool clearSuperseded(const QString& directory,
                     const QByteArray& identity,
                     const QByteArray& publishedFromBase,
                     QString* error)
{
    Pending pending;
    QString findError;
    if (!find(directory, identity, &pending, &findError)) {
        if (!findError.isEmpty()) {
            if (error) {
                *error = findError;
            }
            return false;
        }
        return true;
    }
    if (!isValidRevision(publishedFromBase) || pending.baseRevision != publishedFromBase) {
        if (error) {
            *error = QStringLiteral("Pending recovery is not bound to the published tip; refusing to clear");
        }
        return false;
    }
    if (!QFile::remove(pending.filePath)) {
        if (error) {
            *error = QStringLiteral("Remote save succeeded, but superseded recovery copy could not be removed");
        }
        return false;
    }
    return true;
}

} // namespace CoordinatedRecoveryStore
