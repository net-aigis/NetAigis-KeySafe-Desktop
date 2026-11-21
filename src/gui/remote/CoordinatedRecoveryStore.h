/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <QByteArray>
#include <QString>

/**
 * Durable encrypted KDBX recovery copy written before coordinator publish.
 * Filename binds database identity + base revision (same scheme as Android
 * AtomicRecoveryStore). Never auto-merges CONFLICT; never deletes without
 * matching content hash acknowledgement.
 */
namespace CoordinatedRecoveryStore {

enum class RecoveryAction { AlreadyPublished, Publish, Conflict };

struct Pending {
    QString filePath;
    QByteArray baseRevision; // "0" or 64 lowercase hex
};

/** Identity must be url + NUL + databaseId (no token), matching KeySafe Android. */
QString recoveryDirectory();

bool find(const QString& directory, const QByteArray& identity, Pending* out, QString* error);
bool retain(const QString& directory,
            const QByteArray& identity,
            const QByteArray& baseRevision,
            const QByteArray& encryptedDatabase,
            QString* error);
RecoveryAction decide(const Pending& pending, const QByteArray& remoteRevision, QString* error);
bool acknowledge(const QString& directory,
                 const QByteArray& identity,
                 const QByteArray& expectedContentHash,
                 QString* error);

/**
 * After a successful merge publish, drop a pending copy that was bound to the
 * tip just replaced (base == publishedFromBase). Exact content match still
 * goes through acknowledge(); this path only covers rewritten merge ciphertext.
 */
bool clearSuperseded(const QString& directory,
                     const QByteArray& identity,
                     const QByteArray& publishedFromBase,
                     QString* error);

QByteArray sha256Hex(const QByteArray& bytes);
bool canReplace(const QByteArray& previousBase,
                const QByteArray& previousContentHash,
                const QByteArray& newBase);

} // namespace CoordinatedRecoveryStore
