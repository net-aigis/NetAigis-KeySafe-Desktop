# NetAigis KeySafe Desktop — 1.0.0

Aligned with Android KeySafe **1.0.0**.

## This release

- Product version `.version` = `1.0.0`
- App id `de.netaigis.keysafe.desktop`
- Coordinated KDBX + recovery store
- Local Xvfb proofs: unlock/publish, crash reopen, edit+Ctrl+S tip advance, dual-writer busy (423)

## Packaging still operator-owned

- [ ] Linux package / AppImage / Flatpak channel choice
- [ ] Windows / macOS codesigning when those artifacts are produced
- [ ] Convey Corresponding Source with any binary distribution (GPL)

Shared policy: Android tree `docs/PRIVACY.md`, `docs/KEYSAFE_THREAT_MODEL.md`, `docs/KEYSAFE_RELEASE_NOTES.md`.

## Security backports (branch `security/upstream-keepassxc-fixes`)

Cherry-picked from KeePassXC upstream (not a full merge):

- Importer integer overflows (`70e439eb`)
- KeeShare reject refs without `<Group>` (`13f56db7`)
- KDB reader single UUID / UAF hardening (`20820846`, CVE-2026-69150 related)
- KeeShare OOB integer wrap (`6bcb901a`)
- Passkeys register/auth UAF (`300f0801`, #14011)
- Browser subdomain/wildcard domain matching (`f33f01bf`, #14045)

Already present on the coordinated branch before this backport: OpenSSL cnf/engines hardening, browser reference-injection fixes, native-messaging OOB write fix, Pageant shared-memory randomization, and related 2.8.0-beta1 security items.
