# NetAigis KeySafe (Desktop)

**Independent NetAigis desktop password manager fork of KeePassXC.**

Android and Linux are platform variants of the **same** KeySafe project
(see https://net-aigis.de/keysafe.html — “Ein KeySafe. Zwei Plattformen.”).
This tree is the Linux/desktop fork; the Android fork lives in
`NetAigis-KeySafe`.

Experimental HTTPS coordination for shared encrypted KDBX databases is under
development. **Not suitable for production password data.**

## Desktop application identity

- Display name: **NetAigis KeySafe**
- Project directory / product: `NetAigis-KeySafe-Desktop`
- Desktop / Flatpak style app id: `de.netaigis.keysafe.desktop`
- Linux binary: `keysafe` (CLI currently still builds as `keepassxc-cli`)
- Version: `0.1.0-dev` (same scheme as Android KeySafe; not 1.x until a real release)
- GitHub: https://github.com/net-aigis/NetAigis-KeySafe-Desktop
- Upstream CMake `project(KeePassXC)` / internal library names retained for
  mergeability — they are **not** the user-visible product name

## Attribution

Derived from **KeePassXC** (KeePassXC Team and contributors), GPL-2.0-or-later /
GPL-3.0-or-later as in upstream. See `COPYING` and `docs/KEYSAFE_DESKTOP_FORK_NOTICES.md`.
Not an official KeePassXC application.

Coordination protocol work is aligned with NetAigis KeySafe on Android
(`de.netaigis.keysafe`). Auto-publish / merge authorization remains denied until
proven.
