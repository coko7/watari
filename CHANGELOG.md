# Changelog

## [0.5.0](https://github.com/coko7/watari/compare/watari-v0.4.0...watari-v0.5.0) (2026-07-06)


### Features

* **ui:** redesign layout with sidebar navigation and dark mode ([fc24101](https://github.com/coko7/watari/commit/fc24101cfa0d2e5fb35e4d09f71fd2e85026ec0e))

## [0.4.0](https://github.com/coko7/watari/compare/watari-v0.3.0...watari-v0.4.0) (2026-07-06)


### Features

* **upload:** add drag-and-drop file upload with size display ([7449a43](https://github.com/coko7/watari/commit/7449a43b9d5cd89622c40425bc400add3f364ce2))

## [0.3.0](https://github.com/coko7/watari/compare/watari-v0.2.0...watari-v0.3.0) (2026-07-06)


### Features

* implement KyoSabi per kyosabi.md spec ([b7adf2d](https://github.com/coko7/watari/commit/b7adf2d2b2aa7e859b9817fbb039f49a87418e2c))
* **oidc:** support Zitadel and other multi-audience OIDC providers ([2328727](https://github.com/coko7/watari/commit/2328727d3c8ef046916a1094d7741e6d2e6cf556))


### Bug Fixes

* **db:** handle relative paths in sqlite connection ([5806790](https://github.com/coko7/watari/commit/58067903e9dfbf8a49f0dd21428debefbec1db39))

## v0.2.0

Project renamed from **KyoSabi** to **Watari**. No functional changes to the app itself — this release is naming, docs, and CI groundwork.

### Changed

- 🏷️ **Renamed KyoSabi → Watari**, throughout the crate, Docker service/volume names, and all docs/comments (`kyosabi.md` → `watari.md`).
- 📄 README rewrite: project description, badges (crates.io, license, top-language, CI), and WIP disclaimer.
- 🎨 HTML templates reformatted to consistent 2-space indentation.

### CI

- ✅ Added GitHub Actions pipeline (`rust.yml`): build + test, clippy lints, and `cargo fmt --check` on push/PR to `main`.

## v0.1.0

Initial release. Web GUI frontend for [rustypaste](https://github.com/orhun/rustypaste), adding SSO, per-group access control, and optional client-side encryption on top of rustypaste's bearer-token-only API.

### Features

- 🔐 **OpenID Connect SSO** — login flow (PKCE + state/nonce), silent token refresh, tested against Zitadel and other multi-audience OIDC providers.
- 🗂️ **Per-group token mapping** — `token-bindings.yaml` maps OIDC groups to rustypaste tokens/permissions; first matching rule wins. Admin status derived from the `delete` permission.
- 🔒 **Client-side encryption** — optional password-based AES-GCM (WebCrypto) encryption; plaintext/password never reach the server.
- 📋 Dashboard, upload, paste, and shorten-URL pages (HTMX + Askama).
- 🗑️ Paste management: paginated listing, delete via `/api/pastes/{id}`.
- 🛡️ Admin token-bindings viewer.
- 🌐 Public, SSRF-guarded decrypt endpoint for sharing encrypted links.
- ⚙️ CSRF protection, static CSP headers, and rate limiting on all mutating routes.
- 🗄️ SQLite-backed sessions and upload log, migrations run automatically at startup.
- 🐳 Docker Compose deployment path.
