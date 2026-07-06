# ☕ Watari

**Watari** is a web GUI frontend for [rustypaste](https://github.com/orhun/rustypaste).

The project name comes from the japanese word **渡り** (`watari`, also written as **ワタリ** in [Katakana](https://en.wikipedia.org/wiki/Katakana)) which means ["crossing, passage, transit"](https://jisho.org/search/%22watari%22) and symbolizes the relationship with **rustypaste**.

<img alt="watari banner image" src="https://github.com/user-attachments/assets/817412d7-eb96-485a-8316-67f4af6cf578" />

<p align="center">
    <a href="https://github.com/coko7/watari/releases/latest"><img src="https://img.shields.io/github/v/release/coko7/watari" alt="Release info"></a>
    <a href="LICENSE"><img src="https://img.shields.io/github/license/coko7/watari?color=blue" alt="License: MIT"></a>
    <img src="https://img.shields.io/github/languages/top/coko7/watari?color=orange" alt="Rust">
    <a href="https://github.com/coko7/watari/actions/workflows/rust.yml"><img src="https://github.com/coko7/watari/actions/workflows/rust.yml/badge.svg" alt="Tests"></a>
</p>

> [!WARNING]
> 🚧 **Early stages — big work in progress.** Expect rough edges and breaking changes. 🚧

On top of providing a GUI, it comes with some additional features:

- 🔐 [OpenID Connect](https://openid.net/developers/how-connect-works/) Single sign-on (tested against [Zitadel](https://zitadel.com/))
- 🗂️ Per-group token mapping
- 🔒 Optional client-side ([WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)) password encryption

All built with a ***based*** technical stack: [axum](https://github.com/tokio-rs/axum) + [Askama](https://github.com/askama-rs/askama) + [HTMX](https://htmx.org/) + [SQLite](https://sqlite.org)

This project has been **vibe-scaffolded** with [Claude](https://claude.ai), you can find the full design here: [`watari.md`](./watari.md)

## Running with Docker Compose (recommended)

1. `cp env.example .env` and fill in `SESSION_SECRET` (`openssl rand -hex 32`),
   `OIDC_CLIENT_SECRET`, and two distinct `RUSTYPASTE_TOKEN_*` secrets.
2. `cp rustypaste-config.example.toml rustypaste-config.toml` and paste the
   same two rustypaste token values into `auth_tokens`/`delete_tokens`.
3. `cp token-bindings.example.yaml token-bindings.yaml` and adjust the
   `groups` to match your IdP.
4. Edit `docker-compose.yml`'s `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`,
   `APP_BASE_URL`/`RUSTYPASTE_PUBLIC_URL` for your deployment.
5. `docker compose up -d --build`

## Running locally for development

Requires Rust (edition 2024, so a recent stable toolchain) and no external
services besides an OIDC provider and a rustypaste instance to point at.

```sh
cargo build
cargo test
export $(cat .env | xargs)  # or set the vars below directly
cargo run
```

Required environment variables (see `watari.md` §5 for the full list with
defaults): `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`OIDC_REDIRECT_URI`, `SESSION_SECRET`, `RUSTYPASTE_INTERNAL_URL`,
`RUSTYPASTE_PUBLIC_URL`, `APP_BASE_URL`. A `token-bindings.yaml` must also
exist at `TOKEN_BINDINGS_PATH` (default `token-bindings.yaml`), with each
`env_var` it references set.

Database migrations run automatically at startup (`DATABASE_PATH`, default
`/data/app.db` — for local dev, point this somewhere writable, e.g.
`./dev.db`).

## Project layout

- `src/` — the Axum application; see `CLAUDE.md` for a module-by-module map.
- `templates/` — Askama HTML templates, compiled into the binary at build time.
- `static/` — served as-is at `/static` (vendored HTMX, `app.css`, `app.js`).
- `migrations/` — sqlx SQL migrations, embedded into the binary at build time.
- `token-bindings.example.yaml` — OIDC-group → rustypaste-token mapping (§7).
- `rustypaste-config.example.toml` — matching rustypaste server config.

## License

AGPLv3 — see [`LICENSE`](./LICENSE).
