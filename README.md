# 🔐 KyoSabi 共錆

A web GUI for [rustypaste](https://github.com/orhun/rustypaste) that adds OIDC
SSO, per-group token mapping, and optional client-side (WebCrypto) password
encryption — without modifying rustypaste itself. Single Rust binary: Axum +
Askama + HTMX + SQLite. Full design: [`kyosabi.md`](./kyosabi.md).

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

Required environment variables (see `kyosabi.md` §5 for the full list with
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
