# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
cargo build              # compile
cargo run                # run (needs env vars — see README.md / watari.md §5)
cargo test                # unit tests (token binding resolution, rustypaste URL parsing, etc.)
cargo test <name>         # run a single test, e.g. `cargo test first_match_wins`
cargo clippy              # lint
```

There is no JS build step — `static/app.js` and `static/htmx.min.js` are served as-is.

## What Watari is

Watari is a Rust/Axum web GUI that sits in front of [rustypaste](https://github.com/orhun/rustypaste) (a minimal self-hosted pastebin/file-upload server that only exposes a bearer-token-secured HTTP API with no user concept). It adds per-user OIDC SSO, per-group token mapping, and optional client-side encryption, without modifying rustypaste itself.

`watari.md` is the original design spec and is still the source of truth for *intent*; this file documents how the actual implementation realizes (and in a few places, knowingly deviates from) it.

## Module map (`src/`)

- `main.rs` — startup sequence (config → DB → token bindings → OIDC discovery → router) and router assembly.
- `config.rs` — `AppConfig::from_env()`; fails fast with a clear error if a required var is missing/invalid.
- `state.rs` — `AppState` (the Axum `State`), plus `FromRef` impls so `axum_extra`'s cookie `Key` and `axum_csrf`'s `CsrfConfig` can be extracted from it.
- `db.rs` — `sqlx` SQLite pool + typed query functions for `sessions`/`upload_log`. Uses the runtime query API (`sqlx::query`/`query_as`), not the `query!` macro, so there's no compile-time `DATABASE_URL` requirement.
- `session.rs` — the `UserSession` extractor (`FromRequestParts`): reads the `session_id` cookie, loads the session row, does best-effort silent OIDC token refresh, redirects to `/auth/login` on any failure. `Option<UserSession>` (via `OptionalFromRequestParts`) never redirects, for public pages that still want the signed-in sidebar. Also owns the `__oidc_state` cookie helpers (PKCE verifier/state/nonce, private/encrypted via `axum_extra::PrivateCookieJar`).
- `oidc.rs` — OIDC discovery + the `/auth/login`, `/auth/callback`, `/auth/logout` handlers. Deliberately does **not** store the built `openidconnect::CoreClient` anywhere — oauth2 5.x's typestate-encoded endpoint generics make that type impractical to name in a struct field, so it's cheaply rebuilt from plain fields (`ClientId`, discovered `ProviderMetadata`, etc.) wherever needed.
- `token_map.rs` — loads `token-bindings.yaml`, resolves each `env_var`, and resolves a user's OIDC groups to a `TokenBinding` (first matching rule wins). `TokenBinding::is_admin()` is defined as "has the `delete` permission".
- `rustypaste.rs` — the rustypaste HTTP client. Field names/headers here were confirmed against rustypaste's actual source, not guessed — see the "rustypaste's real API" doc comment at the top of the file before changing it.
- `csrf.rs` / `csp.rs` / `ratelimit.rs` — `axum_csrf` verification helper, static CSP header middleware, and `tower_governor` layer factories.
- `templates.rs` — `Tpl<T>`, a tiny `IntoResponse` wrapper around `askama::Template::render()` (replaces the `askama_axum` crate, which no longer exists as of askama ≥0.13), and `Layout`, the struct every page template embeds as a `layout: Layout` field for the data `base.html` needs (csrf token, pbkdf2 iterations, user email, admin flag).
- `routes/` — `pages.rs` (home overview at `/home`, dashboard, upload/paste/shorten form pages; the Home diagram in `templates/home.html` is hand-aligned box-drawing text, so keep columns intact when editing it), `api.rs` (the mutating `/api/*` proxy endpoints + pagination), `decrypt.rs` (public, SSRF-guarded; `/decrypt` is also the "Decrypt" sidebar tab, and `share_link` builds the `/decrypt?url=…` link shown after encrypted uploads), `admin.rs` (token bindings viewer).

## Known deviations from `watari.md`

- No generic `config` crate / optional `config.yaml` override (§5) — plain `std::env::var` reads cover everything actually specified.
- No `askama_axum` (removed upstream) — see `templates.rs::Tpl`.
- `/api/pastes/{id}` (not the spec's shorthand `/api/[id]`) for the delete endpoint, to keep it next to the `/api/pastes` pagination endpoint.
- "Admin" (for gating `/admin/tokens`) is defined as *the resolved token binding has the `delete` permission* — the spec doesn't define it more precisely.
- Encrypted URL-shortening: rustypaste's `url` field is a redirect target, so it can't hold ciphertext. When password-protection is on, `/api/shorten` uploads the encrypted URL as a `.enc` **file** instead of calling rustypaste's shorten endpoint (still logged with `kind: "url"` in `upload_log` for display purposes).
- Text paste has no filename/extension field (§8): only the content matters. `/api/paste` ignores any `filename` field and sends rustypaste a generated unique `paste-<8 hex>.txt` (unique so deployments without `random_url` don't 409 on name collisions). The dashboard label (`display_name`) is the paste's first non-blank line, or rustypaste's resulting filename for encrypted pastes, whose content the server can't read.
- CSP has no nonce — every template ended up with zero inline `<script>`/`<style>` (HTMX config goes through the `hx-headers` body attribute, encryption logic lives in `static/app.js`), so a static policy is enough.

## Architecture invariants worth preserving

- Rustypaste bearer tokens must never be logged, returned in HTTP responses, or stored in the database — only referenced by `token_id` in session rows and resolved from the in-memory `TokenMap` built from env vars at startup (`TokenBinding`'s `Debug` impl redacts the token value; keep it that way).
- `routes/decrypt.rs::fetch`'s check that `url` starts with `RUSTYPASTE_PUBLIC_URL` is a security boundary (SSRF prevention), not a convenience check — do not relax it.
- Permission enforcement in `routes/api.rs` (e.g. `delete` requiring a binding with that permission) is explicitly a soft boundary — direct rustypaste API access bypasses it. Real enforcement is whatever `auth_tokens`/`delete_tokens` are configured in rustypaste's own `config.toml`.
- CSRF: every mutating handler calls `csrf::verify(&csrf_token, &headers)` near the top, checking the `X-CSRF-Token` header HTMX attaches via `hx-headers` (set in `base.html`). Any new mutating route needs the same call.
- Templates and migrations are compiled into the binary (Askama, `sqlx::migrate!`) — only `static/` needs to ship alongside the binary at runtime (see `Dockerfile`).
- Password/plaintext content must never reach the server for encrypted uploads — `static/app.js` does the AES-GCM encryption client-side and intercepts the form's `submit` event (not HTMX's `configRequest`, which isn't awaitable) to send the ciphertext via `fetch()` directly.
