pub mod admin;
pub mod api;
pub mod decrypt;
pub mod pages;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};

use crate::ratelimit;
use crate::state::AppState;

/// Public routes: no session required (watari.md §9.3 — `/decrypt` is
/// intentionally reachable by recipients without an SSO account).
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/decrypt", get(decrypt::page))
        .route("/decrypt/fetch", get(decrypt::fetch))
}

/// Session-guarded application routes (watari.md §3's route table, minus
/// `/auth/*` and `/decrypt`, which are public — see main.rs).
pub fn router(max_body_bytes: usize) -> Router<AppState> {
    let mutating_api = Router::new()
        .route("/api/upload", post(api::upload))
        .route("/api/paste", post(api::paste))
        .route("/api/shorten", post(api::shorten))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(ratelimit::api_governor_layer());

    Router::new()
        .route("/", get(pages::dashboard))
        .route("/home", get(pages::home_page))
        .route("/upload", get(pages::upload_page))
        .route("/paste", get(pages::paste_page))
        .route("/shorten", get(pages::shorten_page))
        .route("/admin/tokens", get(admin::tokens_page))
        .route("/api/pastes", get(api::list_pastes))
        .route("/api/pastes/{id}", delete(api::delete_paste))
        .merge(mutating_api)
}
