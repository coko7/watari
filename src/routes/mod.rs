pub mod admin;
pub mod api;
pub mod decrypt;
pub mod pages;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};

use crate::ratelimit;
use crate::state::AppState;

/// Public routes: no session required. `/decrypt` is reachable by recipients
/// without an SSO account (watari.md §9.3); `/home` is the public landing page,
/// and `/` sends anonymous visitors there (signed-in users get the dashboard).
/// These handlers take `Option<UserSession>` so signed-in users keep their
/// sidebar; everything in `router()` below requires SSO.
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::dashboard))
        .route("/home", get(pages::home_page))
        .route("/decrypt", get(decrypt::page))
        .route("/decrypt/fetch", get(decrypt::fetch))
}

/// Session-guarded application routes (watari.md §3's route table, minus
/// `/auth/*` and the public routes above — see main.rs). Each handler takes
/// `UserSession`, which redirects to `/auth/login` without a valid session.
pub fn router(max_body_bytes: usize) -> Router<AppState> {
    let mutating_api = Router::new()
        .route("/api/upload", post(api::upload))
        .route("/api/paste", post(api::paste))
        .route("/api/shorten", post(api::shorten))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(ratelimit::api_governor_layer());

    Router::new()
        .route("/upload", get(pages::upload_page))
        .route("/paste", get(pages::paste_page))
        .route("/shorten", get(pages::shorten_page))
        .route("/admin/tokens", get(admin::tokens_page))
        .route("/api/pastes", get(api::list_pastes))
        .route("/api/pastes/{id}", delete(api::delete_paste))
        .merge(mutating_api)
}
