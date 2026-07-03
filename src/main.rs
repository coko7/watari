mod config;
mod csp;
mod csrf;
mod db;
mod error;
mod oidc;
mod ratelimit;
mod routes;
mod rustypaste;
mod session;
mod state;
mod templates;
mod token_map;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use axum_csrf::CsrfConfig;
use axum_extra::extract::cookie::Key;
use sha2::{Digest, Sha512};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = config::AppConfig::from_env()?;
    tracing::info!(?config, "starting kyosabi");

    let db = db::connect(&config.database_path).await?;

    let token_map = token_map::TokenMap::load(&config.token_bindings_path)
        .map_err(|e| anyhow::anyhow!("failed to load token bindings: {e}"))?;

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.rustypaste_timeout_secs,
        ))
        .build()?;

    let rustypaste =
        rustypaste::RustypasteClient::new(http.clone(), config.rustypaste_internal_url.clone());

    let oidc = oidc::OidcContext::discover(
        &http,
        &config.oidc_issuer_url,
        &config.oidc_client_id,
        &config.oidc_client_secret,
        &config.oidc_redirect_uri,
    )
    .await?;

    // cookie 0.18's `Key::from` needs exactly/at-least 64 bytes; our SESSION_SECRET
    // is only required to be 32+ bytes (kyosabi.md §5), so expand it deterministically.
    let cookie_key = Key::from(&Sha512::digest(&config.session_secret));
    let csrf_config = CsrfConfig::default().with_key(Some(cookie_key.clone()));

    let state = AppState {
        config: Arc::new(config),
        db,
        http,
        token_map: Arc::new(token_map),
        rustypaste,
        oidc: Arc::new(oidc),
        cookie_key,
        csrf_config,
    };

    let auth_routes = Router::new()
        .route("/auth/callback", get(oidc::callback))
        .layer(ratelimit::auth_governor_layer());

    let max_body_bytes = state.config.rustypaste_max_body_bytes as usize;

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/auth/login", get(oidc::login))
        .route("/auth/logout", axum::routing::post(oidc::logout))
        .merge(auth_routes)
        .merge(routes::router(max_body_bytes))
        .merge(routes::public_router())
        .nest_service("/static", ServeDir::new("static"))
        .layer(axum::middleware::from_fn(csp::csp_middleware))
        .with_state(state.clone());

    let addr = format!("0.0.0.0:{}", state.config.app_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
