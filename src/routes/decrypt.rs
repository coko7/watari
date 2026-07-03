use askama::Template;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_csrf::CsrfToken;
use serde::Deserialize;

use crate::error::AppError;
use crate::state::AppState;
use crate::templates::{Layout, Tpl};

#[derive(Deserialize)]
pub struct DecryptQuery {
    url: String,
}

#[derive(Template)]
#[template(path = "decrypt.html")]
struct DecryptTemplate {
    layout: Layout,
    url: String,
}

/// `GET /decrypt?url=...` — intentionally unauthenticated (kyosabi.md §9.3) so
/// recipients without an SSO account can decrypt shared content. Renders the
/// password prompt; actual bytes are fetched client-side from `/decrypt/fetch`.
pub async fn page(
    State(state): State<AppState>,
    csrf_token: CsrfToken,
    Query(query): Query<DecryptQuery>,
) -> Response {
    let csrf = match csrf_token.authenticity_token() {
        Ok(t) => t,
        Err(e) => {
            return AppError::Internal(anyhow::anyhow!("csrf token error: {e}")).into_response();
        }
    };
    let layout = Layout::anonymous(csrf, state.config.pbkdf2_iterations);
    (
        csrf_token,
        Tpl(DecryptTemplate {
            layout,
            url: query.url,
        }),
    )
        .into_response()
}

/// `GET /decrypt/fetch?url=...` — the actual SSRF-guarded proxy. This is a
/// security boundary, not a convenience check (kyosabi.md, "Architecture
/// invariants"): `url` must be prefixed by `RUSTYPASTE_PUBLIC_URL`, full stop.
pub async fn fetch(State(state): State<AppState>, Query(query): Query<DecryptQuery>) -> Response {
    if !query.url.starts_with(&state.config.rustypaste_public_url) {
        return AppError::BadRequest("url must point at this rustypaste instance".into())
            .into_response();
    }

    // Rewrite to the internal Docker-network URL so the fetch doesn't leave
    // the deployment and doesn't depend on the public URL being reachable
    // from inside the container.
    let internal_url = format!(
        "{}{}",
        state.config.rustypaste_internal_url,
        &query.url[state.config.rustypaste_public_url.len()..]
    );

    let resp = match state.http.get(&internal_url).send().await {
        Ok(r) => r,
        Err(e) => {
            return AppError::Upstream(format!("could not reach rustypaste: {e}")).into_response();
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return (
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            "the requested paste could not be found or has expired",
        )
            .into_response();
    }

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return AppError::Upstream(format!("failed reading rustypaste response: {e}"))
                .into_response();
        }
    };

    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
}
