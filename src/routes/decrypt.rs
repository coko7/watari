use askama::Template;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_csrf::CsrfToken;
use serde::Deserialize;

use crate::error::AppError;
use crate::session::UserSession;
use crate::state::AppState;
use crate::templates::{Layout, Tpl};

/// The link to share for password-protected content: Watari's decrypt page
/// with the rustypaste URL prefilled, so recipients only type the password.
pub fn share_link(app_base_url: &str, paste_url: &str) -> String {
    let encoded: String = url::form_urlencoded::byte_serialize(paste_url.as_bytes()).collect();
    format!(
        "{}/decrypt?url={encoded}",
        app_base_url.trim_end_matches('/')
    )
}

#[derive(Deserialize)]
pub struct DecryptPageQuery {
    url: Option<String>,
}

#[derive(Deserialize)]
pub struct DecryptQuery {
    url: String,
}

#[derive(Template)]
#[template(path = "decrypt.html")]
struct DecryptTemplate {
    layout: Layout,
    /// Prefills the link field; empty when opened from the sidebar tab.
    url: String,
}

/// `GET /decrypt[?url=...]` — intentionally unauthenticated (watari.md §9.3) so
/// recipients without an SSO account can decrypt shared content. Renders the
/// link + password form; actual bytes are fetched client-side from
/// `/decrypt/fetch`. Signed-in users (it's also a sidebar tab) keep their
/// normal sidebar.
pub async fn page(
    State(state): State<AppState>,
    session: Option<UserSession>,
    csrf_token: CsrfToken,
    Query(query): Query<DecryptPageQuery>,
) -> Response {
    let layout = match &session {
        Some(session) => super::pages::layout_for(&state, &csrf_token, session),
        None => csrf_token
            .authenticity_token()
            .map(|csrf| Layout::anonymous(csrf, state.config.pbkdf2_iterations))
            .map_err(|e| anyhow::anyhow!("csrf token error: {e}")),
    };
    let layout = match layout {
        Ok(l) => l,
        Err(e) => return AppError::Internal(e).into_response(),
    };
    (
        csrf_token,
        Tpl(DecryptTemplate {
            layout,
            url: query.url.unwrap_or_default(),
        }),
    )
        .into_response()
}

/// `GET /decrypt/fetch?url=...` — the actual SSRF-guarded proxy. This is a
/// security boundary, not a convenience check (watari.md, "Architecture
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

#[cfg(test)]
mod tests {
    use super::share_link;

    #[test]
    fn share_link_encodes_the_paste_url() {
        assert_eq!(
            share_link(
                "https://watari.example.com/",
                "https://paste.example.com/safe-toad.txt?x=1&y=2"
            ),
            "https://watari.example.com/decrypt?url=https%3A%2F%2Fpaste.example.com%2Fsafe-toad.txt%3Fx%3D1%26y%3D2"
        );
        assert_eq!(
            share_link(
                "https://watari.example.com",
                "https://paste.example.com/a.txt"
            ),
            "https://watari.example.com/decrypt?url=https%3A%2F%2Fpaste.example.com%2Fa.txt"
        );
    }
}
