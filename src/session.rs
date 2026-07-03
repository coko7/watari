use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar, PrivateCookieJar, SameSite};
use serde::{Deserialize, Serialize};
use time::Duration as TimeDuration;
use time::OffsetDateTime;

use crate::db;
use crate::state::AppState;

pub const SESSION_COOKIE: &str = "session_id";
pub const OIDC_STATE_COOKIE: &str = "__oidc_state";
pub const OIDC_STATE_TTL_SECONDS: i64 = 600; // 10 minutes, per kyosabi.md §6.2

/// What we stash in the short-lived, encrypted `__oidc_state` cookie while the
/// user is off at the IdP mid-login (kyosabi.md §6.2).
#[derive(Debug, Serialize, Deserialize)]
pub struct OidcState {
    pub pkce_verifier: String,
    pub csrf_state: String,
    pub nonce: String,
    pub created_at: i64,
}

pub fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub fn set_oidc_state_cookie(jar: PrivateCookieJar, state: &OidcState) -> PrivateCookieJar {
    let value = serde_json::to_string(state).expect("OidcState always serializes");
    let cookie = Cookie::build((OIDC_STATE_COOKIE, value))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(TimeDuration::seconds(OIDC_STATE_TTL_SECONDS))
        .build();
    jar.add(cookie)
}

pub fn take_oidc_state_cookie(jar: PrivateCookieJar) -> (PrivateCookieJar, Option<OidcState>) {
    let raw = jar.get(OIDC_STATE_COOKIE).map(|c| c.value().to_string());
    let jar = jar.remove(Cookie::from(OIDC_STATE_COOKIE));
    let state = raw
        .and_then(|v| serde_json::from_str::<OidcState>(&v).ok())
        .and_then(|s| {
            if now_unix() - s.created_at > OIDC_STATE_TTL_SECONDS {
                None
            } else {
                Some(s)
            }
        });
    (jar, state)
}

pub fn set_session_cookie(jar: CookieJar, session_id: &str, ttl_seconds: i64) -> CookieJar {
    let cookie = Cookie::build((SESSION_COOKIE, session_id.to_string()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(TimeDuration::seconds(ttl_seconds))
        .build();
    jar.add(cookie)
}

pub fn clear_session_cookie(jar: CookieJar) -> CookieJar {
    jar.remove(Cookie::from(SESSION_COOKIE))
}

/// An authenticated user, extracted from the `session_id` cookie + a live
/// SQLite session row (kyosabi.md §6.3). Unauthenticated or expired sessions
/// redirect to `/auth/login` rather than returning a bare 401, matching the
/// spec's session middleware behavior.
#[derive(Debug, Clone)]
pub struct UserSession {
    pub session_id: String,
    pub user_sub: String,
    pub email: String,
    pub groups: Vec<String>,
    pub token_id: String,
}

pub struct RedirectToLogin;

impl IntoResponse for RedirectToLogin {
    fn into_response(self) -> Response {
        Redirect::to("/auth/login").into_response()
    }
}

impl FromRequestParts<AppState> for UserSession {
    type Rejection = RedirectToLogin;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let session_id = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .ok_or(RedirectToLogin)?;

        let row = db::get_session(&state.db, &session_id)
            .await
            .ok()
            .flatten()
            .ok_or(RedirectToLogin)?;

        let now = now_unix();
        if row.expires_at <= now {
            let _ = db::delete_session(&state.db, &session_id).await;
            return Err(RedirectToLogin);
        }

        // Best-effort silent refresh (kyosabi.md §6.6). If it fails, the spec
        // calls for invalidating the session and sending the user to login.
        if let (Some(refresh_token), Some(access_expires_at)) = (
            row.oidc_refresh_token.as_deref(),
            row.oidc_access_token_expires_at,
        ) && access_expires_at - now < 60
        {
            match state.oidc.refresh(&state.http, refresh_token).await {
                Ok(refreshed) => {
                    let _ = db::update_session_oidc_tokens(
                        &state.db,
                        &session_id,
                        refreshed.refresh_token.as_deref(),
                        refreshed.access_token_expires_at,
                    )
                    .await;
                }
                Err(err) => {
                    tracing::warn!(error = ?err, "OIDC token refresh failed, invalidating session");
                    let _ = db::delete_session(&state.db, &session_id).await;
                    return Err(RedirectToLogin);
                }
            }
        }

        let _ = db::touch_session(&state.db, &session_id, now).await;

        let groups: Vec<String> = serde_json::from_str(&row.groups).unwrap_or_default();

        Ok(UserSession {
            session_id: row.id,
            user_sub: row.user_sub,
            email: row.email,
            groups,
            token_id: row.token_id,
        })
    }
}
