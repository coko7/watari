use askama::Template;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum_csrf::CsrfToken;
use serde::Deserialize;

use crate::error::AppError;
use crate::rustypaste::{FileMode, RustypasteError, UrlMode};
use crate::session::UserSession;
use crate::state::AppState;
use crate::templates::Tpl;
use crate::token_map::Permission;
use crate::{csrf, db};

use super::pages::{LoadMoreTemplate, PAGE_SIZE, PasteRowsTemplate, UploadRowView};

#[derive(Template)]
#[template(path = "partials/flash.html")]
struct FlashTemplate {
    ok: bool,
    message: String,
    url: Option<String>,
}

fn flash_ok(message: impl Into<String>, url: String) -> Response {
    Tpl(FlashTemplate {
        ok: true,
        message: message.into(),
        url: Some(url),
    })
    .into_response()
}

fn flash_err(message: impl Into<String>) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Tpl(FlashTemplate {
            ok: false,
            message: message.into(),
            url: None,
        }),
    )
        .into_response()
}

/// Ciphertext produced by `static/app.js` always starts with the `RPEN`
/// envelope magic (kyosabi.md §9.1) — self-describing, so the server doesn't
/// need to trust a client-supplied "is this encrypted" flag.
fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(b"RPEN")
}

fn humantime_expire(raw: &Option<String>) -> Option<String> {
    raw.as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

struct ParsedUpload {
    bytes: Vec<u8>,
    content_type: String,
    file_name: Option<String>,
    override_filename: Option<String>,
    expire: Option<String>,
    oneshot: bool,
    /// Present only for the /api/shorten flow's plaintext (non-encrypted) case.
    url: Option<String>,
}

async fn parse_multipart(mut multipart: Multipart) -> Result<ParsedUpload, AppError> {
    let mut out = ParsedUpload {
        bytes: Vec::new(),
        content_type: "application/octet-stream".to_string(),
        file_name: None,
        override_filename: None,
        expire: None,
        oneshot: false,
        url: None,
    };
    let mut have_file = false;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("malformed form data: {e}")))?
    {
        match field.name().unwrap_or_default() {
            "file" => {
                out.file_name = field.file_name().map(str::to_string);
                out.content_type = field
                    .content_type()
                    .map(str::to_string)
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                out.bytes = field.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                have_file = true;
            }
            "content" => {
                // The "paste" form's textarea, wrapped as a file (kyosabi.md §8.3).
                out.bytes = field.text().await.unwrap_or_default().into_bytes();
                out.content_type = "text/plain; charset=utf-8".to_string();
                have_file = true;
            }
            "url" => out.url = field.text().await.ok().filter(|s| !s.is_empty()),
            "filename" => out.override_filename = field.text().await.ok().filter(|s| !s.is_empty()),
            "expire" => out.expire = field.text().await.ok().filter(|s| !s.is_empty()),
            "oneshot" => out.oneshot = field.text().await.map(|v| v == "true").unwrap_or(false),
            // "password"/"password-confirm" must never reach the server; app.js
            // strips them client-side. If they somehow arrive, ignore the value.
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    if !have_file && out.url.is_none() {
        return Err(AppError::BadRequest(
            "no file, text, or URL content was submitted".into(),
        ));
    }

    Ok(out)
}

fn permission_check(
    state: &AppState,
    session: &UserSession,
    perm: Permission,
) -> Result<String, AppError> {
    match state.token_map.get(&session.token_id) {
        Some(binding) if binding.has(perm) => Ok(binding.token.clone()),
        _ => Err(AppError::Forbidden),
    }
}

async fn log_upload(
    state: &AppState,
    session: &UserSession,
    display_name: &str,
    paste_url: &str,
    kind: &str,
    encrypted: bool,
    expire: &Option<String>,
) {
    let now = crate::session::now_unix();
    let expires_at = expire
        .as_deref()
        .and_then(|e| humantime::parse_duration(e).ok())
        .map(|d| now + d.as_secs() as i64);
    let res = db::insert_upload_log(
        &state.db,
        db::NewUploadLog {
            id: &uuid::Uuid::new_v4().to_string(),
            user_sub: &session.user_sub,
            email: &session.email,
            display_name,
            paste_url,
            kind,
            encrypted,
            created_at: now,
            expires_at,
        },
    )
    .await;
    if let Err(err) = res {
        tracing::error!(error = ?err, "failed to record upload_log row");
    }
}

pub async fn upload(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    if let Err(e) = csrf::verify(&csrf_token, &headers) {
        return e.into_response();
    }
    let token = match permission_check(&state, &session, Permission::Upload) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let parsed = match parse_multipart(multipart).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let filename = parsed
        .override_filename
        .or(parsed.file_name)
        .unwrap_or_else(|| "upload.bin".to_string());
    let encrypted = is_encrypted(&parsed.bytes);
    let mode = if parsed.oneshot {
        FileMode::OneShot
    } else {
        FileMode::Normal
    };

    match state
        .rustypaste
        .upload_file(
            &token,
            mode,
            &filename,
            parsed.bytes,
            &parsed.content_type,
            humantime_expire(&parsed.expire).as_deref(),
        )
        .await
    {
        Ok(url) => {
            log_upload(
                &state,
                &session,
                &filename,
                &url,
                "file",
                encrypted,
                &parsed.expire,
            )
            .await;
            flash_ok("Uploaded successfully.", url)
        }
        Err(e) => flash_err(upstream_message(e)),
    }
}

pub async fn paste(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    if let Err(e) = csrf::verify(&csrf_token, &headers) {
        return e.into_response();
    }
    let token = match permission_check(&state, &session, Permission::Paste) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let parsed = match parse_multipart(multipart).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let filename = parsed
        .override_filename
        .unwrap_or_else(|| "paste.txt".to_string());
    let encrypted = is_encrypted(&parsed.bytes);
    let mode = if parsed.oneshot {
        FileMode::OneShot
    } else {
        FileMode::Normal
    };

    match state
        .rustypaste
        .upload_file(
            &token,
            mode,
            &filename,
            parsed.bytes,
            &parsed.content_type,
            humantime_expire(&parsed.expire).as_deref(),
        )
        .await
    {
        Ok(url) => {
            log_upload(
                &state,
                &session,
                &filename,
                &url,
                "paste",
                encrypted,
                &parsed.expire,
            )
            .await;
            flash_ok("Pasted successfully.", url)
        }
        Err(e) => flash_err(upstream_message(e)),
    }
}

pub async fn shorten(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    if let Err(e) = csrf::verify(&csrf_token, &headers) {
        return e.into_response();
    }
    let token = match permission_check(&state, &session, Permission::Shorten) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let parsed = match parse_multipart(multipart).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let expire = humantime_expire(&parsed.expire);

    // Plaintext case: rustypaste's `url`/`oneshot_url` fields shorten a real
    // URL. Encrypted case: the target URL is opaque ciphertext, which
    // rustypaste can't treat as a redirect target — app.js instead sends it
    // as an encrypted *file* (kyosabi.md §9.1's ".enc" convention), so it's
    // handled exactly like an upload.
    if let Some(url) = parsed.url {
        let mode = if parsed.oneshot {
            UrlMode::OneShotUrl
        } else {
            UrlMode::Shorten
        };
        return match state
            .rustypaste
            .shorten(&token, mode, &url, expire.as_deref())
            .await
        {
            Ok(short_url) => {
                log_upload(
                    &state,
                    &session,
                    &url,
                    &short_url,
                    "url",
                    false,
                    &parsed.expire,
                )
                .await;
                flash_ok("Shortened successfully.", short_url)
            }
            Err(e) => flash_err(upstream_message(e)),
        };
    }

    let filename = parsed
        .override_filename
        .unwrap_or_else(|| "shortened-url.enc".to_string());
    let encrypted = is_encrypted(&parsed.bytes);
    let mode = if parsed.oneshot {
        FileMode::OneShot
    } else {
        FileMode::Normal
    };
    match state
        .rustypaste
        .upload_file(
            &token,
            mode,
            &filename,
            parsed.bytes,
            &parsed.content_type,
            expire.as_deref(),
        )
        .await
    {
        Ok(url) => {
            log_upload(
                &state,
                &session,
                &filename,
                &url,
                "url",
                encrypted,
                &parsed.expire,
            )
            .await;
            flash_ok("Shortened successfully.", url)
        }
        Err(e) => flash_err(upstream_message(e)),
    }
}

fn upstream_message(err: RustypasteError) -> String {
    tracing::warn!(error = ?err, "rustypaste rejected a request");
    match err {
        RustypasteError::Upstream { status, .. } => {
            format!("rustypaste rejected the request ({status})")
        }
        RustypasteError::Request(_) => "could not reach rustypaste".to_string(),
    }
}

pub async fn delete_paste(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = csrf::verify(&csrf_token, &headers) {
        return e.into_response();
    }
    let token = match permission_check(&state, &session, Permission::Delete) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let row = match db::get_upload_for_user(&state.db, &id, &session.user_sub).await {
        Ok(Some(row)) => row,
        Ok(None) => return AppError::NotFound.into_response(),
        Err(e) => return AppError::Internal(e.into()).into_response(),
    };

    let Some(filename) = crate::rustypaste::filename_from_paste_url(&row.paste_url) else {
        return AppError::Internal(anyhow::anyhow!("stored paste_url has no filename segment"))
            .into_response();
    };

    if let Err(e) = state.rustypaste.delete(&token, &filename).await {
        return flash_err(upstream_message(e));
    }

    let _ = db::delete_upload_log(&state.db, &id).await;
    // Empty 200 body: HTMX removes the row via hx-swap="outerHTML" (kyosabi.md §8.4).
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
pub struct PastesQuery {
    before: Option<i64>,
}

pub async fn list_pastes(
    State(state): State<AppState>,
    session: UserSession,
    Query(query): Query<PastesQuery>,
) -> Response {
    let db_rows = db::list_uploads_page(&state.db, &session.user_sub, query.before, PAGE_SIZE)
        .await
        .unwrap_or_default();
    let has_more = db_rows.len() as i64 == PAGE_SIZE;
    let next_cursor = db_rows.last().map(|r| r.created_at);
    let rows: Vec<UploadRowView> = db_rows.iter().map(UploadRowView::from).collect();
    let can_delete = state
        .token_map
        .get(&session.token_id)
        .map(|b| b.has(Permission::Delete))
        .unwrap_or(false);

    let rows_html = PasteRowsTemplate { rows, can_delete }
        .render()
        .unwrap_or_default();
    let load_more_html = LoadMoreTemplate {
        has_more,
        next_cursor,
    }
    .render()
    .unwrap_or_default();
    axum::response::Html(format!("{rows_html}{load_more_html}")).into_response()
}
