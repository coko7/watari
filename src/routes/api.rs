use askama::Template;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum_csrf::CsrfToken;
use serde::Deserialize;

use crate::db::UploadKind;
use crate::error::AppError;
use crate::rustypaste::{FileMode, RustypasteError, UrlMode};
use crate::session::UserSession;
use crate::state::AppState;
use crate::templates::Tpl;
use crate::token_map::Permission;
use crate::{csrf, db};

use super::pages::{LoadMoreTemplate, PasteRowsTemplate, load_section_page};

#[derive(Template)]
#[template(path = "partials/flash.html")]
struct FlashTemplate {
    ok: bool,
    message: String,
    url: Option<String>,
    /// Adds the "how to open password-protected content" explanation.
    protected: bool,
}

/// Success flash after an upload/paste/shorten. For encrypted content the link
/// shown is Watari's decrypt page (what recipients should open), not the raw
/// rustypaste URL, which only serves ciphertext.
fn flash_ok(
    state: &AppState,
    message: impl Into<String>,
    url: String,
    encrypted: bool,
) -> Response {
    let url = if encrypted {
        super::decrypt::share_link(&state.config.app_base_url, &url)
    } else {
        url
    };
    Tpl(FlashTemplate {
        ok: true,
        message: message.into(),
        url: Some(url),
        protected: encrypted,
    })
    .into_response()
}

fn flash_err(message: impl Into<String>) -> Response {
    flash_err_status(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn flash_err_status(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Tpl(FlashTemplate {
            ok: false,
            message: message.into(),
            url: None,
            protected: false,
        }),
    )
        .into_response()
}

/// Ciphertext produced by `static/app.js` always starts with the `RPEN`
/// envelope magic (watari.md §9.1) — self-describing, so the server doesn't
/// need to trust a client-supplied "is this encrypted" flag.
fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(b"RPEN")
}

fn humantime_expire(raw: &Option<String>) -> Option<String> {
    raw.as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Dashboard label for a plaintext paste (the `display_name` "text snippet" of
/// watari.md §10): its first non-blank line, truncated.
fn paste_snippet(bytes: &[u8]) -> Option<String> {
    const MAX_CHARS: usize = 60;
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let mut snippet: String = line.chars().take(MAX_CHARS).collect();
    if line.chars().count() > MAX_CHARS {
        snippet.push('…');
    }
    Some(snippet)
}

fn format_bytes(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = UNITS[0];
    for candidate in &UNITS[1..] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = candidate;
    }
    format!("{value:.1} {unit}")
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
                // The "paste" form's textarea, wrapped as a file (watari.md §8.3).
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
    kind: UploadKind,
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
    let size = format_bytes(parsed.bytes.len());
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
                UploadKind::File,
                encrypted,
                &parsed.expire,
            )
            .await;
            flash_ok(
                &state,
                format!("Uploaded successfully ({size})."),
                url,
                encrypted,
            )
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

    // Pastes are unnamed; only the content matters. With rustypaste's
    // `random_url` set, the name only contributes its `.txt` extension; without
    // it the name is used verbatim, so it must be unique or rustypaste answers
    // 409 "file already exists". Any `filename` form field is ignored.
    let filename = format!(
        "paste-{}.txt",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let encrypted = is_encrypted(&parsed.bytes);
    // The server can't read encrypted content, so those fall back to the
    // upstream filename once rustypaste has picked it.
    let snippet = if encrypted {
        None
    } else {
        paste_snippet(&parsed.bytes)
    };
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
            let display_name = snippet
                .or_else(|| crate::rustypaste::filename_from_paste_url(&url))
                .unwrap_or(filename);
            log_upload(
                &state,
                &session,
                &display_name,
                &url,
                UploadKind::Paste,
                encrypted,
                &parsed.expire,
            )
            .await;
            flash_ok(&state, "Pasted successfully.", url, encrypted)
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
    // as an encrypted *file* (watari.md §9.1's ".enc" convention), so it's
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
                    UploadKind::Url,
                    false,
                    &parsed.expire,
                )
                .await;
                flash_ok(&state, "Shortened successfully.", short_url, false)
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
                UploadKind::Url,
                encrypted,
                &parsed.expire,
            )
            .await;
            flash_ok(&state, "Shortened successfully.", url, encrypted)
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

/// Every error path returns a flash fragment (not the full-page `AppError`
/// template): the dashboard's Delete button swaps error bodies into its
/// `data-error-target` (see `static/app.js`).
pub async fn delete_paste(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = csrf::verify(&csrf_token, &headers) {
        return flash_err(format!(
            "Delete failed: {e}. Reload the page and try again."
        ));
    }
    let Ok(token) = permission_check(&state, &session, Permission::Delete) else {
        return flash_err_status(
            StatusCode::FORBIDDEN,
            "Delete failed: you don't have permission to delete pastes.",
        );
    };

    let row = match db::get_upload_for_user(&state.db, &id, &session.user_sub).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return flash_err_status(
                StatusCode::NOT_FOUND,
                "Delete failed: paste not found. It may already have been deleted; reload the page.",
            );
        }
        Err(e) => {
            tracing::error!(error = ?e, "failed to load upload_log row for delete");
            return flash_err_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Delete failed: internal server error.",
            );
        }
    };

    let Some(filename) = crate::rustypaste::filename_from_paste_url(&row.paste_url) else {
        tracing::error!(paste_url = %row.paste_url, "stored paste_url has no filename segment");
        return flash_err_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Delete failed: internal server error.",
        );
    };

    match state.rustypaste.delete(&token, &filename).await {
        Ok(()) => {}
        // rustypaste answers 404 ("file is not found or expired") for anything
        // it no longer serves: expired items, and one-shot files/URLs that were
        // already viewed (it renames them with a past timestamp on first view).
        // The paste is already gone upstream, so just drop our log row.
        Err(RustypasteError::Upstream { status, .. }) if status == StatusCode::NOT_FOUND => {
            tracing::info!(%filename, "paste already gone upstream; removing log row");
        }
        Err(e) => return flash_err(format!("Delete failed: {}.", upstream_message(e))),
    }

    let _ = db::delete_upload_log(&state.db, &id).await;
    // Empty 200 body: HTMX removes the row via hx-swap="outerHTML" (watari.md §8.4).
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
pub struct PastesQuery {
    /// Which dashboard section is paginating.
    kind: UploadKind,
    before: Option<i64>,
}

pub async fn list_pastes(
    State(state): State<AppState>,
    session: UserSession,
    Query(query): Query<PastesQuery>,
) -> Response {
    let kind = query.kind;
    let page = load_section_page(&state, &session.user_sub, kind, query.before).await;
    let can_delete = state
        .token_map
        .get(&session.token_id)
        .map(|b| b.has(Permission::Delete))
        .unwrap_or(false);

    let rows_html = PasteRowsTemplate {
        kind,
        rows: page.rows,
        can_delete,
    }
    .render()
    .unwrap_or_default();
    let load_more_html = LoadMoreTemplate {
        kind,
        has_more: page.has_more,
        next_cursor: page.next_cursor,
    }
    .render()
    .unwrap_or_default();
    axum::response::Html(format!("{rows_html}{load_more_html}")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_is_first_non_blank_line() {
        assert_eq!(
            paste_snippet(b"\n   \n  hello world  \nsecond line"),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn snippet_truncates_long_lines_on_char_boundaries() {
        let line = "é".repeat(80);
        let snippet = paste_snippet(line.as_bytes()).unwrap();
        assert_eq!(snippet, format!("{}…", "é".repeat(60)));
    }

    #[test]
    fn snippet_is_none_for_blank_or_non_utf8_content() {
        assert_eq!(paste_snippet(b"  \n\t\n"), None);
        assert_eq!(paste_snippet(&[0xff, 0xfe, 0x00]), None);
    }
}
