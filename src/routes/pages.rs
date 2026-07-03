use askama::Template;
use axum::extract::State;
use axum::response::IntoResponse;
use axum_csrf::CsrfToken;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::db;
use crate::session::UserSession;
use crate::state::AppState;
use crate::templates::{Layout, Tpl};
use crate::token_map::Permission;

pub const PAGE_SIZE: i64 = 20;

#[derive(Clone)]
pub struct UploadRowView {
    pub id: String,
    pub display_name: String,
    pub paste_url: String,
    pub kind: String,
    pub encrypted: bool,
    pub created_at_display: String,
}

impl From<&db::UploadLogRow> for UploadRowView {
    fn from(row: &db::UploadLogRow) -> Self {
        let created_at_display = OffsetDateTime::from_unix_timestamp(row.created_at)
            .ok()
            .and_then(|t| t.format(&Rfc3339).ok())
            .unwrap_or_default();
        Self {
            id: row.id.clone(),
            display_name: row.display_name.clone(),
            paste_url: row.paste_url.clone(),
            kind: row.kind.clone(),
            encrypted: row.encrypted,
            created_at_display,
        }
    }
}

#[derive(Template)]
#[template(path = "partials/paste_row.html")]
pub struct PasteRowsTemplate {
    pub rows: Vec<UploadRowView>,
    pub can_delete: bool,
}

#[derive(Template)]
#[template(path = "partials/load_more.html")]
pub struct LoadMoreTemplate {
    pub has_more: bool,
    pub next_cursor: Option<i64>,
}

fn is_admin(state: &AppState, token_id: &str) -> bool {
    state
        .token_map
        .get(token_id)
        .map(|b| b.is_admin())
        .unwrap_or(false)
}

fn can_delete(state: &AppState, token_id: &str) -> bool {
    state
        .token_map
        .get(token_id)
        .map(|b| b.has(Permission::Delete))
        .unwrap_or(false)
}

fn layout_for(
    state: &AppState,
    token: &CsrfToken,
    session: &UserSession,
) -> anyhow::Result<Layout> {
    let csrf_token = token
        .authenticity_token()
        .map_err(|e| anyhow::anyhow!("csrf token error: {e}"))?;
    Ok(Layout::for_user(
        csrf_token,
        state.config.pbkdf2_iterations,
        session.email.clone(),
        is_admin(state, &session.token_id),
    ))
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    layout: Layout,
    rows: Vec<UploadRowView>,
    can_delete: bool,
    has_more: bool,
    next_cursor: Option<i64>,
}

pub async fn dashboard(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
) -> axum::response::Response {
    let layout = match layout_for(&state, &csrf_token, &session) {
        Ok(l) => l,
        Err(e) => return crate::error::AppError::Internal(e).into_response(),
    };

    let db_rows = db::list_uploads_page(&state.db, &session.user_sub, None, PAGE_SIZE)
        .await
        .unwrap_or_default();
    let has_more = db_rows.len() as i64 == PAGE_SIZE;
    let next_cursor = db_rows.last().map(|r| r.created_at);
    let rows = db_rows.iter().map(UploadRowView::from).collect();

    (
        csrf_token,
        Tpl(DashboardTemplate {
            layout,
            rows,
            can_delete: can_delete(&state, &session.token_id),
            has_more,
            next_cursor,
        }),
    )
        .into_response()
}

#[derive(Template)]
#[template(path = "upload.html")]
struct UploadTemplate {
    layout: Layout,
}

pub async fn upload_page(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
) -> axum::response::Response {
    match layout_for(&state, &csrf_token, &session) {
        Ok(layout) => (csrf_token, Tpl(UploadTemplate { layout })).into_response(),
        Err(e) => crate::error::AppError::Internal(e).into_response(),
    }
}

#[derive(Template)]
#[template(path = "paste.html")]
struct PasteTemplate {
    layout: Layout,
}

pub async fn paste_page(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
) -> axum::response::Response {
    match layout_for(&state, &csrf_token, &session) {
        Ok(layout) => (csrf_token, Tpl(PasteTemplate { layout })).into_response(),
        Err(e) => crate::error::AppError::Internal(e).into_response(),
    }
}

#[derive(Template)]
#[template(path = "shorten.html")]
struct ShortenTemplate {
    layout: Layout,
}

pub async fn shorten_page(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
) -> axum::response::Response {
    match layout_for(&state, &csrf_token, &session) {
        Ok(layout) => (csrf_token, Tpl(ShortenTemplate { layout })).into_response(),
        Err(e) => crate::error::AppError::Internal(e).into_response(),
    }
}
