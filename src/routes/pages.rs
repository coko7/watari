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
    pub encrypted: bool,
    /// RFC 3339 (UTC); `static/app.js` turns it into "14:05" / "3 days ago" in
    /// the viewer's timezone.
    pub created_at_iso: String,
}

/// Dashboard wording for each section (one per `UploadKind`).
impl db::UploadKind {
    pub fn title(self) -> &'static str {
        match self {
            db::UploadKind::Paste => "Pastes",
            db::UploadKind::File => "Uploads",
            db::UploadKind::Url => "Short URLs",
        }
    }

    pub fn name_header(self) -> &'static str {
        match self {
            db::UploadKind::Paste => "Content",
            db::UploadKind::File => "File",
            db::UploadKind::Url => "Target",
        }
    }

    pub fn link_header(self) -> &'static str {
        match self {
            db::UploadKind::Paste | db::UploadKind::File => "Link",
            db::UploadKind::Url => "Short link",
        }
    }

    /// Singular noun, used in "Delete this …?" and "No …s yet."
    pub fn noun(self) -> &'static str {
        match self {
            db::UploadKind::Paste => "paste",
            db::UploadKind::File => "upload",
            db::UploadKind::Url => "short URL",
        }
    }

    pub fn create_page(self) -> &'static str {
        match self {
            db::UploadKind::Paste => "/paste",
            db::UploadKind::File => "/upload",
            db::UploadKind::Url => "/shorten",
        }
    }

    pub fn create_label(self) -> &'static str {
        match self {
            db::UploadKind::Paste => "Paste some text",
            db::UploadKind::File => "Upload a file",
            db::UploadKind::Url => "Shorten a URL",
        }
    }
}

/// One page of a dashboard section, newest first.
pub struct SectionPage {
    pub rows: Vec<UploadRowView>,
    pub has_more: bool,
    pub next_cursor: Option<i64>,
}

pub async fn load_section_page(
    state: &AppState,
    user_sub: &str,
    kind: db::UploadKind,
    before: Option<i64>,
) -> SectionPage {
    let db_rows = db::list_uploads_page(&state.db, user_sub, kind, before, PAGE_SIZE)
        .await
        .unwrap_or_default();
    SectionPage {
        has_more: db_rows.len() as i64 == PAGE_SIZE,
        next_cursor: db_rows.last().map(|r| r.created_at),
        rows: db_rows.iter().map(UploadRowView::from).collect(),
    }
}

impl From<&db::UploadLogRow> for UploadRowView {
    fn from(row: &db::UploadLogRow) -> Self {
        let created_at_iso = OffsetDateTime::from_unix_timestamp(row.created_at)
            .ok()
            .and_then(|t| t.format(&Rfc3339).ok())
            .unwrap_or_default();
        Self {
            id: row.id.clone(),
            display_name: row.display_name.clone(),
            paste_url: row.paste_url.clone(),
            encrypted: row.encrypted,
            created_at_iso,
        }
    }
}

#[derive(Template)]
#[template(path = "partials/paste_row.html")]
pub struct PasteRowsTemplate {
    pub kind: db::UploadKind,
    pub rows: Vec<UploadRowView>,
    pub can_delete: bool,
}

#[derive(Template)]
#[template(path = "partials/load_more.html")]
pub struct LoadMoreTemplate {
    pub kind: db::UploadKind,
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

struct DashboardSection {
    kind: db::UploadKind,
    page: SectionPage,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    layout: Layout,
    sections: Vec<DashboardSection>,
    can_delete: bool,
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

    let mut sections = Vec::with_capacity(db::UploadKind::ALL.len());
    for kind in db::UploadKind::ALL {
        let page = load_section_page(&state, &session.user_sub, kind, None).await;
        sections.push(DashboardSection { kind, page });
    }

    (
        csrf_token,
        Tpl(DashboardTemplate {
            layout,
            sections,
            can_delete: can_delete(&state, &session.token_id),
        }),
    )
        .into_response()
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate {
    layout: Layout,
}

pub async fn home_page(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
) -> axum::response::Response {
    match layout_for(&state, &csrf_token, &session) {
        Ok(layout) => (csrf_token, Tpl(HomeTemplate { layout })).into_response(),
        Err(e) => crate::error::AppError::Internal(e).into_response(),
    }
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
