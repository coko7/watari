use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum_csrf::CsrfToken;

use crate::error::AppError;
use crate::session::UserSession;
use crate::state::AppState;
use crate::templates::{Layout, Tpl};
use crate::token_map::BindingView;

#[derive(Template)]
#[template(path = "admin/tokens.html")]
struct AdminTokensTemplate {
    layout: Layout,
    bindings: Vec<BindingView>,
}

/// `GET /admin/tokens` — accessible only to sessions whose resolved token
/// binding is admin (kyosabi.md §8.3); we key "admin" off having the `delete`
/// permission, since the spec doesn't define it more precisely than that.
pub async fn tokens_page(
    State(state): State<AppState>,
    session: UserSession,
    csrf_token: CsrfToken,
) -> Response {
    let is_admin = state
        .token_map
        .get(&session.token_id)
        .map(|b| b.is_admin())
        .unwrap_or(false);
    if !is_admin {
        return AppError::Forbidden.into_response();
    }

    let csrf = match csrf_token.authenticity_token() {
        Ok(t) => t,
        Err(e) => {
            return AppError::Internal(anyhow::anyhow!("csrf token error: {e}")).into_response();
        }
    };
    let layout = Layout::for_user(
        csrf,
        state.config.pbkdf2_iterations,
        session.email.clone(),
        true,
    );
    let bindings = state.token_map.bindings_view();

    (csrf_token, Tpl(AdminTokensTemplate { layout, bindings })).into_response()
}
