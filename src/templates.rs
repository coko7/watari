use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

/// Wraps an Askama template so it can be returned directly from an Axum handler.
///
/// `askama_axum` (the integration crate the spec names) was removed upstream once
/// askama merged with rinja (askama >=0.13) — this replaces it in a few lines.
pub struct Tpl<T>(pub T);

impl<T: Template> IntoResponse for Tpl<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => {
                tracing::error!(error = ?err, "template render error");
                (StatusCode::INTERNAL_SERVER_ERROR, "template render error").into_response()
            }
        }
    }
}

/// Shared layout data every page template embeds as a `layout: Layout` field
/// (base.html reads `layout.*`) — askama's `{% extends %}` resolves field
/// paths against each child struct, so composition works fine even without
/// a common base struct.
pub struct Layout {
    pub csrf_token: String,
    pub pbkdf2_iterations: u32,
    pub user_email: Option<String>,
    pub is_admin: bool,
}

impl Layout {
    pub fn anonymous(csrf_token: String, pbkdf2_iterations: u32) -> Self {
        Self {
            csrf_token,
            pbkdf2_iterations,
            user_email: None,
            is_admin: false,
        }
    }

    pub fn for_user(
        csrf_token: String,
        pbkdf2_iterations: u32,
        user_email: String,
        is_admin: bool,
    ) -> Self {
        Self {
            csrf_token,
            pbkdf2_iterations,
            user_email: Some(user_email),
            is_admin,
        }
    }
}
