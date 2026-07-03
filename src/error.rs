use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::templates::Tpl;

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub status: u16,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("the requested resource was not found")]
    NotFound,
    #[error("you don't have permission to do that")]
    Forbidden,
    #[error("{0}")]
    BadRequest(String),
    #[error("upstream rustypaste error: {0}")]
    Upstream(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::BadRequest(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Upstream(_) => StatusCode::BAD_GATEWAY,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let AppError::Internal(err) = &self {
            tracing::error!(error = ?err, "internal error");
        }
        let status = self.status();
        let message = match &self {
            AppError::Internal(_) => "internal server error".to_string(),
            other => other.to_string(),
        };
        (
            status,
            Tpl(ErrorTemplate {
                status: status.as_u16(),
                message,
            }),
        )
            .into_response()
    }
}
