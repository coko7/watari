use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// All dynamic behavior is external (`/static/app.js`) or driven by HTMX's
/// `hx-headers` body attribute — no inline `<script>`/`<style>` blocks exist
/// in any template, so a static policy (no nonce) is enough (kyosabi.md §12).
const CSP: &str = "default-src 'self'; \
    script-src 'self'; \
    style-src 'self'; \
    img-src 'self' data:; \
    object-src 'none'; \
    base-uri 'self'; \
    form-action 'self'; \
    frame-ancestors 'none'";

pub async fn csp_middleware(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    res.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    res.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    res.headers_mut().insert(
        axum::http::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    res
}
