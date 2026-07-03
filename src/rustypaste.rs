use reqwest::multipart::{Form, Part};

/// Thin client for rustypaste's real HTTP API, confirmed against its source
/// (github.com/orhun/rustypaste: src/{auth,header,paste,server}.rs) rather than
/// guessed from kyosabi.md §14's open question:
///
/// - `POST /` multipart, distinguished by field *name*: `file` (upload),
///   `oneshot` (one-shot file), `url` (shorten), `oneshot_url` (one-shot URL).
/// - Header `expire: <humantime duration>` (e.g. `10min`) sets expiry.
/// - `Authorization: <token>` — rustypaste takes the last whitespace-separated
///   token in the header, so `Bearer <token>` works.
/// - `DELETE /<file>` + `Authorization` — only enabled if rustypaste's own
///   `delete_tokens` are configured and the token matches one of those.
/// - `GET /<file>` requires no auth.
/// - The upload response body is plain text: the resulting URL.
#[derive(Clone)]
pub struct RustypasteClient {
    http: reqwest::Client,
    internal_base_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RustypasteError {
    #[error("failed to reach rustypaste: {0}")]
    Request(#[from] reqwest::Error),
    #[error("rustypaste rejected the request ({status}): {body}")]
    Upstream {
        status: reqwest::StatusCode,
        body: String,
    },
}

pub enum FileMode {
    Normal,
    OneShot,
}

pub enum UrlMode {
    Shorten,
    OneShotUrl,
}

impl RustypasteClient {
    pub fn new(http: reqwest::Client, internal_base_url: String) -> Self {
        Self {
            http,
            internal_base_url: internal_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Uploads raw bytes (file upload or a text paste wrapped as a file).
    pub async fn upload_file(
        &self,
        token: &str,
        mode: FileMode,
        filename: &str,
        bytes: Vec<u8>,
        content_type: &str,
        expire: Option<&str>,
    ) -> Result<String, RustypasteError> {
        let field_name = match mode {
            FileMode::Normal => "file",
            FileMode::OneShot => "oneshot",
        };
        let part = Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str(content_type)
            .unwrap_or_else(|_| Part::bytes(Vec::new()));
        let form = Form::new().part(field_name.to_string(), part);
        self.submit(token, form, expire).await
    }

    /// Shortens (or one-shot shortens) a target URL.
    pub async fn shorten(
        &self,
        token: &str,
        mode: UrlMode,
        target_url: &str,
        expire: Option<&str>,
    ) -> Result<String, RustypasteError> {
        let field_name = match mode {
            UrlMode::Shorten => "url",
            UrlMode::OneShotUrl => "oneshot_url",
        };
        let form = Form::new().text(field_name.to_string(), target_url.to_string());
        self.submit(token, form, expire).await
    }

    async fn submit(
        &self,
        token: &str,
        form: Form,
        expire: Option<&str>,
    ) -> Result<String, RustypasteError> {
        let mut req = self
            .http
            .post(&self.internal_base_url)
            .header("Authorization", format!("Bearer {token}"))
            .multipart(form);
        if let Some(expire) = expire {
            req = req.header("expire", expire);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(RustypasteError::Upstream { status, body });
        }
        Ok(body.trim().to_string())
    }

    /// Deletes a previously uploaded paste by its filename (the last path
    /// segment of the URL rustypaste returned at upload time).
    pub async fn delete(&self, token: &str, filename: &str) -> Result<(), RustypasteError> {
        let url = format!("{}/{}", self.internal_base_url, filename);
        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RustypasteError::Upstream { status, body });
        }
        Ok(())
    }
}

/// Extracts the filename (last path segment) from a rustypaste-returned URL,
/// for use with [`RustypasteClient::delete`].
pub fn filename_from_paste_url(paste_url: &str) -> Option<String> {
    let url = url::Url::parse(paste_url).ok()?;
    url.path_segments()?
        .next_back()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_filename_from_url() {
        assert_eq!(
            filename_from_paste_url("https://paste.site.com/safe-toad.txt"),
            Some("safe-toad.txt".to_string())
        );
        assert_eq!(filename_from_paste_url("not a url"), None);
        assert_eq!(filename_from_paste_url("https://paste.site.com/"), None);
    }
}
