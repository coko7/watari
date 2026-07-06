use anyhow::{Context, Result, bail};
use tracing::debug;

#[derive(Clone)]
pub struct AppConfig {
    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_redirect_uri: String,
    pub oidc_groups_claim: String,

    pub session_secret: Vec<u8>,
    pub session_ttl_seconds: i64,

    pub rustypaste_internal_url: String,
    pub rustypaste_public_url: String,
    pub rustypaste_timeout_secs: u64,
    pub rustypaste_max_body_bytes: u64,

    pub token_bindings_path: String,

    pub app_base_url: String,
    pub app_port: u16,
    pub database_path: String,
    pub pbkdf2_iterations: u32,
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("oidc_issuer_url", &self.oidc_issuer_url)
            .field("oidc_client_id", &self.oidc_client_id)
            .field("oidc_client_secret", &"***")
            .field("oidc_redirect_uri", &self.oidc_redirect_uri)
            .field("oidc_groups_claim", &self.oidc_groups_claim)
            .field("session_secret", &"***")
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .field("rustypaste_internal_url", &self.rustypaste_internal_url)
            .field("rustypaste_public_url", &self.rustypaste_public_url)
            .field("rustypaste_timeout_secs", &self.rustypaste_timeout_secs)
            .field("rustypaste_max_body_bytes", &self.rustypaste_max_body_bytes)
            .field("token_bindings_path", &self.token_bindings_path)
            .field("app_base_url", &self.app_base_url)
            .field("app_port", &self.app_port)
            .field("database_path", &self.database_path)
            .field("pbkdf2_iterations", &self.pbkdf2_iterations)
            .finish()
    }
}

fn required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required environment variable {key}"))
}

fn optional(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn parse_optional<T: std::str::FromStr>(key: &str, default: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    let raw = optional(key, default);
    raw.parse::<T>()
        .map_err(|e| anyhow::anyhow!("{key} has an invalid value {raw:?}: {e}"))
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        debug!("retrieving session secret");
        let session_secret_hex = required("SESSION_SECRET")
            .context("SESSION_SECRET is required: 32+ bytes of hex-encoded random data, e.g. `openssl rand -hex 32`")?;
        let session_secret =
            hex::decode(&session_secret_hex).context("SESSION_SECRET must be valid hex")?;

        debug!("validating session secret length");
        if session_secret.len() < 32 {
            bail!(
                "SESSION_SECRET must decode to at least 32 bytes, got {}",
                session_secret.len()
            );
        }

        debug!("creating config struct");
        let config = Self {
            oidc_issuer_url: required("OIDC_ISSUER_URL")?,
            oidc_client_id: required("OIDC_CLIENT_ID")?,
            oidc_client_secret: required("OIDC_CLIENT_SECRET")?,
            oidc_redirect_uri: required("OIDC_REDIRECT_URI")?,
            oidc_groups_claim: optional("OIDC_GROUPS_CLAIM", "groups"),

            session_secret,
            session_ttl_seconds: parse_optional("SESSION_TTL_SECONDS", "28800")?,

            rustypaste_internal_url: required("RUSTYPASTE_INTERNAL_URL")?,
            rustypaste_public_url: required("RUSTYPASTE_PUBLIC_URL")?,
            rustypaste_timeout_secs: parse_optional("RUSTYPASTE_TIMEOUT_SECS", "30")?,
            rustypaste_max_body_bytes: parse_optional("RUSTYPASTE_MAX_BODY_BYTES", "104857600")?,

            token_bindings_path: optional("TOKEN_BINDINGS_PATH", "token-bindings.yaml"),

            app_base_url: required("APP_BASE_URL")?,
            app_port: parse_optional("APP_PORT", "3000")?,
            database_path: optional("DATABASE_PATH", "/data/app.db"),
            pbkdf2_iterations: parse_optional("PBKDF2_ITERATIONS", "310000")?,
        };

        Ok(config)
    }
}
