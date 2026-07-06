use anyhow::Context;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{CookieJar, PrivateCookieJar};
use base64::Engine;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthenticationFlow, CoreClaimName, CoreClaimType, CoreClient,
    CoreClientAuthMethod, CoreGrantType, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalProviderMetadata, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, ProviderMetadata, RedirectUrl, RefreshToken, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::db;
use crate::error::AppError;
use crate::session::{self, OidcState};
use crate::state::AppState;

/// Many IdPs (including the reference Zitadel deployment) advertise RP-initiated
/// logout via `end_session_endpoint`, a field from the OIDC Session Management
/// draft rather than OIDC Discovery core — so it isn't on `CoreProviderMetadata`.
/// Captured the same way the crate's own Google example captures a custom
/// `revocation_endpoint`.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct EndSessionProviderMetadata {
    end_session_endpoint: Option<String>,
}
impl AdditionalProviderMetadata for EndSessionProviderMetadata {}

type DiscoveredProviderMetadata = ProviderMetadata<
    EndSessionProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// Holds everything needed to (re)build an OIDC client on demand. Deliberately
/// *not* storing the built `CoreClient` itself: oauth2 5.x's typestate-encoded
/// endpoint markers make that type painful to name in a struct field, and
/// rebuilding it from these plain values is just cheap struct construction
/// (no I/O) — see watari.md implementation notes.
#[derive(Debug)]
pub struct OidcContext {
    provider_metadata: DiscoveredProviderMetadata,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_uri: RedirectUrl,
    pub end_session_endpoint: Option<String>,
}

/// `CoreClient` after `from_provider_metadata` + `set_redirect_uri`: discovery
/// always yields an auth URL (`EndpointSet`) but only *maybe* a token/userinfo
/// URL depending on what the provider's discovery document included
/// (`EndpointMaybeSet`); device-auth/introspection/revocation stay unset.
/// Determined by reading the compiler's own diagnostic for the concrete type
/// rather than guessing, since oauth2 5.x's typestate encodes this in the type.
type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub struct RefreshedTokens {
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<i64>,
}

impl OidcContext {
    pub async fn discover(
        http: &reqwest::Client,
        issuer_url: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> anyhow::Result<Self> {
        debug!("running OIDC discover");
        let issuer = IssuerUrl::new(issuer_url.to_string())
            .map_err(|e| anyhow::anyhow!("invalid OIDC_ISSUER_URL: {e}"))?;
        let provider_metadata = DiscoveredProviderMetadata::discover_async(issuer, http)
            .await
            .map_err(|e| anyhow::anyhow!("OIDC discovery against {issuer_url} failed: {e}"))?;
        let end_session_endpoint = provider_metadata
            .additional_metadata()
            .end_session_endpoint
            .clone();

        let oidc_context = Self {
            provider_metadata,
            client_id: ClientId::new(client_id.to_string()),
            client_secret: ClientSecret::new(client_secret.to_string()),
            redirect_uri: RedirectUrl::new(redirect_uri.to_string())
                .map_err(|e| anyhow::anyhow!("invalid OIDC_REDIRECT_URI: {e}"))?,
            end_session_endpoint,
        };

        trace!("retrieved OIDC context: {oidc_context:#?}");
        Ok(oidc_context)
    }

    fn build_client(&self) -> DiscoveredClient {
        CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.client_id.clone(),
            Some(self.client_secret.clone()),
        )
        .set_redirect_uri(self.redirect_uri.clone())
    }

    pub async fn refresh(
        &self,
        http: &reqwest::Client,
        refresh_token: &str,
    ) -> anyhow::Result<RefreshedTokens> {
        debug!("performing OIDC token refresh");
        let client = self.build_client();

        debug!("sending oidc refresh token request");
        let token_response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .map_err(|e| anyhow::anyhow!("failed to build refresh token request: {e}"))?
            .request_async(http)
            .await
            .map_err(|e| anyhow::anyhow!("refresh token exchange failed: {e}"))?;

        debug!("getting expire time from refresh token");
        let access_token_expires_at = token_response
            .expires_in()
            .map(|d| session::now_unix() + d.as_secs() as i64);

        debug!("getting refresh token value");
        let refresh_token = token_response
            .refresh_token()
            .map(|t| t.secret().clone())
            .or_else(|| Some(refresh_token.to_string()));

        Ok(RefreshedTokens {
            refresh_token,
            access_token_expires_at,
        })
    }
}

pub async fn login(State(state): State<AppState>, jar: PrivateCookieJar) -> impl IntoResponse {
    debug!("OIDC login init");
    let client = state.oidc.build_client();

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    debug!("generating OIDC login URL");
    let (auth_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // `openid` is added automatically for CoreAuthenticationFlow::AuthorizationCode.
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        // Most providers (Zitadel, Keycloak, Auth0, Okta) expose group/role
        // membership under a "groups" scope by convention; watari.md §6.2
        // calls for requesting a groups scope but doesn't name one since the
        // app is provider-agnostic.
        .add_scope(Scope::new("groups".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    debug!("creating OIDC state");
    let oidc_state = OidcState {
        pkce_verifier: pkce_verifier.secret().clone(),
        csrf_state: csrf_state.secret().clone(),
        nonce: nonce.secret().clone(),
        created_at: session::now_unix(),
    };
    let jar = session::set_oidc_state_cookie(jar, &oidc_state);

    (jar, Redirect::to(auth_url.as_str()))
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    debug!("OIDC callback init");
    let (jar, oidc_state) = session::take_oidc_state_cookie(jar);
    let oidc_state = oidc_state.ok_or_else(|| {
        AppError::BadRequest(
            "login session expired or is invalid, please try logging in again".into(),
        )
    })?;

    debug!("checking query error");
    if let Some(err) = query.error {
        return Err(AppError::BadRequest(format!(
            "identity provider returned an error: {err} ({})",
            query.error_description.unwrap_or_default()
        )));
    }

    debug!("getting OIDC auth code");
    let code = query
        .code
        .ok_or_else(|| AppError::BadRequest("missing authorization code".into()))?;

    debug!("getting OIDC returned state");
    let returned_state = query
        .state
        .ok_or_else(|| AppError::BadRequest("missing state parameter".into()))?;

    debug!("validating OIDC state CSRF token");
    if returned_state != oidc_state.csrf_state {
        return Err(AppError::BadRequest(
            "state mismatch — possible CSRF, please try again".into(),
        ));
    }

    debug!("creating OIDC token exchange client");
    let client = state.oidc.build_client();
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| anyhow::anyhow!("failed to build token exchange request: {e}"))?
        .set_pkce_verifier(PkceCodeVerifier::new(oidc_state.pkce_verifier))
        .request_async(&state.http)
        .await
        .map_err(|e| anyhow::anyhow!("token exchange with the identity provider failed: {e}"))?;

    debug!("getting OIDC ID token from token response");
    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow::anyhow!("identity provider did not return an id_token"))?;

    // openidconnect-rs rejects any `aud` entry beyond our own client_id unless
    // explicitly trusted. Zitadel (and other project-scoped IdPs) legitimately
    // add a second audience — the project's resource ID — alongside the
    // client_id; the OIDC spec allows this as long as `azp` identifies the
    // actual authorized party, which the crate still enforces separately.
    debug!("performing OIDC ID token verification (audience check)");
    let verifier = client
        .id_token_verifier()
        .set_other_audience_verifier_fn(|_aud| true);

    debug!("validating OIDC nonce");
    let nonce = Nonce::new(oidc_state.nonce);
    let claims = id_token
        .claims(&verifier, &nonce)
        .map_err(|e| anyhow::anyhow!("id_token verification failed: {e}"))?;

    debug!("getting user sub from ID token");
    let user_sub = claims.subject().as_str().to_string();
    let email = claims
        .email()
        .map(|e| e.as_str().to_string())
        .unwrap_or_default();

    // The id_token's signature was just verified above; re-reading its payload
    // as raw JSON (rather than fighting openidconnect's AdditionalClaims
    // generics) is safe and lets OIDC_GROUPS_CLAIM name an arbitrary claim.
    let raw_claims = decode_jwt_payload_unverified(&id_token.to_string())
        .context("failed to inspect id_token payload for the groups claim")?;
    let groups = extract_groups(&raw_claims, &state.config.oidc_groups_claim);

    debug!("resolving rustypaste token binding");
    let binding = state
        .token_map
        .resolve(&groups)
        .ok_or(AppError::Forbidden)?;

    let now = session::now_unix();
    let session_id = uuid::Uuid::new_v4().to_string();
    let expires_at = now + state.config.session_ttl_seconds;
    let access_token_expires_at = token_response
        .expires_in()
        .map(|d| now + d.as_secs() as i64);
    let refresh_token = token_response.refresh_token().map(|t| t.secret().clone());

    debug!("storing session in database");
    db::insert_session(
        &state.db,
        db::NewSession {
            id: &session_id,
            user_sub: &user_sub,
            email: &email,
            groups_json: &serde_json::to_string(&groups).unwrap_or_default(),
            token_id: &binding.id,
            oidc_refresh_token: refresh_token.as_deref(),
            oidc_access_token_expires_at: access_token_expires_at,
            created_at: now,
            expires_at,
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to persist session: {e}"))?;

    let session_jar = session::set_session_cookie(
        CookieJar::new(),
        &session_id,
        state.config.session_ttl_seconds,
    );

    Ok((jar, session_jar, Redirect::to("/")).into_response())
}

pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    debug!("OIDC logout init");
    if let Some(session_id) = jar
        .get(session::SESSION_COOKIE)
        .map(|c| c.value().to_string())
    {
        debug!("deleting existing session");
        let _ = db::delete_session(&state.db, &session_id).await;
    }

    debug!("clear session cookie");
    let jar = session::clear_session_cookie(jar);

    let redirect_url = match &state.oidc.end_session_endpoint {
        Some(endpoint) => match url::Url::parse(endpoint) {
            Ok(mut url) => {
                url.query_pairs_mut()
                    .append_pair("post_logout_redirect_uri", &state.config.app_base_url);
                url.to_string()
            }
            Err(_) => state.config.app_base_url.clone(),
        },
        None => state.config.app_base_url.clone(),
    };

    (jar, Redirect::to(&redirect_url))
}

fn decode_jwt_payload_unverified(compact: &str) -> anyhow::Result<serde_json::Value> {
    let mut parts = compact.split('.');
    let _header = parts.next().context("malformed JWT: missing header")?;
    let payload = parts.next().context("malformed JWT: missing payload")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("failed to base64-decode JWT payload")?;
    serde_json::from_slice(&bytes).context("JWT payload is not valid JSON")
}

/// Handles the two shapes watari.md §14 anticipated: a flat JSON array of
/// strings (most providers), or a JSON object whose top-level keys are the
/// group/role names — e.g. Zitadel's `urn:zitadel:iam:org:project:roles`
/// claim (`{"role-name": {"org-id": "org-name"}, ...}`).
fn extract_groups(claims: &serde_json::Value, claim_name: &str) -> Vec<String> {
    debug!("extracting groups from OIDC token");
    match claims.get(claim_name) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
        Some(_) => {
            tracing::warn!(
                claim = claim_name,
                "groups claim is present but is neither an array nor an object; treating as no groups"
            );
            Vec::new()
        }
        None => {
            tracing::warn!(claim = claim_name, "groups claim not present in id_token");
            Vec::new()
        }
    }
}
