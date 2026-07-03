use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Upload,
    Paste,
    Shorten,
    View,
    Delete,
}

#[derive(Debug, Deserialize)]
struct RawFile {
    tokens: Vec<RawToken>,
    bindings: Vec<RawBindingEntry>,
}

#[derive(Debug, Deserialize)]
struct RawToken {
    id: String,
    env_var: String,
    permissions: Vec<Permission>,
}

#[derive(Debug, Deserialize)]
struct RawMatch {
    groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawBindingEntry {
    #[serde(rename = "match")]
    match_: Option<RawMatch>,
    token_id: Option<String>,
    default: Option<String>,
}

/// A resolved rustypaste token: the actual secret value plus what our own
/// UI/proxy allow attempting with it. This is *not* rustypaste's real
/// enforcement — that lives in rustypaste's own `auth_tokens`/`delete_tokens`
/// config (see kyosabi.md §7.2). A group can only be given a permission here
/// if the underlying token is also actually configured that way on the
/// rustypaste side.
pub struct TokenBinding {
    pub id: String,
    pub token: String,
    pub permissions: HashSet<Permission>,
}

impl TokenBinding {
    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn is_admin(&self) -> bool {
        self.has(Permission::Delete)
    }
}

impl std::fmt::Debug for TokenBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBinding")
            .field("id", &self.id)
            .field("token", &"***")
            .field("permissions", &self.permissions)
            .finish()
    }
}

enum Rule {
    /// Matches if the user belongs to *any* of `groups` (first-match-wins).
    Match {
        groups: HashSet<String>,
        token_id: String,
    },
    /// Terminal rule: either falls through to a named token, or denies.
    Default(Option<String>),
}

pub struct TokenMap {
    tokens: HashMap<String, TokenBinding>,
    rules: Vec<Rule>,
}

impl TokenMap {
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read token bindings file at {path:?}"))?;
        Self::parse(&raw)
    }

    fn parse(raw: &str) -> Result<Self> {
        let file: RawFile =
            serde_yaml::from_str(raw).context("failed to parse token bindings YAML")?;

        let mut tokens = HashMap::new();
        for t in file.tokens {
            let token = std::env::var(&t.env_var).with_context(|| {
                format!(
                    "token binding {:?} references env var {:?}, which is not set",
                    t.id, t.env_var
                )
            })?;
            if token.is_empty() {
                bail!(
                    "token binding {:?} resolves to an empty value via env var {:?}",
                    t.id,
                    t.env_var
                );
            }
            tokens.insert(
                t.id.clone(),
                TokenBinding {
                    id: t.id,
                    token,
                    permissions: t.permissions.into_iter().collect(),
                },
            );
        }

        let mut rules = Vec::with_capacity(file.bindings.len());
        for (i, entry) in file.bindings.into_iter().enumerate() {
            match (entry.match_, entry.token_id, entry.default) {
                (Some(m), Some(token_id), None) => {
                    if !tokens.contains_key(&token_id) {
                        bail!("bindings[{i}] references unknown token_id {token_id:?}");
                    }
                    rules.push(Rule::Match {
                        groups: m.groups.into_iter().collect(),
                        token_id,
                    });
                }
                (None, None, Some(default)) => {
                    if default == "deny" {
                        rules.push(Rule::Default(None));
                    } else {
                        if !tokens.contains_key(&default) {
                            bail!("bindings[{i}].default references unknown token_id {default:?}");
                        }
                        rules.push(Rule::Default(Some(default)));
                    }
                }
                _ => bail!(
                    "bindings[{i}] must be either {{match, token_id}} or {{default}}, got a malformed entry"
                ),
            }
        }

        Ok(Self { tokens, rules })
    }

    /// Resolves a user's rustypaste token binding from their OIDC groups.
    /// Rules are evaluated in file order; the first `match` whose `groups`
    /// overlaps the user's groups wins, falling through to `default` if none match.
    pub fn resolve(&self, user_groups: &[String]) -> Option<&TokenBinding> {
        let user_groups: HashSet<&str> = user_groups.iter().map(String::as_str).collect();
        for rule in &self.rules {
            match rule {
                Rule::Match { groups, token_id } => {
                    if groups.iter().any(|g| user_groups.contains(g.as_str())) {
                        return self.tokens.get(token_id);
                    }
                }
                Rule::Default(token_id) => {
                    return token_id.as_deref().and_then(|id| self.tokens.get(id));
                }
            }
        }
        None
    }

    pub fn get(&self, token_id: &str) -> Option<&TokenBinding> {
        self.tokens.get(token_id)
    }

    pub fn all(&self) -> impl Iterator<Item = &TokenBinding> {
        self.tokens.values()
    }

    /// Read-only summary for `GET /admin/tokens` (kyosabi.md §8.3): which
    /// groups map to each token id, and what it's allowed to attempt. Never
    /// includes the token secret itself.
    pub fn bindings_view(&self) -> Vec<BindingView> {
        let mut views: Vec<BindingView> = self
            .tokens
            .values()
            .map(|token| {
                let mut groups: Vec<String> = self
                    .rules
                    .iter()
                    .filter_map(|rule| match rule {
                        Rule::Match { groups, token_id } if token_id == &token.id => {
                            Some(groups.clone())
                        }
                        _ => None,
                    })
                    .flatten()
                    .collect();
                if self
                    .rules
                    .iter()
                    .any(|rule| matches!(rule, Rule::Default(Some(id)) if id == &token.id))
                {
                    groups.push("(default)".to_string());
                }
                groups.sort();

                let mut permissions: Vec<String> = token
                    .permissions
                    .iter()
                    .map(|p| format!("{p:?}").to_lowercase())
                    .collect();
                permissions.sort();

                BindingView {
                    token_id: token.id.clone(),
                    groups,
                    permissions,
                }
            })
            .collect();
        views.sort_by(|a, b| a.token_id.cmp(&b.token_id));
        views
    }
}

pub struct BindingView {
    pub token_id: String,
    pub groups: Vec<String>,
    pub permissions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = r#"
tokens:
  - id: readonly
    env_var: TEST_RP_TOKEN_READONLY
    permissions: [upload, paste, shorten, view]
  - id: admin
    env_var: TEST_RP_TOKEN_ADMIN
    permissions: [upload, paste, shorten, view, delete]

bindings:
  - match:
      groups: ["pastebin-admins"]
    token_id: admin
  - match:
      groups: ["pastebin-users"]
    token_id: readonly
  - default: deny
"#;

    fn with_env<T>(f: impl FnOnce() -> T) -> T {
        // SAFETY: tests run single-threaded within this module (no #[test] parallelism
        // concerns here since we only ever set these two keys).
        unsafe {
            std::env::set_var("TEST_RP_TOKEN_READONLY", "ro-secret");
            std::env::set_var("TEST_RP_TOKEN_ADMIN", "admin-secret");
        }
        let result = f();
        unsafe {
            std::env::remove_var("TEST_RP_TOKEN_READONLY");
            std::env::remove_var("TEST_RP_TOKEN_ADMIN");
        }
        result
    }

    #[test]
    fn first_match_wins_and_resolves_env_var() {
        with_env(|| {
            let map = TokenMap::parse(YAML).unwrap();

            let admin = map.resolve(&["pastebin-admins".to_string()]).unwrap();
            assert_eq!(admin.id, "admin");
            assert_eq!(admin.token, "admin-secret");
            assert!(admin.is_admin());

            let ro = map.resolve(&["pastebin-users".to_string()]).unwrap();
            assert_eq!(ro.id, "readonly");
            assert!(!ro.is_admin());

            // a user in both groups matches the first rule in file order (admin)
            let both = map
                .resolve(&["pastebin-users".to_string(), "pastebin-admins".to_string()])
                .unwrap();
            assert_eq!(both.id, "admin");

            assert!(map.resolve(&["unrelated-group".to_string()]).is_none());
        });
    }
}
