use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use tracing::debug;

pub type Db = SqlitePool;

pub async fn connect(database_path: &str) -> anyhow::Result<Db> {
    // `SqliteConnectOptions::from_str("sqlite://...")` parses the path as a
    // URL, which mangles relative paths like `./dev.db` (`.` gets read as
    // the URL host, so it ends up trying to open `/dev.db` at the filesystem
    // root). `.filename()` takes the path as a plain filesystem path instead.
    let opts = SqliteConnectOptions::new()
        .filename(database_path)
        .create_if_missing(true);

    debug!("opening Sqlite databse");
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .context("failed to open sqlite database")?;

    debug!("running DB migrations");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("failed to run database migrations")?;

    Ok(pool)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRow {
    pub id: String,
    pub user_sub: String,
    pub email: String,
    pub groups: String,
    pub token_id: String,
    pub oidc_refresh_token: Option<String>,
    pub oidc_access_token_expires_at: Option<i64>,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
}

pub struct NewSession<'a> {
    pub id: &'a str,
    pub user_sub: &'a str,
    pub email: &'a str,
    pub groups_json: &'a str,
    pub token_id: &'a str,
    pub oidc_refresh_token: Option<&'a str>,
    pub oidc_access_token_expires_at: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
}

pub async fn insert_session(db: &Db, s: NewSession<'_>) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO sessions
            (id, user_sub, email, groups, token_id, oidc_refresh_token,
             oidc_access_token_expires_at, created_at, last_seen_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(s.id)
    .bind(s.user_sub)
    .bind(s.email)
    .bind(s.groups_json)
    .bind(s.token_id)
    .bind(s.oidc_refresh_token)
    .bind(s.oidc_access_token_expires_at)
    .bind(s.created_at)
    .bind(s.created_at)
    .bind(s.expires_at)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_session(db: &Db, id: &str) -> sqlx::Result<Option<SessionRow>> {
    sqlx::query_as::<_, SessionRow>("SELECT * FROM sessions WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn touch_session(db: &Db, id: &str, now: i64) -> sqlx::Result<()> {
    sqlx::query("UPDATE sessions SET last_seen_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn update_session_oidc_tokens(
    db: &Db,
    id: &str,
    refresh_token: Option<&str>,
    access_token_expires_at: Option<i64>,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE sessions SET oidc_refresh_token = ?, oidc_access_token_expires_at = ? WHERE id = ?",
    )
    .bind(refresh_token)
    .bind(access_token_expires_at)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_session(db: &Db, id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct UploadLogRow {
    pub id: String,
    pub user_sub: String,
    pub email: String,
    pub display_name: String,
    pub paste_url: String,
    pub kind: String,
    pub encrypted: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// What an `upload_log` row records; `as_str()` is the stored `kind` value.
/// Also the `kind` query parameter of `/api/pastes` (one dashboard section each).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UploadKind {
    Paste,
    File,
    Url,
}

impl UploadKind {
    /// Dashboard section order.
    pub const ALL: [UploadKind; 3] = [UploadKind::Paste, UploadKind::File, UploadKind::Url];

    pub fn as_str(self) -> &'static str {
        match self {
            UploadKind::Paste => "paste",
            UploadKind::File => "file",
            UploadKind::Url => "url",
        }
    }
}

pub struct NewUploadLog<'a> {
    pub id: &'a str,
    pub user_sub: &'a str,
    pub email: &'a str,
    pub display_name: &'a str,
    pub paste_url: &'a str,
    pub kind: UploadKind,
    pub encrypted: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

pub async fn insert_upload_log(db: &Db, u: NewUploadLog<'_>) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO upload_log
            (id, user_sub, email, display_name, paste_url, kind, encrypted, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(u.id)
    .bind(u.user_sub)
    .bind(u.email)
    .bind(u.display_name)
    .bind(u.paste_url)
    .bind(u.kind.as_str())
    .bind(u.encrypted)
    .bind(u.created_at)
    .bind(u.expires_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Keyset pagination: returns up to `limit` rows of `kind` for `user_sub` older than
/// `before_created_at` (or the most recent rows if `before_created_at` is `None`), newest first.
pub async fn list_uploads_page(
    db: &Db,
    user_sub: &str,
    kind: UploadKind,
    before_created_at: Option<i64>,
    limit: i64,
) -> sqlx::Result<Vec<UploadLogRow>> {
    match before_created_at {
        Some(before) => {
            sqlx::query_as::<_, UploadLogRow>(
                "SELECT * FROM upload_log
                 WHERE user_sub = ? AND kind = ? AND created_at < ?
                 ORDER BY created_at DESC LIMIT ?",
            )
            .bind(user_sub)
            .bind(kind.as_str())
            .bind(before)
            .bind(limit)
            .fetch_all(db)
            .await
        }
        None => {
            sqlx::query_as::<_, UploadLogRow>(
                "SELECT * FROM upload_log
                 WHERE user_sub = ? AND kind = ?
                 ORDER BY created_at DESC LIMIT ?",
            )
            .bind(user_sub)
            .bind(kind.as_str())
            .bind(limit)
            .fetch_all(db)
            .await
        }
    }
}

pub async fn get_upload_for_user(
    db: &Db,
    id: &str,
    user_sub: &str,
) -> sqlx::Result<Option<UploadLogRow>> {
    sqlx::query_as::<_, UploadLogRow>("SELECT * FROM upload_log WHERE id = ? AND user_sub = ?")
        .bind(id)
        .bind(user_sub)
        .fetch_optional(db)
        .await
}

pub async fn delete_upload_log(db: &Db, id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM upload_log WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn insert(db: &Db, id: &str, user_sub: &str, kind: UploadKind, created_at: i64) {
        insert_upload_log(
            db,
            NewUploadLog {
                id,
                user_sub,
                email: "someone@example.com",
                display_name: id,
                paste_url: "https://paste.example.com/x.txt",
                kind,
                encrypted: false,
                created_at,
                expires_at: None,
            },
        )
        .await
        .unwrap();
    }

    fn ids(rows: Vec<UploadLogRow>) -> Vec<String> {
        rows.into_iter().map(|r| r.id).collect()
    }

    #[tokio::test]
    async fn list_uploads_page_filters_by_kind_and_paginates() {
        // A file, not `:memory:`: each pooled connection would get its own empty DB.
        let path = std::env::temp_dir().join(format!("watari-test-{}.db", uuid::Uuid::new_v4()));
        let db = connect(path.to_str().unwrap()).await.unwrap();

        insert(&db, "a", "alice", UploadKind::Paste, 1).await;
        insert(&db, "b", "alice", UploadKind::File, 2).await;
        insert(&db, "c", "alice", UploadKind::Paste, 3).await;
        insert(&db, "d", "alice", UploadKind::Url, 4).await;
        insert(&db, "e", "alice", UploadKind::Paste, 5).await;
        insert(&db, "z", "bob", UploadKind::Paste, 6).await;

        let first = list_uploads_page(&db, "alice", UploadKind::Paste, None, 2).await;
        assert_eq!(ids(first.unwrap()), ["e", "c"]);
        let next = list_uploads_page(&db, "alice", UploadKind::Paste, Some(3), 2).await;
        assert_eq!(ids(next.unwrap()), ["a"]);
        let files = list_uploads_page(&db, "alice", UploadKind::File, None, 20).await;
        assert_eq!(ids(files.unwrap()), ["b"]);
        let urls = list_uploads_page(&db, "alice", UploadKind::Url, None, 20).await;
        assert_eq!(ids(urls.unwrap()), ["d"]);

        db.close().await;
        let _ = std::fs::remove_file(&path);
    }
}
