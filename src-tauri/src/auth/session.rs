//! ============================================================
//! AUTH SESSION MANAGEMENT
//! ============================================================
//!
//! This module handles authenticated sessions for the offline
//! Tauri application.
//
//! Important security design:
//
//! 1. A random session token is generated when the user logs in.
//! 2. The RAW token is returned to the frontend.
//! 3. ONLY the SHA-256 hash of the token is stored in SQLite.
//! 4. The frontend keeps the raw token and sends it when needed.
//! 5. We never store the raw session token in the database.
//!
//! Example:
//
//! Frontend receives:
//!     "9f7c....random-token...."
//!
//! Database stores:
//!     SHA256("9f7c....random-token....")
//!
//! If the database is copied, the attacker does not immediately
//! obtain usable session tokens.
//! ============================================================

use chrono::{ Duration, Utc};
use rand::{distr::Alphanumeric, Rng};
use sea_orm::{
    ActiveModelTrait,
    ColumnTrait,
    DatabaseConnection,
    EntityTrait,
    QueryFilter,
    Set,
};
use sha2::{Digest, Sha256};

use super::entity::session;


// ============================================================
// SESSION CONFIGURATION
// ============================================================

/// How long a normal session remains valid.
///
/// Change this value if you want a different session lifetime.
const SESSION_DURATION_HOURS: i64 = 24;

/// How long a session can remain unused before it is considered
/// inactive.
///
/// Example:
///
/// User logs in at 10:00.
/// If they do not use the application until after the inactivity
/// period, the session will be rejected.
///
/// This is separate from SESSION_DURATION_HOURS.
const SESSION_IDLE_TIMEOUT_HOURS: i64 = 8;


// ============================================================
// SESSION TOKEN GENERATION
// ============================================================

/// Generate a cryptographically random session token.
///
/// This token is returned to the frontend.
///
/// IMPORTANT:
/// The token itself is NOT stored in the database.
///
/// Only its SHA-256 hash is stored.
pub fn generate_session_token() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}


// ============================================================
// HASH SESSION TOKEN
// ============================================================

/// Convert the raw session token into a SHA-256 hash.
///
/// The database stores this hash instead of the raw token.
pub fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();

    hasher.update(token.as_bytes());

    let result = hasher.finalize();

    hex::encode(result)
}


// ============================================================
// CREATE SESSION
// ============================================================

/// Create a new authenticated session.
///
/// Returns the RAW session token.
///
/// The raw token should be sent to the frontend and kept there.
///
/// The database receives only the hash.
///
/// `device_id` and `device_name` are optional because the desktop
/// application may not always provide device information.
pub async fn create_session(
    db: &DatabaseConnection,
    user_id: i32,
    device_id: Option<String>,
    device_name: Option<String>,
) -> Result<String, String> {
    // --------------------------------------------------------
    // Generate secure random token
    // --------------------------------------------------------

    let raw_token = generate_session_token();

    // --------------------------------------------------------
    // Hash token before storing it
    // --------------------------------------------------------

    let token_hash = hash_session_token(&raw_token);

    // --------------------------------------------------------
    // Current time
    // --------------------------------------------------------

    let now = Utc::now().naive_utc();
    
    // --------------------------------------------------------
    // Session expiration
    // --------------------------------------------------------
    
    
    let expires_at =
        now + Duration::hours(SESSION_DURATION_HOURS);

    // --------------------------------------------------------
    // Create SeaORM ActiveModel
    // --------------------------------------------------------

    let session = session::ActiveModel {
        user_id: Set(user_id),

        // IMPORTANT:
        // Store only the hash, never the raw token.
        token_hash: Set(token_hash),

        device_id: Set(device_id),

        device_name: Set(device_name),

        created_at: Set(now),

        expires_at: Set(expires_at),

        last_activity_at: Set(now),

        revoked_at: Set(None),

        is_active: Set(true),

        ..Default::default()
    };

    // --------------------------------------------------------
    // Insert session
    // --------------------------------------------------------

    session
        .insert(db)
        .await
        .map_err(|e| {
            format!("Failed to create session: {}", e)
        })?;

    // --------------------------------------------------------
    // Return raw token
    // --------------------------------------------------------
    //
    // The raw token is never stored in SQLite.
    //
    // The caller should return this token to the frontend.
    // --------------------------------------------------------

    Ok(raw_token)
}


// ============================================================
// FIND SESSION
// ============================================================

/// Find a session using a raw session token.
///
/// The token is hashed first, then the database is searched
/// using the hash.
///
/// This means the raw token never needs to be stored.
pub async fn find_session(
    db: &DatabaseConnection,
    raw_token: &str,
) -> Result<Option<session::Model>, String> {
    if raw_token.trim().is_empty() {
        return Ok(None);
    }

    let token_hash = hash_session_token(raw_token);

    session::Entity::find()
        .filter(session::Column::TokenHash.eq(token_hash))
        .one(db)
        .await
        .map_err(|e| {
            format!("Failed to find session: {}", e)
        })
}


// ============================================================
// VALIDATE SESSION
// ============================================================

/// Validate a session token.
///
/// A session is valid only when:
///
/// - Session exists
/// - Session is active
/// - Session has not been revoked
/// - Session has not expired
/// - Session has not been idle for too long
///
/// Returns the session model if valid.
pub async fn validate_session(
    db: &DatabaseConnection,
    raw_token: &str,
) -> Result<session::Model, String> {
    // --------------------------------------------------------
    // Find session
    // --------------------------------------------------------

    let session = find_session(db, raw_token)
        .await?
        .ok_or_else(|| {
            "Invalid or expired session".to_string()
        })?;

    let now = Utc::now().naive_utc();

    // --------------------------------------------------------
    // Check active status
    // --------------------------------------------------------

    if !session.is_active {
        return Err("Session is inactive".to_string());
    }

    // --------------------------------------------------------
    // Check revoked status
    // --------------------------------------------------------

    if session.revoked_at.is_some() {
        return Err("Session has been revoked".to_string());
    }

    // --------------------------------------------------------
    // Check absolute expiration
    // --------------------------------------------------------

    if session.expires_at <= now {
        // Automatically deactivate expired session.
        deactivate_session(db, session.id).await?;

        return Err("Session has expired".to_string());
    }

    

    // --------------------------------------------------------
    // Check idle timeout
    // --------------------------------------------------------

    let idle_limit =
        now - Duration::hours(SESSION_IDLE_TIMEOUT_HOURS);

    if session.last_activity_at < idle_limit {
        deactivate_session(db, session.id).await?;

        return Err(
            "Session expired due to inactivity".to_string()
        );
    }

    // --------------------------------------------------------
    // Session is valid
    // --------------------------------------------------------

    Ok(session)
}


// ============================================================
// UPDATE SESSION ACTIVITY
// ============================================================

/// Update the last activity timestamp of a session.
///
/// Call this after a successfully authenticated operation.
///
/// Example:
///
/// login
///   ↓
/// validate_session()
///   ↓
/// update_session_activity()
pub async fn update_session_activity(
    db: &DatabaseConnection,
    session_id: i32,
) -> Result<(), String> {
    let session = session::Entity::find_by_id(session_id)
        .one(db)
        .await
        .map_err(|e| {
            format!("Failed to find session: {}", e)
        })?
        .ok_or_else(|| {
            "Session not found".to_string()
        })?;

    let mut active_model: session::ActiveModel =
        session.into();

    active_model.last_activity_at = Set(Utc::now().naive_utc());

    active_model
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to update session activity: {}",
                e
            )
        })?;

    Ok(())
}


// ============================================================
// REVOKE SESSION
// ============================================================

/// Revoke one session.
///
/// This is used by logout.
///
/// The session is not deleted because keeping the record gives
/// us an audit/history trail.
pub async fn revoke_session(
    db: &DatabaseConnection,
    session_id: i32,
) -> Result<(), String> {
    let session = session::Entity::find_by_id(session_id)
        .one(db)
        .await
        .map_err(|e| {
            format!("Failed to find session: {}", e)
        })?;

    let Some(session) = session else {
        // Already gone / already invalid.
        return Ok(());
    };

    let mut active_model: session::ActiveModel =
        session.into();

    active_model.is_active = Set(false);

    active_model.revoked_at = Set(Some(Utc::now().naive_utc()));

    active_model
        .update(db)
        .await
        .map_err(|e| {
            format!("Failed to revoke session: {}", e)
        })?;

    Ok(())
}


// ============================================================
// REVOKE SESSION BY TOKEN
// ============================================================

/// Revoke the session represented by a raw token.
///
/// This is useful for logout.
///
/// Flow:
///
/// raw token
///     ↓
/// hash token
///     ↓
/// find session
///     ↓
/// revoke session
pub async fn revoke_session_by_token(
    db: &DatabaseConnection,
    raw_token: &str,
) -> Result<(), String> {
    let session = find_session(db, raw_token).await?;

    let Some(session) = session else {
        // Treat an already-invalid session as successfully logged
        // out. This makes logout idempotent.
        return Ok(());
    };

    revoke_session(db, session.id).await
}


// ============================================================
// DEACTIVATE SESSION
// ============================================================

/// Deactivate a session.
///
/// This is mainly used internally when a session expires.
///
/// Difference:
///
/// revoke_session()
///     → explicit logout/revocation
///
/// deactivate_session()
///     → automatic expiration/inactivity
pub async fn deactivate_session(
    db: &DatabaseConnection,
    session_id: i32,
) -> Result<(), String> {
    let session = session::Entity::find_by_id(session_id)
        .one(db)
        .await
        .map_err(|e| {
            format!("Failed to find session: {}", e)
        })?;

    let Some(session) = session else {
        return Ok(());
    };

    let mut active_model: session::ActiveModel =
        session.into();

    active_model.is_active = Set(false);

    active_model
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to deactivate session: {}",
                e
            )
        })?;

    Ok(())
}


// ============================================================
// REVOKE ALL USER SESSIONS
// ============================================================

/// Revoke every active session belonging to a user.
///
/// Useful when:
///
/// - Super Admin resets a password
/// - User is disabled
/// - User is locked
/// - Security administrator wants to log the user out
///   everywhere
pub async fn revoke_all_user_sessions(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<(), String> {
    let sessions = session::Entity::find()
        .filter(session::Column::UserId.eq(user_id))
        .filter(session::Column::IsActive.eq(true))
        .all(db)
        .await
        .map_err(|e| {
            format!("Failed to find user sessions: {}", e)
        })?;

    let now = Utc::now().naive_utc();

    for item in sessions {
        let mut active_model: session::ActiveModel =
            item.into();

        active_model.is_active = Set(false);

        active_model.revoked_at = Set(Some(now));

        active_model
            .update(db)
            .await
            .map_err(|e| {
                format!(
                    "Failed to revoke user session: {}",
                    e
                )
            })?;
    }

    Ok(())
}


// ============================================================
// DELETE OLD SESSIONS
// ============================================================

/// Delete old inactive sessions.
///
/// This is optional maintenance.
///
/// We generally don't want to delete sessions immediately because
/// session records can be useful for security/audit purposes.
///
/// You can periodically delete records older than a retention
/// period.
///
/// Example usage:
///
/// cleanup_old_sessions(&db, 90).await?;
pub async fn cleanup_old_sessions(
    db: &DatabaseConnection,
    retention_days: i64,
) -> Result<u64, String> {
    use sea_orm::QueryFilter;

    let cutoff =
        Utc::now() - Duration::days(retention_days);

    let result = session::Entity::delete_many()
        .filter(
            session::Column::IsActive
                .eq(false),
        )
        .filter(
            session::Column::CreatedAt
                .lt(cutoff),
        )
        .exec(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to cleanup old sessions: {}",
                e
            )
        })?;

    Ok(result.rows_affected)
}


// ============================================================
// SESSION EXPIRATION CLEANUP
// ============================================================

/// Mark expired sessions as inactive.
///
/// This does not delete the records.
///
/// You can call this when the application starts or periodically.
pub async fn deactivate_expired_sessions(
    db: &DatabaseConnection,
) -> Result<u64, String> {
    let now = Utc::now().naive_utc();

    let sessions = session::Entity::find()
        .filter(session::Column::IsActive.eq(true))
        .filter(session::Column::ExpiresAt.lt(now))
        .all(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to find expired sessions: {}",
                e
            )
        })?;

    let mut affected = 0u64;

    for item in sessions {
        let mut active_model: session::ActiveModel =
            item.into();

        active_model.is_active = Set(false);

        active_model
            .update(db)
            .await
            .map_err(|e| {
                format!(
                    "Failed to deactivate expired session: {}",
                    e
                )
            })?;

        affected += 1;
    }

    Ok(affected)
}