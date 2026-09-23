//! ============================================================
//! AUTH AUDIT LOGGING
//! ============================================================
//!
//! Centralized audit logging for authentication/security events.
//!
//! IMPORTANT:
//! - Never store passwords here.
//! - Never store raw session tokens.
//! - Keep descriptions short and useful.
//! - Audit logs should describe WHAT happened, WHO did it,
//!   and WHICH entity was affected.
//! ============================================================

use chrono::Utc;

use sea_orm::{
    ActiveModelTrait,
    DatabaseConnection,
    Set,
};

use super::entity::audit_log;


// ============================================================
// AUDIT ACTIONS
// ============================================================

/// Standard authentication/security audit actions.
///
/// Using constants instead of random strings throughout the
/// application prevents spelling inconsistencies.
pub mod action {
    pub const INITIAL_SETUP: &str = "INITIAL_SETUP";

    pub const LOGIN: &str = "LOGIN";
    pub const LOGIN_FAILED: &str = "LOGIN_FAILED";
    pub const LOGOUT: &str = "LOGOUT";

    pub const CREATE_USER: &str = "CREATE_USER";

    pub const ENABLE_USER: &str = "ENABLE_USER";
    pub const DISABLE_USER: &str = "DISABLE_USER";
    pub const UNLOCK_USER: &str = "UNLOCK_USER";

    pub const CHANGE_PASSWORD: &str = "CHANGE_PASSWORD";
    pub const RESET_PASSWORD: &str = "RESET_PASSWORD";

    pub const ASSIGN_ROLE: &str = "ASSIGN_ROLE";
    pub const REVOKE_ROLE: &str = "REVOKE_ROLE";

    pub const REVOKE_SESSIONS: &str = "REVOKE_SESSIONS";

    pub const SESSION_EXPIRED: &str = "SESSION_EXPIRED";
}


// ============================================================
// ENTITY TYPES
// ============================================================

pub mod entity_type {
    pub const USER: &str = "USER";
    pub const SESSION: &str = "SESSION";
    pub const ROLE: &str = "ROLE";
    pub const USER_ROLE: &str = "USER_ROLE";
}


// ============================================================
// CREATE AUDIT LOG
// ============================================================

/// Create a security audit log entry.
///
/// `user_id`
///     User who performed the action.
///
/// `action`
///     One of the constants from `action`.
///
/// `entity_type`
///     Type of entity affected.
///
/// `entity_id`
///     ID of affected entity.
///
/// `description`
///     Human-readable description.
///
/// `device_id`
///     Optional device identifier.
///
/// IMPORTANT:
/// Never pass passwords, password hashes, raw session tokens,
/// or other secrets in `description`, `old_values`, or
/// `new_values`.
pub async fn log(
    db: &DatabaseConnection,
    user_id: Option<i32>,
    action: &str,
    entity_type: Option<&str>,
    entity_id: Option<&str>,
    description: Option<&str>,
    device_id: Option<&str>,
) -> Result<(), String> {
    let now = Utc::now().naive_utc();

    let model = audit_log::ActiveModel {
        user_id: Set(user_id),

        action: Set(
            action.to_string()
        ),

        entity_type: Set(
            entity_type
                .map(str::to_string)
        ),

        entity_id: Set(
            entity_id
                .map(str::to_string)
        ),

        description: Set(
            description
                .map(str::to_string)
        ),

        // We intentionally leave these empty for authentication
        // events. Do NOT put passwords or tokens here.
        old_values: Set(None),

        new_values: Set(None),

        device_id: Set(
            device_id
                .map(str::to_string)
        ),

        created_at: Set(now),

        ..Default::default()
    };

    model
        .insert(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to create audit log: {}",
                e
            )
        })?;

    Ok(())
}


// ============================================================
// LOG LOGIN
// ============================================================

pub async fn login(
    db: &DatabaseConnection,
    user_id: i32,
    device_id: Option<&str>,
) -> Result<(), String> {
    log(
        db,
        Some(user_id),
        action::LOGIN,
        Some(entity_type::USER),
        Some(&user_id.to_string()),
        Some("User logged in successfully"),
        device_id,
    )
    .await
}


// ============================================================
// LOG FAILED LOGIN
// ============================================================

pub async fn login_failed(
    db: &DatabaseConnection,
    user_id: Option<i32>,
    username: &str,
    reason: &str,
    device_id: Option<&str>,
) -> Result<(), String> {
    // Username is safe to log.
    //
    // Password is NEVER passed here.
    let description = format!(
        "Failed login attempt for username '{}' ({})",
        username,
        reason
    );

    log(
        db,
        user_id,
        action::LOGIN_FAILED,
        Some(entity_type::USER),
        user_id.map(|id| id.to_string()).as_deref(),
        Some(&description),
        device_id,
    )
    .await
}


// ============================================================
// LOG LOGOUT
// ============================================================

pub async fn logout(
    db: &DatabaseConnection,
    user_id: i32,
    device_id: Option<&str>,
) -> Result<(), String> {
    log(
        db,
        Some(user_id),
        action::LOGOUT,
        Some(entity_type::USER),
        Some(&user_id.to_string()),
        Some("User logged out"),
        device_id,
    )
    .await
}


// ============================================================
// LOG USER CREATION
// ============================================================

pub async fn user_created(
    db: &DatabaseConnection,
    creator_id: i32,
    created_user_id: i32,
) -> Result<(), String> {
    log(
        db,
        Some(creator_id),
        action::CREATE_USER,
        Some(entity_type::USER),
        Some(&created_user_id.to_string()),
        Some("New user account created"),
        None,
    )
    .await
}


// ============================================================
// LOG PASSWORD CHANGE
// ============================================================

pub async fn password_changed(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<(), String> {
    log(
        db,
        Some(user_id),
        action::CHANGE_PASSWORD,
        Some(entity_type::USER),
        Some(&user_id.to_string()),
        Some("User password changed"),
        None,
    )
    .await
}


// ============================================================
// LOG PASSWORD RESET
// ============================================================

pub async fn password_reset(
    db: &DatabaseConnection,
    administrator_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    log(
        db,
        Some(administrator_id),
        action::RESET_PASSWORD,
        Some(entity_type::USER),
        Some(&target_user_id.to_string()),
        Some("Administrator reset user password"),
        None,
    )
    .await
}


// ============================================================
// LOG USER ENABLE
// ============================================================

pub async fn user_enabled(
    db: &DatabaseConnection,
    administrator_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    log(
        db,
        Some(administrator_id),
        action::ENABLE_USER,
        Some(entity_type::USER),
        Some(&target_user_id.to_string()),
        Some("User account enabled"),
        None,
    )
    .await
}


// ============================================================
// LOG USER DISABLE
// ============================================================

pub async fn user_disabled(
    db: &DatabaseConnection,
    administrator_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    log(
        db,
        Some(administrator_id),
        action::DISABLE_USER,
        Some(entity_type::USER),
        Some(&target_user_id.to_string()),
        Some("User account disabled"),
        None,
    )
    .await
}


// ============================================================
// LOG USER UNLOCK
// ============================================================

pub async fn user_unlocked(
    db: &DatabaseConnection,
    administrator_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    log(
        db,
        Some(administrator_id),
        action::UNLOCK_USER,
        Some(entity_type::USER),
        Some(&target_user_id.to_string()),
        Some("User account unlocked"),
        None,
    )
    .await
}


// ============================================================
// LOG ROLE ASSIGNMENT
// ============================================================

pub async fn role_assigned(
    db: &DatabaseConnection,
    administrator_id: i32,
    target_user_id: i32,
    role_id: i32,
) -> Result<(), String> {
    let description = format!(
        "Role {} assigned to user",
        role_id
    );

    log(
        db,
        Some(administrator_id),
        action::ASSIGN_ROLE,
        Some(entity_type::USER_ROLE),
        Some(&target_user_id.to_string()),
        Some(&description),
        None,
    )
    .await
}


// ============================================================
// LOG ROLE REVOCATION
// ============================================================

pub async fn role_revoked(
    db: &DatabaseConnection,
    administrator_id: i32,
    target_user_id: i32,
    role_id: i32,
) -> Result<(), String> {
    let description = format!(
        "Role {} revoked from user",
        role_id
    );

    log(
        db,
        Some(administrator_id),
        action::REVOKE_ROLE,
        Some(entity_type::USER_ROLE),
        Some(&target_user_id.to_string()),
        Some(&description),
        None,
    )
    .await
}


// ============================================================
// LOG SESSION REVOCATION
// ============================================================

pub async fn sessions_revoked(
    db: &DatabaseConnection,
    administrator_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    log(
        db,
        Some(administrator_id),
        action::REVOKE_SESSIONS,
        Some(entity_type::USER),
        Some(&target_user_id.to_string()),
        Some("All sessions for user were revoked"),
        None,
    )
    .await
}