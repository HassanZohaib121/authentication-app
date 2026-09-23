//! ============================================================
//! AUTHENTICATION SERVICE
//! ============================================================
//!
//! This module contains the core authentication/business logic.
//
//! `commands.rs` should ideally remain thin and call functions
//! from this file.
//
//! Responsibilities:
//!
//! - First-user setup
//! - Login
//! - Password verification
//! - Account lockout
//! - Password changes
//! - Password reset
//! - User creation
//! - Role assignment
//! - User enable/disable
//! - Session creation/revocation
//! - Super Admin protection
//!
//! IMPORTANT:
//! Passwords are NEVER written to audit logs.
//! ============================================================

use chrono::{Duration, Utc};

use sea_orm::{
    ActiveModelTrait,
    ColumnTrait,
    DatabaseConnection,
    EntityTrait,
    PaginatorTrait,
    QueryFilter,
    QueryOrder,
    QuerySelect,
    Set,
    TransactionTrait,
};

use serde::{Deserialize, Serialize};

use super::entity::{
    app_setting,
    audit_log,
    login_attempt,
    password_history,
    role,
    user,
    user_role,
};

use crate::auth::session::{create_session, find_session, revoke_session, validate_session, update_session_activity, revoke_all_user_sessions};
use crate::auth::error::AuthError;

use super::password::{
    hash_password,
    verify_password,
};


// ============================================================
// CONFIGURATION
// ============================================================

/// Maximum failed login attempts before the account is locked.
const MAX_LOGIN_ATTEMPTS: i32 = 5;

/// Number of minutes for an account lockout.
const LOCKOUT_MINUTES: i64 = 15;

/// Password history entries to keep/check.
///
/// Example:
///
/// 5 means the user cannot reuse their last 5 passwords.
const PASSWORD_HISTORY_LIMIT: usize = 5;


// ============================================================
// DTOs
// ============================================================

/// Information about the authenticated user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: i32,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
}


/// Result returned after successful login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResult {
    pub user: AuthUser,

    /// Raw session token.
    ///
    /// This is returned to the frontend.
    ///
    /// IMPORTANT:
    /// It is NOT stored in the database.
    pub session_token: String,

    pub expires_at: String,

    pub must_change_password: bool,
}


/// Setup status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatus {
    pub setup_completed: bool,
    pub has_super_admin: bool,
}


/// Generic user information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: i32,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub is_active: bool,
    pub is_locked: bool,
    pub failed_login_attempts: i32,
    pub locked_until: Option<String>,
    pub last_login_at: Option<String>,
    pub must_change_password: bool,
    pub roles: Vec<String>,
}


// ============================================================
// INPUT DTOs
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupInput {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserInput {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password: String,
    pub role_id: Option<i32>,
    pub must_change_password: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordInput {
    pub user_id: i32,
    pub current_password: String,
    pub new_password: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordInput {
    pub target_user_id: i32,
    pub new_password: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignRoleInput {
    pub target_user_id: i32,
    pub role_id: i32,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActionInput {
    pub target_user_id: i32,
}


// ============================================================
// NORMALIZE USERNAME
// ============================================================

pub fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
}


// ============================================================
// VALIDATE USERNAME
// ============================================================

pub fn validate_username(username: &str) -> Result<String, String> {
    let username = normalize_username(username);

    if username.is_empty() {
        return Err("Username is required".to_string());
    }

    if username.len() < 3 {
        return Err(
            "Username must contain at least 3 characters"
                .to_string(),
        );
    }

    if username.len() > 50 {
        return Err(
            "Username cannot exceed 50 characters"
                .to_string(),
        );
    }

    // Only allow predictable username characters.
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(
            "Username may contain only letters, numbers, _, - and ."
                .to_string(),
        );
    }

    Ok(username)
}


// ============================================================
// VALIDATE PASSWORD
// ============================================================

pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err(
            "Password must contain at least 8 characters"
                .to_string(),
        );
    }

    if password.len() > 128 {
        return Err(
            "Password cannot exceed 128 characters"
                .to_string(),
        );
    }

    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(
            "Password must contain at least one uppercase letter"
                .to_string(),
        );
    }

    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(
            "Password must contain at least one lowercase letter"
                .to_string(),
        );
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(
            "Password must contain at least one number"
                .to_string(),
        );
    }

    Ok(())
}


// ============================================================
// FIND USER BY USERNAME
// ============================================================

pub async fn find_user_by_username(
    db: &DatabaseConnection,
    username: &str,
) -> Result<Option<user::Model>, String> {
    let username = normalize_username(username);

    user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(db)
        .await
        .map_err(|e| {
            format!("Failed to find user: {}", e)
        })
}


// ============================================================
// FIND USER BY ID
// ============================================================

pub async fn find_user_by_id(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<Option<user::Model>, String> {
    user::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|e| {
            format!("Failed to find user: {}", e)
        })
}


// ============================================================
// CHECK SUPER ADMIN
// ============================================================

pub async fn is_super_admin(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<bool, String> {
    let result = user_role::Entity::find()
        .filter(user_role::Column::UserId.eq(user_id))
        .find_also_related(role::Entity)
        .all(db)
        .await
        .map_err(|e| e.to_string())?;

    Ok(result.iter().any(|(_, role)| {
        role.as_ref()
            .map(|r| r.name == "SUPER_ADMIN" && r.is_active)
            .unwrap_or(false)
    }))
}


// ============================================================
// REQUIRE SUPER ADMIN
// ============================================================

pub async fn require_super_admin(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<(), String> {
    if !is_super_admin(db, user_id).await? {
        return Err(
            "Only SUPER_ADMIN can perform this action"
                .to_string(),
        );
    }

    Ok(())
}


// ============================================================
// GET USER ROLES
// ============================================================

pub async fn get_user_roles(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<Vec<String>, String> {
    let rows = user_role::Entity::find()
        .filter(user_role::Column::UserId.eq(user_id))
        .find_also_related(role::Entity)
        .all(db)
        .await
        .map_err(|e| {
            format!("Failed to load user roles: {}", e)
        })?;

    let mut roles = Vec::new();

    for (_, role_model) in rows {
        if let Some(role_model) = role_model {
            if role_model.is_active {
                roles.push(role_model.name);
            }
        }
    }

    roles.sort();

    Ok(roles)
}


// ============================================================
// BUILD AUTH USER
// ============================================================

pub async fn build_auth_user(
    db: &DatabaseConnection,
    user_model: &user::Model,
) -> Result<AuthUser, String> {
    let roles =
        get_user_roles(db, user_model.id).await?;

    Ok(AuthUser {
        id: user_model.id,
        username: user_model.username.clone(),
        name: user_model.name.clone(),
        email: user_model.email.clone(),
        roles,
    })
}


// ============================================================
// GET SETUP STATUS
// ============================================================

pub async fn get_setup_status(
    db: &DatabaseConnection,
) -> Result<SetupStatus, String> {
    let settings = app_setting::Entity::find_by_id(1)
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    let setup_completed = settings
        .as_ref()
        .map(|s| s.setup_completed)
        .unwrap_or(false);

    let has_super_admin = count_super_admins(db).await? > 0;

    Ok(SetupStatus {
        setup_completed,
        has_super_admin,
    })
}


// ============================================================
// COUNT SUPER ADMINS
// ============================================================

pub async fn count_super_admins(
    db: &DatabaseConnection,
) -> Result<i64, String> {
    let role_model = role::Entity::find()
        .filter(role::Column::Name.eq("SUPER_ADMIN"))
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    let Some(role_model) = role_model else {
        return Ok(0);
    };

    let count = user_role::Entity::find()
        .filter(user_role::Column::RoleId.eq(role_model.id))
        .count(db)
        .await
        .map_err(|e| e.to_string())? as i64;

    Ok(count)
}


// ============================================================
// FIRST USER SETUP
// ============================================================

/// Create the first user.
///
/// The first user automatically becomes SUPER_ADMIN.
///
/// Setup can only happen once.

pub async fn setup_first_user(
    db: &DatabaseConnection,
    input: SetupInput,
) -> Result<AuthUser, String> {
    let username =
        validate_username(&input.username)?;
    // let password = validate_password(&input.password)?;

    if input.name.trim().is_empty() {
        return Err("Name is required".to_string());
    }
    // --------------------------------------------------------
    // Check setup state
    // --------------------------------------------------------

    let settings = app_setting::Entity::find_by_id(1)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            "Application settings have not been initialized"
                .to_string()
        })?;

    if settings.setup_completed {
        return Err(
            "Initial setup has already been completed"
                .to_string(),
        );
    }

    // --------------------------------------------------------
    // Make sure no SUPER_ADMIN already exists
    // --------------------------------------------------------

    if count_super_admins(db).await? > 0 {
        return Err(
            "A SUPER_ADMIN already exists"
                .to_string(),
        );
    }

    // --------------------------------------------------------
    // Make sure username is unique
    // --------------------------------------------------------

    if find_user_by_username(db, &username)
        .await?
        .is_some()
    {
        return Err(
            "Username is already in use"
                .to_string(),
        );
    }

    // --------------------------------------------------------
    // Find SUPER_ADMIN role
    // --------------------------------------------------------

    let super_admin_role =
        role::Entity::find()
            .filter(
                role::Column::Name
                    .eq("SUPER_ADMIN"),
            )
            .one(db)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                "SUPER_ADMIN role is missing from the database"
                    .to_string()
            })?;


    // --------------------------------------------------------
    // Hash password
    // --------------------------------------------------------

    let password_hash =
        hash_password(&input.password)?;

    let now = Utc::now().naive_utc();

    // --------------------------------------------------------
    // Use transaction
    // --------------------------------------------------------

    let txn = db
        .begin()
        .await
        .map_err(|e| {
            format!("Failed to start setup transaction: {}", e)
        })?;

    // --------------------------------------------------------
    // Create first user
    // --------------------------------------------------------

    let new_user = user::ActiveModel {
        username: Set(username),
        email: Set(input.email),
        name: Set(input.name.trim().to_string()),
        password_hash: Set(password_hash.clone()),
        password_changed_at: Set(Some(now)),
        is_active: Set(true),
        is_locked: Set(false),
        failed_login_attempts: Set(0),
        locked_until: Set(None),
        last_login_at: Set(None),
        last_login_device: Set(None),
        must_change_password: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
        created_by: Set(None),
        ..Default::default()
    };

    let new_user = new_user
        .insert(&txn)
        .await
        .map_err(|e| {
            format!(
                "Failed to create first user: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Assign SUPER_ADMIN role
    // --------------------------------------------------------

    let user_role_model = user_role::ActiveModel {
        user_id: Set(new_user.id),
        role_id: Set(super_admin_role.id),
        assigned_by: Set(None),
        assigned_at: Set(now),
        ..Default::default()
    };

    user_role_model
        .insert(&txn)
        .await
        .map_err(|e| {
            format!(
                "Failed to assign SUPER_ADMIN role: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Save initial password in password history
    // --------------------------------------------------------

    let history = password_history::ActiveModel {
        user_id: Set(new_user.id),
        password_hash: Set(password_hash),
        created_at: Set(now),
        changed_by: Set(None),
        ..Default::default()
    };

    history
        .insert(&txn)
        .await
        .map_err(|e| {
            format!(
                "Failed to save password history: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Mark setup complete
    // --------------------------------------------------------

    let mut settings_model: app_setting::ActiveModel =
        settings.into();

    settings_model.setup_completed = Set(true);
    settings_model.setup_completed_at =
        Set(Some(now));
    settings_model.setup_completed_by =
        Set(Some(new_user.id));
    settings_model.updated_at = Set(now);

    settings_model
        .update(&txn)
        .await
        .map_err(|e| {
            format!(
                "Failed to finalize application setup: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Audit setup
    // --------------------------------------------------------

    let audit = audit_log::ActiveModel {
        user_id: Set(Some(new_user.id)),
        action: Set("INITIAL_SETUP".to_string()),
        entity_type: Set(Some("USER".to_string())),
        entity_id: Set(Some(new_user.id.to_string())),
        description: Set(Some(
            "Initial SUPER_ADMIN account created"
                .to_string(),
        )),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    };

    audit
        .insert(&txn)
        .await
        .map_err(|e| {
            format!(
                "Failed to create setup audit log: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Commit
    // --------------------------------------------------------

    txn.commit()
        .await
        .map_err(|e| {
            format!(
                "Failed to commit setup transaction: {}",
                e
            )
        })?;

    build_auth_user(db, &new_user).await
}


// ============================================================
// LOGIN
// ============================================================

pub async fn login(
    db: &DatabaseConnection,
    input: LoginInput,
) -> Result<LoginResult, String> {
    let username =
        validate_username(&input.username)?;

    if input.password.is_empty() {
        return Err("Password is required".to_string());
    }

    // --------------------------------------------------------
    // Find user
    // --------------------------------------------------------

    let Some(user_model) =
        find_user_by_username(db, &username).await?
    else {
        // Do not reveal whether username exists.
        record_login_attempt(
            db,
            None,
            &username,
            false,
            Some("INVALID_CREDENTIALS"),
            input.device_id.clone(),
        )
        .await?;

        return Err(
            "Invalid username or password".to_string()
        );
    };

    // --------------------------------------------------------
    // Check active
    // --------------------------------------------------------

    if !user_model.is_active {
        record_login_attempt(
            db,
            Some(user_model.id),
            &username,
            false,
            Some("ACCOUNT_DISABLED"),
            input.device_id.clone(),
        )
        .await?;

        return Err(
            "This account has been disabled"
                .to_string(),
        );
    }

    // --------------------------------------------------------
    // Check lock
    // --------------------------------------------------------

    if user_model.is_locked {
        let now = Utc::now().naive_utc();

        if let Some(locked_until) =
            user_model.locked_until
        {
            if locked_until > now {
                record_login_attempt(
                    db,
                    Some(user_model.id),
                    &username,
                    false,
                    Some("ACCOUNT_LOCKED"),
                    input.device_id.clone(),
                )
                .await?;

                return Err(format!(
                    "Account is locked until {}",
                    locked_until
                ));
            }
        }

        // Lock expired.
        unlock_expired_account(
            db,
            &user_model,
        )
        .await?;
    }

    // --------------------------------------------------------
    // Verify password
    // --------------------------------------------------------

    let password_valid =
        verify_password(
            &input.password,
            &user_model.password_hash,
        )?;

    if !password_valid {
        handle_failed_login(
            db,
            &user_model,
            input.device_id.clone(),
        )
        .await?;

        return Err(
            "Invalid username or password"
                .to_string(),
        );
    }

    // --------------------------------------------------------
    // Successful login
    // --------------------------------------------------------

    let now = Utc::now().naive_utc();

    let mut active_user: user::ActiveModel =
        user_model.clone().into();

    active_user.failed_login_attempts =
        Set(0);

    active_user.is_locked =
        Set(false);

    active_user.locked_until =
        Set(None);

    active_user.last_login_at =
        Set(Some(now));

    active_user.last_login_device =
        Set(input.device_name.clone());

    active_user.updated_at =
        Set(now);

    let updated_user = active_user
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to update login information: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Create session
    // --------------------------------------------------------

    let session_token =
        create_session(
            db,
            updated_user.id,
            input.device_id.clone(),
            input.device_name.clone(),
        )
        .await?;

    // --------------------------------------------------------
    // Record successful login
    // --------------------------------------------------------

    record_login_attempt(
        db,
        Some(updated_user.id),
        &username,
        true,
        None,
        input.device_id.clone(),
    )
    .await?;

    // --------------------------------------------------------
    // Audit login
    // --------------------------------------------------------

    create_audit_log(
        db,
        Some(updated_user.id),
        "LOGIN",
        Some("USER"),
        Some(updated_user.id.to_string()),
        Some("User logged in successfully"),
        input.device_id.clone(),
    )
    .await?;

    // --------------------------------------------------------
    // Build response
    // --------------------------------------------------------

    let auth_user =
        build_auth_user(db, &updated_user)
            .await?;

    // Fetch session to obtain exact expiration time.
    let session_model =
        find_session(
            db,
            &session_token,
        )
        .await?
        .ok_or_else(|| {
            "Failed to create login session"
                .to_string()
        })?;

    Ok(LoginResult {
        user: auth_user,
        session_token,
        expires_at: session_model
            .expires_at
            .to_string(),
        must_change_password:
            updated_user.must_change_password,
    })
}


// ============================================================
// FAILED LOGIN
// ============================================================

async fn handle_failed_login(
    db: &DatabaseConnection,
    user_model: &user::Model,
    device_id: Option<String>,
) -> Result<(), String> {
    let now = Utc::now().naive_utc();

    let new_attempts =
        user_model.failed_login_attempts + 1;

    let should_lock =
        new_attempts >= MAX_LOGIN_ATTEMPTS;

    let locked_until =
        if should_lock {
            Some(
                now + Duration::minutes(
                    LOCKOUT_MINUTES,
                ),
            )
        } else {
            None
        };

    let mut active_user: user::ActiveModel =
        user_model.clone().into();

    active_user.failed_login_attempts =
        Set(new_attempts);

    active_user.is_locked =
        Set(should_lock);

    active_user.locked_until =
        Set(locked_until);

    active_user.updated_at =
        Set(now);

    active_user
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to update failed login attempts: {}",
                e
            )
        })?;

    let reason =
        if should_lock {
            "ACCOUNT_LOCKED"
        } else {
            "INVALID_CREDENTIALS"
        };

    record_login_attempt(
        db,
        Some(user_model.id),
        &user_model.username,
        false,
        Some(reason),
        device_id,
    )
    .await?;

    Ok(())
}


// ============================================================
// UNLOCK EXPIRED ACCOUNT
// ============================================================

async fn unlock_expired_account(
    db: &DatabaseConnection,
    user_model: &user::Model,
) -> Result<(), String> {
    let now = Utc::now().naive_utc();

    let mut active_user: user::ActiveModel =
        user_model.clone().into();

    active_user.is_locked =
        Set(false);

    active_user.failed_login_attempts =
        Set(0);

    active_user.locked_until =
        Set(None);

    active_user.updated_at =
        Set(now);

    active_user
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to unlock expired account: {}",
                e
            )
        })?;

    Ok(())
}


// ============================================================
// RECORD LOGIN ATTEMPT
// ============================================================

pub async fn record_login_attempt(
    db: &DatabaseConnection,
    user_id: Option<i32>,
    username: &str,
    success: bool,
    failure_reason: Option<&str>,
    device_id: Option<String>,
) -> Result<(), String> {
    let model = login_attempt::ActiveModel {
        user_id: Set(user_id),
        username: Set(
            normalize_username(username)
        ),
        success: Set(success),
        failure_reason: Set(
            failure_reason.map(str::to_string)
        ),
        device_id: Set(device_id),
        attempted_at: Set(
            Utc::now().naive_utc()
        ),
        ..Default::default()
    };

    model
        .insert(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to record login attempt: {}",
                e
            )
        })?;

    Ok(())
}


// ============================================================
// LOGOUT
// ============================================================

pub async fn logout(
    db: &DatabaseConnection,
    session_token: &str,
) -> Result<(), String> {
    if session_token.trim().is_empty() {
        return Ok(());
    }

    let session_model =
        find_session(
            db,
            session_token,
        )
        .await?;

    let Some(session_model) =
        session_model
    else {
        return Ok(());
    };

    revoke_session(
        db,
        session_model.id,
    )
    .await?;

    create_audit_log(
        db,
        Some(session_model.user_id),
        "LOGOUT",
        Some("SESSION"),
        Some(session_model.id.to_string()),
        Some("User logged out"),
        session_model.device_id,
    )
    .await?;

    Ok(())
}


// ============================================================
// CURRENT USER FROM SESSION
// ============================================================

pub async fn current_user(
    db: &DatabaseConnection,
    session_token: &str,
) -> Result<AuthUser, String> {
    let session_model =
        validate_session(
            db,
            session_token,
        )
        .await?;

    let user_model =
        find_user_by_id(
            db,
            session_model.user_id,
        )
        .await?
        .ok_or_else(|| {
            "User account no longer exists"
                .to_string()
        })?;

    if !user_model.is_active {
        revoke_session(
            db,
            session_model.id,
        )
        .await?;

        return Err(
            "User account is disabled"
                .to_string()
        );
    }

    if user_model.is_locked {
        revoke_session(
            db,
            session_model.id,
        )
        .await?;

        return Err(
            "User account is locked"
                .to_string()
        );
    }

    update_session_activity(
        db,
        session_model.id,
    )
    .await?;

    build_auth_user(
        db,
        &user_model,
    )
    .await
}


// ============================================================
// CREATE USER
// ============================================================

pub async fn create_user(
    db: &DatabaseConnection,
    requester_id: i32,
    input: CreateUserInput,
) -> Result<UserInfo, String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    let username =
        validate_username(&input.username)?;

    validate_password(&input.password)?;

    if input.name.trim().is_empty() {
        return Err(
            "Name is required".to_string()
        );
    }

    // --------------------------------------------------------
    // Username uniqueness
    // --------------------------------------------------------

    if find_user_by_username(
        db,
        &username,
    )
    .await?
    .is_some()
    {
        return Err(
            "Username is already in use"
                .to_string()
        );
    }

    // --------------------------------------------------------
    // Prevent manually creating another SUPER_ADMIN
    // through this generic function unless explicitly handled
    // by a dedicated role operation.
    // --------------------------------------------------------

    if let Some(role_id) = input.role_id {
        let requested_role =
            role::Entity::find_by_id(role_id)
                .one(db)
                .await
                .map_err(|e| e.to_string())?;

        if let Some(requested_role) =
            requested_role
        {
            if requested_role.name
                == "SUPER_ADMIN"
            {
                return Err(
                    "Use the dedicated role management operation to assign SUPER_ADMIN"
                        .to_string()
                );
            }
        }
    }

    // --------------------------------------------------------
    // Hash password
    // --------------------------------------------------------

    let password_hash =
        hash_password(&input.password)?;

    let now =
        Utc::now().naive_utc();

    // --------------------------------------------------------
    // Create user
    // --------------------------------------------------------

    let new_user =
        user::ActiveModel {
            username: Set(username),
            email: Set(input.email),
            name: Set(
                input.name
                    .trim()
                    .to_string()
            ),
            password_hash:
                Set(password_hash.clone()),
            password_changed_at:
                Set(Some(now)),
            is_active:
                Set(true),
            is_locked:
                Set(false),
            failed_login_attempts:
                Set(0),
            locked_until:
                Set(None),
            last_login_at:
                Set(None),
            last_login_device:
                Set(None),
            must_change_password:
                Set(
                    input.must_change_password
                ),
            created_at:
                Set(now),
            updated_at:
                Set(now),
            created_by:
                Set(Some(requester_id)),
            ..Default::default()
        }
        .insert(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to create user: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Save password history
    // --------------------------------------------------------

    let history =
        password_history::ActiveModel {
            user_id:
                Set(new_user.id),
            password_hash:
                Set(password_hash),
            created_at:
                Set(now),
            changed_by:
                Set(Some(requester_id)),
            ..Default::default()
        };

    history
        .insert(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to save password history: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Assign requested role
    // --------------------------------------------------------

    if let Some(role_id) =
        input.role_id
    {
        assign_role_internal(
            db,
            new_user.id,
            role_id,
            Some(requester_id),
        )
        .await?;
    }

    // --------------------------------------------------------
    // Audit
    // --------------------------------------------------------

    create_audit_log(
        db,
        Some(requester_id),
        "CREATE_USER",
        Some("USER"),
        Some(new_user.id.to_string()),
        Some("New user account created"),
        None,
    )
    .await?;

    build_user_info(
        db,
        &new_user,
    )
    .await
}


// ============================================================
// CHANGE OWN PASSWORD
// ============================================================

pub async fn change_password(
    db: &DatabaseConnection,
    user_id: i32,
    current_password: &str,
    new_password: &str,
) -> Result<(), String> {
    validate_password(new_password)?;

    if current_password == new_password {
        return Err(
            "New password must be different from current password"
                .to_string()
        );
    }

    let user_model =
        find_user_by_id(
            db,
            user_id,
        )
        .await?
        .ok_or_else(|| {
            "User not found".to_string()
        })?;

    // --------------------------------------------------------
    // Verify old password
    // --------------------------------------------------------

    if !verify_password(
        current_password,
        &user_model.password_hash,
    )? {
        return Err(
            "Current password is incorrect"
                .to_string()
        );
    }

    // --------------------------------------------------------
    // Password history
    // --------------------------------------------------------

    ensure_password_not_reused(
        db,
        user_id,
        new_password,
    )
    .await?;

    // --------------------------------------------------------
    // Hash new password
    // --------------------------------------------------------

    let new_hash =
        hash_password(new_password)?;

    let now =
        Utc::now().naive_utc();

    // --------------------------------------------------------
    // Update user
    // --------------------------------------------------------

    let mut active_user:
        user::ActiveModel =
        user_model.into();

    active_user.password_hash =
        Set(new_hash.clone());

    active_user.password_changed_at =
        Set(Some(now));

    active_user.must_change_password =
        Set(false);

    active_user.updated_at =
        Set(now);

    active_user
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to change password: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Password history
    // --------------------------------------------------------

    password_history::ActiveModel {
        user_id: Set(user_id),
        password_hash: Set(new_hash),
        created_at: Set(now),
        changed_by: Set(Some(user_id)),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| {
        format!(
            "Failed to save password history: {}",
            e
        )
    })?;

    // --------------------------------------------------------
    // Revoke other sessions
    // --------------------------------------------------------
    //
    // Password changes should invalidate existing sessions.
    // The current session can be recreated by the frontend.
    // --------------------------------------------------------

    revoke_all_user_sessions(
        db,
        user_id,
    )
    .await?;

    create_audit_log(
        db,
        Some(user_id),
        "CHANGE_PASSWORD",
        Some("USER"),
        Some(user_id.to_string()),
        Some("User changed password"),
        None,
    )
    .await?;

    Ok(())
}


// ============================================================
// RESET USER PASSWORD
// ============================================================

pub async fn reset_password(
    db: &DatabaseConnection,
    requester_id: i32,
    target_user_id: i32,
    new_password: &str,
) -> Result<(), String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    validate_password(new_password)?;

    let target_user =
        find_user_by_id(
            db,
            target_user_id,
        )
        .await?
        .ok_or_else(|| {
            "Target user not found"
                .to_string()
        })?;

    ensure_password_not_reused(
        db,
        target_user_id,
        new_password,
    )
    .await?;

    let new_hash =
        hash_password(new_password)?;

    let now =
        Utc::now().naive_utc();

    let mut active_user:
        user::ActiveModel =
        target_user.into();

    active_user.password_hash =
        Set(new_hash.clone());

    active_user.password_changed_at =
        Set(Some(now));

    active_user.must_change_password =
        Set(true);

    active_user.updated_at =
        Set(now);

    active_user
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to reset password: {}",
                e
            )
        })?;

    // --------------------------------------------------------
    // Save history
    // --------------------------------------------------------

    password_history::ActiveModel {
        user_id: Set(target_user_id),
        password_hash: Set(new_hash),
        created_at: Set(now),
        changed_by: Set(Some(requester_id)),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| {
        format!(
            "Failed to save password history: {}",
            e
        )
    })?;

    // --------------------------------------------------------
    // Revoke all sessions
    // --------------------------------------------------------

    revoke_all_user_sessions(
        db,
        target_user_id,
    )
    .await?;

    create_audit_log(
        db,
        Some(requester_id),
        "RESET_PASSWORD",
        Some("USER"),
        Some(target_user_id.to_string()),
        Some("Super Admin reset user password"),
        None,
    )
    .await?;

    Ok(())
}


// ============================================================
// CHECK PASSWORD HISTORY
// ============================================================

async fn ensure_password_not_reused(
    db: &DatabaseConnection,
    user_id: i32,
    new_password: &str,
) -> Result<(), String> {
    let histories =
        password_history::Entity::find()
            .filter(
                password_history::Column::UserId
                    .eq(user_id),
            )
            .order_by_desc(
                password_history::Column::CreatedAt,
            )
            .limit(
                PASSWORD_HISTORY_LIMIT as u64,
            )
            .all(db)
            .await
            .map_err(|e| {
                format!(
                    "Failed to check password history: {}",
                    e
                )
            })?;

    for history in histories {
        if verify_password(
            new_password,
            &history.password_hash,
        )? {
            return Err(
                "You cannot reuse one of your recent passwords"
                    .to_string()
            );
        }
    }

    Ok(())
}


// ============================================================
// ENABLE USER
// ============================================================

pub async fn enable_user(
    db: &DatabaseConnection,
    requester_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    let target =
        find_user_by_id(
            db,
            target_user_id,
        )
        .await?
        .ok_or_else(|| {
            "User not found".to_string()
        })?;

    let mut active:
        user::ActiveModel =
        target.into();

    active.is_active =
        Set(true);

    active.updated_at =
        Set(
            Utc::now()
                .naive_utc()
        );

    active
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to enable user: {}",
                e
            )
        })?;

    create_audit_log(
        db,
        Some(requester_id),
        "ENABLE_USER",
        Some("USER"),
        Some(target_user_id.to_string()),
        Some("User account enabled"),
        None,
    )
    .await?;

    Ok(())
}


// ============================================================
// DISABLE USER
// ============================================================

pub async fn disable_user(
    db: &DatabaseConnection,
    requester_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    // --------------------------------------------------------
    // Never disable yourself
    // --------------------------------------------------------

    if requester_id == target_user_id {
        return Err(
            "You cannot disable your own account"
                .to_string()
        );
    }

    // --------------------------------------------------------
    // Protect last SUPER_ADMIN
    // --------------------------------------------------------

    if is_super_admin(
        db,
        target_user_id,
    )
    .await?
    {
        let count =
            count_super_admins(db)
                .await?;

        if count <= 1 {
            return Err(
                "The last SUPER_ADMIN cannot be disabled"
                    .to_string()
            );
        }
    }

    let target =
        find_user_by_id(
            db,
            target_user_id,
        )
        .await?
        .ok_or_else(|| {
            "User not found".to_string()
        })?;

    let mut active:
        user::ActiveModel =
        target.into();

    active.is_active =
        Set(false);

    active.updated_at =
        Set(
            Utc::now()
                .naive_utc()
        );

    active
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to disable user: {}",
                e
            )
        })?;

    // Immediately revoke sessions.
    revoke_all_user_sessions(
        db,
        target_user_id,
    )
    .await?;

    create_audit_log(
        db,
        Some(requester_id),
        "DISABLE_USER",
        Some("USER"),
        Some(target_user_id.to_string()),
        Some("User account disabled"),
        None,
    )
    .await?;

    Ok(())
}


// ============================================================
// UNLOCK USER
// ============================================================

pub async fn unlock_user(
    db: &DatabaseConnection,
    requester_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    let target =
        find_user_by_id(
            db,
            target_user_id,
        )
        .await?
        .ok_or_else(|| {
            "User not found".to_string()
        })?;

    let mut active:
        user::ActiveModel =
        target.into();

    active.is_locked =
        Set(false);

    active.failed_login_attempts =
        Set(0);

    active.locked_until =
        Set(None);

    active.updated_at =
        Set(
            Utc::now()
                .naive_utc()
        );

    active
        .update(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to unlock user: {}",
                e
            )
        })?;

    create_audit_log(
        db,
        Some(requester_id),
        "UNLOCK_USER",
        Some("USER"),
        Some(target_user_id.to_string()),
        Some("User account unlocked"),
        None,
    )
    .await?;

    Ok(())
}


// ============================================================
// ASSIGN ROLE
// ============================================================

pub async fn assign_role(
    db: &DatabaseConnection,
    requester_id: i32,
    target_user_id: i32,
    role_id: i32,
) -> Result<(), String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    // --------------------------------------------------------
    // Check target user
    // --------------------------------------------------------

    if find_user_by_id(
        db,
        target_user_id,
    )
    .await?
    .is_none()
    {
        return Err(
            "Target user not found"
                .to_string()
        );
    }

    // --------------------------------------------------------
    // Check role
    // --------------------------------------------------------

    let requested_role =
        role::Entity::find_by_id(
            role_id,
        )
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            "Role not found".to_string()
        })?;

    if !requested_role.is_active {
        return Err(
            "Role is inactive".to_string()
        );
    }

    // --------------------------------------------------------
    // Prevent duplicate assignment
    // --------------------------------------------------------

    let existing =
        user_role::Entity::find()
            .filter(
                user_role::Column::UserId
                    .eq(target_user_id),
            )
            .filter(
                user_role::Column::RoleId
                    .eq(role_id),
            )
            .one(db)
            .await
            .map_err(|e| e.to_string())?;

    if existing.is_some() {
        return Ok(());
    }

    assign_role_internal(
        db,
        target_user_id,
        role_id,
        Some(requester_id),
    )
    .await?;

    create_audit_log(
        db,
        Some(requester_id),
        "ASSIGN_ROLE",
        Some("USER_ROLE"),
        Some(target_user_id.to_string()),
        Some(&format!(
            "Assigned role {}",
            requested_role.name
        )),
        None,
    )
    .await?;

    Ok(())
}


// ============================================================
// INTERNAL ROLE ASSIGNMENT
// ============================================================

async fn assign_role_internal(
    db: &DatabaseConnection,
    target_user_id: i32,
    role_id: i32,
    assigned_by: Option<i32>,
) -> Result<(), String> {
    let now =
        Utc::now().naive_utc();

    let model =
        user_role::ActiveModel {
            user_id:
                Set(target_user_id),
            role_id:
                Set(role_id),
            assigned_by:
                Set(assigned_by),
            assigned_at:
                Set(now),
            ..Default::default()
        };

    model
        .insert(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to assign role: {}",
                e
            )
        })?;

    Ok(())
}


// ============================================================
// REVOKE ROLE
// ============================================================

pub async fn revoke_role(
    db: &DatabaseConnection,
    requester_id: i32,
    target_user_id: i32,
    role_id: i32,
) -> Result<(), String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    // --------------------------------------------------------
    // Never allow yourself to lose your last role accidentally.
    // --------------------------------------------------------

    if requester_id == target_user_id {
        let roles =
            user_role::Entity::find()
                .filter(
                    user_role::Column::UserId
                        .eq(target_user_id),
                )
                .all(db)
                .await
                .map_err(|e| e.to_string())?;

        if roles.len() <= 1 {
            return Err(
                "You cannot revoke your only role"
                    .to_string()
            );
        }
    }

    // --------------------------------------------------------
    // Protect the last SUPER_ADMIN
    // --------------------------------------------------------

    let target_is_super_admin =
        user_role::Entity::find()
            .filter(
                user_role::Column::UserId
                    .eq(target_user_id),
            )
            .filter(
                user_role::Column::RoleId
                    .eq(role_id),
            )
            .find_also_related(role::Entity)
            .all(db)
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .any(|(_, r)| {
                r.as_ref()
                    .map(|r| r.name == "SUPER_ADMIN")
                    .unwrap_or(false)
            });

    if target_is_super_admin {
        let super_admin_count =
            count_super_admins(db)
                .await?;

        if super_admin_count <= 1 {
            return Err(
                "The last SUPER_ADMIN role cannot be revoked"
                    .to_string()
            );
        }
    }

    user_role::Entity::delete_many()
        .filter(
            user_role::Column::UserId
                .eq(target_user_id),
        )
        .filter(
            user_role::Column::RoleId
                .eq(role_id),
        )
        .exec(db)
        .await
        .map_err(|e| {
            format!(
                "Failed to revoke role: {}",
                e
            )
        })?;

    create_audit_log(
        db,
        Some(requester_id),
        "REVOKE_ROLE",
        Some("USER_ROLE"),
        Some(target_user_id.to_string()),
        Some("Role revoked from user"),
        None,
    )
    .await?;

    Ok(())
}


// ============================================================
// REVOKE ALL SESSIONS
// ============================================================

pub async fn revoke_user_sessions(
    db: &DatabaseConnection,
    requester_id: i32,
    target_user_id: i32,
) -> Result<(), String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    revoke_all_user_sessions(
        db,
        target_user_id,
    )
    .await?;

    create_audit_log(
        db,
        Some(requester_id),
        "REVOKE_SESSIONS",
        Some("USER"),
        Some(target_user_id.to_string()),
        Some("All user sessions revoked"),
        None,
    )
    .await?;

    Ok(())
}


// ============================================================
// GET USERS
// ============================================================

pub async fn get_users(
    db: &DatabaseConnection,
    requester_id: i32,
) -> Result<Vec<UserInfo>, String> {
    require_super_admin(
        db,
        requester_id,
    )
    .await?;

    let users =
        user::Entity::find()
            .order_by_asc(
                user::Column::Username,
            )
            .all(db)
            .await
            .map_err(|e| {
                format!(
                    "Failed to load users: {}",
                    e
                )
            })?;

    let mut result =
        Vec::with_capacity(users.len());

    for user_model in users {
        result.push(
            build_user_info(
                db,
                &user_model,
            )
            .await?,
        );
    }

    Ok(result)
}


// ============================================================
// BUILD USER INFO
// ============================================================

pub async fn build_user_info(
    db: &DatabaseConnection,
    user_model: &user::Model,
) -> Result<UserInfo, String> {
    let roles =
        get_user_roles(
            db,
            user_model.id,
        )
        .await?;

    Ok(UserInfo {
        id: user_model.id,
        username: user_model.username.clone(),
        name: user_model.name.clone(),
        email: user_model.email.clone(),
        is_active: user_model.is_active,
        is_locked: user_model.is_locked,
        failed_login_attempts:
            user_model.failed_login_attempts,
        locked_until:
            user_model.locked_until
                .map(|v| v.to_string()),
        last_login_at:
            user_model.last_login_at
                .map(|v| v.to_string()),
        must_change_password:
            user_model.must_change_password,
        roles,
    })
}


// ============================================================
// CREATE AUDIT LOG
// ============================================================

pub async fn create_audit_log(
    db: &DatabaseConnection,
    user_id: Option<i32>,
    action: &str,
    entity_type: Option<&str>,
    entity_id: Option<String>,
    description: Option<&str>,
    device_id: Option<String>,
) -> Result<(), String> {
    let model =
        audit_log::ActiveModel {
            user_id:
                Set(user_id),
            action:
                Set(action.to_string()),
            entity_type:
                Set(
                    entity_type
                        .map(str::to_string)
                ),
            entity_id:
                Set(entity_id),
            description:
                Set(
                    description
                        .map(str::to_string)
                ),
            old_values:
                Set(None),
            new_values:
                Set(None),
            device_id:
                Set(device_id),
            created_at:
                Set(
                    Utc::now()
                        .naive_utc()
                ),
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


pub(crate) async fn ensure_default_roles(
    db: &DatabaseConnection,
) -> Result<(), AuthError> {
    let now = Utc::now().naive_utc();

    let default_roles = [
        ("SUPER_ADMIN", "Full access to the application"),
        ("ADMIN", "Manage users and application settings"),
        ("USER", "Standard application access"),
        ("AUDITOR", "Read-only access to audit information"),
    ];

    for (name, description) in default_roles {
        if let Some(existing_role) = role::Entity::find()
            .filter(role::Column::Name.eq(name))
            .one(db)
            .await?
        {
            if !existing_role.is_active {
                let mut active_role: role::ActiveModel = existing_role.into();

                active_role.is_active = Set(true);
                active_role.updated_at = Set(now);
                active_role.update(db).await?;
            }

            continue;
        }

        role::ActiveModel {
            name: Set(name.to_string()),
            description: Set(Some(description.to_string())),
            is_system: Set(true),
            is_active: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(db)
        .await?;
    }

    Ok(())
}