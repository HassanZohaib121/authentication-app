use chrono::{Duration, Utc};
use rand::{distr::Alphanumeric, Rng};
use sea_orm::{
    ActiveModelTrait,
    ColumnTrait,
    DatabaseConnection,
    EntityTrait,
    QueryFilter,
    Set,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::entity::{
    app_setting,
    audit_log,
    login_attempt,
    password_history,
    role,
    session,
    user,
    user_role,
};

use super::password::{
    hash_password,
    verify_password,
};



// ============================================================
// CONSTANTS
// ============================================================

const MAX_LOGIN_ATTEMPTS: i32 = 5;
const LOCK_MINUTES: i64 = 15;
const SESSION_DAYS: i64 = 30;


// ============================================================
// DTOs
// ============================================================

#[derive(Debug, Serialize)]
pub struct AuthUser {
    pub id: i32,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
}


#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub session_token: Option<String>,
    pub user: Option<AuthUser>,
}


#[derive(Debug, Serialize)]
pub struct SetupStatus {
    pub setup_completed: bool,
    pub has_users: bool,
}


#[derive(Debug, Serialize)]
pub struct UserResponse {
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


#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub name: String,
    pub username: String,
    pub email: Option<String>,
    pub password: String,
}


#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
}


#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password: String,
    pub role: String,
}


#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub session_token: String,
    pub current_password: String,
    pub new_password: String,
}


#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub session_token: String,
    pub name: String,
    pub email: Option<String>,
}


#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub session_token: String,
    pub user_id: i32,
    pub new_password: String,
}


#[derive(Debug, Deserialize)]
pub struct UserActionRequest {
    pub session_token: String,
    pub user_id: i32,
}


#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub session_token: String,
    pub user_id: i32,
    pub role: String,
}


// ============================================================
// HELPERS
// ============================================================

fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
}


fn validate_username(username: &str) -> Result<(), String> {
    let username = username.trim();

    if username.len() < 3 {
        return Err("Username must contain at least 3 characters.".into());
    }

    if username.len() > 50 {
        return Err("Username cannot exceed 50 characters.".into());
    }

    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(
            "Username may only contain letters, numbers, _, ., and -.".into()
        );
    }

    Ok(())
}


fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must contain at least 8 characters.".into());
    }

    if password.len() > 128 {
        return Err("Password cannot exceed 128 characters.".into());
    }

    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("Password must contain at least one uppercase letter.".into());
    }

    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err("Password must contain at least one lowercase letter.".into());
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one number.".into());
    }

    Ok(())
}


fn generate_session_token() -> String {
    let random: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    format!("{}.{}", Uuid::new_v4(), random)
}


fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();

    hasher.update(token.as_bytes());

    hex::encode(hasher.finalize())
}


async fn get_user_roles(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<Vec<String>, String> {
    let rows = user_role::Entity::find()
        .filter(user_role::Column::UserId.eq(user_id))
        .find_also_related(role::Entity)
        .all(db)
        .await
        .map_err(|e| e.to_string())?;

    Ok(rows
        .into_iter()
        .filter_map(|(_, role)| role.map(|r| r.name))
        .collect())
}


async fn get_auth_user(
    db: &DatabaseConnection,
    model: user::Model,
) -> Result<AuthUser, String> {
    let roles = get_user_roles(db, model.id).await?;

    Ok(AuthUser {
        id: model.id,
        username: model.username,
        name: model.name,
        email: model.email,
        roles,
    })
}


// ============================================================
// SESSION AUTHENTICATION
// ============================================================

async fn get_session_user(
    db: &DatabaseConnection,
    token: &str,
) -> Result<user::Model, String> {
    if token.trim().is_empty() {
        return Err("Authentication required.".into());
    }

    let token_hash = hash_session_token(token);

    let session_model = session::Entity::find()
        .filter(session::Column::TokenHash.eq(token_hash))
        .filter(session::Column::IsActive.eq(true))
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid or expired session.".to_string())?;

    let now = Utc::now().naive_utc();

    if session_model.expires_at <= now {
        let mut active: session::ActiveModel = session_model.into();

        active.is_active = Set(false);

        active.update(db)
            .await
            .map_err(|e| e.to_string())?;

        return Err("Session has expired.".into());
    }

    let user_model = user::Entity::find_by_id(session_model.user_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "User account no longer exists.".to_string())?;

    if !user_model.is_active {
        return Err("User account is disabled.".into());
    }

    if user_model.is_locked {
        if let Some(until) = user_model.locked_until {
            if until > now {
                return Err("User account is locked.".into());
            }
        }
    }

    // Refresh session activity.
    let mut active_session: session::ActiveModel = session_model.into();

    active_session.last_activity_at = Set(now);

    active_session
        .update(db)
        .await
        .map_err(|e| e.to_string())?;

    Ok(user_model)
}


// ============================================================
// CHECK INITIAL SETUP
// ============================================================

#[tauri::command]
pub async fn get_setup_status(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
) -> Result<SetupStatus, String> {
    let db: &DatabaseConnection = db.inner();

    let settings = app_setting::Entity::find_by_id(1)
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    let user_exists = user::Entity::find()
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .is_some();

    Ok(SetupStatus {
        setup_completed: settings
            .map(|s| s.setup_completed)
            .unwrap_or(false),

        has_users: user_exists,
    })
}


// ============================================================
// FIRST-TIME SETUP
// ============================================================

#[tauri::command]
pub async fn setup_first_user(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: SetupRequest,
) -> Result<AuthUser, String> {
    let db: &DatabaseConnection = db.inner();

    let username = normalize_username(&request.username);

    validate_username(&username)?;
    validate_password(&request.password)?;

    if request.name.trim().is_empty() {
        return Err("Name is required.".into());
    }

    // --------------------------------------------------------
    // Check whether setup has already completed.
    // --------------------------------------------------------

    let settings = app_setting::Entity::find_by_id(1)
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(settings) = settings {
        if settings.setup_completed {
            return Err(
                "Initial setup has already been completed.".into()
            );
        }
    }

    // --------------------------------------------------------
    // Extra protection: never allow a second initial account.
    // --------------------------------------------------------

    let existing_user = user::Entity::find()
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    if existing_user.is_some() {
        return Err(
            "A user already exists. Initial setup is no longer available."
                .into(),
        );
    }

    let txn = db
        .begin()
        .await
        .map_err(|e| e.to_string())?;

    // --------------------------------------------------------
    // Make absolutely sure username isn't already used.
    // --------------------------------------------------------

    let username_exists = user::Entity::find()
        .filter(user::Column::Username.eq(username.clone()))
        .one(&txn)
        .await
        .map_err(|e| e.to_string())?;

    if username_exists.is_some() {
        return Err("Username already exists.".into());
    }

    // --------------------------------------------------------
    // Hash password.
    // --------------------------------------------------------

    let password_hash = hash_password(&request.password)
        .map_err(|e| e.to_string())?;

    let now = Utc::now().naive_utc();

    // --------------------------------------------------------
    // Create first user.
    // --------------------------------------------------------

    let new_user = user::ActiveModel {
        username: Set(username),
        email: Set(request.email),
        name: Set(request.name.trim().to_string()),
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
        .map_err(|e| e.to_string())?;

    // --------------------------------------------------------
    // Find SUPER_ADMIN role.
    // --------------------------------------------------------

    let super_admin = role::Entity::find()
        .filter(role::Column::Name.eq("SUPER_ADMIN"))
        .one(&txn)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            "SUPER_ADMIN role has not been initialized.".to_string()
        })?;

    // --------------------------------------------------------
    // Assign SUPER_ADMIN.
    // --------------------------------------------------------

    user_role::ActiveModel {
        user_id: Set(new_user.id),
        role_id: Set(super_admin.id),
        assigned_by: Set(None),
        assigned_at: Set(now),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| e.to_string())?;

    // --------------------------------------------------------
    // Save password history.
    // --------------------------------------------------------

    password_history::ActiveModel {
        user_id: Set(new_user.id),
        password_hash: Set(password_hash),
        created_at: Set(now),
        changed_by: Set(None),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| e.to_string())?;

    // --------------------------------------------------------
    // Mark setup completed.
    // --------------------------------------------------------

    let settings = app_setting::Entity::find_by_id(1)
        .one(&txn)
        .await
        .map_err(|e| e.to_string())?;

    match settings {
        Some(settings) => {
            let mut active: app_setting::ActiveModel = settings.into();

            active.setup_completed = Set(true);
            active.setup_completed_at = Set(Some(now));
            active.setup_completed_by = Set(Some(new_user.id));
            active.updated_at = Set(now);

            active
                .update(&txn)
                .await
                .map_err(|e| e.to_string())?;
        }

        None => {
            app_setting::ActiveModel {
                id: Set(1),
                setup_completed: Set(true),
                setup_completed_at: Set(Some(now)),
                setup_completed_by: Set(Some(new_user.id)),
                app_name: Set(None),
                app_version: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            }
            .insert(&txn)
            .await
            .map_err(|e| e.to_string())?;
        }
    }

    // --------------------------------------------------------
    // Audit.
    // --------------------------------------------------------

    audit_log::ActiveModel {
        user_id: Set(Some(new_user.id)),
        action: Set("INITIAL_SETUP".to_string()),
        entity_type: Set(Some("USER".to_string())),
        entity_id: Set(Some(new_user.id.to_string())),
        description: Set(Some(
            "Initial SUPER_ADMIN account created.".to_string()
        )),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| e.to_string())?;

    txn.commit()
        .await
        .map_err(|e| e.to_string())?;

    get_auth_user(db, new_user).await
}


// ============================================================
// LOGIN
// ============================================================

#[tauri::command]
pub async fn login(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: LoginRequest,
) -> Result<LoginResponse, String> {
    let db: &DatabaseConnection = db.inner();

    let username = normalize_username(&request.username);

    if username.is_empty() || request.password.is_empty() {
        return Err("Username and password are required.".into());
    }

    let user_model = user::Entity::find()
        .filter(user::Column::Username.eq(username.clone()))
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    // --------------------------------------------------------
    // Don't reveal whether username exists.
    // --------------------------------------------------------

    let Some(user_model) = user_model else {
        record_login_attempt(
            db,
            None,
            username,
            false,
            Some("INVALID_CREDENTIALS".into()),
            request.device_id.clone(),
        )
        .await?;

        return Err("Invalid username or password.".into());
    };

    let now = Utc::now().naive_utc();

    // --------------------------------------------------------
    // Account disabled.
    // --------------------------------------------------------

    if !user_model.is_active {
        record_login_attempt(
            db,
            Some(user_model.id),
            username,
            false,
            Some("ACCOUNT_DISABLED".into()),
            request.device_id.clone(),
        )
        .await?;

        return Err("This account is disabled.".into());
    }

    // --------------------------------------------------------
    // Check lockout.
    // --------------------------------------------------------

    if user_model.is_locked {
        if let Some(until) = user_model.locked_until {
            if until > now {
                record_login_attempt(
                    db,
                    Some(user_model.id),
                    username,
                    false,
                    Some("ACCOUNT_LOCKED".into()),
                    request.device_id.clone(),
                )
                .await?;

                return Err(
                    "Account temporarily locked. Please try again later."
                        .into(),
                );
            }
        }

        // Lock expired.
        let mut active: user::ActiveModel = user_model.clone().into();

        active.is_locked = Set(false);
        active.locked_until = Set(None);
        active.failed_login_attempts = Set(0);
        active.updated_at = Set(now);

        active
            .update(db)
            .await
            .map_err(|e| e.to_string())?;
    }

    // --------------------------------------------------------
    // Verify password.
    // --------------------------------------------------------

    let valid = verify_password(
        &request.password,
        &user_model.password_hash,
    )
    .map_err(|e| e.to_string())?;

    if !valid {
        handle_failed_login(
            db,
            &user_model,
            request.device_id.clone(),
        )
        .await?;

        return Err("Invalid username or password.".into());
    }

    // --------------------------------------------------------
    // Successful login.
    // --------------------------------------------------------

    let token = generate_session_token();
    let token_hash = hash_session_token(&token);

    let expires_at = now + Duration::days(SESSION_DAYS);

    let mut active_user: user::ActiveModel = user_model.clone().into();

    active_user.failed_login_attempts = Set(0);
    active_user.is_locked = Set(false);
    active_user.locked_until = Set(None);
    active_user.last_login_at = Set(Some(now));
    active_user.last_login_device =
        Set(request.device_name.clone());
    active_user.updated_at = Set(now);

    let updated_user = active_user
        .update(db)
        .await
        .map_err(|e| e.to_string())?;

    // --------------------------------------------------------
    // Create session.
    // --------------------------------------------------------

    session::ActiveModel {
        user_id: Set(updated_user.id),
        token_hash: Set(token_hash),
        device_id: Set(request.device_id.clone()),
        device_name: Set(request.device_name.clone()),
        created_at: Set(now),
        expires_at: Set(expires_at),
        last_activity_at: Set(now),
        revoked_at: Set(None),
        is_active: Set(true),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    // --------------------------------------------------------
    // Audit.
    // --------------------------------------------------------

    audit_log::ActiveModel {
        user_id: Set(Some(updated_user.id)),
        action: Set("LOGIN".to_string()),
        entity_type: Set(Some("USER".to_string())),
        entity_id: Set(Some(updated_user.id.to_string())),
        description: Set(Some("User logged in.".to_string())),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(request.device_id.clone()),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    record_login_attempt(
        db,
        Some(updated_user.id),
        updated_user.username.clone(),
        true,
        None,
        request.device_id,
    )
    .await?;

    let auth_user = get_auth_user(db, updated_user).await?;

    Ok(LoginResponse {
        success: true,
        message: "Login successful.".into(),
        session_token: Some(token),
        user: Some(auth_user),
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

    let new_attempts = user_model.failed_login_attempts + 1;

    let mut active: user::ActiveModel = user_model.clone().into();

    active.failed_login_attempts = Set(new_attempts);
    active.updated_at = Set(now);

    if new_attempts >= MAX_LOGIN_ATTEMPTS {
        active.is_locked = Set(true);

        active.locked_until =
            Set(Some(now + Duration::minutes(LOCK_MINUTES)));
    }

    active
        .update(db)
        .await
        .map_err(|e| e.to_string())?;

    record_login_attempt(
        db,
        Some(user_model.id),
        user_model.username.clone(),
        false,
        Some("INVALID_CREDENTIALS".into()),
        device_id,
    )
    .await?;

    Ok(())
}


// ============================================================
// RECORD LOGIN ATTEMPT
// ============================================================

async fn record_login_attempt(
    db: &DatabaseConnection,
    user_id: Option<i32>,
    username: String,
    success: bool,
    failure_reason: Option<String>,
    device_id: Option<String>,
) -> Result<(), String> {
    login_attempt::ActiveModel {
        user_id: Set(user_id),
        username: Set(username),
        success: Set(success),
        failure_reason: Set(failure_reason),
        device_id: Set(device_id),
        attempted_at: Set(Utc::now().naive_utc()),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}


// ============================================================
// LOGOUT
// ============================================================

#[tauri::command]
pub async fn logout(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    session_token: String,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();

    let token_hash = hash_session_token(&session_token);

    let session_model = session::Entity::find()
        .filter(session::Column::TokenHash.eq(token_hash))
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    let Some(session_model) = session_model else {
        return Ok(());
    };

    let now = Utc::now().naive_utc();

    let user_id = session_model.user_id;

    let mut active: session::ActiveModel = session_model.into();

    active.is_active = Set(false);
    active.revoked_at = Set(Some(now));

    active
        .update(db)
        .await
        .map_err(|e| e.to_string())?;

    audit_log::ActiveModel {
        user_id: Set(Some(user_id)),
        action: Set("LOGOUT".to_string()),
        entity_type: Set(Some("SESSION".to_string())),
        entity_id: Set(None),
        description: Set(Some("User logged out.".into())),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}


// ============================================================
// CURRENT USER
// ============================================================

#[tauri::command]
pub async fn current_user(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    session_token: String,
) -> Result<AuthUser, String> {
    let db: &DatabaseConnection = db.inner();

    let user_model =
        get_session_user(db, &session_token).await?;

    get_auth_user(db, user_model).await
}


// ============================================================
// UPDATE OWN PROFILE
// ============================================================

#[tauri::command]
pub async fn update_profile(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: UpdateProfileRequest,
) -> Result<AuthUser, String> {
    let db: &DatabaseConnection = db.inner();
    let current_user = get_session_user(db, &request.session_token).await?;

    if request.name.trim().is_empty() {
        return Err("Name is required.".into());
    }

    let now = Utc::now().naive_utc();
    let mut active: user::ActiveModel = current_user.clone().into();

    active.name = Set(request.name.trim().to_string());
    active.email = Set(request
        .email
        .map(|email| email.trim().to_string())
        .filter(|email| !email.is_empty()));
    active.updated_at = Set(now);

    let updated_user = active.update(db).await.map_err(|e| e.to_string())?;

    audit_log::ActiveModel {
        user_id: Set(Some(updated_user.id)),
        action: Set("UPDATE_PROFILE".into()),
        entity_type: Set(Some("USER".into())),
        entity_id: Set(Some(updated_user.id.to_string())),
        description: Set(Some("User profile updated.".into())),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    get_auth_user(db, updated_user).await
}


// ============================================================
// CREATE USER
// ============================================================

#[tauri::command]
pub async fn create_user(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    session_token: String,
    request: CreateUserRequest,
) -> Result<UserResponse, String> {
    let db: &DatabaseConnection = db.inner();

    let creator =
        get_session_user(db, &session_token).await?;

    require_super_admin(db, creator.id).await?;

    let username = normalize_username(&request.username);

    validate_username(&username)?;
    validate_password(&request.password)?;

    if request.name.trim().is_empty() {
        return Err("Name is required.".into());
    }

    let role_name = request.role.trim().to_uppercase();

    let role_model = role::Entity::find()
        .filter(role::Column::Name.eq(role_name.clone()))
        .filter(role::Column::IsActive.eq(true))
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Requested role does not exist.".to_string())?;

    let exists = user::Entity::find()
        .filter(user::Column::Username.eq(username.clone()))
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    if exists.is_some() {
        return Err("Username already exists.".into());
    }

    let password_hash =
        hash_password(&request.password)
            .map_err(|e| e.to_string())?;

    let now = Utc::now().naive_utc();

    let txn = db
        .begin()
        .await
        .map_err(|e| e.to_string())?;

    let new_user = user::ActiveModel {
        username: Set(username),
        email: Set(request.email),
        name: Set(request.name.trim().to_string()),
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
        created_by: Set(Some(creator.id)),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| e.to_string())?;

    user_role::ActiveModel {
        user_id: Set(new_user.id),
        role_id: Set(role_model.id),
        assigned_by: Set(Some(creator.id)),
        assigned_at: Set(now),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| e.to_string())?;

    password_history::ActiveModel {
        user_id: Set(new_user.id),
        password_hash: Set(password_hash),
        created_at: Set(now),
        changed_by: Set(Some(creator.id)),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| e.to_string())?;

    audit_log::ActiveModel {
        user_id: Set(Some(creator.id)),
        action: Set("CREATE_USER".into()),
        entity_type: Set(Some("USER".into())),
        entity_id: Set(Some(new_user.id.to_string())),
        description: Set(Some(format!(
            "Created user '{}' with role '{}'.",
            new_user.username,
            role_model.name
        ))),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(&txn)
    .await
    .map_err(|e| e.to_string())?;

    txn.commit()
        .await
        .map_err(|e| e.to_string())?;

    build_user_response(db, new_user).await
}


// ============================================================
// LIST USERS
// ============================================================

#[tauri::command]
pub async fn get_users(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    session_token: String,
) -> Result<Vec<UserResponse>, String> {
    let db: &DatabaseConnection = db.inner();

    let requester =
        get_session_user(db, &session_token).await?;

    require_super_admin(db, requester.id).await?;

    let users = user::Entity::find()
        .all(db)
        .await
        .map_err(|e| e.to_string())?;

    let mut result = Vec::with_capacity(users.len());

    for model in users {
        result.push(build_user_response(db, model).await?);
    }

    Ok(result)
}


// ============================================================
// ENABLE USER
// ============================================================

#[tauri::command]
pub async fn enable_user(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: UserActionRequest,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();
    set_user_active(
        db,
        &request.session_token,
        request.user_id,
        true,
    )
    .await
}


// ============================================================
// DISABLE USER
// ============================================================

#[tauri::command]
pub async fn disable_user(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: UserActionRequest,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();
    set_user_active(
        db,
        &request.session_token,
        request.user_id,
        false,
    )
    .await
}


// ============================================================
// ENABLE / DISABLE
// ============================================================

async fn set_user_active(
    db: &DatabaseConnection,
    session_token: &str,
    user_id: i32,
    active_state: bool,
) -> Result<(), String> {
    let requester =
        get_session_user(db, session_token).await?;

    require_super_admin(db, requester.id).await?;

    // Super Admin cannot disable himself.
    if requester.id == user_id && !active_state {
        return Err(
            "You cannot disable your own account.".into()
        );
    }

    let target = user::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "User not found.".to_string())?;

    let now = Utc::now().naive_utc();

    let mut active: user::ActiveModel = target.into();

    active.is_active = Set(active_state);
    active.updated_at = Set(now);

    active
        .update(db)
        .await
        .map_err(|e| e.to_string())?;

    audit_log::ActiveModel {
        user_id: Set(Some(requester.id)),
        action: Set(if active_state {
            "ENABLE_USER".into()
        } else {
            "DISABLE_USER".into()
        }),
        entity_type: Set(Some("USER".into())),
        entity_id: Set(Some(user_id.to_string())),
        description: Set(None),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}


// ============================================================
// UNLOCK USER
// ============================================================

#[tauri::command]
pub async fn unlock_user(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: UserActionRequest,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();

    let requester =
        get_session_user(db, &request.session_token).await?;

    require_super_admin(db, requester.id).await?;

    let target = user::Entity::find_by_id(request.user_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "User not found.".to_string())?;

    let now = Utc::now().naive_utc();

    let mut active: user::ActiveModel = target.into();

    active.is_locked = Set(false);
    active.locked_until = Set(None);
    active.failed_login_attempts = Set(0);
    active.updated_at = Set(now);

    active
        .update(db)
        .await
        .map_err(|e| e.to_string())?;

    audit_log::ActiveModel {
        user_id: Set(Some(requester.id)),
        action: Set("UNLOCK_USER".into()),
        entity_type: Set(Some("USER".into())),
        entity_id: Set(Some(request.user_id.to_string())),
        description: Set(Some("User account unlocked.".into())),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}


// ============================================================
// CHANGE OWN PASSWORD
// ============================================================

#[tauri::command]
pub async fn change_password(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: ChangePasswordRequest,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();

    let current_user =
        get_session_user(db, &request.session_token).await?;

    validate_password(&request.new_password)?;

    let valid =
        verify_password(
            &request.current_password,
            &current_user.password_hash,
        )
        .map_err(|e| e.to_string())?;

    if !valid {
        return Err("Current password is incorrect.".into());
    }

    if request.current_password == request.new_password {
        return Err(
            "New password must be different from current password."
                .into(),
        );
    }

    change_user_password(
        db,
        current_user.id,
        &request.new_password,
        Some(current_user.id),
    )
    .await?;

    Ok(())
}


// ============================================================
// SUPER ADMIN RESET PASSWORD
// ============================================================

#[tauri::command]
pub async fn reset_user_password(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: ResetPasswordRequest,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();

    let requester =
        get_session_user(db, &request.session_token).await?;

    require_super_admin(db, requester.id).await?;

    validate_password(&request.new_password)?;

    change_user_password(
        db,
        request.user_id,
        &request.new_password,
        Some(requester.id),
    )
    .await?;

    Ok(())
}


// ============================================================
// PASSWORD UPDATE INTERNAL
// ============================================================

async fn change_user_password(
    db: &DatabaseConnection,
    user_id: i32,
    new_password: &str,
    changed_by: Option<i32>,
) -> Result<(), String> {
    let target = user::Entity::find_by_id(user_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "User not found.".to_string())?;

    let new_hash =
        hash_password(new_password)
            .map_err(|e| e.to_string())?;

    // Don't allow same password.
    if verify_password(new_password, &target.password_hash)
        .map_err(|e| e.to_string())?
    {
        return Err(
            "New password must be different from the current password."
                .into(),
        );
    }

    let now = Utc::now().naive_utc();

    let mut active: user::ActiveModel = target.into();

    active.password_hash = Set(new_hash.clone());
    active.password_changed_at = Set(Some(now));
    active.must_change_password = Set(false);
    active.updated_at = Set(now);

    active
        .update(db)
        .await
        .map_err(|e| e.to_string())?;

    password_history::ActiveModel {
        user_id: Set(user_id),
        password_hash: Set(new_hash),
        created_at: Set(now),
        changed_by: Set(changed_by),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    // Revoke all existing sessions after password change.
    let sessions = session::Entity::find()
        .filter(session::Column::UserId.eq(user_id))
        .filter(session::Column::IsActive.eq(true))
        .all(db)
        .await
        .map_err(|e| e.to_string())?;

    for item in sessions {
        let mut active_session: session::ActiveModel =
            item.into();

        active_session.is_active = Set(false);
        active_session.revoked_at = Set(Some(now));

        active_session
            .update(db)
            .await
            .map_err(|e| e.to_string())?;
    }

    audit_log::ActiveModel {
        user_id: Set(changed_by),
        action: Set("CHANGE_PASSWORD".into()),
        entity_type: Set(Some("USER".into())),
        entity_id: Set(Some(user_id.to_string())),
        description: Set(Some("Password changed.".into())),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}


// ============================================================
// ASSIGN ROLE
// ============================================================

#[tauri::command]
pub async fn assign_role(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: AssignRoleRequest,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();

    let requester =
        get_session_user(db, &request.session_token).await?;

    require_super_admin(db, requester.id).await?;

    let role_name = request.role.trim().to_uppercase();

    let role_model = role::Entity::find()
        .filter(role::Column::Name.eq(role_name.clone()))
        .filter(role::Column::IsActive.eq(true))
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Role not found.".to_string())?;

    let target = user::Entity::find_by_id(request.user_id)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "User not found.".to_string())?;

    // Prevent removing the only SUPER_ADMIN later.
    if role_name != "SUPER_ADMIN" {
        let current_roles =
            get_user_roles(db, target.id).await?;

        if current_roles
            .iter()
            .any(|r| r == "SUPER_ADMIN")
        {
            let count = count_super_admins(db).await?;

            if count <= 1 {
                return Err(
                    "The system must always have at least one SUPER_ADMIN."
                        .into(),
                );
            }
        }
    }

    let existing = user_role::Entity::find()
        .filter(user_role::Column::UserId.eq(request.user_id))
        .filter(user_role::Column::RoleId.eq(role_model.id))
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    if existing.is_some() {
        return Ok(());
    }

    let now = Utc::now().naive_utc();

    user_role::ActiveModel {
        user_id: Set(request.user_id),
        role_id: Set(role_model.id),
        assigned_by: Set(Some(requester.id)),
        assigned_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    audit_log::ActiveModel {
        user_id: Set(Some(requester.id)),
        action: Set("ASSIGN_ROLE".into()),
        entity_type: Set(Some("USER_ROLE".into())),
        entity_id: Set(Some(request.user_id.to_string())),
        description: Set(Some(format!(
            "Assigned role '{}' to user.",
            role_model.name
        ))),
        old_values: Set(None),
        new_values: Set(Some(role_model.name)),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}


// ============================================================
// REVOKE ROLE
// ============================================================

#[tauri::command]
pub async fn revoke_role(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: AssignRoleRequest,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();

    let requester =
        get_session_user(db, &request.session_token).await?;

    require_super_admin(db, requester.id).await?;

    let role_name = request.role.trim().to_uppercase();

    let role_model = role::Entity::find()
        .filter(role::Column::Name.eq(role_name.clone()))
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Role not found.".to_string())?;

    // Prevent removing the final SUPER_ADMIN.
    if role_name == "SUPER_ADMIN" {
        let count = count_super_admins(db).await?;

        if count <= 1 {
            return Err(
                "The last SUPER_ADMIN cannot be removed.".into()
            );
        }
    }

    let assignment = user_role::Entity::find()
        .filter(user_role::Column::UserId.eq(request.user_id))
        .filter(user_role::Column::RoleId.eq(role_model.id))
        .one(db)
        .await
        .map_err(|e| e.to_string())?;

    let Some(assignment) = assignment else {
        return Ok(());
    };

    user_role::Entity::delete_by_id(assignment.id)
        .exec(db)
        .await
        .map_err(|e| e.to_string())?;

    let now = Utc::now().naive_utc();

    audit_log::ActiveModel {
        user_id: Set(Some(requester.id)),
        action: Set("REVOKE_ROLE".into()),
        entity_type: Set(Some("USER_ROLE".into())),
        entity_id: Set(Some(request.user_id.to_string())),
        description: Set(Some(format!(
            "Revoked role '{}' from user.",
            role_model.name
        ))),
        old_values: Set(Some(role_model.name)),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}


// ============================================================
// REVOKE ALL USER SESSIONS
// ============================================================

#[tauri::command]
pub async fn revoke_user_sessions(
    db: tauri::State<'_, sea_orm::DatabaseConnection>,
    request: UserActionRequest,
) -> Result<(), String> {
    let db: &DatabaseConnection = db.inner();

    let requester =
        get_session_user(db, &request.session_token).await?;

    require_super_admin(db, requester.id).await?;

    let now = Utc::now().naive_utc();

    let sessions = session::Entity::find()
        .filter(session::Column::UserId.eq(request.user_id))
        .filter(session::Column::IsActive.eq(true))
        .all(db)
        .await
        .map_err(|e| e.to_string())?;

    for item in sessions {
        let mut active: session::ActiveModel = item.into();

        active.is_active = Set(false);
        active.revoked_at = Set(Some(now));

        active
            .update(db)
            .await
            .map_err(|e| e.to_string())?;
    }

    audit_log::ActiveModel {
        user_id: Set(Some(requester.id)),
        action: Set("REVOKE_SESSIONS".into()),
        entity_type: Set(Some("USER".into())),
        entity_id: Set(Some(request.user_id.to_string())),
        description: Set(Some(
            "All user sessions were revoked.".into()
        )),
        old_values: Set(None),
        new_values: Set(None),
        device_id: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}


// ============================================================
// SUPER ADMIN CHECK
// ============================================================

async fn require_super_admin(
    db: &DatabaseConnection,
    user_id: i32,
) -> Result<(), String> {
    let roles = get_user_roles(db, user_id).await?;

    if !roles.iter().any(|r| r == "SUPER_ADMIN") {
        return Err(
            "Only SUPER_ADMIN can perform this operation.".into()
        );
    }

    Ok(())
}


// ============================================================
// COUNT SUPER ADMINS
// ============================================================

async fn count_super_admins(
    db: &DatabaseConnection,
) -> Result<i64, String> {
    use sea_orm::PaginatorTrait;

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
// BUILD USER RESPONSE
// ============================================================

async fn build_user_response(
    db: &DatabaseConnection,
    model: user::Model,
) -> Result<UserResponse, String> {
    let roles = get_user_roles(db, model.id).await?;

    Ok(UserResponse {
        id: model.id,
        username: model.username,
        name: model.name,
        email: model.email,
        is_active: model.is_active,
        is_locked: model.is_locked,
        failed_login_attempts: model.failed_login_attempts,
        locked_until: model.locked_until.map(|x| x.to_string()),
        last_login_at: model.last_login_at.map(|x| x.to_string()),
        must_change_password: model.must_change_password,
        roles,
    })
}