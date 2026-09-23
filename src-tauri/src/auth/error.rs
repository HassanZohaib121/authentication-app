//! ============================================================
//! AUTHENTICATION ERRORS
//! ============================================================
//!
//! Central error type for the authentication subsystem.
//
//! Instead of having:
//
//!     Err("User not found".to_string())
//
//!     Err("Account locked".to_string())
//
//!     Err("Invalid password".to_string())
//
//! everywhere, authentication functions can return AuthError.
//
//! Tauri commands can finally convert AuthError into String.
//! ============================================================

use std::fmt;


// ============================================================
// AUTH ERROR
// ============================================================

#[derive(Debug, Clone)]
pub enum AuthError {
    // --------------------------------------------------------
    // Authentication
    // --------------------------------------------------------

    InvalidCredentials,

    AccountDisabled,

    AccountLocked,

    SessionInvalid,

    SessionExpired,

    SessionRevoked,

    // --------------------------------------------------------
    // Setup
    // --------------------------------------------------------

    SetupAlreadyCompleted,

    SetupNotInitialized,

    SuperAdminAlreadyExists,

    SuperAdminRoleMissing,

    // --------------------------------------------------------
    // User
    // --------------------------------------------------------

    UserNotFound,

    UsernameAlreadyExists,

    InvalidUsername,

    InvalidName,

    // --------------------------------------------------------
    // Password
    // --------------------------------------------------------

    PasswordRequired,

    PasswordTooShort,

    PasswordTooLong,

    PasswordMissingUppercase,

    PasswordMissingLowercase,

    PasswordMissingNumber,

    PasswordReuse,

    CurrentPasswordIncorrect,

    PasswordHashingFailed,

    PasswordVerificationFailed,

    // --------------------------------------------------------
    // Authorization
    // --------------------------------------------------------

    Unauthorized,

    Forbidden,

    NotSuperAdmin,

    CannotDisableSelf,

    CannotDisableLastSuperAdmin,

    CannotRemoveLastSuperAdmin,

    CannotRemoveOnlyRole,

    // --------------------------------------------------------
    // Role
    // --------------------------------------------------------

    RoleNotFound,

    RoleInactive,

    RoleAlreadyAssigned,

    RoleNotAssigned,

    // --------------------------------------------------------
    // Database / internal
    // --------------------------------------------------------

    Database(String),

    Internal(String),
}


// ============================================================
// DISPLAY
// ============================================================

impl fmt::Display for AuthError {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let message = match self {

            // ------------------------------------------------
            // Authentication
            // ------------------------------------------------

            Self::InvalidCredentials =>
                "Invalid username or password",

            Self::AccountDisabled =>
                "This account has been disabled",

            Self::AccountLocked =>
                "This account is temporarily locked",

            Self::SessionInvalid =>
                "Invalid session",

            Self::SessionExpired =>
                "Session has expired",

            Self::SessionRevoked =>
                "Session has been revoked",

            // ------------------------------------------------
            // Setup
            // ------------------------------------------------

            Self::SetupAlreadyCompleted =>
                "Initial setup has already been completed",

            Self::SetupNotInitialized =>
                "Application setup has not been initialized",

            Self::SuperAdminAlreadyExists =>
                "A SUPER_ADMIN account already exists",

            Self::SuperAdminRoleMissing =>
                "SUPER_ADMIN role is missing",

            // ------------------------------------------------
            // User
            // ------------------------------------------------

            Self::UserNotFound =>
                "User not found",

            Self::UsernameAlreadyExists =>
                "Username is already in use",

            Self::InvalidUsername =>
                "Invalid username",

            Self::InvalidName =>
                "Name is required",

            // ------------------------------------------------
            // Password
            // ------------------------------------------------

            Self::PasswordRequired =>
                "Password is required",

            Self::PasswordTooShort =>
                "Password must contain at least 8 characters",

            Self::PasswordTooLong =>
                "Password cannot exceed 128 characters",

            Self::PasswordMissingUppercase =>
                "Password must contain at least one uppercase letter",

            Self::PasswordMissingLowercase =>
                "Password must contain at least one lowercase letter",

            Self::PasswordMissingNumber =>
                "Password must contain at least one number",

            Self::PasswordReuse =>
                "You cannot reuse one of your recent passwords",

            Self::CurrentPasswordIncorrect =>
                "Current password is incorrect",

            Self::PasswordHashingFailed =>
                "Failed to securely hash password",

            Self::PasswordVerificationFailed =>
                "Failed to verify password",

            // ------------------------------------------------
            // Authorization
            // ------------------------------------------------

            Self::Unauthorized =>
                "Authentication is required",

            Self::Forbidden =>
                "You do not have permission to perform this action",

            Self::NotSuperAdmin =>
                "Only SUPER_ADMIN can perform this action",

            Self::CannotDisableSelf =>
                "You cannot disable your own account",

            Self::CannotDisableLastSuperAdmin =>
                "The last SUPER_ADMIN cannot be disabled",

            Self::CannotRemoveLastSuperAdmin =>
                "The last SUPER_ADMIN role cannot be revoked",

            Self::CannotRemoveOnlyRole =>
                "You cannot revoke your only role",

            // ------------------------------------------------
            // Role
            // ------------------------------------------------

            Self::RoleNotFound =>
                "Role not found",

            Self::RoleInactive =>
                "Role is inactive",

            Self::RoleAlreadyAssigned =>
                "Role is already assigned",

            Self::RoleNotAssigned =>
                "Role is not assigned",

            // ------------------------------------------------
            // Internal
            // ------------------------------------------------

            Self::Database(message) =>
                message,

            Self::Internal(message) =>
                message,
        };

        write!(f, "{}", message)
    }
}


// ============================================================
// ERROR TRAIT
// ============================================================

impl std::error::Error for AuthError {}


// ============================================================
// DATABASE ERROR CONVERSION
// ============================================================

impl From<sea_orm::DbErr> for AuthError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Database(
            error.to_string()
        )
    }
}


// ============================================================
// STRING CONVERSION
// ============================================================

impl From<AuthError> for String {
    fn from(error: AuthError) -> Self {
        error.to_string()
    }
}


// ============================================================
// RESULT TYPE ALIAS
// ============================================================

/// Convenient Result type for authentication operations.
///
/// Instead of:
///
///     Result<User, AuthError>
///
/// you can write:
///
///     AuthResult<User>
pub type AuthResult<T> = Result<T, AuthError>;