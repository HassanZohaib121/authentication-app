use argon2::{ password_hash::{ phc::PasswordHash, PasswordHasher, PasswordVerifier }, Argon2 };

// ==============================
// HASH PASSWORD
// ==============================

pub fn hash_password(password: &str) -> Result<String, String> {
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes()).map_err(|e| e.to_string())?;
    Ok(password_hash.to_string())
}

// ==============================
// VERIFY PASSWORD
// ==============================

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, String> {
    let parsed_hash = PasswordHash::new(password_hash).map_err(|e| e.to_string())?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}