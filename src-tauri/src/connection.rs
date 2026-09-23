
use sea_orm::Database;
use std::fs;
use std::path::Path;

pub async fn initialize_database(data_dir: &Path) -> Result<sea_orm::DatabaseConnection, String> {
    fs::create_dir_all(data_dir)
        .map_err(|e| format!("Failed to create database directory {:?}: {}", data_dir, e))?;

    let db_path = data_dir.join("auth.sqlite");
    migrate_legacy_database(&db_path)?;

    println!("========================================");
    println!("Database location: {:?}", db_path);
    println!("========================================");

    // Convert Windows path to SQLite URL
    let database_url = format!(
        "sqlite://{}?mode=rwc",
        db_path.to_string_lossy().replace('\\', "/")
    );

    println!("Database URL: {}", database_url);

    // =========================================================
    // CONNECT DATABASE
    // =========================================================

    let db = Database::connect(&database_url).await.map_err(|e|
        format!("Failed to connect to database: {}", e)
    )?;

    // =========================================================
    // CREATE / SYNC SEAORM TABLES
    // =========================================================

    db
        .get_schema_registry("app_lib::*")
        .sync(&db).await
        .map_err(|e| format!("Failed to synchronize database schema: {}", e))?;

    crate::auth::service::ensure_default_roles(&db)
        .await
        .map_err(|e| format!("Failed to initialize default roles: {}", e))?;

    // =========================================================
    // SEED DEFAULT SETTINGS
    // =========================================================

    println!("Database initialized successfully!");

    Ok(db)
}

fn migrate_legacy_database(db_path: &Path) -> Result<(), String> {
    if db_path.exists() {
        return Ok(());
    }

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let Some(exe_dir) = exe_dir else {
        return Ok(());
    };
    let legacy_path = exe_dir.join("db.sqlite");

    if legacy_path.exists() && legacy_path != db_path {
        fs::copy(&legacy_path, db_path).map_err(|e| {
            format!(
                "Failed to migrate legacy database from {:?} to {:?}: {}",
                legacy_path, db_path, e
            )
        })?;
    }

    Ok(())
}
