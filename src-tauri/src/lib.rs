pub mod connection; 
pub mod auth;

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder
        ::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("Failed to resolve app data directory: {}", e))?;
            let db = tauri::async_runtime::block_on(connection::initialize_database(&data_dir))
                .map_err(|e| format!("Failed to initialize database: {}", e))?;

            app.manage(db);
            Ok(())
        })
        // =========================
        // LOG PLUGIN
        // =========================

        // .plugin(tauri_plugin_log::Builder::default().level(log::LevelFilter::Info).build())
        .invoke_handler(tauri::generate_handler![
            auth::commands::get_setup_status,
            auth::commands::setup_first_user,

            auth::commands::login,
            auth::commands::logout,
            auth::commands::current_user,
            auth::commands::update_profile,

            auth::commands::create_user,
            auth::commands::get_users,

            auth::commands::enable_user,
            auth::commands::disable_user,
            auth::commands::unlock_user,

            auth::commands::change_password,
            auth::commands::reset_user_password,

            auth::commands::assign_role,
            auth::commands::revoke_role,

            auth::commands::revoke_user_sessions,
        ])
        .setup(|app| {
            let show_i =
                MenuItem::with_id(
                    app,
                    "show",
                    "Show",
                    true,
                    None::<&str>,
                )?;

            let quit_i =
                MenuItem::with_id(
                    app,
                    "quit",
                    "Quit",
                    true,
                    None::<&str>,
                )?;

            let menu = Menu::with_items(
                app,
                &[&show_i, &quit_i],
            )?;

            let _tray = TrayIconBuilder::new()
                .icon(
                    app.default_window_icon()
                        .unwrap()
                        .clone(),
                )
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "show" => {
                            if let Some(window) =
                                app.get_webview_window("main")
                            {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }

                        "quit" => {
                            app.exit(0);
                        }

                        _ => {}
                    }
                })
                .build(app)?;

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
