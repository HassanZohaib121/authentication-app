use sea_orm::entity::prelude::*;

// ============================================================
// USER
// ============================================================

pub mod user {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,

        pub username: String,

        pub email: Option<String>,

        pub name: String,

        pub password_hash: String,

        pub password_changed_at: Option<DateTime>,

        pub is_active: bool,

        pub is_locked: bool,

        pub failed_login_attempts: i32,

        pub locked_until: Option<DateTime>,

        pub last_login_at: Option<DateTime>,

        pub last_login_device: Option<String>,

        pub must_change_password: bool,

        pub created_at: DateTime,

        pub updated_at: DateTime,

        pub created_by: Option<i32>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(has_many = "super::session::Entity")]
        Session,

        #[sea_orm(has_many = "super::login_attempt::Entity")]
        LoginAttempt,

        #[sea_orm(has_many = "super::password_history::Entity")]
        PasswordHistory,

        #[sea_orm(has_many = "super::user_role::Entity")]
        UserRole,

        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::CreatedBy",
            to = "Column::Id",
            on_delete = "SetNull"
        )]
        Creator,
    }

    impl Related<super::session::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Session.def()
        }
    }

    impl Related<super::login_attempt::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::LoginAttempt.def()
        }
    }

    impl Related<super::password_history::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::PasswordHistory.def()
        }
    }

    impl Related<super::user_role::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::UserRole.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// ============================================================
// ROLE
// ============================================================

pub mod role {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "roles")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,

        pub name: String,

        pub description: Option<String>,

        pub is_system: bool,

        pub is_active: bool,

        pub created_at: DateTime,

        pub updated_at: DateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(has_many = "super::user_role::Entity")]
        UserRole,
    }

    impl Related<super::user_role::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::UserRole.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// ============================================================
// USER ROLE
// ============================================================

pub mod user_role {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_roles")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,

        pub user_id: i32,

        pub role_id: i32,

        pub assigned_by: Option<i32>,

        pub assigned_at: DateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id",
            on_delete = "Cascade"
        )]
        User,

        #[sea_orm(
            belongs_to = "super::role::Entity",
            from = "Column::RoleId",
            to = "super::role::Column::Id",
            on_delete = "Cascade"
        )]
        Role,
    }

    impl Related<super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl Related<super::role::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::Role.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// ============================================================
// SESSION
// ============================================================

pub mod session {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,

        pub user_id: i32,

        pub token_hash: String,

        pub device_id: Option<String>,

        pub device_name: Option<String>,

        pub created_at: DateTime,

        pub expires_at: DateTime,

        pub last_activity_at: DateTime,

        pub revoked_at: Option<DateTime>,

        pub is_active: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id",
            on_delete = "Cascade"
        )]
        User,
    }

    impl Related<super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// ============================================================
// LOGIN ATTEMPTS
// ============================================================

pub mod login_attempt {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "login_attempts")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,

        pub user_id: Option<i32>,

        pub username: String,

        pub success: bool,

        pub failure_reason: Option<String>,

        pub device_id: Option<String>,

        pub attempted_at: DateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id",
            on_delete = "SetNull"
        )]
        User,
    }

    impl Related<super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// ============================================================
// PASSWORD HISTORY
// ============================================================

pub mod password_history {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "password_histories")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,

        pub user_id: i32,

        pub password_hash: String,

        pub created_at: DateTime,

        pub changed_by: Option<i32>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id",
            on_delete = "Cascade"
        )]
        User,
    }

    impl Related<super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// ============================================================
// AUDIT LOG
// ============================================================

pub mod audit_log {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "audit_logs")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,

        pub user_id: Option<i32>,

        pub action: String,

        pub entity_type: Option<String>,

        pub entity_id: Option<String>,

        pub description: Option<String>,

        pub old_values: Option<String>,

        pub new_values: Option<String>,

        pub device_id: Option<String>,

        pub created_at: DateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::UserId",
            to = "super::user::Column::Id",
            on_delete = "SetNull"
        )]
        User,
    }

    impl Related<super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// ============================================================
// APPLICATION SETTINGS
// ============================================================

pub mod app_setting {
    use super::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "app_settings")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,

        pub setup_completed: bool,

        pub setup_completed_at: Option<DateTime>,

        pub setup_completed_by: Option<i32>,

        pub app_name: Option<String>,

        pub app_version: Option<String>,

        pub created_at: DateTime,

        pub updated_at: DateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::user::Entity",
            from = "Column::SetupCompletedBy",
            to = "super::user::Column::Id",
            on_delete = "SetNull"
        )]
        SetupCompletedBy,
    }

    impl Related<super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::SetupCompletedBy.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// ============================================================
// PRELUDE
// ============================================================

pub mod prelude {
    pub use super::app_setting::Entity as AppSetting;
    pub use super::audit_log::Entity as AuditLog;
    pub use super::login_attempt::Entity as LoginAttempt;
    pub use super::password_history::Entity as PasswordHistory;
    pub use super::role::Entity as Role;
    pub use super::session::Entity as Session;
    pub use super::user::Entity as User;
    pub use super::user_role::Entity as UserRole;
}