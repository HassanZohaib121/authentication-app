# Authentication App

A small desktop authentication and user-management app built with Tauri, Rust, Next.js, and SQLite. The frontend handles the screens and interaction, while the Rust side owns authentication, sessions, password hashing, role checks, and database access.

## What it does

- Creates the first account as `SUPER_ADMIN` during initial setup
- Signs users in and out with revocable database-backed sessions
- Stores passwords as Argon2 hashes rather than plain text
- Locks accounts after repeated failed login attempts
- Lets users update their profile and change their password
- Lets super admins create users and assign roles
- Records important authentication and account-management actions in an audit log
- Seeds the built-in roles `SUPER_ADMIN`, `ADMIN`, `USER`, and `AUDITOR`

## Requirements

Install the following before starting development:

- Node.js 20 or newer
- Rust and Cargo
- Tauri's Windows prerequisites, including WebView2
- Windows 10 or newer

The Rust toolchain version is documented in `src-tauri/Cargo.toml`.

## Run the app

Install the JavaScript dependencies:

```bash
npm install
```

Start the desktop application in development mode:

```bash
npm run tauri dev
```

Tauri starts the Next.js development server automatically using the configuration in `src-tauri/tauri.conf.json`. Running `npm run dev` alone is useful for working on the web UI, but Tauri commands such as login and setup require the desktop shell.

## First run

On a new database, open the signup screen and create the first account. That account receives the `SUPER_ADMIN` role. Once setup is complete, the signup route redirects to login and cannot be used to create another initial account.

After signing in, open **Settings** to update your profile or password. Super admins also get the user-management section for creating accounts and assigning roles.

## Roles

The app currently seeds these roles when the database starts:

| Role          | Purpose                                         |
| ------------- | ----------------------------------------------- |
| `SUPER_ADMIN` | Full access, including user and role management |
| `ADMIN`       | Reserved for broader administrative permissions |
| `USER`        | Standard application access                     |
| `AUDITOR`     | Intended for read-only audit access             |

Role checks are enforced in Rust commands as well as reflected in the dashboard UI. The UI should not be treated as the security boundary.

## Useful commands

```bash
# Run the desktop app
npm run tauri dev

# Run the frontend development server only
npm run dev

# Check the frontend
npm run lint
npx tsc --noEmit

# Build the desktop installer and bundles
npm run tauri build

# Check the Rust backend
cd src-tauri
cargo check
```

## Project layout

```text
src/                       Next.js pages and React components
src/components/auth/       Login and first-user setup forms
src/components/dashboard/  Dashboard shell, navigation, and settings
src-tauri/src/auth/        Rust commands, entities, sessions, passwords, and audit logic
src-tauri/src/connection.rs Database creation and default-role initialization
public/                    Static frontend assets
```

## Local data

The SQLite database is created as `auth.sqlite` inside the Tauri application data directory. The exact directory is platform-specific. The Rust startup code prints the resolved database path to the development console.

Deleting that database starts the application over with a fresh setup state. Do this only when you intentionally want to remove local users, sessions, and audit records.

## Notes for contributors

Authentication commands live in `src-tauri/src/auth/commands.rs`. Keep authorization checks in the Rust layer when adding new account or role operations. Frontend components should call those commands through Tauri's `invoke` API and should not implement their own password or permission logic.
