"use client";

import { FormEvent, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type AuthUser = {
  id: number;
  username: string;
  name: string;
  email: string | null;
  roles: string[];
};

type User = AuthUser & {
  is_active: boolean;
};

const availableRoles = ["SUPER_ADMIN", "ADMIN", "USER", "AUDITOR"];

function getSessionToken() {
  return localStorage.getItem("auth.session") ?? "";
}

export default function SettingsPage() {
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [profileName, setProfileName] = useState("");
  const [profileEmail, setProfileEmail] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPasswordForUser, setNewPasswordForUser] = useState("");
  const [newRole, setNewRole] = useState(availableRoles[0]);
  const [roleToAssign, setRoleToAssign] = useState(availableRoles[0]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const isSuperAdmin = currentUser?.roles.includes("SUPER_ADMIN") ?? false;

  async function loadUsers() {
    const sessionToken = getSessionToken();
    const loadedUsers = await invoke<User[]>("get_users", { sessionToken });
    setUsers(loadedUsers);
  }

  useEffect(() => {
    async function loadSettings() {
      try {
        const sessionToken = getSessionToken();
        const user = await invoke<AuthUser>("current_user", { sessionToken });

        setCurrentUser(user);
        setProfileName(user.name);
        setProfileEmail(user.email ?? "");

        if (user.roles.includes("SUPER_ADMIN")) {
          await loadUsers();
        }
      } catch (err) {
        setError(typeof err === "string" ? err : "Unable to load settings.");
      } finally {
        setLoading(false);
      }
    }

    void loadSettings();
  }, []);

  function clearFeedback() {
    setError("");
    setMessage("");
  }

  async function handleProfileSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearFeedback();

    try {
      const user = await invoke<AuthUser>("update_profile", {
        request: {
          sessionToken: getSessionToken(),
          name: profileName,
          email: profileEmail.trim() || null,
        },
      });

      setCurrentUser(user);
      localStorage.setItem("auth.name", user.name);
      setMessage("Profile updated.");
    } catch (err) {
      setError(typeof err === "string" ? err : "Unable to update profile.");
    }
  }

  async function handlePasswordSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearFeedback();

    try {
      await invoke("change_password", {
        request: {
          sessionToken: getSessionToken(),
          currentPassword,
          newPassword,
        },
      });

      setCurrentPassword("");
      setNewPassword("");
      setMessage("Password changed.");
    } catch (err) {
      setError(typeof err === "string" ? err : "Unable to change password.");
    }
  }

  async function handleCreateUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearFeedback();

    try {
      await invoke("create_user", {
        sessionToken: getSessionToken(),
        request: {
          username: newUsername,
          name: newName,
          email: newEmail.trim() || null,
          password: newPasswordForUser,
          role: newRole,
        },
      });

      setNewUsername("");
      setNewName("");
      setNewEmail("");
      setNewPasswordForUser("");
      await loadUsers();
      setMessage("User created.");
    } catch (err) {
      setError(typeof err === "string" ? err : "Unable to create user.");
    }
  }

  async function assignRole(userId: number) {
    clearFeedback();

    try {
      await invoke("assign_role", {
        request: {
          sessionToken: getSessionToken(),
          userId,
          role: roleToAssign,
        },
      });

      await loadUsers();
      setMessage("Role assigned.");
    } catch (err) {
      setError(typeof err === "string" ? err : "Unable to assign role.");
    }
  }

  if (loading) {
    return null;
  }

  return (
    <div className="flex flex-1 flex-col gap-6 p-4 md:p-6">
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Manage your profile and account access.
        </p>
      </div>

      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
      {message && <p className="text-sm text-green-600">{message}</p>}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
            <CardDescription>
              Update the details shown on your account.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="grid gap-4" onSubmit={handleProfileSubmit}>
              <div className="grid gap-2">
                <Label htmlFor="profile-username">Username</Label>
                <Input
                  id="profile-username"
                  value={currentUser?.username ?? ""}
                  disabled
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="profile-name">Name</Label>
                <Input
                  id="profile-name"
                  value={profileName}
                  onChange={(event) => setProfileName(event.target.value)}
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="profile-email">Email</Label>
                <Input
                  id="profile-email"
                  type="email"
                  value={profileEmail}
                  onChange={(event) => setProfileEmail(event.target.value)}
                />
              </div>
              <Button type="submit">Save profile</Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Password</CardTitle>
            <CardDescription>Change your account password.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="grid gap-4" onSubmit={handlePasswordSubmit}>
              <div className="grid gap-2">
                <Label htmlFor="current-password">Current password</Label>
                <Input
                  id="current-password"
                  type="password"
                  value={currentPassword}
                  onChange={(event) => setCurrentPassword(event.target.value)}
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="new-password">New password</Label>
                <Input
                  id="new-password"
                  type="password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  required
                />
              </div>
              <Button type="submit">Change password</Button>
            </form>
          </CardContent>
        </Card>
      </div>

      {isSuperAdmin && (
        <Card>
          <CardHeader>
            <CardTitle>User access</CardTitle>
            <CardDescription>
              Create users and assign application roles.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-8">
            <form
              className="grid gap-4 md:grid-cols-2"
              onSubmit={handleCreateUser}
            >
              <div className="grid gap-2">
                <Label htmlFor="new-username">Username</Label>
                <Input
                  id="new-username"
                  value={newUsername}
                  onChange={(event) => setNewUsername(event.target.value)}
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="new-name">Name</Label>
                <Input
                  id="new-name"
                  value={newName}
                  onChange={(event) => setNewName(event.target.value)}
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="new-email">Email</Label>
                <Input
                  id="new-email"
                  type="email"
                  value={newEmail}
                  onChange={(event) => setNewEmail(event.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="new-user-password">Temporary password</Label>
                <Input
                  id="new-user-password"
                  type="password"
                  value={newPasswordForUser}
                  onChange={(event) =>
                    setNewPasswordForUser(event.target.value)
                  }
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="new-role">Role</Label>
                <select
                  id="new-role"
                  className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm"
                  value={newRole}
                  onChange={(event) => setNewRole(event.target.value)}
                >
                  {availableRoles.map((role) => (
                    <option key={role} value={role}>
                      {role}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-end">
                <Button type="submit">Create user</Button>
              </div>
            </form>

            <div className="grid gap-3">
              <div className="flex items-center justify-between gap-4">
                <h2 className="font-medium">Existing users</h2>
                <select
                  className="h-8 rounded-lg border border-input bg-transparent px-2 text-sm"
                  value={roleToAssign}
                  onChange={(event) => setRoleToAssign(event.target.value)}
                  aria-label="Role to assign"
                >
                  {availableRoles.map((role) => (
                    <option key={role} value={role}>
                      {role}
                    </option>
                  ))}
                </select>
              </div>
              <div className="divide-y rounded-lg border">
                {users.map((user) => (
                  <div
                    className="flex flex-wrap items-center justify-between gap-3 p-3"
                    key={user.id}
                  >
                    <div>
                      <p className="font-medium">{user.name}</p>
                      <p className="text-sm text-muted-foreground">
                        @{user.username} · {user.roles.join(", ") || "No role"}
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => void assignRole(user.id)}
                    >
                      Assign role
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
