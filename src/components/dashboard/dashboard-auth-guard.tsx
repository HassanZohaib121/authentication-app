"use client";

import { invoke } from "@tauri-apps/api/core";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

type AuthUser = {
  roles: string[];
};

export function DashboardAuthGuard({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [authorized, setAuthorized] = useState(false);

  useEffect(() => {
    const sessionToken = localStorage.getItem("auth.session");

    if (!sessionToken) {
      router.replace("/login");
      return;
    }

    invoke<AuthUser>("current_user", { sessionToken })
      .then(() => {
        setAuthorized(true);
      })
      .catch(() => {
        localStorage.removeItem("auth.session");
        router.replace("/login");
      });
  }, [router]);

  if (!authorized) {
    return null;
  }

  return children;
}
