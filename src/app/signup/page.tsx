"use client";

import { invoke } from "@tauri-apps/api/core";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { SignupForm } from "@/components/auth/signup-form";

type SetupStatus = {
  setup_completed: boolean;
  has_users: boolean;
};

export default function SignUpPage() {
  const router = useRouter();
  const [setupAvailable, setSetupAvailable] = useState(false);

  useEffect(() => {
    invoke<SetupStatus>("get_setup_status")
      .then((status) => {
        if (status.setup_completed || status.has_users) {
          router.replace("/login");
          return;
        }

        setSetupAvailable(true);
      })
      .catch(() => {
        router.replace("/login");
      });
  }, [router]);

  if (!setupAvailable) {
    return null;
  }

  return (
    <div className="flex min-h-svh w-full items-center justify-center p-6 md:p-10">
      <div className="w-full max-w-sm">
        <SignupForm />
      </div>
    </div>
  );
}
