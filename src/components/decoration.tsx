"use client";

import { Button } from "./ui/button";
import { X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";

export default function Decoration() {
  const handleMinimizeToTray = async () => {
    const window = getCurrentWindow();
    await window.hide();
  };

  return (
    <header
      data-tauri-drag-region
      className="flex h-12 select-none items-center justify-between border-b bg-background/95 px-3 backdrop-blur supports-backdrop-filter:bg-background/80"
    >
      {/* Draggable area */}
      <div
        data-tauri-drag-region
        className="flex h-full flex-1 items-center gap-2"
      >
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <span className="text-xs font-bold">D</span>
        </div>

        <h1 className="text-sm font-semibold tracking-tight">
          Authentication App
        </h1>
      </div>

      {/* Window controls */}
      <div className="flex items-center">
        <Button
          type="button"
          size="icon"
          variant="ghost"
          className="h-8 w-8 rounded-md text-muted-foreground transition-colors hover:bg-destructive hover:text-white"
          onClick={handleMinimizeToTray}
        >
          <X className="h-4 w-4" />
          <span className="sr-only">Minimize to tray</span>
        </Button>
      </div>
    </header>
  );
}
