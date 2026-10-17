import { Moon, Sparkles, Sun } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { Scene } from "./Scene";
import { cx } from "./ui";

function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="size-7" aria-hidden>
      <circle cx="14" cy="14" r="7.5" fill="none" stroke="rgb(var(--lens))" strokeWidth="2.6" />
      <path d="M19.5 19.5 26 26" stroke="rgb(var(--lens))" strokeWidth="3" strokeLinecap="round" />
      <path d="M10.5 14h7" stroke="rgb(var(--bad))" strokeWidth="2.2" strokeLinecap="round" />
    </svg>
  );
}

type Theme = "neon" | "dark" | "light";
const NEXT: Record<Theme, Theme> = { neon: "dark", dark: "light", light: "neon" };
const NAME: Record<Theme, string> = { neon: "Neon", dark: "Dark", light: "Light" };

function readTheme(): Theme {
  const c = document.documentElement.classList;
  return c.contains("neon") ? "neon" : c.contains("dark") ? "dark" : "light";
}

function applyTheme(t: Theme) {
  const c = document.documentElement.classList;
  c.toggle("neon", t === "neon");
  c.toggle("dark", t !== "light");
  try { localStorage.setItem("phishlens-theme", t); } catch { /* ignore */ }
}

function ThemeToggle({ theme, onChange }: { theme: Theme; onChange: (t: Theme) => void }) {
  const next = NEXT[theme];
  const Icon = theme === "neon" ? Sparkles : theme === "dark" ? Moon : Sun;
  return (
    <button
      type="button"
      onClick={() => { applyTheme(next); onChange(next); }}
      aria-label={`Theme: ${NAME[theme]}. Switch to ${NAME[next]}`}
      title={`Theme: ${NAME[theme]} (click for ${NAME[next]})`}
      className="inline-flex items-center gap-1.5 h-9 px-2.5 rounded text-sm text-muted hover:text-ink"
    >
      <Icon size={16} /> <span className="hidden sm:inline">{NAME[theme]}</span>
    </button>
  );
}

export function Layout() {
  const [theme, setTheme] = useState<Theme>(readTheme);
  const nav = ({ isActive }: { isActive: boolean }) =>
    cx("px-3 h-9 inline-flex items-center rounded text-sm", isActive ? "text-ink bg-panel" : "text-muted hover:text-ink");
  return (
    <div className="relative min-h-screen flex flex-col">
      {theme === "neon" && <Scene />}
      <header className="no-print sticky top-0 z-20 border-b border-line bg-base/70 backdrop-blur-md">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 h-14 flex items-center gap-6">
          <NavLink to="/" className="font-display flex items-center gap-2 font-semibold tracking-wide text-[18px]">
            <Logo /> PhishLens
          </NavLink>
          <nav className="flex items-center gap-1">
            <NavLink to="/" end className={nav}>Analyze</NavLink>
            <NavLink to="/sources" className={nav}>Sources</NavLink>
          </nav>
          <div className="ml-auto"><ThemeToggle theme={theme} onChange={setTheme} /></div>
        </div>
      </header>
      <main className="flex-1 mx-auto w-full max-w-6xl px-4 sm:px-6 py-8">
        <Outlet />
      </main>
      <footer className="no-print mx-auto w-full max-w-6xl px-4 sm:px-6 py-6 text-xs text-muted">
        Self-hosted. Email files are analysed in memory; attachments are hashed and never opened.
      </footer>
    </div>
  );
}
