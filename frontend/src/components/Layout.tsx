import { Moon, Sun } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
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

function ThemeToggle() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  const flip = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    try { localStorage.setItem("phishlens-theme", next ? "dark" : "light"); } catch { /* ignore */ }
  };
  return (
    <button
      type="button"
      onClick={flip}
      aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
      className="inline-flex items-center justify-center size-9 rounded text-muted hover:text-ink"
    >
      {dark ? <Sun size={17} /> : <Moon size={17} />}
    </button>
  );
}

export function Layout() {
  const nav = ({ isActive }: { isActive: boolean }) =>
    cx("px-3 h-9 inline-flex items-center rounded text-sm", isActive ? "text-ink bg-panel" : "text-muted hover:text-ink");
  return (
    <div className="min-h-screen flex flex-col">
      <header className="no-print border-b border-line">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 h-14 flex items-center gap-6">
          <NavLink to="/" className="flex items-center gap-2 font-semibold tracking-tight text-[17px]">
            <Logo /> PhishLens
          </NavLink>
          <nav className="flex items-center gap-1">
            <NavLink to="/" end className={nav}>Analyze</NavLink>
            <NavLink to="/sources" className={nav}>Sources</NavLink>
          </nav>
          <div className="ml-auto"><ThemeToggle /></div>
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
