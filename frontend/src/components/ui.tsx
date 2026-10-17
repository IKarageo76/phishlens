import { Check, Copy } from "lucide-react";
import { useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import type { SourceStatus } from "../lib/types";

export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

export function Button({
  variant = "plain",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "plain" | "quiet" }) {
  return (
    <button
      {...props}
      className={cx(
        "inline-flex items-center gap-2 rounded px-3.5 h-9 text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed",
        variant === "primary" && "bg-lens text-base hover:bg-lens/90",
        variant === "plain" && "border border-line bg-panel hover:border-muted",
        variant === "quiet" && "text-muted hover:text-ink",
        className,
      )}
    />
  );
}

export function LinkButton({ href, children, download }: { href: string; children: ReactNode; download?: boolean }) {
  return (
    <a
      href={href}
      download={download}
      className="inline-flex items-center gap-2 rounded px-3.5 h-9 text-sm font-medium border border-line bg-panel hover:border-muted"
    >
      {children}
    </a>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1400);
        } catch { /* clipboard blocked */ }
      }}
      className="inline-flex shrink-0 items-center justify-center size-7 rounded text-muted hover:text-ink hover:bg-sunk"
    >
      {done ? <Check size={14} className="text-good" /> : <Copy size={14} />}
    </button>
  );
}

const statusStyle: Record<SourceStatus, string> = {
  hit: "text-bad bg-bad/10 border-bad/30",
  clean: "text-good bg-good/10 border-good/30",
  info: "text-ink bg-sunk border-line",
  skipped: "text-muted bg-transparent border-line border-dashed",
  error: "text-warn bg-warn/10 border-warn/30",
};
const statusText: Record<SourceStatus, string> = {
  hit: "Flagged",
  clean: "Clean",
  info: "Info",
  skipped: "Not checked",
  error: "Failed",
};

export function StatusChip({ status, title }: { status: SourceStatus; title?: string }) {
  return (
    <span title={title} className={cx("inline-flex items-center rounded-sm border px-1.5 py-px text-xs font-medium whitespace-nowrap", statusStyle[status])}>
      {statusText[status]}
    </span>
  );
}

export function Tag({ tone = "muted", children }: { tone?: "muted" | "bad" | "warn" | "good" | "lens"; children: ReactNode }) {
  const tones = {
    muted: "text-muted border-line",
    bad: "text-bad border-bad/40",
    warn: "text-warn border-warn/40",
    good: "text-good border-good/40",
    lens: "text-lens border-lens/40",
  };
  return <span className={cx("inline-flex items-center rounded-sm border px-1.5 text-xs whitespace-nowrap", tones[tone])}>{children}</span>;
}

export function Panel({ title, aside, children, className }: { title?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cx("rounded-lg border border-line bg-panel", className)}>
      {title && (
        <header className="flex items-center justify-between gap-4 px-5 pt-4 pb-3">
          <h2 className="text-[15px] font-semibold">{title}</h2>
          {aside}
        </header>
      )}
      <div className={title ? "px-5 pb-5" : "p-5"}>{children}</div>
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="text-sm text-muted py-2">{children}</p>;
}

export function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-lens hover:underline underline-offset-2">
      {children}
    </a>
  );
}
