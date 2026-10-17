import { ChevronDown, ChevronRight, ExternalLink as ExtIcon, Printer } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { defang, sourceTitle } from "../lib/format";
import type { Indicator, Report, SourceResult } from "../lib/types";
import { Button, CopyButton, cx, StatusChip } from "./ui";

const order = { hit: 0, info: 1, clean: 2, error: 3, skipped: 4 } as const;
const originText: Record<string, string> = {
  input: "checked value", header: "from the headers", body: "from the message body", attachment: "attachment",
  mx: "mail server", web: "website", redirect: "redirect target", sender: "sender", reply_to: "reply-to", link: "link",
};

const linkSite: Record<string, string> = { dns: "MXToolbox", rdap: "ICANN Lookup", internetdb: "InternetDB", phishstats: "PhishStats API" };

function when(iso: string | null) {
  if (!iso) return "time not recorded";
  const d = new Date(iso);
  return `${d.toLocaleString()} (${d.toISOString().slice(0, 16).replace("T", " ")} UTC)`;
}

function fmt(v: unknown): string {
  if (v == null || v === "") return "";
  if (Array.isArray(v)) return v.map(fmt).filter(Boolean).join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function label(k: string) {
  return k.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
}

function EvidenceRow({ r, open, toggle }: { r: SourceResult; open: boolean; toggle: () => void }) {
  const details = Object.entries(r.details ?? {}).filter(([, v]) => fmt(v) !== "");
  const raw = r.raw == null ? null : typeof r.raw === "string" ? r.raw : JSON.stringify(r.raw, null, 2);
  const title = sourceTitle[r.source] ?? r.source;
  return (
    <li className="py-2.5 break-inside-avoid">
      <div className="flex flex-wrap items-start gap-x-3 gap-y-1">
        <button type="button" onClick={toggle} aria-expanded={open} className="no-print mt-0.5 text-muted hover:text-ink" aria-label={open ? "Hide details" : "Show details"}>
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </button>
        <span className="w-40 shrink-0 font-medium">{title}</span>
        <StatusChip status={r.status} />
        <span className="flex-1 min-w-[200px]">{r.summary}</span>
        {r.link && (
          <a href={r.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sm text-lens hover:underline whitespace-nowrap">
            {r.status === "skipped" ? "Check manually on" : "Open in"} {linkSite[r.source] ?? title} <ExtIcon size={13} />
          </a>
        )}
      </div>
      {r.status !== "skipped" && (
        <p className="ml-7 mt-0.5 text-xs text-muted">
          Checked {when(r.checked_at)}{r.cached ? ", served from cache (original check time)" : ""}
        </p>
      )}
      {open && (
        <div className="ml-7 mt-2 space-y-3 rounded border border-line bg-sunk/60 p-3 text-sm">
          {details.length > 0 && (
            <dl className="grid grid-cols-[150px_1fr] gap-x-3 gap-y-1">
              {details.map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-muted">{label(k)}</dt>
                  <dd className="break-words">{fmt(v)}</dd>
                </div>
              ))}
            </dl>
          )}
          {(r.link || r.extra_links?.length > 0) && (
            <div>
              <p className="text-muted mb-1">Verify at the source</p>
              <ul className="space-y-1">
                {r.link && <li className="flex items-center gap-1"><a href={r.link} target="_blank" rel="noopener noreferrer" className="data text-lens hover:underline">{r.link}</a><CopyButton text={r.link} label="Copy link" /></li>}
                {r.extra_links?.map((l) => (
                  <li key={l.url} className="flex items-center gap-1"><span className="text-muted">{l.label}:</span> <a href={l.url} target="_blank" rel="noopener noreferrer" className="data text-lens hover:underline">{l.url}</a><CopyButton text={l.url} label="Copy link" /></li>
                ))}
              </ul>
            </div>
          )}
          {r.query && (
            <div>
              <p className="text-muted mb-1">Request sent (keys removed)</p>
              <p className="data">{r.query}</p>
            </div>
          )}
          {raw && (
            <div>
              <div className="flex items-center justify-between">
                <p className="text-muted">Raw response</p>
                <CopyButton text={raw} label="Copy raw response" />
              </div>
              <pre className="evidence-raw data mt-1 max-h-72 overflow-auto whitespace-pre-wrap rounded bg-panel p-2">{raw}</pre>
            </div>
          )}
          {!details.length && !raw && !r.query && <p className="text-muted">The source returned no further data for this check.</p>}
        </div>
      )}
    </li>
  );
}

export function EvidenceSection({ r }: { r: Report }) {
  const groups = useMemo(() => {
    const byKey = new Map<string, { ind: Indicator; results: SourceResult[] }>();
    for (const x of r.results) {
      const key = `${x.indicator.type}:${x.indicator.value}`;
      if (!byKey.has(key)) byKey.set(key, { ind: x.indicator, results: [] });
      byKey.get(key)!.results.push(x);
    }
    const list = [...byKey.values()];
    list.forEach((g) => g.results.sort((a, b) => order[a.status] - order[b.status] || a.source.localeCompare(b.source)));
    return list.sort((a, b) => order[a.results[0].status] - order[b.results[0].status]);
  }, [r.results]);

  const key = (x: SourceResult) => `${x.source}|${x.indicator.type}|${x.indicator.value}`;
  const [open, setOpen] = useState<Set<string>>(() => new Set(r.results.filter((x) => x.status === "hit").map(key)));
  const allOpen = open.size >= r.results.length;

  useEffect(() => {
    let before: Set<string> | null = null;
    const expand = () => { before = open; setOpen(new Set(r.results.map(key))); };
    const restore = () => { if (before) setOpen(before); };
    window.addEventListener("beforeprint", expand);
    window.addEventListener("afterprint", restore);
    return () => { window.removeEventListener("beforeprint", expand); window.removeEventListener("afterprint", restore); };
  }, [open, r.results]);

  if (!r.results.length) return null;
  return (
    <section className="evidence rounded-lg border border-line bg-panel">
      <header className="flex flex-wrap items-start justify-between gap-3 px-5 pt-4 pb-2">
        <div>
          <h2 className="text-[15px] font-semibold">Evidence</h2>
          <p className="text-sm text-muted max-w-2xl">
            Each result as returned by its source, with the time it was checked. Open a link to verify it on the
            source's own site and take your screenshot there.
          </p>
        </div>
        <div className="no-print flex gap-2">
          <Button onClick={() => setOpen(allOpen ? new Set() : new Set(r.results.map(key)))}>
            {allOpen ? "Collapse all" : "Expand all"}
          </Button>
          <Button onClick={() => window.print()}><Printer size={15} /> Print or save as PDF</Button>
        </div>
      </header>
      <div className="px-5 pb-4 space-y-5">
        {groups.map((g) => (
          <div key={`${g.ind.type}:${g.ind.value}`} className="break-inside-avoid-page">
            <h3 className="flex flex-wrap items-baseline gap-x-2 border-b border-line pb-1.5">
              <span className="data font-medium">{g.ind.type === "hash" ? g.ind.value : defang(g.ind.value)}</span>
              <span className="text-sm text-muted">{g.ind.type}, {originText[g.ind.origin] ?? g.ind.origin}</span>
            </h3>
            <ul className={cx("divide-y divide-line")}>
              {g.results.map((x) => (
                <EvidenceRow
                  key={key(x)}
                  r={x}
                  open={open.has(key(x))}
                  toggle={() => setOpen((s) => { const n = new Set(s); n.has(key(x)) ? n.delete(key(x)) : n.add(key(x)); return n; })}
                />
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}
