import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, FileText, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Button, CopyButton, cx, Empty, ExternalLink, LinkButton, Panel, StatusChip, Tag } from "../components/ui";
import { VerdictPanel } from "../components/Verdict";
import { api } from "../lib/api";
import { bytes, defang, inputTypeText, sourceTitle } from "../lib/format";
import type { DomainProfile, Headers, Report, SourceResult } from "../lib/types";

type Tab = "overview" | "headers" | "links" | "attachments" | "sources" | "raw";

export function ReportPage() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["report", id], queryFn: () => api.report(id) });
  const [tab, setTab] = useState<Tab>("overview");
  const navigate = useNavigate();
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: () => api.remove(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["recent"] }); navigate("/"); },
  });

  if (q.isPending) return <p className="text-muted" role="status">Loading report</p>;
  if (q.isError)
    return (
      <div>
        <p role="alert">{q.error.message}</p>
        <Link to="/" className="text-lens">Start a new check</Link>
      </div>
    );
  const r = q.data;
  const isEml = r.input_type === "eml";
  const tabs: { id: Tab; label: string; show: boolean }[] = [
    { id: "overview", label: "Overview", show: true },
    { id: "headers", label: "Headers", show: isEml },
    { id: "links", label: `Links ${r.links.length}`, show: r.links.length > 0 || isEml },
    { id: "attachments", label: `Attachments ${r.attachments.length}`, show: isEml },
    { id: "sources", label: `Sources ${new Set(r.results.map((x) => x.source)).size}`, show: true },
    { id: "raw", label: "Raw headers", show: isEml },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
            <ArrowLeft size={15} /> New check
          </Link>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight break-words">{isEml ? r.title : defang(r.title)}</h1>
          <p className="mt-1 text-sm text-muted">
            {inputTypeText[r.input_type]}, checked {new Date(r.created_at).toLocaleString()}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <CaseNoteCopy id={r.id} />
          <LinkButton href={api.caseNoteUrl(r.id)} download><FileText size={15} /> Case note</LinkButton>
          <LinkButton href={api.iocsUrl(r.id)} download><Download size={15} /> IOCs CSV</LinkButton>
          <Button variant="quiet" onClick={() => del.mutate()} aria-label="Delete report" title="Delete report">
            <Trash2 size={15} />
          </Button>
        </div>
      </div>

      <VerdictPanel verdict={r.verdict} signals={r.signals} />

      <div>
        <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-line">
          {tabs.filter((t) => t.show).map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
              className={cx(
                "px-3 h-10 text-sm whitespace-nowrap border-b-2 -mb-px",
                tab === t.id ? "border-lens text-ink font-medium" : "border-transparent text-muted hover:text-ink",
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="pt-5" role="tabpanel">
          {tab === "overview" && <Overview r={r} />}
          {tab === "headers" && r.headers && <HeadersTab h={r.headers} />}
          {tab === "links" && <LinksTab r={r} />}
          {tab === "attachments" && <AttachmentsTab r={r} />}
          {tab === "sources" && <SourcesTab results={r.results} />}
          {tab === "raw" && r.headers && <RawTab h={r.headers} />}
        </div>
      </div>
    </div>
  );
}

function CaseNoteCopy({ id }: { id: string }) {
  const [state, setState] = useState<"idle" | "done" | "fail">("idle");
  return (
    <Button
      onClick={async () => {
        try {
          const text = await (await fetch(api.caseNoteUrl(id))).text();
          await navigator.clipboard.writeText(text);
          setState("done");
        } catch { setState("fail"); }
        setTimeout(() => setState("idle"), 1600);
      }}
    >
      {state === "done" ? "Case note copied" : state === "fail" ? "Copy failed" : "Copy case note"}
    </Button>
  );
}

function roleText(d: DomainProfile) {
  return { sender: "Sender", reply_to: "Reply-To", link: "Link", input: "Checked" }[d.role];
}

function Overview({ r }: { r: Report }) {
  const hits = r.results.filter((x) => x.status === "hit");
  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_340px]">
      <div className="space-y-6 min-w-0">
        {r.address && <AddressPanel r={r} />}
        <Panel title="Domains">
          {r.domains.length === 0 ? <Empty>No domains in this check.</Empty> : (
            <div className="overflow-x-auto -mx-1">
              <table className="w-full min-w-[620px] text-sm">
                <thead className="text-left text-muted">
                  <tr className="whitespace-nowrap"><th className="font-normal py-1.5 px-1">Domain</th><th className="font-normal px-1">Role</th><th className="font-normal px-1">Age</th><th className="font-normal px-1">Mail records</th><th className="font-normal px-1">Notes</th></tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {r.domains.map((d) => (
                    <tr key={d.domain + d.role} className="align-top">
                      <td className="py-2 px-1 data">{defang(d.registrable)}</td>
                      <td className="py-2 px-1 whitespace-nowrap">{roleText(d)}</td>
                      <td className="py-2 px-1 whitespace-nowrap">
                        {d.age_days == null ? <span className="text-muted">unknown</span> :
                          <span className={d.age_days < 30 ? "text-bad" : d.age_days < 90 ? "text-warn" : ""}>{d.age_days.toLocaleString()} days</span>}
                      </td>
                      <td className="py-2 px-1">
                        {d.checks_run.includes("dns") ? (
                          <div className="flex flex-wrap gap-1">
                            <Tag tone={d.mx.length ? "muted" : "warn"}>{d.mx.length ? "MX" : "no MX"}</Tag>
                            <Tag tone={d.spf ? "muted" : "warn"}>{d.spf ? "SPF" : "no SPF"}</Tag>
                            <Tag tone={d.dmarc ? (d.dmarc_policy === "none" ? "warn" : "good") : "warn"}>{d.dmarc ? `DMARC ${d.dmarc_policy}` : "no DMARC"}</Tag>
                          </div>
                        ) : <span className="text-muted whitespace-nowrap">{d.role === "link" ? "not needed" : "not checked"}</span>}
                      </td>
                      <td className="py-2 px-1 space-y-1">
                        {d.exists === false && <p className="text-bad">Domain does not exist</p>}
                        {d.null_mx && <p className="text-bad">Accepts no mail (null MX)</p>}
                        {d.mail_provider && <p>Mail: {d.mail_provider}</p>}
                        {d.checks_run.includes("dns") && d.exists !== false && d.has_website === false && <p className="text-warn">No website</p>}
                        {d.lookalike_reason && <p className={d.lookalike_strong ? "text-bad" : "text-warn"}>{d.lookalike_reason}</p>}
                        {d.is_freemail && <p className="text-muted">Free-mail provider</p>}
                        {d.is_disposable && <p className="text-bad">Disposable mailbox</p>}
                        {d.registrar && <p className="text-muted">{d.registrar}</p>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <IpPanel r={r} />
        {r.body_preview && (
          <Panel title="Message text" aside={<span className="text-xs text-muted">Plain text only, links are not clickable</span>}>
            <pre className="data whitespace-pre-wrap max-h-80 overflow-auto rounded bg-sunk p-3 text-ink/90">{r.body_preview}</pre>
          </Panel>
        )}
      </div>
      <div className="space-y-6">
        <Panel title="Threat intelligence hits">
          {hits.length === 0 ? (
            <Empty>
              No source flagged an indicator.
              {r.verdict.sources_skipped > 0 && ` ${r.verdict.sources_skipped} source${r.verdict.sources_skipped > 1 ? "s were" : " was"} not checked; see the Sources tab.`}
            </Empty>
          ) : (
            <ul className="space-y-3">
              {hits.map((h, i) => (
                <li key={i} className="text-sm">
                  <p className="font-medium">{sourceTitle[h.source] ?? h.source}</p>
                  <p className="data text-muted">{defang(h.indicator.value)}</p>
                  <p>{h.summary}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        {r.notes.length > 0 && (
          <Panel title="Notes">
            <ul className="space-y-2 text-sm text-muted">{r.notes.map((n) => <li key={n}>{n}</li>)}</ul>
          </Panel>
        )}
      </div>
    </div>
  );
}

function AddressPanel({ r }: { r: Report }) {
  const a = r.address!;
  const d = r.domains.find((x) => x.role === "sender" || x.role === "input");
  const own = r.results.filter((x) => x.indicator.type === "email");
  const rows: [string, React.ReactNode][] = [
    ["Mailbox name", <span className="data">{a.local_part}</span>],
    ["Pattern", a.looks_random ? <span className="text-warn">{a.random_reasons.join("; ")}</span> : "Looks like a normal name or word"],
    ["Role word", a.role_word ? <span className={d?.is_freemail ? "text-warn" : ""}>{a.role_word}{d?.is_freemail ? " (on free-mail)" : ""}</span> : "None"],
    ["Mail hosted by", d?.mail_provider ?? (d?.is_freemail ? "Free-mail provider" : <span className="text-muted">unknown</span>)],
  ];
  if (a.plus_tag) rows.push(["Plus tag", <span className="data">+{a.plus_tag}</span>]);
  return (
    <Panel title="Sender address">
      <dl className="grid grid-cols-[130px_1fr] gap-x-3 gap-y-2 text-sm">
        {rows.map(([k, v]) => (
          <div key={k} className="contents"><dt className="text-muted">{k}</dt><dd>{v}</dd></div>
        ))}
        {own.map((x) => (
          <div key={x.source} className="contents">
            <dt className="text-muted">{sourceTitle[x.source] ?? x.source}</dt>
            <dd className="flex flex-wrap items-center gap-2"><StatusChip status={x.status} /> <span>{x.summary}</span></dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}

const ipRole: Record<string, string> = { header: "Sending server", mx: "Mail server", web: "Website", input: "Checked" };
const ipCols = ["ipinfo", "abuseipdb", "spamhaus", "internetdb", "stopforumspam", "otx", "virustotal"] as const;

function IpPanel({ r }: { r: Report }) {
  const ips = r.indicators.filter((i) => i.type === "ip");
  if (!ips.length) return null;
  return (
    <Panel title="IP addresses">
      <ul className="divide-y divide-line -my-2">
        {ips.map((ip) => {
          const res = r.results.filter((x) => x.indicator.value === ip.value && x.status !== "skipped");
          const info = res.find((x) => x.source === "ipinfo");
          const rest = ipCols.filter((c) => c !== "ipinfo").map((c) => res.find((x) => x.source === c)).filter(Boolean) as SourceResult[];
          return (
            <li key={ip.value} className="py-3">
              <div className="flex flex-wrap items-baseline gap-x-3">
                <span className="data">{ip.value}</span>
                <span className="text-sm text-muted">{ipRole[ip.origin] ?? ip.origin}</span>
                {info && <span className="text-sm">{info.summary}</span>}
              </div>
              {rest.length === 0 ? <p className="text-sm text-muted mt-1">No IP source checked this address.</p> : (
                <ul className="mt-1.5 space-y-1 text-sm">
                  {rest.map((x) => (
                    <li key={x.source} className="flex flex-wrap items-center gap-2">
                      <span className="w-32 text-muted">{sourceTitle[x.source]}</span>
                      <StatusChip status={x.status} />
                      <span className="min-w-0">{x.summary}</span>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

function authTone(v: string | null): "good" | "bad" | "warn" | "muted" {
  if (v === "pass") return "good";
  if (v === "fail" || v === "permerror") return "bad";
  if (v === "softfail" || v === "temperror" || v === "neutral") return "warn";
  return "muted";
}

function HeadersTab({ h }: { h: Headers }) {
  const rows: [string, string | null][] = [
    ["From", h.from_display ? `${h.from_display} <${h.from_address ?? ""}>` : h.from_address],
    ["Reply-To", h.reply_to],
    ["Return-Path", h.return_path],
    ["To", h.to.join(", ") || null],
    ["Subject", h.subject],
    ["Date", h.date],
    ["Message-ID", h.message_id],
    ["Mailer", h.x_mailer],
  ];
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel title="Sender identity">
        <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-2 text-sm">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted">{k}</dt>
              <dd className="data">{v ?? <span className="text-muted font-sans">not set</span>}</dd>
            </div>
          ))}
        </dl>
        {h.mismatches.length > 0 && (
          <ul className="mt-4 space-y-1.5 text-sm">
            {h.mismatches.map((m) => <li key={m} className="text-warn">{m}</li>)}
          </ul>
        )}
      </Panel>
      <Panel title="Authentication">
        <div className="flex gap-6">
          {(["spf", "dkim", "dmarc"] as const).map((k) => (
            <div key={k}>
              <p className="text-sm text-muted">{k.toUpperCase()}</p>
              <p className={cx("text-lg font-semibold", { good: "text-good", bad: "text-bad", warn: "text-warn", muted: "text-muted" }[authTone(h.auth[k])])}>
                {h.auth[k] ?? "none"}
              </p>
            </div>
          ))}
        </div>
        {h.auth.raw[0] && <p className="mt-4 data text-muted">{h.auth.raw[0]}</p>}
      </Panel>
      <Panel title="Delivery path" className="lg:col-span-2" aside={<span className="text-xs text-muted">First hop at the top</span>}>
        {h.hops.length === 0 ? <Empty>No Received headers.</Empty> : (
          <ol className="relative ml-2 border-l border-line">
            {h.hops.map((hop) => (
              <li key={hop.index} className="relative pl-5 pb-4 last:pb-0">
                <span className={cx("absolute -left-[5px] top-1.5 size-2.5 rounded-full border-2 border-panel", hop.ip === h.origin_ip ? "bg-lens" : "bg-muted")} />
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className="data">{hop.from_host ?? "unknown"}</span>
                  <span className="text-muted text-sm">to</span>
                  <span className="data">{hop.by_host ?? "unknown"}</span>
                  {hop.delay_seconds != null && <span className={cx("text-sm", hop.delay_seconds > 300 ? "text-warn" : "text-muted")}>+{hop.delay_seconds}s</span>}
                </div>
                <p className="text-sm text-muted">
                  {hop.ip ? <span className="data">{hop.ip}</span> : "no IP"}
                  {hop.ip === h.origin_ip && " (origin)"}
                  {hop.timestamp && `, ${new Date(hop.timestamp).toLocaleString()}`}
                </p>
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}

function resultsFor(r: Report, value: string) {
  return r.results.filter((x) => x.indicator.value === value);
}

function LinksTab({ r }: { r: Report }) {
  if (!r.links.length) return <Empty>No links found in this message.</Empty>;
  return (
    <ul className="divide-y divide-line border-y border-line">
      {r.links.map((l) => {
        const res = resultsFor(r, l.final_url ?? l.url);
        return (
          <li key={l.url} className="py-3 grid gap-2 md:grid-cols-[1fr_auto]">
            <div className="min-w-0">
              <div className="flex items-start gap-1">
                <span className="data">{l.defanged}</span>
                <CopyButton text={l.defanged} label="Copy defanged URL" />
              </div>
              {l.display_text && <p className={cx("text-sm", l.deceptive ? "text-bad" : "text-muted")}>Shown as: {l.display_text}</p>}
              {l.final_url && <p className="text-sm text-muted">Redirects to <span className="data">{defang(l.final_url)}</span></p>}
              <div className="mt-1 flex gap-1">
                {l.deceptive && <Tag tone="bad">text shows another domain</Tag>}
                {l.is_shortener && <Tag tone="warn">shortener</Tag>}
              </div>
            </div>
            <div className="flex flex-wrap content-start gap-1.5 md:justify-end md:max-w-xs">
              {res.length === 0 ? <span className="text-sm text-muted">No source checked this link</span> :
                res.map((x) => <span key={x.source} className="inline-flex items-center gap-1 text-sm"><span className="text-muted">{sourceTitle[x.source]}</span><StatusChip status={x.status} title={x.summary} /></span>)}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function AttachmentsTab({ r }: { r: Report }) {
  if (!r.attachments.length) return <Empty>No attachments.</Empty>;
  return (
    <ul className="space-y-4">
      {r.attachments.map((a) => {
        const res = resultsFor(r, a.sha256);
        return (
          <li key={a.sha256 + a.filename}>
            <Panel>
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="font-medium break-all">{a.filename}</p>
                <p className="text-sm text-muted">{a.detected_type}, {bytes(a.size)}{a.risky && <span className="text-bad">, risky</span>}</p>
              </div>
              <div className="mt-1 flex items-center gap-1">
                <span className="data text-muted">SHA-256 {a.sha256}</span>
                <CopyButton text={a.sha256} label="Copy SHA-256" />
              </div>
              {a.reasons.length > 0 && <ul className="mt-2 list-disc pl-5 text-sm space-y-0.5">{a.reasons.map((x) => <li key={x}>{x}</li>)}</ul>}
              <div className="mt-3 flex flex-wrap gap-3">
                {res.map((x) => <span key={x.source} className="inline-flex items-center gap-1 text-sm"><span className="text-muted">{sourceTitle[x.source]}</span><StatusChip status={x.status} title={x.summary} /></span>)}
              </div>
            </Panel>
          </li>
        );
      })}
    </ul>
  );
}

function SourcesTab({ results }: { results: SourceResult[] }) {
  const order = { hit: 0, error: 1, info: 2, clean: 3, skipped: 4 };
  const sorted = [...results].sort((a, b) => order[a.status] - order[b.status]);
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-sm">
        <thead className="text-left text-muted border-b border-line">
          <tr><th className="font-normal py-2 pr-3">Source</th><th className="font-normal pr-3">Result</th><th className="font-normal pr-3">Indicator</th><th className="font-normal pr-3">Details</th><th className="font-normal" /></tr>
        </thead>
        <tbody className="divide-y divide-line">
          {sorted.map((x, i) => (
            <tr key={i} className="align-top">
              <td className="py-2.5 pr-3 whitespace-nowrap font-medium">{sourceTitle[x.source] ?? x.source}</td>
              <td className="py-2.5 pr-3"><StatusChip status={x.status} /></td>
              <td className="py-2.5 pr-3 data text-muted max-w-[260px]">{defang(x.indicator.value)}</td>
              <td className="py-2.5 pr-3">{x.summary}{x.cached && <span className="text-muted"> (cached)</span>}</td>
              <td className="py-2.5 whitespace-nowrap">{x.link && <ExternalLink href={x.link}>Open</ExternalLink>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RawTab({ h }: { h: Headers }) {
  return (
    <div className="rounded-lg border border-line bg-panel overflow-x-auto">
      <table className="w-full text-sm">
        <tbody className="divide-y divide-line">
          {h.raw_headers.map(([k, v], i) => (
            <tr key={i} className="align-top">
              <td className="py-1.5 px-3 data text-muted whitespace-nowrap">{k}</td>
              <td className="py-1.5 px-3 data">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
