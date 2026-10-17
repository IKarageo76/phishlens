import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileUp, Loader2, Search } from "lucide-react";
import { useEffect, useRef, useState, type DragEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, cx, Empty } from "../components/ui";
import { HeroArt } from "../components/HeroArt";
import { VerdictDot } from "../components/Verdict";
import { api } from "../lib/api";
import { inputTypeText, timeAgo, verdictText } from "../lib/format";
import type { Report } from "../lib/types";

const RAW_EMAIL = /^(Received|Return-Path|Delivered-To|From|Message-ID|Authentication-Results):/im;

export function AnalyzePage() {
  const [value, setValue] = useState("");
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const recent = useQuery({ queryKey: ["recent"], queryFn: api.recent });

  const run = useMutation({
    mutationFn: (input: string | File) => (typeof input === "string" ? api.analyzeValue(input) : api.analyzeFile(input)),
    onSuccess: (report: Report) => {
      qc.setQueryData(["report", report.id], report);
      qc.invalidateQueries({ queryKey: ["recent"] });
      navigate(`/report/${report.id}`);
    },
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement?.tagName !== "TEXTAREA" && document.activeElement?.tagName !== "INPUT") {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const looksRaw = value.includes("\n") && RAW_EMAIL.test(value);
  const submit = () => {
    const v = value.trim();
    if (!v || run.isPending) return;
    run.mutate(looksRaw ? new File([value], "pasted-message.eml", { type: "message/rfc822" }) : v);
  };
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) run.mutate(file);
  };

  return (
    <div>
     <div className="relative grid items-center gap-6 lg:grid-cols-[minmax(0,1fr)_420px]">
      <div className="hero-scan" aria-hidden />
      <div className="min-w-0 max-w-3xl py-2 lg:py-8">
      <h1 className="neon-title text-[34px] sm:text-[46px] leading-[1.05] font-bold">Is this email safe?</h1>
      <p className="mt-2 text-muted max-w-xl">
        Paste just the sender's address to check who is behind it. You can also check a domain, link, IP or file
        hash, or drop the whole .eml file for the full picture.
      </p>

      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={cx(
          "console mt-7 rounded-lg border bg-panel transition-[border-color,box-shadow]",
          dragging ? "border-lens ring-2 ring-lens/30" : "border-line focus-within:border-lens",
        )}
      >
        <div className="flex items-start gap-3 p-3">
          <Search size={18} className="mt-2.5 ml-1 text-muted shrink-0" aria-hidden />
          <label htmlFor="q" className="sr-only">Indicator or raw email source</label>
          <textarea
            id="q"
            ref={inputRef}
            autoFocus
            spellCheck={false}
            rows={value.includes("\n") ? 8 : 1}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey && !value.includes("\n")) {
                e.preventDefault();
                submit();
              }
            }}
            placeholder="security@micros0ft.com"
            className={cx(
              "flex-1 resize-none bg-transparent outline-none focus-visible:outline-none py-2 placeholder:text-muted/60",
              value.includes("\n") ? "data" : "text-[17px]",
            )}
          />
          <Button variant="primary" onClick={submit} disabled={!value.trim() || run.isPending} className="h-10 px-5">
            {run.isPending ? <Loader2 size={16} className="animate-spin" /> : null}
            {looksRaw ? "Analyse source" : "Check"}
          </Button>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2.5 text-sm text-muted">
          <span>{dragging ? "Drop to analyse" : "Defanged input like hxxps://evil[.]com works too. Paste raw headers to analyse them."}</span>
          <button type="button" onClick={() => fileRef.current?.click()} className="inline-flex items-center gap-1.5 text-ink hover:text-lens">
            <FileUp size={15} /> Upload .eml
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".eml,message/rfc822"
            className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) run.mutate(f); e.target.value = ""; }}
          />
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
        <span className="text-muted">Try an example:</span>
        {["billing@paypa1-secure.com", "x7k2q9p@gmail.com", "micros0ft-login.com"].map((ex) => (
          <button
            key={ex}
            type="button"
            onClick={() => { setValue(ex); run.mutate(ex); }}
            className="rounded border border-line px-2 py-0.5 data hover:border-lens hover:text-lens"
          >
            {ex}
          </button>
        ))}
      </div>

      {run.isPending && <p className="mt-4 text-sm text-muted" role="status">Querying sources. Free-tier lookups can take a few seconds.</p>}
      {run.isError && (
        <p role="alert" className="mt-4 rounded border border-bad/40 bg-bad/10 px-4 py-3 text-sm">
          {run.error.message}
        </p>
      )}

      </div>
      <HeroArt className="hero-art w-full max-w-[420px] justify-self-end" />
     </div>

      <section className="mt-12 max-w-3xl">
        <h2 className="text-[15px] font-semibold mb-3">Recent checks</h2>
        {recent.isError && <Empty>Recent checks are unavailable: {recent.error.message}</Empty>}
        {recent.data?.length === 0 && <Empty>Nothing checked yet. Results are kept for the retention period, then deleted.</Empty>}
        {!!recent.data?.length && (
          <ul className="divide-y divide-line border-y border-line">
            {recent.data.map((r) => (
              <li key={r.id}>
                <Link to={`/report/${r.id}`} className="flex items-center gap-4 py-2.5 px-1 hover:bg-panel">
                  <VerdictDot label={r.label} />
                  <span className="w-10 tabular-nums text-sm font-semibold">{r.score}</span>
                  <span className="flex-1 truncate">{r.title}</span>
                  <span className="hidden sm:block text-sm text-muted w-28">{inputTypeText[r.input_type]}</span>
                  <span className="hidden sm:block text-sm text-muted w-28">{verdictText[r.label]}</span>
                  <span className="text-sm text-muted w-20 text-right">{timeAgo(r.created_at)}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
