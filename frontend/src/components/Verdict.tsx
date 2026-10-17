import { useState } from "react";
import { sourceTitle, verdictAdvice, verdictText, verdictTone } from "../lib/format";
import type { Signal, Verdict, VerdictLabel } from "../lib/types";
import { cx } from "./ui";

const toneText = { good: "text-good", warn: "text-warn", bad: "text-bad" } as const;
const toneBg = { good: "bg-good", warn: "bg-warn", bad: "bg-bad" } as const;

export function VerdictDot({ label }: { label: VerdictLabel }) {
  return <span aria-label={verdictText[label]} className={cx("inline-block size-2.5 rounded-full shrink-0", toneBg[verdictTone[label]])} />;
}

/** The score as a ledger: each signal is a segment of the 0-100 bar, so the number is never a black box. */
function ScoreBar({ signals, score, tone, active }: { signals: Signal[]; score: number; tone: keyof typeof toneBg; active: number | null }) {
  let cum = 0;
  const positive = signals.filter((s) => s.weight > 0);
  const segments = positive.map((s, i) => {
    const start = cum;
    const width = Math.max(0, Math.min(s.weight, 100 - cum));
    cum += width;
    return { s, i, start, width };
  });
  const credit = Math.max(0, cum - score);
  return (
    <div className="relative pt-1 pb-6" aria-hidden>
      <div className="relative h-3.5 rounded-sm bg-sunk overflow-hidden">
        {segments.map(({ s, i, start, width }) =>
          width > 0 ? (
            <div
              key={s.id}
              className={cx("absolute inset-y-0 border-r-2 border-panel transition-opacity", toneBg[tone], active !== null && active !== i ? "opacity-30" : i % 2 ? "opacity-75" : "opacity-100")}
              style={{ left: `${start}%`, width: `${width}%` }}
            />
          ) : null,
        )}
        {credit > 0 && (
          <div
            className="absolute inset-y-0 bg-[repeating-linear-gradient(135deg,rgb(var(--good))_0_3px,transparent_3px_7px)] opacity-80"
            style={{ left: `${score}%`, width: `${credit}%` }}
          />
        )}
      </div>
      {[30, 60].map((t) => (
        <div key={t} className="absolute top-0 h-[22px] border-l border-dashed border-muted/60" style={{ left: `${t}%` }}>
          <span className="absolute top-[24px] -translate-x-1/2 text-[11px] text-muted whitespace-nowrap">
            {t === 30 ? "30 suspicious" : "60 malicious"}
          </span>
        </div>
      ))}
    </div>
  );
}

export function VerdictPanel({ verdict, signals }: { verdict: Verdict; signals: Signal[] }) {
  const tone = verdictTone[verdict.label];
  const [active, setActive] = useState<number | null>(null);
  const positive = signals.filter((s) => s.weight > 0);
  const credits = signals.filter((s) => s.weight < 0);
  const total = verdict.sources_run + verdict.sources_skipped;

  return (
    <section className="rounded-lg border border-line bg-panel">
      <div className="grid md:grid-cols-[220px_1fr]">
        <div className="p-5 md:border-r border-b md:border-b-0 border-line">
          <div className="flex items-baseline gap-1">
            <span className={cx("text-[64px] leading-none font-semibold tracking-tight tabular-nums", toneText[tone])}>{verdict.score}</span>
            <span className="text-muted">/100</span>
          </div>
          <p className={cx("mt-2 text-xl font-semibold", toneText[tone])}>{verdictText[verdict.label]}</p>
          <p className="mt-3 text-sm text-muted">
            Confidence {verdict.confidence}: {verdict.sources_run} of {total} sources ran.
            {verdict.confidence !== "high" && verdict.sources_skipped > 0 && " Add API keys to check more."}
          </p>
          {verdict.hard_override && (
            <p className="mt-3 text-sm">A source already knows this indicator as malicious, so the verdict is fixed.</p>
          )}
        </div>
        <div className="p-5 min-w-0">
          <p className="text-[15px]">{verdictAdvice[verdict.label]}</p>
          <div className="mt-4">
            <ScoreBar signals={signals} score={verdict.score} tone={tone} active={active} />
          </div>
          {signals.length === 0 ? (
            <p className="text-sm text-muted">No risk signals in the checks that ran. The score starts at 0 and only evidence moves it.</p>
          ) : (
            <ol className="mt-1 divide-y divide-line">
              {positive.map((s, i) => (
                <li
                  key={s.id}
                  onMouseEnter={() => setActive(i)}
                  onMouseLeave={() => setActive(null)}
                  className="grid grid-cols-[44px_1fr] sm:grid-cols-[44px_1fr_120px] gap-x-3 py-2"
                >
                  <span className={cx("tabular-nums font-semibold", toneText[tone])}>+{s.weight}</span>
                  <div className="min-w-0">
                    <p className="font-medium">{s.label}</p>
                    <p className="text-sm text-muted break-words">{s.evidence}</p>
                  </div>
                  <span className="hidden sm:block text-sm text-muted text-right">{sourceTitle[s.source] ?? s.source}</span>
                </li>
              ))}
              {credits.map((s) => (
                <li key={s.id} className="grid grid-cols-[44px_1fr] sm:grid-cols-[44px_1fr_120px] gap-x-3 py-2">
                  <span className="tabular-nums font-semibold text-good">{s.weight}</span>
                  <div className="min-w-0">
                    <p className="font-medium">{s.label.replace(/^Trust credit: /, "")}</p>
                    <p className="text-sm text-muted break-words">{s.evidence}</p>
                  </div>
                  <span className="hidden sm:block text-sm text-muted text-right">{sourceTitle[s.source] ?? s.source}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </section>
  );
}
