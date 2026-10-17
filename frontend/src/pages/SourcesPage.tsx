import { useQuery } from "@tanstack/react-query";
import { Empty, ExternalLink, Panel, Tag } from "../components/ui";
import { api } from "../lib/api";

export function SourcesPage() {
  const sources = useQuery({ queryKey: ["sources"], queryFn: api.sources });
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings });
  const missing = sources.data?.filter((s) => !s.configured).length ?? 0;

  return (
    <div className="space-y-8 max-w-4xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Sources</h1>
        <p className="mt-2 text-muted max-w-2xl">
          Keys are read from the server's environment and never sent to the browser. To add one, set it in
          <span className="data"> .env</span> and restart with <span className="data">docker compose up -d</span>.
          {missing > 0 && ` ${missing} source${missing > 1 ? "s are" : " is"} not configured yet.`}
        </p>
      </div>

      {sources.isError && <p role="alert">{sources.error.message}</p>}
      <ul className="divide-y divide-line border-y border-line">
        {sources.data?.map((s) => (
          <li key={s.name} className="py-4 grid gap-2 sm:grid-cols-[200px_1fr_auto]">
            <div>
              <p className="font-medium">{s.title}</p>
              <p className="text-sm text-muted">{s.indicator_types.join(", ")}</p>
            </div>
            <div className="text-sm">
              <p>{s.rate_limit}</p>
              <p className="text-muted">{s.licence_note}</p>
            </div>
            <div className="sm:text-right space-y-1">
              {s.configured ? <Tag tone="good">{s.needs_key ? "Key set" : "On"}</Tag> : <Tag tone="warn">{s.needs_key ? "No key" : "Off"}</Tag>}
              {!s.configured && s.signup_url && <p className="text-sm"><ExternalLink href={s.signup_url}>Get a key</ExternalLink></p>}
            </div>
          </li>
        ))}
      </ul>

      <Panel title="Behaviour">
        {settings.data ? (
          <dl className="grid grid-cols-[220px_1fr] gap-y-2 text-sm">
            <dt className="text-muted">Privacy mode</dt>
            <dd>{settings.data.privacy_mode ? "On: full email addresses stay on this server" : "Off"}</dd>
            <dt className="text-muted">Resolve short links</dt>
            <dd>{settings.data.unshorten_enabled ? "On (HEAD requests only)" : "Off: attacker infrastructure is never contacted"}</dd>
            <dt className="text-muted">VirusTotal lookups per check</dt>
            <dd>{settings.data.vt_max_lookups}</dd>
            <dt className="text-muted">Report retention</dt>
            <dd>{settings.data.retention_days} days</dd>
            <dt className="text-muted">Protected domains</dt>
            <dd>{settings.data.protected_domains.length ? <span className="data">{settings.data.protected_domains.join(", ")}</span> : "Built-in brand list only. Add yours with PROTECTED_DOMAINS."}</dd>
          </dl>
        ) : <Empty>Loading</Empty>}
      </Panel>
    </div>
  );
}
