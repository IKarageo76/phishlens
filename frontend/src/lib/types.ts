export type IndicatorType = "url" | "domain" | "ip" | "email" | "hash";
export type SourceStatus = "hit" | "clean" | "info" | "skipped" | "error";
export type VerdictLabel = "likely_legitimate" | "suspicious" | "malicious";

export interface Indicator { type: IndicatorType; value: string; origin: string }
export interface SourceResult {
  source: string; indicator: Indicator; status: SourceStatus; summary: string;
  severity: "none" | "low" | "medium" | "high"; details: Record<string, unknown>;
  link: string | null; cached: boolean;
}
export interface Hop { index: number; from_host: string | null; by_host: string | null; ip: string | null; timestamp: string | null; delay_seconds: number | null }
export interface Headers {
  subject: string | null; date: string | null; message_id: string | null; from_display: string | null;
  from_address: string | null; reply_to: string | null; return_path: string | null; to: string[];
  auth: { spf: string | null; dkim: string | null; dmarc: string | null; raw: string[] };
  hops: Hop[]; origin_ip: string | null; mismatches: string[]; x_mailer: string | null;
  raw_headers: [string, string][];
}
export interface Link { url: string; defanged: string; domain: string | null; display_text: string | null; is_shortener: boolean; deceptive: boolean; final_url: string | null }
export interface Attachment { filename: string; content_type: string; size: number; sha256: string; md5: string; detected_type: string; risky: boolean; reasons: string[] }
export interface DomainProfile {
  domain: string; registrable: string; role: "sender" | "reply_to" | "link" | "input";
  mx: string[]; spf: string | null; dmarc: string | null; dmarc_policy: string | null;
  created: string | null; age_days: number | null; registrar: string | null;
  is_freemail: boolean; is_disposable: boolean; lookalike_of: string | null; lookalike_reason: string | null; lookalike_strong: boolean;
  checks_run: string[];
}
export interface Signal { id: string; label: string; weight: number; evidence: string; source: string }
export interface Verdict { score: number; label: VerdictLabel; confidence: "low" | "medium" | "high"; sources_run: number; sources_skipped: number; hard_override: boolean; reasons: string[] }
export interface Report {
  id: string; created_at: string; input_type: "email_address" | "domain" | "url" | "ip" | "hash" | "eml";
  input_value: string; title: string; headers: Headers | null; body_preview: string | null;
  links: Link[]; attachments: Attachment[]; domains: DomainProfile[]; indicators: Indicator[];
  results: SourceResult[]; signals: Signal[]; verdict: Verdict; notes: string[];
}
export interface ReportSummary { id: string; created_at: string; input_type: string; title: string; score: number; label: VerdictLabel }
export interface SourceInfo { name: string; title: string; configured: boolean; needs_key: boolean; indicator_types: string[]; rate_limit: string; licence_note: string; signup_url: string | null }
export interface PublicSettings { privacy_mode: boolean; unshorten_enabled: boolean; retention_days: number; vt_max_lookups: number; max_upload_mb: number; protected_domains: string[] }
