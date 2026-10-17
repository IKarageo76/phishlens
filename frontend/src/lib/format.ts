import type { VerdictLabel } from "./types";

export const verdictText: Record<VerdictLabel, string> = {
  likely_legitimate: "Likely legitimate",
  suspicious: "Suspicious",
  malicious: "Malicious",
};

export const verdictTone: Record<VerdictLabel, "good" | "warn" | "bad"> = {
  likely_legitimate: "good",
  suspicious: "warn",
  malicious: "bad",
};

export const verdictAdvice: Record<VerdictLabel, string> = {
  likely_legitimate: "No strong risk signals. Close if the context matches what the user expected.",
  suspicious: "Mixed signals. Review the evidence below before you answer the user.",
  malicious: "Treat as a threat. Block the indicators and check whether other mailboxes received it.",
};

export const inputTypeText: Record<string, string> = {
  email_address: "Sender address",
  domain: "Domain",
  url: "URL",
  ip: "IP address",
  hash: "File hash",
  eml: "Email file",
};

export const sourceTitle: Record<string, string> = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  urlscan: "urlscan.io",
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  malwarebazaar: "MalwareBazaar",
  hibp: "Have I Been Pwned",
  dns: "DNS",
  rdap: "RDAP",
  lookalike: "Lookalike check",
  headers: "Headers",
  body: "Message body",
  attachments: "Attachments",
  lists: "Domain lists",
};

export function timeAgo(iso: string): string {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function defang(v: string): string {
  if (v.includes("://")) {
    const [scheme, rest] = v.split("://", 2);
    const slash = rest.indexOf("/");
    const host = slash === -1 ? rest : rest.slice(0, slash);
    const path = slash === -1 ? "" : rest.slice(slash);
    return `${scheme.replace(/^http/i, "hxxp")}://${host.replaceAll(".", "[.]")}${path}`;
  }
  if (v.includes("@")) {
    const at = v.lastIndexOf("@");
    return `${v.slice(0, at)}[@]${v.slice(at + 1).replaceAll(".", "[.]")}`;
  }
  return /^[0-9a-f]{32,64}$/i.test(v) ? v : v.replaceAll(".", "[.]");
}
