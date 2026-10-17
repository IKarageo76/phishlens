import type { PublicSettings, Report, ReportSummary, SourceInfo } from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, "Can't reach the PhishLens API. Check that the backend container is running.");
  }
  if (!res.ok) {
    let detail = `Request failed (HTTP ${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch { /* keep default */ }
    throw new ApiError(res.status, detail);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  analyzeValue: (value: string) =>
    call<Report>("/api/analyze/indicator", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ value }) }),
  analyzeFile: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return call<Report>("/api/analyze/eml", { method: "POST", body: form });
  },
  report: (id: string) => call<Report>(`/api/reports/${id}`),
  recent: () => call<ReportSummary[]>("/api/reports?limit=12"),
  remove: (id: string) => call<void>(`/api/reports/${id}`, { method: "DELETE" }),
  sources: () => call<SourceInfo[]>("/api/settings/sources"),
  settings: () => call<PublicSettings>("/api/settings"),
  caseNoteUrl: (id: string) => `/api/reports/${id}/case-note.md`,
  iocsUrl: (id: string) => `/api/reports/${id}/iocs.csv`,
};
