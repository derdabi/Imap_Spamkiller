export type MailboxSettings = {
  provider: string;
  email: string;
  imap_host: string;
  imap_port: number;
  imap_username: string;
  inbox_folder: string;
  quarantine_folder: string;
  poll_interval_seconds: number;
  auto_delete_enabled: boolean;
  auto_delete_after_days: number;
  spam_score_threshold: number;
  uncertain_score_threshold: number;
  enabled: boolean;
  has_password: boolean;
  password_unreadable: boolean;
};

export type MailboxPayload = MailboxSettings & { password?: string };

export type LlmSettings = {
  provider: "off" | "openai" | "anthropic";
  model: string;
  enabled: boolean;
  send_body_excerpt: boolean;
  max_excerpt_chars: number;
  has_api_key: boolean;
  api_key_unreadable: boolean;
};

export type LlmPayload = LlmSettings & { api_key?: string };

export type LlmModelsResult = {
  ok: boolean;
  models: string[];
  message: string;
};

export type QuarantineMessage = {
  id: number;
  sender: string;
  subject: string;
  received_at: string | null;
  final_verdict: string;
  explanation: string;
  quarantined_at: string | null;
};

export type InboxMessage = {
  id: number;
  sender: string;
  subject: string;
  received_at: string | null;
  source_folder: string;
  status: string;
  final_verdict: string;
  explanation: string;
  analysis: {
    rspamd_score: number;
    rspamd_action: string;
    rspamd_symbols: string[];
    suspicious_indicators: string[];
    llm_provider: string;
    llm_verdict: string;
    llm_confidence: number;
  } | null;
};

export type AuditEvent = {
  id: number;
  event_type: string;
  details: Record<string, unknown>;
  created_at: string;
};

export type ScanRunResult = {
  folder?: string;
  trigger?: string;
  batch_size?: number;
  scanned?: number;
  clean?: number;
  review?: number;
  quarantined?: number;
  deleted?: number;
  failed?: number;
  skipped_existing?: number;
  reevaluated?: number;
  missing_from_folder?: number;
  candidate_count?: number;
  folder_message_count?: number | null;
  duration_seconds?: number;
  message?: string;
};

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    }
  });
  if (!response.ok) {
    const detail = await response.text();
    let message = detail || response.statusText;
    try {
      const parsed = JSON.parse(detail) as { detail?: unknown };
      message = typeof parsed.detail === "string" ? parsed.detail : message;
    } catch {
      // Keep the raw response text when the server did not return JSON.
    }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export const getMailboxSettings = () => api<MailboxSettings>("/api/settings/mailbox");
export const saveMailboxSettings = (payload: MailboxPayload) =>
  api<MailboxSettings>("/api/settings/mailbox", { method: "PUT", body: JSON.stringify(payload) });
export const testMailboxSettings = (payload: MailboxPayload) =>
  api<{ ok: boolean; message: string }>("/api/settings/mailbox/test", { method: "POST", body: JSON.stringify(payload) });
export const listMailboxFolders = (payload: MailboxPayload) =>
  api<string[]>("/api/settings/mailbox/folders", { method: "POST", body: JSON.stringify(payload) });
export const getLlmSettings = () => api<LlmSettings>("/api/settings/llm");
export const saveLlmSettings = (payload: LlmPayload) =>
  api<LlmSettings>("/api/settings/llm", { method: "PUT", body: JSON.stringify(payload) });
export const testLlmSettings = (payload: LlmPayload) =>
  api<{ ok: boolean; message: string }>("/api/settings/llm/test", { method: "POST", body: JSON.stringify(payload) });
export const listLlmModels = (payload: LlmPayload) =>
  api<LlmModelsResult>("/api/settings/llm/models", { method: "POST", body: JSON.stringify(payload) });
export const resetSavedCredentials = () =>
  api<{ ok: boolean; message: string }>("/api/settings/credentials/reset", { method: "POST" });
export const runScan = () => api<ScanRunResult>("/api/scan/run", { method: "POST" });
export const reevaluateScan = () => api<ScanRunResult>("/api/scan/reevaluate", { method: "POST" });
export const getQuarantine = () => api<QuarantineMessage[]>("/api/messages/quarantine");
export const getInboxMessages = () => api<InboxMessage[]>("/api/messages/inbox");
export const restoreMessage = (id: number) => api<{ restored: number }>(`/api/messages/${id}/restore`, { method: "POST" });
export const confirmSpam = (id: number) => api<{ ok: boolean }>(`/api/messages/${id}/confirm-spam`, { method: "POST" });
export const getAudit = () => api<AuditEvent[]>("/api/audit");
