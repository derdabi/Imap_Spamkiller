import { FormEvent, ReactNode, useEffect, useState, useTransition } from "react";
import { Bot, CheckCircle2, Clock, MailCheck, RefreshCw, ShieldCheck, Trash2, Undo2 } from "lucide-react";
import {
  AuditEvent,
  LlmSettings,
  MailboxPayload,
  MailboxSettings,
  InboxMessage,
  QuarantineMessage,
  ScanRunResult,
  confirmSpam,
  getAudit,
  getLlmSettings,
  getMailboxSettings,
  getQuarantine,
  getInboxMessages,
  listLlmModels,
  listMailboxFolders,
  reevaluateScan,
  resetSavedCredentials,
  restoreMessage,
  runScan,
  saveLlmSettings,
  saveMailboxSettings,
  testLlmSettings,
  testMailboxSettings
} from "./api";

const defaultMailbox: MailboxSettings = {
  provider: "t-online",
  email: "",
  imap_host: "secureimap.t-online.de",
  imap_port: 993,
  imap_username: "",
  inbox_folder: "INBOX",
  quarantine_folder: "SpamKiller/Quarantine",
  poll_interval_seconds: 300,
  auto_delete_enabled: true,
  auto_delete_after_days: 15,
  spam_score_threshold: 6,
  uncertain_score_threshold: 4,
  enabled: false,
  has_password: false,
  password_unreadable: false
};

const mailProviderPresets = [
  { provider: "t-online", label: "t-online", imap_host: "secureimap.t-online.de", imap_port: 993, note: "Use the separate Telekom email password." },
  { provider: "gmail", label: "Gmail", imap_host: "imap.gmail.com", imap_port: 993, note: "Requires IMAP to be enabled and usually an app password." },
  { provider: "outlook", label: "Outlook / Hotmail / Microsoft 365", imap_host: "outlook.office365.com", imap_port: 993, note: "Personal and Microsoft 365 accounts may require an app password or modern auth settings." },
  { provider: "yahoo", label: "Yahoo Mail", imap_host: "imap.mail.yahoo.com", imap_port: 993, note: "Usually requires an app password." },
  { provider: "gmx", label: "GMX", imap_host: "imap.gmx.net", imap_port: 993, note: "Enable IMAP in your mailbox settings if needed." },
  { provider: "web-de", label: "WEB.DE", imap_host: "imap.web.de", imap_port: 993, note: "Enable IMAP in your mailbox settings if needed." },
  { provider: "icloud", label: "iCloud Mail", imap_host: "imap.mail.me.com", imap_port: 993, note: "Requires an app-specific password." },
  { provider: "aol", label: "AOL Mail", imap_host: "imap.aol.com", imap_port: 993, note: "Usually requires an app password." }
];

const scanIntervalOptions = [
  { value: 60, label: "Every minute" },
  { value: 300, label: "Every 5 minutes" },
  { value: 900, label: "Every 15 minutes" },
  { value: 1800, label: "Every 30 minutes" },
  { value: 3600, label: "Hourly" },
  { value: 21600, label: "Every 6 hours" },
  { value: 86400, label: "Daily" }
];

const defaultLlm: LlmSettings = {
  provider: "off",
  model: "",
  enabled: false,
  send_body_excerpt: true,
  max_excerpt_chars: 12000,
  has_api_key: false,
  api_key_unreadable: false
};

const AUTO_REFRESH_MS = 15_000;
const BODY_EXCERPT_CHARS = 12_000;

const signalCopy: Record<string, { label: string; description: string }> = {
  ARC_REJECT: {
    label: "ARC failed",
    description: "ARC authentication failed, so forwarded-mail trust information could not be verified."
  },
  CTYPE_MIXED_BOGUS: {
    label: "Odd content type",
    description: "The message declares a suspicious or inconsistent content type."
  },
  DATE_IN_PAST: {
    label: "Old date",
    description: "The message date is far in the past compared with delivery time."
  },
  FORGED_SENDER: {
    label: "Forged sender",
    description: "Rspamd found evidence that the visible sender may be forged."
  },
  FREEMAIL_ENVRCPT: {
    label: "Free-mail recipient",
    description: "The envelope recipient is on a free-mail domain. This is usually informational by itself."
  },
  FROM_DN_EQ_ADDR: {
    label: "Sender name is address",
    description: "The sender display name is the same as the email address."
  },
  FROM_EQ_ENVFROM: {
    label: "Sender matches",
    description: "The visible From address matches the SMTP envelope sender."
  },
  FROM_HAS_DN: {
    label: "Named sender",
    description: "The sender includes a display name."
  },
  FROM_NEQ_ENVFROM: {
    label: "Sender mismatch",
    description: "The visible From address differs from the SMTP envelope sender."
  },
  INVALID_MSGID: {
    label: "Invalid Message-ID",
    description: "The message has a malformed Message-ID header."
  },
  LOCAL_OUTBOUND: {
    label: "Local route",
    description: "Rspamd classified the message route as local or outbound context."
  },
  MANY_INVISIBLE_PARTS: {
    label: "Invisible parts",
    description: "The message contains many invisible or hidden parts, which can be used to disguise content."
  },
  MID_MISSING_BRACKETS: {
    label: "Bad Message-ID format",
    description: "The Message-ID is missing the expected angle-bracket format."
  },
  MID_RHS_NOT_FQDN: {
    label: "Bad Message-ID domain",
    description: "The Message-ID domain is not a fully qualified domain name. This is a weak but useful authenticity signal."
  },
  MIME_HTML_ONLY: {
    label: "HTML only",
    description: "The email only contains an HTML body and no plain-text alternative."
  },
  MISSING_MIME_VERSION: {
    label: "Missing MIME version",
    description: "The message is missing the MIME-Version header."
  },
  MV_CASE: {
    label: "MIME casing issue",
    description: "The MIME-Version header uses unusual casing or formatting."
  },
  PREVIOUSLY_DELIVERED: {
    label: "Previously delivered",
    description: "The message appears to have already passed through delivery handling."
  },
  RCVD_COUNT_TWO: {
    label: "Two mail hops",
    description: "The message has two Received headers. This is usually routing context."
  },
  REPLYTO_ADDR_EQ_FROM: {
    label: "Reply-To matches",
    description: "The Reply-To address matches the visible From address."
  },
  REPLYTO_DOM_NEQ_FROM_DOM: {
    label: "Reply-To mismatch",
    description: "The Reply-To domain differs from the visible sender domain."
  },
  SUBJ_EXCESS_BASE64: {
    label: "Encoded subject",
    description: "The subject uses an unusually high amount of Base64 encoding."
  },
  SUBJECT_NEEDS_ENCODING: {
    label: "Subject encoding issue",
    description: "The subject contains characters that should have been MIME-encoded."
  },
  TO_DN_ALL: {
    label: "Recipients named",
    description: "All recipients include display names."
  },
  TO_DN_NONE: {
    label: "No recipient name",
    description: "Recipients do not include display names."
  },
  TO_MATCH_ENVRCPT_ALL: {
    label: "Recipient matches",
    description: "Visible recipients match the SMTP envelope recipients."
  },
  ZERO_FONT: {
    label: "Zero-size text",
    description: "The message uses zero-size text, often to hide content from readers while influencing scanners."
  },
  body_hidden_unicode_controls: {
    label: "Hidden Unicode in body",
    description: "The email body contains invisible Unicode control characters."
  },
  freemail_sender_with_institution_claim: {
    label: "Institution from free mail",
    description: "The message claims to be from an institution but uses a free-mail sender domain."
  },
  institution_claim_with_external_link_domain: {
    label: "External link domain",
    description: "The message claims an institution but links to a different external domain."
  },
  message_id_domain_not_fqdn: {
    label: "Bad Message-ID domain",
    description: "The Message-ID domain is not a fully qualified domain name."
  },
  reply_to_domain_mismatch: {
    label: "Reply-To mismatch",
    description: "The Reply-To domain differs from the sender domain."
  },
  sender_hidden_unicode_controls: {
    label: "Hidden Unicode in sender",
    description: "The sender field contains invisible Unicode control characters."
  },
  sender_obfuscation: {
    label: "Obfuscated sender",
    description: "The sender name appears to use punctuation to disguise a word or brand."
  },
  subject_hidden_unicode_controls: {
    label: "Hidden Unicode in subject",
    description: "The subject contains invisible Unicode control characters."
  },
  subject_obfuscation: {
    label: "Obfuscated subject",
    description: "The subject appears to use punctuation to disguise a word or brand."
  }
};

export function App() {
  const [mailbox, setMailbox] = useState<MailboxSettings>(defaultMailbox);
  const [savedMailbox, setSavedMailbox] = useState<MailboxSettings>(defaultMailbox);
  const [password, setPassword] = useState("");
  const [llm, setLlm] = useState<LlmSettings>(defaultLlm);
  const [savedLlm, setSavedLlm] = useState<LlmSettings>(defaultLlm);
  const [apiKey, setApiKey] = useState("");
  const [quarantine, setQuarantine] = useState<QuarantineMessage[]>([]);
  const [checkedInbox, setCheckedInbox] = useState<InboxMessage[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [folderOptions, setFolderOptions] = useState<string[]>([]);
  const [modelOptions, setModelOptions] = useState<string[]>([]);
  const [notice, setNotice] = useState("Load settings to begin.");
  const [error, setError] = useState("");
  const [showWizard, setShowWizard] = useState(false);
  const [wizardDismissed, setWizardDismissed] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isReevaluating, setIsReevaluating] = useState(false);
  const [isPending, startTransition] = useTransition();
  const hasUnreadableCredentials = mailbox.password_unreadable || llm.api_key_unreadable;
  const displayedFolderOptions = [...new Set([
    mailbox.inbox_folder,
    mailbox.quarantine_folder,
    ...folderOptions
  ].filter(Boolean))];

  useEffect(() => {
    void refreshAll();
  }, []);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      void refreshLiveData();
    }, AUTO_REFRESH_MS);

    return () => window.clearInterval(intervalId);
  }, []);

  useEffect(() => {
    void refreshModels();
  }, [llm.provider]);

  async function refreshAll(nextNotice = "System is ready.", fallbackEvent?: AuditEvent, nextError = "") {
    try {
      const [mailboxSettings, llmSettings, quarantined, inboxMessages, events] = await Promise.all([
        getMailboxSettings(),
        getLlmSettings(),
        getQuarantine(),
        getInboxMessages(),
        getAudit()
      ]);
      const nextAudit = fallbackEvent && !hasScanActivitySince(events, fallbackEvent.created_at) ? [fallbackEvent, ...events] : events;
      const normalizedLlmSettings = normalizeLlmSettings(llmSettings);
      startTransition(() => {
        setMailbox(mailboxSettings);
        setSavedMailbox(mailboxSettings);
        setShowWizard(isMailboxUnconfigured(mailboxSettings) && !wizardDismissed);
        setLlm(normalizedLlmSettings);
        setSavedLlm(normalizedLlmSettings);
        setQuarantine(quarantined);
        setCheckedInbox(inboxMessages);
        setAudit(nextAudit);
        setNotice(nextNotice);
        setError(nextError);
        void refreshModels(normalizedLlmSettings);
      });
      return nextAudit;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load data.");
      return null;
    }
  }

  async function refreshLiveData() {
    try {
      const [quarantined, inboxMessages, events] = await Promise.all([
        getQuarantine(),
        getInboxMessages(),
        getAudit()
      ]);
      startTransition(() => {
        setQuarantine(quarantined);
        setCheckedInbox(inboxMessages);
        setAudit(events);
      });
    } catch {
      // Keep the current UI state when a background refresh fails.
    }
  }

  async function saveMailbox(event: FormEvent) {
    event.preventDefault();
    try {
      const saved = await saveMailboxSettings({ ...mailbox, password: password || undefined });
      setMailbox(saved);
      setSavedMailbox(saved);
      setPassword("");
      setNotice("Mailbox settings saved.");
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save mailbox settings.");
    }
  }

  async function saveMailboxToggle(nextMailbox: MailboxSettings) {
    const previousMailbox = mailbox;
    setMailbox(nextMailbox);
    try {
      const saved = await saveMailboxSettings(nextMailbox);
      setMailbox(saved);
      setSavedMailbox(saved);
      setNotice("Mailbox settings saved.");
      setError("");
    } catch (err) {
      setMailbox(previousMailbox);
      setError(err instanceof Error ? err.message : "Could not save mailbox settings.");
    }
  }

  async function testMailbox() {
    try {
      const result = await testMailboxSettings({ ...mailbox, password: password || undefined });
      setNotice(result.message);
      setError(result.ok ? "" : result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Connection test failed.");
    }
  }

  async function refreshFolders() {
    try {
      const folders = await listMailboxFolders({ ...mailbox, password: password || undefined });
      setFolderOptions(folders);
      setNotice(`Loaded ${folders.length} mailbox folders.`);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load mailbox folders.");
    }
  }

  async function saveLlm(event: FormEvent) {
    event.preventDefault();
    try {
      const saved = normalizeLlmSettings(await saveLlmSettings({ ...llm, enabled: llm.provider !== "off", api_key: apiKey || undefined }));
      setLlm(saved);
      setSavedLlm(saved);
      setApiKey("");
      setNotice("LLM settings saved.");
      setError("");
      void refreshModels(saved);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save LLM settings.");
    }
  }

  async function refreshModels(currentSettings: LlmSettings = llm) {
    if (currentSettings.provider === "off") {
      setModelOptions([]);
      setError("");
      return;
    }

    try {
      const result = await listLlmModels({ ...currentSettings, api_key: apiKey || undefined });
      setModelOptions(result.models);
      setError(result.ok ? "" : result.message);
    } catch (err) {
      setModelOptions([]);
      setError(err instanceof Error ? err.message : "Could not load models.");
    }
  }

  async function testLlm() {
    try {
      const result = await testLlmSettings({ ...llm, api_key: apiKey || undefined });
      setNotice(result.message);
      setError(result.ok ? "" : result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "LLM connection test failed.");
    }
  }

  async function resetCredentials() {
    if (!window.confirm("This clears the saved mailbox password and LLM API key. You can re-enter them afterward.")) {
      return;
    }
    try {
      const result = await resetSavedCredentials();
      setPassword("");
      setApiKey("");
      await refreshAll(result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reset saved credentials.");
    }
  }

  async function scanNow() {
    const scanStartedAt = new Date().toISOString();
    setIsScanning(true);
    setNotice("Scan started...");
    setError("");
    try {
      const result = await runScan();
      const fallbackEvent = clientScanEvent(result, undefined, scanStartedAt);
      const refreshedEvents = await refreshAll(formatScanResult(result), fallbackEvent);
      if (!refreshedEvents) {
        setAudit((events) => hasScanActivitySince(events, scanStartedAt) ? events : [fallbackEvent, ...events]);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Scan failed.";
      const fallbackEvent = clientScanEvent(undefined, message, scanStartedAt);
      setError(message);
      const refreshedEvents = await refreshAll("Scan failed. See Recent Activity for details.", fallbackEvent, message);
      if (!refreshedEvents) {
        setError(message);
        setAudit((events) => hasScanActivitySince(events, scanStartedAt) ? events : [fallbackEvent, ...events]);
      }
    } finally {
      setIsScanning(false);
    }
  }

  async function reevaluateNow() {
    if (!mailbox.inbox_folder.trim()) {
      setError("Choose a scan folder before reevaluating.");
      return;
    }

    setIsReevaluating(true);
    setNotice("Saving mailbox settings before reevaluation...");
    setError("");

    let savedMailbox: MailboxSettings;
    try {
      savedMailbox = await saveMailboxSettings({ ...mailbox, password: password || undefined });
      setMailbox(savedMailbox);
      setSavedMailbox(savedMailbox);
      setPassword("");
    } catch (err) {
      setIsReevaluating(false);
      setNotice("Could not save mailbox settings.");
      setError(err instanceof Error ? err.message : "Could not save mailbox settings.");
      return;
    }

    const scanStartedAt = new Date().toISOString();
    setNotice(`Reevaluating all mail in ${savedMailbox.inbox_folder}...`);
    try {
      const result = await reevaluateScan();
      const fallbackEvent = clientScanEvent(result, undefined, scanStartedAt);
      const refreshedEvents = await refreshAll(formatScanResult(result), fallbackEvent);
      if (!refreshedEvents) {
        setAudit((events) => hasScanActivitySince(events, scanStartedAt) ? events : [fallbackEvent, ...events]);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Reevaluation failed.";
      const fallbackEvent = clientScanEvent(undefined, message, scanStartedAt);
      setError(message);
      const refreshedEvents = await refreshAll("Reevaluation failed. See Recent Activity for details.", fallbackEvent, message);
      if (!refreshedEvents) {
        setError(message);
        setAudit((events) => hasScanActivitySince(events, scanStartedAt) ? events : [fallbackEvent, ...events]);
      }
    } finally {
      setIsReevaluating(false);
    }
  }

  async function restore(id: number) {
    try {
      await restoreMessage(id);
      setNotice("Restore requested.");
      setError("");
      void refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Restore failed.");
    }
  }

  async function markCheckedMessageAsSpam(id: number) {
    const previousCheckedInbox = checkedInbox;
    setCheckedInbox((messages) => messages.filter((message) => message.id !== id));
    try {
      await confirmSpam(id);
      setNotice("Message marked as spam.");
      setError("");
      void refreshLiveData();
    } catch (err) {
      setCheckedInbox(previousCheckedInbox);
      setError(err instanceof Error ? err.message : "Could not move message to quarantine.");
    }
  }

  async function markQuarantinedMessage(id: number) {
    const previousQuarantine = quarantine;
    setQuarantine((messages) => messages.filter((message) => message.id !== id));
    try {
      await confirmSpam(id);
      setNotice("Feedback saved.");
      setError("");
      void refreshLiveData();
    } catch (err) {
      setQuarantine(previousQuarantine);
      setError(err instanceof Error ? err.message : "Could not save feedback.");
    }
  }

  function selectMailProvider(provider: string) {
    if (provider === "custom") {
      setMailbox({ ...mailbox, provider: "custom" });
      return;
    }

    const preset = mailProviderPresets.find((candidate) => candidate.provider === provider);
    if (!preset) {
      return;
    }

    setMailbox({
      ...mailbox,
      provider: preset.provider,
      imap_host: preset.imap_host,
      imap_port: preset.imap_port,
      imap_username: mailbox.email || mailbox.imap_username
    });
  }

  function updateMailboxHost(imap_host: string) {
    setMailbox({ ...mailbox, provider: "custom", imap_host });
  }

  function updateMailboxPort(imap_port: number) {
    setMailbox({ ...mailbox, provider: "custom", imap_port });
  }

  const mailboxHasUsablePassword = mailbox.has_password || password.trim().length > 0;
  const mailboxHasChanges = mailboxSettingsChanged(mailbox, savedMailbox) || password.trim().length > 0;
  const selectedMailProvider = mailProviderPresets.some((preset) => preset.provider === mailbox.provider) ? mailbox.provider : "custom";
  const selectedMailProviderPreset = mailProviderPresets.find((preset) => preset.provider === selectedMailProvider);
  const hasPresetScanInterval = scanIntervalOptions.some((option) => option.value === mailbox.poll_interval_seconds);
  const llmHasUsableKey = llm.provider !== "off" && (llm.has_api_key || apiKey.trim().length > 0);
  const llmHasChanges = llmSettingsChanged(llm, savedLlm) || apiKey.trim().length > 0;
  const mailboxStatus = mailbox.password_unreadable
    ? { label: "Needs reset", tone: "warning" }
    : mailboxHasChanges
      ? { label: "Unsaved changes", tone: "warning" }
      : !mailboxHasUsablePassword
        ? { label: "Needs password", tone: "warning" }
        : mailbox.enabled
          ? { label: "Ready", tone: "good" }
          : { label: "Disabled", tone: "neutral" };
  const llmStatus = llm.api_key_unreadable
    ? { label: "Needs reset", tone: "warning" }
    : llmHasChanges
      ? { label: "Unsaved changes", tone: "warning" }
      : llm.provider === "off"
        ? { label: "Disabled", tone: "neutral" }
        : !llmHasUsableKey
          ? { label: "Needs API key", tone: "warning" }
          : { label: "Ready", tone: "good" };

  return (
    <main className="shell">
      {showWizard && (
        <SetupWizard
          presets={mailProviderPresets}
          base={savedMailbox}
          onSaved={(saved) => {
            setMailbox(saved);
            setSavedMailbox(saved);
            setPassword("");
            setShowWizard(false);
            setNotice("Mailbox configured. SpamKiller is ready to scan.");
            setError("");
          }}
          onSkip={() => {
            setWizardDismissed(true);
            setShowWizard(false);
          }}
        />
      )}
      <section className="hero">
        <div>
          <p className="eyebrow">Self-hosted mailbox protection</p>
          <h1>IMAP SpamKiller</h1>
          <p className="heroText">
            A safe quarantine-first spam cleaner for one mailbox. Built for a family NAS, with Rspamd locally and optional OpenAI or Anthropic review for unclear messages.
          </p>
        </div>
        <div className="heroActions">
          <button className="primaryButton" onClick={scanNow} disabled={isPending || isScanning || isReevaluating}>
            <RefreshCw size={18} /> {isScanning ? "Scanning..." : "Scan now"}
          </button>
          <button onClick={reevaluateNow} disabled={isPending || isScanning || isReevaluating}>
            <RefreshCw size={18} /> {isReevaluating ? "Reevaluating..." : "Reevaluate folder"}
          </button>
        </div>
      </section>

      <section className="statusGrid">
        <StatusCard icon={<ShieldCheck />} label="Mailbox" value={mailbox.enabled ? "Protected" : "Paused"} />
        <StatusCard icon={<MailCheck />} label="Quarantine" value={`${quarantine.length} messages`} />
        <StatusCard icon={<Clock />} label="Scan interval" value={formatScanInterval(mailbox.poll_interval_seconds)} />
        <StatusCard icon={<Clock />} label="Auto delete" value={mailbox.auto_delete_enabled ? `${mailbox.auto_delete_after_days} days` : "Off"} />
        <StatusCard icon={<Bot />} label="Cloud LLM" value={llm.enabled ? llm.provider : "Off"} />
      </section>

      {notice && <div className="notice">{notice}</div>}
      {error && <div className="error">{error}</div>}
      {hasUnreadableCredentials && (
        <section className="warningPanel">
          <div>
            <strong>Saved credentials need attention</strong>
            <p>Your saved mailbox password or API key can't be read. Reset saved credentials, then enter them again.</p>
          </div>
          <button type="button" onClick={resetCredentials}>Reset saved credentials</button>
        </section>
      )}

      <section className="panel settingsPanel">
        <div className="settingsHeader">
          <div>
            <h2>Settings</h2>
            <p className="muted">Daily controls stay visible. Credentials and technical defaults are tucked away until you need them.</p>
          </div>
        </div>
        <div className="settingsGrid">
          <form className="settingsColumn" onSubmit={saveMailbox}>
            <SettingsSection title="Mailbox" status={<InlineStatus label={mailboxStatus.label} tone={mailboxStatus.tone} />}>
              <p className="muted">Choose a provider to prefill IMAP settings. Some providers require an app password instead of your normal web login password.</p>
              {mailbox.password_unreadable ? <p className="fieldWarning">The saved mailbox password can't be read. Reset saved credentials, then enter it again.</p> : null}
              <FieldRow>
                <label>
                  Provider
                  <select value={selectedMailProvider} onChange={(event) => selectMailProvider(event.target.value)}>
                    {mailProviderPresets.map((preset) => <option value={preset.provider} key={preset.provider}>{preset.label}</option>)}
                    <option value="custom">Custom IMAP server</option>
                  </select>
                </label>
                <label>Email<input value={mailbox.email} onChange={(event) => setMailbox({ ...mailbox, email: event.target.value, imap_username: event.target.value })} /></label>
                <label>Scan folder<input list="mailbox-folders" value={mailbox.inbox_folder} onChange={(event) => setMailbox({ ...mailbox, inbox_folder: event.target.value })} /></label>
                <label>Suspicious mail folder<input list="mailbox-folders" value={mailbox.quarantine_folder} onChange={(event) => setMailbox({ ...mailbox, quarantine_folder: event.target.value })} /></label>
              </FieldRow>
              {selectedMailProviderPreset ? <p className="inlineHint">{selectedMailProviderPreset.note}</p> : null}
              <datalist id="mailbox-folders" key={folderOptions.join("\0")}>
                {displayedFolderOptions.map((folder) => <option value={folder} key={folder} />)}
              </datalist>
              <label className="check"><input type="checkbox" checked={mailbox.enabled} onChange={(event) => void saveMailboxToggle({ ...mailbox, enabled: event.target.checked })} /> Enable scanning</label>
              <FieldRow>
                <label>
                  Scan interval
                  <select
                    value={mailbox.poll_interval_seconds}
                    onChange={(event) => setMailbox({ ...mailbox, poll_interval_seconds: Number(event.target.value) })}
                  >
                    {!hasPresetScanInterval ? <option value={mailbox.poll_interval_seconds}>{formatScanInterval(mailbox.poll_interval_seconds)} (current)</option> : null}
                    {scanIntervalOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
                  </select>
                </label>
              </FieldRow>
              <p className="inlineHint">The background worker waits this long between automatic scans. Manual scans can still be started anytime.</p>
              <AdvancedDisclosure title="Connection details">
                <FieldRow compact>
                  <label>Password<input type="password" value={password} placeholder={mailbox.has_password ? "Saved, enter only to replace" : "Required"} onChange={(event) => setPassword(event.target.value)} /></label>
                  <label>IMAP host<input value={mailbox.imap_host} onChange={(event) => updateMailboxHost(event.target.value)} /></label>
                  <label>Port<input type="number" value={mailbox.imap_port} onChange={(event) => updateMailboxPort(Number(event.target.value))} /></label>
                </FieldRow>
              </AdvancedDisclosure>
            </SettingsSection>

            <SettingsSection title="Spam rules" status={<InlineStatus label={mailboxHasChanges ? "Unsaved changes" : "Saved"} tone={mailboxHasChanges ? "warning" : "good"} />}>
              <p className="muted">Review scores mark suspicious mail. Quarantine scores or matching Rspamd actions are moved automatically.</p>
              <FieldRow compact>
                <label>Review score<input type="number" min="0" max="30" step="0.1" value={mailbox.uncertain_score_threshold} onChange={(event) => setMailbox({ ...mailbox, uncertain_score_threshold: Number(event.target.value) })} /></label>
                <label>Quarantine score<input type="number" min="1" max="30" step="0.1" value={mailbox.spam_score_threshold} onChange={(event) => setMailbox({ ...mailbox, spam_score_threshold: Number(event.target.value) })} /></label>
                <label>Delete after days<input type="number" min="1" value={mailbox.auto_delete_after_days} onChange={(event) => setMailbox({ ...mailbox, auto_delete_after_days: Number(event.target.value) })} /></label>
              </FieldRow>
              <label className="check"><input type="checkbox" checked={mailbox.auto_delete_enabled} onChange={(event) => void saveMailboxToggle({ ...mailbox, auto_delete_enabled: event.target.checked })} /> Automatically delete quarantine after retention period</label>
            </SettingsSection>

            {!mailboxHasUsablePassword ? <p className="inlineHint">Enter a mailbox password in connection details, or keep a saved password, before testing or loading folders.</p> : null}
            <div className="actions settingsActions">
              <button type="button" onClick={testMailbox} disabled={!mailboxHasUsablePassword}>Test connection</button>
              <button type="button" onClick={refreshFolders} disabled={!mailboxHasUsablePassword}>Refresh folders</button>
              <button className="primaryButton" type="submit">Save mailbox</button>
            </div>
          </form>

          <form className="settingsColumn" onSubmit={saveLlm}>
            <SettingsSection title="Cloud LLM" status={<InlineStatus label={llmStatus.label} tone={llmStatus.tone} />}>
              <p className="muted">Only uncertain messages are sent. Attachments are never sent.</p>
              {llm.provider !== "off" && !llm.enabled ? <p className="fieldWarning">Cloud LLM is configured but disabled. Save LLM to enable {llm.provider} classification.</p> : null}
              {llm.api_key_unreadable ? <p className="fieldWarning">The saved API key can't be read. Reset saved credentials, then enter it again.</p> : null}
              <FieldRow>
                <label>Provider<select value={llm.provider} onChange={(event) => setLlm({ ...llm, provider: event.target.value as LlmSettings["provider"], enabled: event.target.value !== "off" })}><option value="off">Off</option><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option></select></label>
                {modelOptions.length > 0 ? (
                  <label>
                    Model
                    <select value={llm.model} onChange={(event) => setLlm({ ...llm, model: event.target.value })}>
                      <option value="">Use provider default</option>
                      {llm.model && !modelOptions.includes(llm.model) ? <option value={llm.model}>{llm.model} (custom)</option> : null}
                      {modelOptions.map((model) => <option value={model} key={model}>{model}</option>)}
                    </select>
                  </label>
                ) : (
                  <label>Model<input value={llm.model} placeholder={llm.provider === "anthropic" ? "claude-3-5-haiku-latest" : "gpt-4.1-mini"} onChange={(event) => setLlm({ ...llm, model: event.target.value })} /></label>
                )}
                <label>API key<input type="password" value={apiKey} placeholder={llm.has_api_key ? "Saved, enter only to replace" : "Required for cloud LLM"} onChange={(event) => setApiKey(event.target.value)} /></label>
              </FieldRow>
              <label className="check"><input type="checkbox" checked={llm.send_body_excerpt} onChange={(event) => setLlm({ ...llm, send_body_excerpt: event.target.checked })} /> Send body excerpt to cloud LLM</label>
              {llm.send_body_excerpt ? (
                <FieldRow>
                  <label>Body excerpt characters<input type="number" min="200" max={BODY_EXCERPT_CHARS} value={llm.max_excerpt_chars} onChange={(event) => setLlm({ ...llm, max_excerpt_chars: Number(event.target.value) })} /></label>
                </FieldRow>
              ) : null}
            </SettingsSection>

            {llm.provider === "off" ? <p className="inlineHint">Select a provider before refreshing or testing cloud models.</p> : null}
            {llm.provider !== "off" && !llmHasUsableKey ? <p className="inlineHint">Enter an API key in API details, or keep a saved key, before testing.</p> : null}
            <div className="actions settingsActions">
              <button type="button" onClick={() => void refreshModels()} disabled={llm.provider === "off"}>Refresh models</button>
              <button type="button" onClick={testLlm} disabled={!llmHasUsableKey}>Test LLM</button>
              <button className="primaryButton" type="submit">Save LLM</button>
            </div>
          </form>
        </div>

        <div className="credentialsStrip">
          <div>
            <strong>Saved Credentials</strong>
            <p className="muted">Reset only when passwords or API keys can't be read, or when you want to clear saved secrets.</p>
          </div>
          <button type="button" onClick={resetCredentials}>Reset saved credentials</button>
        </div>
      </section>

      <section className="panel">
        <h2>Current Inbox</h2>
        <p className="muted">Messages currently in <strong>{mailbox.inbox_folder || "the checked folder"}</strong> with saved scan information.</p>
        <div className="messageList">
          {checkedInbox.length === 0 && <p className="muted">No scanned current inbox messages found. Run Reevaluate folder to scan everything currently there.</p>}
          {checkedInbox.map((message) => (
              <article className="message" key={message.id}>
                <div className="messageBody">
                  <strong className="messageSubject">{message.subject || "No subject"}</strong>
                  <MessageSender sender={message.sender} />
                  <div className="messageBadges">
                    <span className="badge badgeSource">Source {message.source_folder || mailbox.inbox_folder || "Unknown"}</span>
                    {hasLlmInspection(message.analysis) ? <span className="badge badgeConfidence">Analysis {formatCheckedMessageConfidence(message.analysis)}</span> : null}
                  </div>
                  <InboxScanSummary message={message} />
                </div>
                <div className="actions">
                  <button onClick={() => markCheckedMessageAsSpam(message.id)}><Trash2 size={16} /> Quarantine</button>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>Quarantine</h2>
        <div className="messageList">
          {quarantine.length === 0 && <p className="muted">No messages are quarantined.</p>}
          {quarantine.map((message) => (
            <article className="message" key={message.id}>
              <div className="messageBody">
                <strong className="messageSubject">{message.subject || "No subject"}</strong>
                <MessageSender sender={message.sender} />
                <MessageExplanation explanation={message.explanation} />
              </div>
              <div className="actions"><button onClick={() => restore(message.id)}><Undo2 size={16} /> Restore</button><button onClick={() => markQuarantinedMessage(message.id)}><Trash2 size={16} /> Confirm spam</button></div>
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>Recent Activity</h2>
        <div className="timeline">
          {audit.length === 0 && <p className="muted">No activity recorded yet.</p>}
          {audit.map((event) => {
            const formatted = formatAuditEvent(event);
            return (
            <article className="timelineItem" key={event.id}>
              <CheckCircle2 size={16} />
              <div className="timelineBody">
                <strong>{formatted.title}</strong>
                {formatted.headline?.length ? <div className="timelineHeadlines">{formatted.headline.map((item) => <span className="timelineBadge" key={item}>{item}</span>)}</div> : null}
                {formatted.details ? <small className={formatted.detailsClassName ?? "timelineDetail"}>{formatted.details}</small> : null}
                {formatted.chips?.length ? <div className="timelineChips">{formatted.chips.map((item) => <span className="timelineChip" key={item}>{item}</span>)}</div> : null}
              </div>
              <time>{formatAuditTime(event.created_at)}</time>
            </article>
          );
        })}
        </div>
      </section>
    </main>
  );
}

function formatScanResult(result: ScanRunResult) {
  const message = result.message ?? "Scan completed.";
  const counts = [
    result.folder ? `folder ${result.folder}` : "",
    result.trigger ? `${result.trigger} trigger` : "",
    typeof result.duration_seconds === "number" ? `took ${formatDuration(result.duration_seconds)}` : "",
    typeof result.batch_size === "number" ? `batch size ${result.batch_size}` : "",
    typeof result.folder_message_count === "number" ? `${result.folder_message_count} in folder` : "",
    typeof result.candidate_count === "number" ? `${result.candidate_count} candidates` : "",
    typeof result.scanned === "number" ? `${result.scanned} scanned` : "",
    typeof result.clean === "number" ? `${result.clean} clean` : "",
    typeof result.review === "number" ? `${result.review} review` : "",
    typeof result.reevaluated === "number" ? `${result.reevaluated} reevaluated` : "",
    typeof result.missing_from_folder === "number" ? `${result.missing_from_folder} no longer in folder` : "",
    typeof result.skipped_existing === "number" ? `${result.skipped_existing} already scanned` : "",
    typeof result.quarantined === "number" ? `${result.quarantined} quarantined` : "",
    typeof result.failed === "number" ? `${result.failed} failed` : "",
    typeof result.deleted === "number" ? `${result.deleted} deleted` : ""
  ].filter(Boolean);
  return counts.length ? `${message} ${counts.join(", ")}.` : message;
}

function formatCheckedMessageConfidence(analysis: InboxMessage["analysis"]) {
  if (!analysis) {
    return "confidence N/A";
  }
  return `confidence ${Math.round(analysis.llm_confidence * 100)}%`;
}

function MessageSender({ sender }: { sender: string }) {
  const parsed = parseSender(sender);
  const fallback = parsed.email || parsed.name || "Unknown sender";
  const initial = (parsed.name || parsed.email || "?").trim().charAt(0).toUpperCase();

  return (
    <div className="messageSender" title={sender || fallback}>
      <span className="senderAvatar" aria-hidden="true">{initial}</span>
      <span className="senderText">
        <span className="senderName">{parsed.name || parsed.email || "Unknown sender"}</span>
        {parsed.email && parsed.email !== parsed.name ? <span className="senderEmail">{parsed.email}</span> : null}
      </span>
    </div>
  );
}

function MessageExplanation({ explanation }: { explanation: string }) {
  const formatted = formatMessageExplanation(explanation);
  return (
    <div className="messageExplanation">
      <div className="messageExplanationHeader">
        {formatted.source ? <span className="messageExplanationSource">{formatted.source}</span> : null}
        {formatted.headline ? <span className="messageExplanationHeadline">{formatted.headline}</span> : null}
      </div>
      {formatted.reasons.length ? (
        <ul className="messageExplanationReasons">
          {formatted.reasons.map((reason) => <li key={reason}>{reason}</li>)}
        </ul>
      ) : (
        <span className="messageExplanationText">{formatted.text || "No explanation recorded."}</span>
      )}
    </div>
  );
}

function InboxScanSummary({ message }: { message: InboxMessage }) {
  const analysis = message.analysis;
  if (!analysis) {
    return (
      <div className="scanSummary scanSummaryMuted">
        <span>{message.explanation}</span>
        <span>Status {message.status}, verdict {message.final_verdict}</span>
      </div>
    );
  }

  const llmProvider = analysis.llm_provider || "off";
  const hasConfidence = hasLlmInspection(analysis);
  const confidence = `${Math.round(analysis.llm_confidence * 100)}%`;
  const scanExplanation = formatScanExplanation(message.explanation);
  const indicators = uniqueSignals([...scanExplanation.phishingIndicators, ...analysis.suspicious_indicators]).slice(0, 8);
  const symbols = uniqueSignals([...scanExplanation.suspiciousSymbols, ...analysis.rspamd_symbols]).slice(0, 8);

  return (
    <div className="scanSummary">
      <div className="scanHeadline">
        <span className={`scanStatusIcon ${verdictClassName(message.final_verdict)}`} aria-hidden="true">
          <ScanStatusIcon verdict={message.final_verdict} />
        </span>
        <div className="scanHeadlineCopy">
          <span className={`verdictPill ${verdictClassName(message.final_verdict)}`}>{message.final_verdict}</span>
          <span className="scanHeadlineReason">{scanExplanation.text}</span>
        </div>
      </div>
      <div className="scanMetricGrid">
        <div className="scanMetric">
          <span>Rspamd score</span>
          <strong>{formatScore(analysis.rspamd_score)}</strong>
        </div>
        <div className="scanMetric">
          <span>Action</span>
          <strong>{analysis.rspamd_action}</strong>
        </div>
        <div className="scanMetric">
          <span>LLM</span>
          <strong>{llmProvider} {analysis.llm_verdict}</strong>
        </div>
        {hasConfidence ? (
          <div className="scanMetric">
            <span>Confidence</span>
            <strong>{confidence}</strong>
          </div>
        ) : null}
      </div>
      {symbols.length || indicators.length ? (
        <div className="signalGroups" aria-label="Analysis signals">
          {symbols.length ? (
            <div className="signalGroup">
              <span className="signalLabel">Rspamd</span>
              <div className="symbolChips" aria-label="Rspamd symbols">
                {symbols.map((symbol) => <SignalChip code={symbol} key={symbol} />)}
              </div>
            </div>
          ) : null}
          {indicators.length ? (
            <div className="signalGroup">
              <span className="signalLabel">Local</span>
              <div className="symbolChips" aria-label="Suspicious indicators">
                {indicators.map((indicator) => <SignalChip code={indicator} indicator key={indicator} />)}
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function ScanStatusIcon({ verdict }: { verdict: string }) {
  const normalized = verdict.toLowerCase();
  if (normalized === "review") {
    return <Clock size={16} />;
  }
  if (normalized === "spam") {
    return <ShieldCheck size={16} />;
  }
  return <CheckCircle2 size={16} />;
}

function SignalChip({ code, indicator = false }: { code: string; indicator?: boolean }) {
  const copy = getSignalCopy(code);
  const tooltip = `${copy.description} Raw signal: ${code}`;
  return (
    <span
      className={indicator ? "symbolChip symbolChipIndicator" : "symbolChip"}
      title={tooltip}
      aria-label={`${copy.label}: ${tooltip}`}
    >
      {copy.label}
    </span>
  );
}

function formatScanExplanation(explanation: string) {
  const suspiciousSymbols: string[] = [];
  const phishingIndicators: string[] = [];
  const text = explanation
    .trim()
    .replace(/\s*:?\s*(suspicious_symbols|phishing_indicators):([a-z0-9_,.-]+)/gi, (_match, kind: string, signals: string) => {
      if (kind.toLowerCase() === "phishing_indicators") {
        phishingIndicators.push(...splitSignalList(signals));
      } else {
        suspiciousSymbols.push(...splitSignalList(signals));
      }
      return "";
    })
    .replace(/\s+([,.;:!?])/g, "$1")
    .replace(/\s{2,}/g, " ")
    .replace(/:\s*$/, ".")
    .trim();

  return {
    text: text || "Suspicious Rspamd symbols triggered review.",
    suspiciousSymbols: uniqueSignals(suspiciousSymbols),
    phishingIndicators: uniqueSignals(phishingIndicators)
  };
}

function getSignalCopy(code: string) {
  const known = signalCopy[code];
  if (known) {
    return known;
  }

  return {
    label: titleCaseSignal(code),
    description: "Rspamd or the local scanner reported this technical signal."
  };
}

function titleCaseSignal(code: string) {
  return code
    .toLowerCase()
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function splitSignalList(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function uniqueSignals(values: string[]) {
  const seen = new Set<string>();
  return values.filter((value) => {
    const key = value.toLowerCase();
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function hasLlmInspection(analysis: InboxMessage["analysis"]) {
  if (!analysis) {
    return false;
  }

  const provider = analysis.llm_provider.toLowerCase();
  const verdict = analysis.llm_verdict.toLowerCase();
  return Boolean(provider) && provider !== "off" && verdict !== "skipped";
}

function verdictClassName(verdict: string) {
  const normalized = verdict.toLowerCase();
  if (normalized === "clean") {
    return "verdictClean";
  }
  if (normalized === "review") {
    return "verdictReview";
  }
  if (normalized === "spam") {
    return "verdictSpam";
  }
  return "verdictNeutral";
}

function formatAuditEvent(event: AuditEvent) {
  const label = event.event_type.replaceAll("_", " ");
  const details = event.details;
  const folder = textDetail(details.folder, "mailbox");
  if (event.event_type === "scan_failed") {
    const context = joinDetails([triggerDetail(details), `folder ${folder}`, durationDetail(details)]);
    return { title: label, details: `${textDetail(details.error, "unknown error")}${context ? ` (${context})` : ""}` };
  }
  if (event.event_type === "scan_mailbox_checked") {
    return {
      title: label,
      details: <><span className="timelineReadyFolder">{folder}</span><span>is ready for scanning</span></>,
      detailsClassName: "timelineReadyDetail",
      headline: [
        `${textDetail(details.folder_message_count, "unknown")} messages`,
        `${textDetail(details.candidate_count, "0")} candidates`,
        compactBatchDetail(details)
      ].filter(Boolean),
      chips: [detailWithLabel("UIDVALIDITY", details.uidvalidity)].filter(Boolean)
    };
  }
  if (event.event_type === "scan_completed") {
    return {
      title: label,
      details: scanCompletedSummary(details),
      headline: [
        triggerDetail(details),
        `folder ${folder}`,
        durationDetail(details)
      ].filter(Boolean),
      chips: [
        compactBatchDetail(details),
        `${textDetail(details.folder_message_count, "unknown")} in folder`,
        `${textDetail(details.candidate_count, "0")} candidates`,
        `${textDetail(details.scanned, "0")} scanned`,
        cleanDetail(details),
        reviewDetail(details),
        typeof details.reevaluated === "number" ? `${details.reevaluated} reevaluated` : "",
        typeof details.missing_from_folder === "number" ? `${details.missing_from_folder} no longer in folder` : "",
        `${textDetail(details.skipped_existing, "0")} already scanned`,
        `${textDetail(details.quarantined, "0")} quarantined`,
        `${textDetail(details.failed, "0")} failed`,
        `${textDetail(details.deleted, "0")} deleted`
      ].filter(Boolean)
    };
  }
  if (event.event_type === "scan_started") {
    return {
      title: label,
      details: "A new mailbox scan has started.",
      headline: [
        triggerDetail(details),
        `folder ${folder}`,
        compactBatchDetail(details)
      ].filter(Boolean),
      chips: [
        detailWithLabel("quarantine", details.quarantine_folder),
        thresholdDetail(details),
        autoDeleteDetail(details)
      ].filter(Boolean)
    };
  }
  if (event.event_type === "scan_disabled") {
    return { title: label, details: joinDetails([textDetail(details.reason, "Mailbox scanning is disabled."), triggerDetail(details), `folder ${folder}`]) };
  }
  if (event.event_type === "message_scanned") {
    const headline = [
      `verdict ${textDetail(details.verdict, "unknown")}`,
      detailWithLabel("score", textDetail(details.score, "n/a")),
      detailWithLabel("action", details.action),
      `thresholds uncertain ${textDetail(details.uncertain_score_threshold, "?")}, spam ${textDetail(details.spam_score_threshold, "?")}`
    ].filter(Boolean);

    const chips = [
      detailWithLabel("from", details.sender),
      detailWithLabel("subject", details.subject),
      llmDetail(details),
      indicatorsDetail(details),
      symbolsDetail(details),
      injectionDetail(details)
    ].filter(Boolean);

    return {
      title: label,
      details: textDetail(details.explanation, ""),
      headline,
      chips
    };
  }
  return { title: label, details: "" };
}

function textDetail(value: unknown, fallback = "") {
  return value === undefined || value === null || value === "" ? fallback : String(value);
}

function parseSender(sender: string) {
  const trimmed = sender.trim();
  const bracketMatch = trimmed.match(/^(.*?)\s*<([^<>@\s]+@[^<>\s]+)>\s*$/);
  if (bracketMatch) {
    return {
      name: cleanSenderName(bracketMatch[1]),
      email: bracketMatch[2].trim()
    };
  }

  const emailMatch = trimmed.match(/[^<>\s]+@[^<>\s]+/);
  if (emailMatch) {
    return {
      name: cleanSenderName(trimmed.replace(emailMatch[0], "")),
      email: emailMatch[0]
    };
  }

  return { name: cleanSenderName(trimmed), email: "" };
}

function cleanSenderName(value: string) {
  return value.trim().replace(/^["']|["']$/g, "");
}

function formatMessageExplanation(explanation: string) {
  const trimmed = explanation.trim();
  const llmMatch = trimmed.match(/^([a-z0-9_-]+)\s+marked\s+suspicious\s+message\s+as\s+spam:\s*(.*)$/i);
  if (llmMatch) {
    const reason = formatVerdictReasonText(llmMatch[2].trim());
    return {
      source: `${capitalize(llmMatch[1])} verdict`,
      headline: reason.headline,
      reasons: reason.reasons,
      text: reason.text
    };
  }

  return { source: "", headline: "", reasons: [], text: trimmed };
}

function formatVerdictReasonText(value: string) {
  const text = value.replace(/\s+/g, " ").trim();
  const headlineMatch = text.match(/^([^:]{8,80}):\s*(.+)$/);
  const headline = headlineMatch ? headlineMatch[1].trim() : "Why it was flagged";
  const detail = headlineMatch ? headlineMatch[2].trim() : text;
  const reasons = splitVerdictReasons(detail).slice(0, 4);

  return { headline, reasons, text };
}

function splitVerdictReasons(value: string) {
  const normalized = value
    .replace(/\(\s*(\d+)\s*\)/g, "; $1.")
    .replace(/\s{2,}/g, " ")
    .trim();

  const separator = normalized.includes(";") ? ";" : ",";
  return splitOutsideGroups(normalized, separator)
    .map((item) => item.replace(/^\s*(and\s+)?\d*[.)]?\s*/i, "").trim())
    .filter((item) => item.length > 0)
    .map((item) => item.replace(/[.;,]\s*$/, ""));
}

function splitOutsideGroups(value: string, separator: string) {
  const parts: string[] = [];
  let current = "";
  let depth = 0;
  let quote = "";

  for (const char of value) {
    if ((char === "'" || char === "\"") && depth >= 0) {
      quote = quote === char ? "" : quote || char;
    }

    if (!quote && char === "(") {
      depth += 1;
    } else if (!quote && char === ")" && depth > 0) {
      depth -= 1;
    }

    if (!quote && depth === 0 && char === separator) {
      parts.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  parts.push(current);
  return parts;
}

function capitalize(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function detailWithLabel(label: string, value: unknown) {
  const text = textDetail(value);
  return text ? `${label} ${text}` : "";
}

function joinDetails(parts: string[]) {
  return parts.filter(Boolean).join(", ");
}

function compactBatchDetail(details: Record<string, unknown>) {
  return typeof details.batch_size === "number" ? `batch ${details.batch_size}` : "";
}

function triggerDetail(details: Record<string, unknown>) {
  const trigger = textDetail(details.trigger);
  return trigger ? `${trigger} trigger` : "";
}

function durationDetail(details: Record<string, unknown>) {
  return typeof details.duration_seconds === "number" ? `took ${formatDuration(details.duration_seconds)}` : "";
}

function cleanDetail(details: Record<string, unknown>) {
  if (typeof details.clean === "number") {
    return `${details.clean} clean`;
  }
  if (typeof details.scanned === "number" && typeof details.quarantined === "number") {
    const review = typeof details.review === "number" ? details.review : 0;
    return `${Math.max(details.scanned - details.quarantined - review, 0)} clean`;
  }
  return "0 clean";
}

function reviewDetail(details: Record<string, unknown>) {
  return typeof details.review === "number" ? `${details.review} review` : "";
}

function formatDuration(seconds: number) {
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)} ms`;
  }
  return `${seconds >= 10 ? seconds.toFixed(0) : seconds.toFixed(1)} s`;
}

function formatScanInterval(seconds: number) {
  const preset = scanIntervalOptions.find((option) => option.value === seconds);
  if (preset) {
    return preset.label.replace(/^Every /, "");
  }
  if (seconds < 3600) {
    const minutes = Math.round(seconds / 60);
    return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  }
  if (seconds < 86400) {
    const hours = Math.round(seconds / 3600);
    return `${hours} hour${hours === 1 ? "" : "s"}`;
  }
  const days = Math.round(seconds / 86400);
  return `${days} day${days === 1 ? "" : "s"}`;
}

function thresholdDetail(details: Record<string, unknown>) {
  if (details.uncertain_score_threshold === undefined && details.spam_score_threshold === undefined) {
    return "";
  }
  return `thresholds uncertain ${textDetail(details.uncertain_score_threshold, "n/a")}, spam ${textDetail(details.spam_score_threshold, "n/a")}`;
}

function autoDeleteDetail(details: Record<string, unknown>) {
  if (details.auto_delete_enabled === false) {
    return "auto-delete off";
  }
  if (details.auto_delete_enabled === true) {
    return `auto-delete after ${textDetail(details.auto_delete_after_days, "?")} days`;
  }
  return "";
}

function scanCompletedSummary(details: Record<string, unknown>) {
  const scanned = numberDetail(details.scanned);
  const skipped = numberDetail(details.skipped_existing);
  const quarantined = numberDetail(details.quarantined);
  const failed = numberDetail(details.failed);

  if (failed > 0) {
    return `${failed} message${failed === 1 ? "" : "s"} failed during this scan.`;
  }
  if (quarantined > 0) {
    return `${quarantined} spam message${quarantined === 1 ? "" : "s"} moved to quarantine.`;
  }
  if (scanned === 0 && skipped > 0) {
    return "No new messages scanned. Everything in this batch was already checked.";
  }
  if (scanned > 0) {
    return `${scanned} message${scanned === 1 ? "" : "s"} scanned.`;
  }
  return "Scan finished.";
}

function numberDetail(value: unknown) {
  return typeof value === "number" ? value : 0;
}

function llmDetail(details: Record<string, unknown>) {
  const provider = textDetail(details.llm_provider);
  const verdict = textDetail(details.llm_verdict);
  if (!provider && !verdict) {
    return "";
  }
  const confidence = typeof details.llm_confidence === "number" ? ` ${Math.round(details.llm_confidence * 100)}%` : "";
  const reason = textDetail(details.llm_reason);
  return `LLM ${provider || "unknown"} ${verdict || "unknown"}${confidence}${reason ? `: ${reason}` : ""}`;
}

function symbolsDetail(details: Record<string, unknown>) {
  if (!Array.isArray(details.rspamd_symbols)) {
    return "";
  }
  const symbols = details.rspamd_symbols
    .map((symbol) => {
      if (!isRecord(symbol)) {
        return "";
      }
      const name = textDetail(symbol.name);
      if (!name) {
        return "";
      }
      const score = typeof symbol.score === "number" ? ` ${formatScore(symbol.score)}` : "";
      return `${name}${score}`;
    })
    .filter(Boolean)
    .slice(0, 8);
  return symbols.length ? `symbols ${symbols.join(", ")}` : "";
}

function indicatorsDetail(details: Record<string, unknown>) {
  if (!Array.isArray(details.suspicious_indicators) || details.suspicious_indicators.length === 0) {
    return "";
  }
  return `indicators ${details.suspicious_indicators.map(String).slice(0, 8).join(", ")}`;
}

function injectionDetail(details: Record<string, unknown>) {
  if (!Array.isArray(details.prompt_injection_markers) || details.prompt_injection_markers.length === 0) {
    return "";
  }
  return `prompt markers ${details.prompt_injection_markers.map(String).join(", ")}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatScore(value: number) {
  return Number.isInteger(value) ? String(value) : value.toFixed(2).replace(/0+$/, "").replace(/\.$/, "");
}

function formatAuditTime(value: string) {
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return parseApiDate(value).toLocaleString(undefined, {
    timeZone,
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short"
  });
}

function parseApiDate(value: string) {
  const hasTimeZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value);
  return new Date(hasTimeZone ? value : `${value}Z`);
}

function hasScanActivitySince(events: AuditEvent[], since: string) {
  const sinceTime = parseApiDate(since).getTime();
  return events.some((event) => event.event_type.startsWith("scan_") && parseApiDate(event.created_at).getTime() >= sinceTime);
}

function clientScanEvent(result?: ScanRunResult, error?: string, createdAt = new Date().toISOString()): AuditEvent {
  return {
    id: -Date.now(),
    event_type: error ? "scan_failed" : "scan_completed",
    details: error ? { error } : {
      scanned: result?.scanned ?? 0,
      skipped_existing: result?.skipped_existing ?? 0,
      reevaluated: result?.reevaluated ?? 0,
      quarantined: result?.quarantined ?? 0,
      review: result?.review ?? 0,
      missing_from_folder: result?.missing_from_folder ?? 0,
      deleted: result?.deleted ?? 0,
      clean: result?.clean ?? 0,
      failed: result?.failed ?? 0,
      folder: result?.folder,
      trigger: result?.trigger,
      batch_size: result?.batch_size,
      candidate_count: result?.candidate_count,
      folder_message_count: result?.folder_message_count,
      duration_seconds: result?.duration_seconds,
      source: "browser fallback"
    },
    created_at: createdAt
  };
}

function isMailboxUnconfigured(mailbox: MailboxSettings) {
  return !mailbox.email.trim() && !mailbox.has_password && !mailbox.enabled;
}

type MailProviderPreset = (typeof mailProviderPresets)[number];

function SetupWizard({
  presets,
  base,
  onSaved,
  onSkip
}: {
  presets: MailProviderPreset[];
  base: MailboxSettings;
  onSaved: (saved: MailboxSettings) => void;
  onSkip: () => void;
}) {
  const knownProvider = presets.some((preset) => preset.provider === base.provider);
  const [provider, setProvider] = useState(knownProvider ? base.provider : presets[0]?.provider ?? "custom");
  const [email, setEmail] = useState(base.email);
  const [password, setPassword] = useState("");
  const [customHost, setCustomHost] = useState(base.imap_host);
  const [customPort, setCustomPort] = useState(base.imap_port);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const selectedPreset = presets.find((preset) => preset.provider === provider);
  const host = selectedPreset ? selectedPreset.imap_host : customHost;
  const port = selectedPreset ? selectedPreset.imap_port : customPort;
  const canSubmit = email.trim().length > 0 && password.trim().length > 0 && host.trim().length > 0;

  function buildPayload(): MailboxPayload {
    return {
      ...base,
      provider,
      email: email.trim(),
      imap_host: host.trim(),
      imap_port: port,
      imap_username: email.trim(),
      password: password || undefined
    };
  }

  async function handleTest() {
    setBusy(true);
    setNotice("Testing connection...");
    setError("");
    try {
      const result = await testMailboxSettings(buildPayload());
      setNotice(result.ok ? result.message : "");
      setError(result.ok ? "" : result.message);
    } catch (err) {
      setNotice("");
      setError(err instanceof Error ? err.message : "Connection test failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleSave() {
    setBusy(true);
    setNotice("Saving mailbox settings...");
    setError("");
    try {
      const saved = await saveMailboxSettings({ ...buildPayload(), enabled: true });
      onSaved(saved);
    } catch (err) {
      setNotice("");
      setError(err instanceof Error ? err.message : "Could not save mailbox settings.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="wizardOverlay" role="dialog" aria-modal="true" aria-labelledby="wizardTitle">
      <div className="wizardCard">
        <header className="wizardHeader">
          <p className="eyebrow">Welcome</p>
          <h2 id="wizardTitle">Set up your mailbox</h2>
          <p className="muted">Pick your email provider and we'll fill in the IMAP server settings for you. You can change anything later in Settings.</p>
        </header>

        <div className="wizardProviders" role="radiogroup" aria-label="Email provider">
          {presets.map((preset) => (
            <button
              type="button"
              key={preset.provider}
              role="radio"
              aria-checked={provider === preset.provider}
              className={provider === preset.provider ? "providerTile providerTileActive" : "providerTile"}
              onClick={() => setProvider(preset.provider)}
            >
              <strong>{preset.label}</strong>
              <span>{preset.imap_host}</span>
            </button>
          ))}
          <button
            type="button"
            role="radio"
            aria-checked={provider === "custom"}
            className={provider === "custom" ? "providerTile providerTileActive" : "providerTile"}
            onClick={() => setProvider("custom")}
          >
            <strong>Custom IMAP server</strong>
            <span>Enter host and port manually</span>
          </button>
        </div>

        {selectedPreset?.note ? <p className="inlineHint">{selectedPreset.note}</p> : null}

        <div className="wizardFields">
          <FieldRow>
            <label>Email address<input type="email" value={email} placeholder="you@example.com" onChange={(event) => setEmail(event.target.value)} /></label>
            <label>Password<input type="password" value={password} placeholder="Mailbox or app password" onChange={(event) => setPassword(event.target.value)} /></label>
          </FieldRow>
          {provider === "custom" ? (
            <FieldRow compact>
              <label>IMAP host<input value={customHost} placeholder="imap.example.com" onChange={(event) => setCustomHost(event.target.value)} /></label>
              <label>Port<input type="number" value={customPort} onChange={(event) => setCustomPort(Number(event.target.value))} /></label>
            </FieldRow>
          ) : (
            <p className="wizardServerInfo">IMAP server <strong>{host}:{port}</strong> over TLS, filled in automatically.</p>
          )}
        </div>

        {notice ? <div className="notice">{notice}</div> : null}
        {error ? <div className="error">{error}</div> : null}

        <div className="wizardActions">
          <button type="button" className="wizardSkip" onClick={onSkip} disabled={busy}>Skip for now</button>
          <div className="actions">
            <button type="button" onClick={handleTest} disabled={busy || !canSubmit}>Test connection</button>
            <button type="button" className="primaryButton" onClick={handleSave} disabled={busy || !canSubmit}>Save &amp; continue</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function SettingsSection({ title, status, children }: { title: string; status: ReactNode; children: ReactNode }) {
  return (
    <section className="settingsSection">
      <div className="settingsSectionHeader">
        <h3>{title}</h3>
        {status}
      </div>
      <div className="settingsSectionBody">{children}</div>
    </section>
  );
}

function FieldRow({ children, compact = false }: { children: ReactNode; compact?: boolean }) {
  return <div className={compact ? "fieldRow fieldRowCompact" : "fieldRow"}>{children}</div>;
}

function InlineStatus({ label, tone }: { label: string; tone: string }) {
  return <span className={`inlineStatus inlineStatus${capitalize(tone)}`}>{label}</span>;
}

function AdvancedDisclosure({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="advancedDisclosure">
      <summary>{title}</summary>
      <div className="advancedDisclosureBody">{children}</div>
    </details>
  );
}

function mailboxSettingsChanged(current: MailboxSettings, saved: MailboxSettings) {
  return current.provider !== saved.provider
    || current.email !== saved.email
    || current.imap_host !== saved.imap_host
    || current.imap_port !== saved.imap_port
    || current.imap_username !== saved.imap_username
    || current.inbox_folder !== saved.inbox_folder
    || current.quarantine_folder !== saved.quarantine_folder
    || current.poll_interval_seconds !== saved.poll_interval_seconds
    || current.auto_delete_enabled !== saved.auto_delete_enabled
    || current.auto_delete_after_days !== saved.auto_delete_after_days
    || current.spam_score_threshold !== saved.spam_score_threshold
    || current.uncertain_score_threshold !== saved.uncertain_score_threshold
    || current.enabled !== saved.enabled;
}

function llmSettingsChanged(current: LlmSettings, saved: LlmSettings) {
  return current.provider !== saved.provider
    || current.model !== saved.model
    || current.enabled !== saved.enabled
    || current.send_body_excerpt !== saved.send_body_excerpt
    || current.max_excerpt_chars !== saved.max_excerpt_chars;
}

function normalizeLlmSettings(settings: LlmSettings): LlmSettings {
  return {
    ...settings,
    send_body_excerpt: settings.send_body_excerpt ?? true,
    max_excerpt_chars: settings.max_excerpt_chars ?? BODY_EXCERPT_CHARS
  };
}

function StatusCard({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return <article className="statusCard"><div>{icon}</div><p>{label}</p><strong>{value}</strong></article>;
}
