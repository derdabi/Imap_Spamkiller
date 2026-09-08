# IMAP SpamKiller

Self-hosted email protection with local Rspamd scoring and optional **LLM-assisted spam and phishing review through OpenAI or Anthropic**. Run it on a NAS or server with Docker Compose or Podman Compose and connect an IMAP mailbox.

## What It Does

- Combines local spam scoring with optional LLM review of uncertain or suspicious messages.
- Lets you choose OpenAI or Anthropic, select a model, and test the connection from the web UI.
- Records LLM verdicts, confidence, explanations, and the signals that triggered review in the audit history.
- Checks one IMAP folder repeatedly, processing previously unscanned messages in batches.
- Moves high-confidence spam to `SpamKiller/Quarantine`.
- Lets you restore quarantined messages from the web UI.
- Automatically deletes quarantined mail after a configurable retention period, default `15` days.

## LLM-Assisted Review

Rspamd scans messages locally first. When cloud review is enabled, SpamKiller can ask an LLM to assess messages that need more context:

- **Borderline scores:** messages between the review and quarantine thresholds, default `4.0` and `6.0`.
- **Suspicious messages with low scores:** forged-sender signals or combinations of indicators such as sender/reply-to mismatches, hidden Unicode, obfuscated subjects, and suspicious links can also trigger review.

The model returns a `spam`, `clean`, or `unsure` verdict, a confidence value, and a short explanation. A `spam` verdict with confidence of at least `0.75` can move a suspicious message to quarantine. A high-confidence `clean` verdict can resolve a borderline score when no stronger rule requires quarantine or manual review. Low-score messages with suspicious indicators remain marked for review unless classified as high-confidence spam.

For example, a message scoring `4.5` can be quarantined after a confident LLM spam verdict or classified as clean after a confident clean verdict. A message scoring below `4.0` can still receive LLM review if suspicious signals are strong enough. Confidence is the model's reported value, not a guarantee of correctness.

### Enable Cloud Review

1. Open **Settings → Cloud LLM** in the web UI.
2. Choose **OpenAI** or **Anthropic** and enter an API key for that provider.
3. Select or enter a model supported by the provider's text classification endpoint. The UI can load available model IDs; not every listed model is suitable for this task.
4. Choose whether to send a body excerpt, test the connection, and save the LLM settings.
5. Use **Scan now** to process unscanned mail, or **Reevaluate folder** to apply the current settings to previously scanned messages. Previously restored messages remain protected from automatic quarantine.

Select **Off** to disable cloud classification. Local Rspamd scanning continues to work without an LLM API key.

### What Is Sent to the LLM?

Cloud review sends the subject, sender, reply-to, sender and reply-to domains, extracted link domains, Rspamd score/action/symbols, and detected suspicious indicators. A plain-text body excerpt of up to `12,000` characters is included by default and can be disabled in the UI.

Attachments, including the contents of attached emails, are excluded from the excerpt. Disabling the excerpt still allows email metadata and extracted link domains to be sent. LLM review is optional and disabled by default; when enabled, selected message data leaves your server for the chosen provider.

Email fields are treated as untrusted data. Detected prompt-injection markers are recorded in the audit history and downgrade a model's `clean` verdict to `unsure`. Failed LLM requests do not stop local decision-making, and an LLM clean verdict does not override Rspamd quarantine rules.

## How Quarantine Decisions Work

| Signal | Result |
| --- | --- |
| LLM returns `spam` with confidence ≥ `0.75` | Quarantine |
| Rspamd score reaches the quarantine threshold, or action is `reject`, `quarantine`, or `discard` | Quarantine |
| Rspamd action is `add header`, `rewrite subject`, `soft reject`, or `greylist` | Manual review, unless a quarantine rule above applies |
| Borderline score with a high-confidence LLM `clean` verdict | Clean, unless a stronger rule above applies |
| Borderline score without a decisive LLM result, or low score with strong suspicious indicators | Manual review |
| Low score without a suspicious-indicator trigger | Clean |

Messages marked for review stay in the scanned folder. You can confirm them as spam from the UI to move them to quarantine and start their retention period. Quarantined messages can be restored from the UI before confirmation; confirming spam removes it from the quarantine list. Automatic deletion uses time spent in quarantine, not the message's original date.

## Safety Model

- The scanner uses `BODY.PEEK[]` so messages are not marked read while scanning.
- New spam is moved to quarantine first.
- Auto-delete only applies to messages already in quarantine and older than the configured retention period.
- Cloud LLM classification is disabled by default.
- Attachments are never sent to cloud LLMs.
- Email content is treated as untrusted data. Prompt-injection-like text in a message is flagged, included in audit details, and prevents the LLM from turning an uncertain message into a trusted clean verdict.

## Quick Start With Docker

```bash
docker compose up --build
```

Open `http://localhost:8080`.

Enter your mailbox's IMAP host, port, username, and password in the web UI, choose the scan and quarantine folders, test the connection, and enable scanning. Use an app-specific password if your mail provider requires one. To add cloud review, follow [Enable Cloud Review](#enable-cloud-review).

The app creates and stores its own encryption secret in the persistent data folder. It does not use built-in web-user authentication.

## Quick Start With Podman

Podman can use the same Compose file and Dockerfile.

```bash
podman compose up -d --build
```

If your system uses the older standalone Compose wrapper, use:

```bash
podman-compose up -d --build
```

Manual fallback:

```bash
podman build -t imap-spamkiller:local .
podman compose up -d
```

The repository also includes a `Containerfile` and `.containerignore` for Podman/Buildah users. They mirror the Docker build setup.

## Podman Notes

- Rootless Podman works with the default `8080:8080` port mapping.
- Avoid ports below `1024` in rootless mode unless your OS is explicitly configured for it.
- Named volumes are used by default and work on Docker and Podman.
- If you change named volumes to bind mounts on SELinux systems, add `:Z`, for example `/srv/spamkiller/data:/data:Z`.
- The app and worker intentionally use the same local image name: `imap-spamkiller:local`.
- Keep the app LAN-only unless you have added HTTPS and a hardened reverse-proxy setup.

## NAS Deployment

1. Install Docker, Container Manager, or Podman on the NAS.
2. Copy this project to a persistent share.
3. Run `docker compose up -d --build` or `podman compose up -d --build`.
4. Open `http://NAS-IP:8080` from your LAN.

## Credential Recovery

Mailbox passwords and optional LLM API keys are encrypted automatically. If the app ever reports that saved credentials can't be read, open the web UI and click `Reset saved credentials`, then re-enter the mailbox password and API key if needed.

Advanced deployments can still set `APP_SECRET` explicitly. Keep it stable after credentials are saved, because changing it makes saved credentials unreadable.

Do not expose this directly to the internet without HTTPS and a hardened reverse proxy such as Caddy or Traefik. Add your preferred authentication at the network/proxy layer instead of in the app.

## Architecture

```text
React UI -> FastAPI app -> SQLite volume
                       -> worker loop -> IMAP mailbox
                                    -> Rspamd
                                    -> OpenAI/Anthropic optional
```

## Current Limitations

- Single mailbox only by design.
- Restore and auto-delete identify quarantined mail by `Message-ID`; unusual messages without that header may require manual handling in the mail client.
- IMAP connections use TLS and password login; OAuth-only mailbox authentication is not implemented. Safe message moves and deletion require the server to advertise `UIDPLUS`.
- There is no built-in web-user authentication. Use authentication and HTTPS at the reverse proxy or network layer before any remote exposure.
- Rspamd learning hooks are not wired yet; confirmation events are stored for the next iteration.

## Help

The web UI has a **Help** button in the top-right corner that explains what the app does, how scoring decisions are made, and how to set it up. Most fields and buttons also show a short explanation on hover.

## Local Development

This is only needed to hack on the code or run the tests. To just run the app, use Docker/Podman above.

- **Linux/macOS:** `./dev-setup.sh` creates a `.venv` and installs backend and frontend dependencies, then prints the commands to run the tests and the dev servers.
- **Windows:** `./start-debug.ps1` sets up the same environment and launches the backend and frontend dev servers (use `-SkipInstall` on later runs).

The Vite dev server proxies `/api` to the backend, so open the frontend URL during development.

With backend dependencies installed, run the regression tests from the `backend` directory:

```bash
python -m unittest discover -s tests -v
```

Build and type-check the frontend from the repository root:

```bash
npm --prefix frontend run build
```

## License

Released under the [MIT License](LICENSE).
