# IMAP SpamKiller

Self-hosted spam quarantine for one IMAP mailbox. The first target is a t-online.de mailbox running on a home NAS through Docker Compose or Podman Compose.

## What It Does

- Checks one IMAP inbox repeatedly.
- Scores messages with local Rspamd and uses Rspamd actions for quarantine decisions.
- Optionally asks OpenAI or Anthropic only for uncertain messages.
- Moves high-confidence spam to `SpamKiller/Quarantine`.
- Lets you restore quarantined messages from the web UI.
- Automatically deletes quarantined mail after a configurable retention period, default `15` days.

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

## Cloud LLM

Supported providers:

- OpenAI
- Anthropic

The LLM is only used when the Rspamd score is between the review threshold and the quarantine threshold and Rspamd did not already return a spam action. By default, the app sends subject, sender, reply-to, link domains, Rspamd symbols, and a short plain-text body excerpt. LLM responses are normalized to the allowed verdicts, malformed responses become `unsure`, and detected prompt-injection markers downgrade any LLM `clean` verdict to `unsure`.

Default thresholds are `4.0` for review and `6.0` for quarantine. Rspamd actions such as `add header`, `rewrite subject`, `reject`, `quarantine`, or `discard` are quarantined even if the numeric score is lower.

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
- Built-in authentication is intentionally simple. Use HTTPS and a reverse proxy before any remote exposure.
- Rspamd learning hooks are not wired yet; confirmation events are stored for the next iteration.

## Help

The web UI has a **Help** button in the top-right corner that explains what the app does, how scoring decisions are made, and how to set it up. Most fields and buttons also show a short explanation on hover.

## Local Development

This is only needed to hack on the code or run the tests. To just run the app, use Docker/Podman above.

- **Linux/macOS:** `./dev-setup.sh` creates a `.venv` and installs backend and frontend dependencies, then prints the commands to run the tests and the dev servers.
- **Windows:** `./start-debug.ps1` sets up the same environment and launches the backend and frontend dev servers (use `-SkipInstall` on later runs).

The Vite dev server proxies `/api` to the backend, so open the frontend URL during development.

## License

Released under the [MIT License](LICENSE).
