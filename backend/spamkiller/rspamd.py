from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import ipaddress
import re

import httpx

from .config import get_settings


@dataclass
class RspamdResult:
    score: float
    action: str
    symbols: dict
    source_ip: str | None = None


_IP_LITERAL_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<=\[)[0-9a-fA-F:.]{3,}(?=\])")
_RECEIVED_BY_RE = re.compile(r"\sby\s", re.IGNORECASE)
MAX_INTERNAL_RECEIVED_HOPS = 5


async def scan_with_rspamd(raw_message: bytes, *, rcpt: str | None = None) -> RspamdResult:
    settings = get_settings()
    url = settings.rspamd_url.rstrip("/") + "/checkv2"
    headers = {"Content-Type": "message/rfc822"}
    metadata = extract_scan_metadata(raw_message, rcpt=rcpt)
    headers.update(metadata)
    if settings.rspamd_settings_id:
        headers["Settings-ID"] = settings.rspamd_settings_id
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, content=raw_message, headers=headers)
        response.raise_for_status()
        payload = response.json()
    return RspamdResult(
        score=float(payload.get("score", 0.0) or 0.0),
        action=str(payload.get("action", "no action")),
        symbols=payload.get("symbols", {}) or {},
        source_ip=metadata.get("IP"),
    )


def extract_scan_metadata(raw_message: bytes, *, rcpt: str | None = None) -> dict[str, str]:
    headers = {}
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
    except Exception:
        message = None

    if message is not None:
        source_ip = _trusted_source_ip_from_message(message)
        if source_ip:
            headers["IP"] = source_ip

        mail_from = _first_address(message.get_all("Return-Path", []) or []) or _first_address(message.get_all("From", []) or [])
        if mail_from:
            headers["From"] = mail_from

    if rcpt:
        headers["Rcpt"] = rcpt

    return headers


def extract_public_source_ip(raw_message: bytes) -> str | None:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
    except Exception:
        return None

    return _trusted_source_ip_from_message(message)


def _trusted_source_ip_from_message(message) -> str | None:
    # Without a client IP Rspamd treats the message as local and skips SPF, DKIM, DMARC and RBL checks.
    # The newest Received headers come from the provider's own relays (e.g. t-online's internal 10.x hops),
    # so skip hops without a public sender IP; the first public one is what the provider's MX saw.
    # Headers below that hop can be forged by the sender and are never consulted.
    received_headers = message.get_all("Received", []) or []
    for header in received_headers[:MAX_INTERNAL_RECEIVED_HOPS]:
        from_part = _RECEIVED_BY_RE.split(str(header), maxsplit=1)[0]
        for value in _IP_LITERAL_RE.findall(from_part):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global:
                return str(address)
    return None


def _first_address(values: list[str]) -> str:
    for _name, address in getaddresses([str(value) for value in values]):
        if address:
            return address
    return ""
