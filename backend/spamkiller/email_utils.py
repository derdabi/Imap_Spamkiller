import html
import re
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.policy import default
from email.utils import parsedate_to_datetime


DOMAIN_RE = re.compile(r"https?://([^/\s\"'>)]+)", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")


def parse_message(raw: bytes) -> EmailMessage | Message:
    return BytesParser(policy=default).parsebytes(raw)


def header_text(message: Message, name: str) -> str:
    value = message.get(name, "")
    return str(value or "")


def message_received_at(message: Message):
    date_header = header_text(message, "Date")
    if not date_header:
        return None
    try:
        return parsedate_to_datetime(date_header)
    except (TypeError, ValueError):
        return None


def extract_plain_text(message: Message, max_chars: int) -> str:
    parts: list[str] = []
    html_parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if part.get_content_type() == "text/plain":
                parts.append(content)
            elif part.get_content_type() == "text/html":
                html_parts.append(content)
    elif message.get_content_type() == "text/plain":
        try:
            parts.append(message.get_content())
        except Exception:
            pass
    elif message.get_content_type() == "text/html":
        try:
            html_parts.append(message.get_content())
        except Exception:
            pass
    if not parts and html_parts:
        parts.extend(_html_to_text(part) for part in html_parts)
    text = "\n".join(parts)
    return re.sub(r"\s+", " ", text).strip()[:max_chars]


def extract_link_domains(text: str) -> list[str]:
    domains = {match.group(1).lower().removeprefix("www.") for match in DOMAIN_RE.finditer(text)}
    return sorted(domains)[:20]


def _html_to_text(value: str) -> str:
    urls = " ".join(match.group(0) for match in DOMAIN_RE.finditer(value))
    value = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", value)
    value = re.sub(r"(?i)</\s*(p|div|li|tr|h[1-6])\s*>", "\n", value)
    return html.unescape(f"{TAG_RE.sub(' ', value)} {urls}")
