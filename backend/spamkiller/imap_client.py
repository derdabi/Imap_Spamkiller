import imaplib
import re

from .crypto import decrypt_secret
from .models import MailboxSettings


def connect(settings: MailboxSettings) -> imaplib.IMAP4_SSL:
    password = decrypt_secret(settings.encrypted_password)
    if not password:
        raise RuntimeError("Mailbox password is not configured.")
    client = imaplib.IMAP4_SSL(settings.imap_host, settings.imap_port, timeout=45)
    client.login(settings.imap_username or settings.email, password)
    return client


def ensure_folder(client: imaplib.IMAP4_SSL, folder: str) -> None:
    current = ""
    for part in folder.split("/"):
        current = part if not current else f"{current}/{part}"
        client.create(_quote(current))


def list_folders(client: imaplib.IMAP4_SSL) -> list[str]:
    status, data = client.list()
    if status != "OK" or not data:
        raise RuntimeError("Could not list mailbox folders.")
    folders: list[str] = []
    for item in data:
        if isinstance(item, bytes):
            folder = _parse_list_folder(item.decode("utf-8", errors="replace"))
            if folder:
                folders.append(folder)
    return sorted(set(folders), key=str.casefold)


def list_recent_uids(client: imaplib.IMAP4_SSL, folder: str, limit: int | None) -> tuple[str, list[str], int | None]:
    status, data = client.select(_quote(folder), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Could not select folder {folder}.")
    message_count = _selected_message_count(data)
    uidvalidity = _selected_uidvalidity(client, folder)
    status, data = client.uid("SEARCH", None, "ALL")
    if status != "OK":
        raise RuntimeError(f"Could not search folder {folder} for message UIDs.")
    if not data or not data[0]:
        if message_count:
            raise RuntimeError(f"Folder {folder} reports {message_count} messages, but UID SEARCH ALL returned no UIDs.")
        return uidvalidity, [], message_count
    uids = data[0].decode("ascii", errors="ignore").split()
    return uidvalidity, uids[-limit:] if limit else uids, message_count


def fetch_raw(client: imaplib.IMAP4_SSL, uid: str) -> bytes:
    status, data = client.uid("FETCH", uid, "(BODY.PEEK[])")
    if status != "OK":
        raise RuntimeError(f"Could not fetch message UID {uid}.")
    for item in data:
        if isinstance(item, tuple):
            return item[1]
    raise RuntimeError(f"Message UID {uid} had no body.")


def move_uid(client: imaplib.IMAP4_SSL, source_folder: str, uid: str, destination_folder: str) -> None:
    _require_uid_expunge(client)
    ensure_folder(client, destination_folder)
    status, _ = client.select(_quote(source_folder), readonly=False)
    if status != "OK":
        raise RuntimeError(f"Could not select folder {source_folder}.")
    status, _ = client.uid("COPY", uid, _quote(destination_folder))
    if status != "OK":
        raise RuntimeError(f"Could not copy UID {uid} to {destination_folder}.")
    status, _ = client.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
    if status != "OK":
        raise RuntimeError(f"Could not delete UID {uid} after copying to {destination_folder}.")
    status, _ = client.uid("EXPUNGE", uid)
    if status != "OK":
        raise RuntimeError(f"Could not UID EXPUNGE UID {uid} from {source_folder}.")


def move_by_message_id(client: imaplib.IMAP4_SSL, source_folder: str, message_id: str, destination_folder: str) -> int:
    _require_uid_expunge(client)
    ensure_folder(client, destination_folder)
    uids = search_by_message_id_in_folder(client, source_folder, message_id)
    for uid in uids:
        status, _ = client.uid("COPY", uid, _quote(destination_folder))
        if status != "OK":
            raise RuntimeError(f"Could not copy UID {uid} to {destination_folder}.")
        status, _ = client.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if status != "OK":
            raise RuntimeError(f"Could not delete UID {uid} after copying to {destination_folder}.")
    if uids:
        status, _ = client.uid("EXPUNGE", ",".join(uids))
        if status != "OK":
            raise RuntimeError(f"Could not UID EXPUNGE messages from {source_folder}.")
    return len(uids)


def move_by_message_id_anywhere(client: imaplib.IMAP4_SSL, folders: list[str], message_id: str, destination_folder: str) -> int:
    for folder in folders:
        try:
            moved = move_by_message_id(client, folder, message_id, destination_folder)
        except RuntimeError:
            continue
        if moved:
            return moved
    return 0


def delete_by_message_id(client: imaplib.IMAP4_SSL, folder: str, message_id: str) -> int:
    _require_uid_expunge(client)
    uids = search_by_message_id_in_folder(client, folder, message_id)
    for uid in uids:
        status, _ = client.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if status != "OK":
            raise RuntimeError(f"Could not delete UID {uid} from {folder}.")
    if uids:
        status, _ = client.uid("EXPUNGE", ",".join(uids))
        if status != "OK":
            raise RuntimeError(f"Could not UID EXPUNGE messages from {folder}.")
    return len(uids)


def delete_by_message_id_anywhere(client: imaplib.IMAP4_SSL, folders: list[str], message_id: str) -> int:
    for folder in folders:
        try:
            removed = delete_by_message_id(client, folder, message_id)
        except RuntimeError:
            continue
        if removed:
            return removed
    return 0


def search_by_message_id(client: imaplib.IMAP4_SSL, message_id: str) -> list[str]:
    status, data = client.uid("SEARCH", None, "HEADER", "Message-ID", _quote(message_id))
    if status != "OK" or not data or not data[0]:
        return []
    return data[0].decode("ascii", errors="ignore").split()


def search_by_message_id_in_folder(client: imaplib.IMAP4_SSL, folder: str, message_id: str) -> list[str]:
    status, _ = client.select(_quote(folder), readonly=False)
    if status != "OK":
        raise RuntimeError(f"Could not select folder {folder}.")
    return search_by_message_id(client, message_id)


def locate_message_id_in_folder(client: imaplib.IMAP4_SSL, folder: str, message_id: str) -> tuple[str, list[str]]:
    status, _ = client.select(_quote(folder), readonly=True)
    if status != "OK":
        raise RuntimeError(f"Could not select folder {folder}.")
    uidvalidity = _selected_uidvalidity(client, folder)
    return uidvalidity, search_by_message_id(client, message_id)


def search_message_id_across_folders(client: imaplib.IMAP4_SSL, folders: list[str], message_id: str) -> tuple[str | None, int]:
    for folder in folders:
        uids = search_by_message_id_in_folder(client, folder, message_id)
        if uids:
            return folder, len(uids)
    return None, 0


def logout_quietly(client: imaplib.IMAP4_SSL | None) -> None:
    if not client:
        return
    try:
        client.logout()
    except Exception:
        pass


def _quote(value: str) -> str:
    escaped = value.replace('"', '\\"')
    return f'"{escaped}"'


def _require_uid_expunge(client: imaplib.IMAP4_SSL) -> None:
    capabilities = set()
    for item in getattr(client, "capabilities", ()) or ():
        text = item.decode("ascii", errors="ignore") if isinstance(item, bytes) else str(item)
        capabilities.update(part.upper() for part in text.split())
    if not capabilities and hasattr(client, "capability"):
        try:
            status, data = client.capability()
        except Exception:
            status, data = "NO", []
        if status == "OK":
            for item in data or []:
                text = item.decode("ascii", errors="ignore") if isinstance(item, bytes) else str(item)
                capabilities.update(part.upper() for part in text.split())
    if "UIDPLUS" not in capabilities:
        raise RuntimeError("IMAP server does not advertise UIDPLUS, so messages cannot be safely expunged by UID.")


def _selected_uidvalidity(client: imaplib.IMAP4_SSL, folder: str) -> str:
    status, data = client.response("UIDVALIDITY")
    if status == "OK" and data:
        for item in data:
            if item:
                return item.decode("ascii", errors="ignore") if isinstance(item, bytes) else str(item)
    status, data = client.status(_quote(folder), "(UIDVALIDITY)")
    if status == "OK" and data:
        for item in data:
            value = item.decode("ascii", errors="ignore") if isinstance(item, bytes) else str(item)
            match = re.search(r"\bUIDVALIDITY\s+(\d+)", value, flags=re.IGNORECASE)
            if match:
                return match.group(1)
    return "unknown"


def _selected_message_count(data) -> int | None:
    if not data:
        return None
    first = data[0]
    if isinstance(first, bytes):
        first = first.decode("ascii", errors="ignore")
    try:
        return int(first)
    except (TypeError, ValueError):
        return None


def _parse_list_folder(line: str) -> str:
    match = re.search(r'\s(?:"((?:\\.|[^"\\])*)"|([^\s]+))$', line)
    if not match:
        return ""
    return (match.group(1) or match.group(2) or "").replace('\\"', '"')
