"""Core parsing, timestamp, transport, scheduling, and reporting logic.

The module has no third-party runtime dependencies and is deliberately usable
from both the Tk GUI and the command-line interface.
"""
from __future__ import annotations

import copy
import csv
import dataclasses
import datetime as dt
import hashlib
import http.client
import io
import itertools
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
import urllib.parse
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

UTC = dt.timezone.utc
APP_VERSION = "1.1.23"


class ReplayError(Exception):
    """Base exception for replay failures."""


class ParseError(ReplayError):
    """Raised when the selected input format is invalid."""


class ConfigurationError(ReplayError):
    """Raised when a replay configuration is invalid."""


@dataclasses.dataclass(slots=True)
class Event:
    """One source event.

    In exact pass-through mode, ``value`` is the original byte sequence read
    from the source file, including its original line terminator when present.
    Legacy parsed modes may still use strings or JSON-compatible values.
    """

    value: Any
    index: int
    timestamp: dt.datetime | None = None
    timestamp_hint: dict[str, Any] | None = None


@dataclasses.dataclass(slots=True)
class SendResult:
    ok: bool
    status: int | None
    message: str
    attempts: int = 1
    response_body: str = ""


@dataclasses.dataclass(slots=True)
class ReplaySummary:
    run_id: str
    status: str
    started_at: str
    completed_at: str
    source_sha256: str
    source_mode: str
    source_bytes: int
    records_read: int
    records_sent: int
    records_failed: int
    requests_failed: int
    retries: int
    loops_completed: int
    average_eps: float
    destination: str
    failed_records_file: str | None = None
    report_file: str | None = None


ISO_RE = re.compile(
    r"(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)"
)
RFC3164_RE = re.compile(
    r"(?P<rfc3164>\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\b)"
)
CEF_RT_RE = re.compile(r"(?P<prefix>\brt=)(?P<value>\d{10,13}|[^|]*?)(?=\s+\w+=|$)")
TIMESTAMP_KEYS = {
    "timestamp",
    "@timestamp",
    "time",
    "eventtime",
    "event_time",
    "eventtimestamp",
    "event_timestamp",
    "datetime",
    "date_time",
    "rt",
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(tz=UTC)


def iso_z(value: dt.datetime) -> str:
    value = ensure_aware(value).astimezone(UTC)
    text = value.isoformat(timespec="milliseconds")
    return text.replace("+00:00", "Z")


def ensure_aware(value: dt.datetime, default_tz: dt.tzinfo = UTC) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=default_tz)
    return value


def parse_datetime(value: Any, *, reference: dt.datetime | None = None) -> dt.datetime | None:
    """Parse common JSON, ISO, epoch, RFC5424, RFC3164, and CEF timestamp forms."""
    reference = ensure_aware(reference or utc_now())
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:  # milliseconds
            number /= 1000.0
        if number > 0:
            try:
                return dt.datetime.fromtimestamp(number, tz=UTC)
            except (ValueError, OSError, OverflowError):
                return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{10,13}", text):
        return parse_datetime(int(text), reference=reference)

    normalized = text.replace(",", ".")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        parsed = dt.datetime.fromisoformat(normalized)
        return ensure_aware(parsed).astimezone(UTC)
    except ValueError:
        pass

    # RFC3164 has no year; prefix the reference year to avoid ambiguous strptime behavior.
    for rfc_pattern in ("%Y %b %d %H:%M:%S", "%Y %b  %d %H:%M:%S"):
        try:
            parsed = dt.datetime.strptime(f"{reference.year} {text}", rfc_pattern)
            if parsed - reference.replace(tzinfo=None) > dt.timedelta(days=180):
                parsed = parsed.replace(year=reference.year - 1)
            return parsed.replace(tzinfo=reference.tzinfo).astimezone(UTC)
        except ValueError:
            continue
    for pattern in (
        "%b %d %Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            parsed = dt.datetime.strptime(text, pattern)
            return parsed.replace(tzinfo=reference.tzinfo).astimezone(UTC)
        except ValueError:
            continue
    return None


def _first_nonempty_lines(text: str, limit: int = 25) -> list[str]:
    result: list[str] = []
    for line in text.splitlines():
        if line.strip():
            result.append(line.strip())
        if len(result) >= limit:
            break
    return result


def detect_format(text: str) -> str:
    """Conservatively detect a supported format without losing ambiguous raw logs."""
    stripped = text.lstrip("\ufeff\r\n \t")
    if not stripped:
        return "raw"

    if stripped[0] in "[{":
        try:
            json.loads(stripped)
            return "json"
        except json.JSONDecodeError:
            pass

    lines = _first_nonempty_lines(text)
    if not lines:
        return "raw"

    if len(lines) >= 2:
        valid_json_lines = 0
        for line in lines:
            try:
                value = json.loads(line)
                if isinstance(value, (dict, list)):
                    valid_json_lines += 1
            except json.JSONDecodeError:
                break
        if valid_json_lines == len(lines):
            return "ndjson"

    first = lines[0]
    if "CEF:" in first:
        return "cef"
    if re.match(r"^<\d{1,3}>1\s", first):
        return "rfc5424"
    if re.match(r"^<\d{1,3}>", first):
        return "rfc3164"

    # CSV detection is intentionally strict to avoid treating comma-rich logs as CSV.
    if len(lines) >= 3:
        sample = "\n".join(lines[:10])
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
            rows = list(csv.reader(io.StringIO(sample), dialect))
            widths = {len(row) for row in rows if row}
            if len(widths) == 1 and next(iter(widths), 0) >= 2 and csv.Sniffer().has_header(sample):
                return "csv"
        except csv.Error:
            pass
    return "raw"


def split_records(text: str, boundary: str = "line") -> list[str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if boundary == "blank":
        return [block.strip("\n") for block in re.split(r"\n\s*\n+", normalized) if block.strip()]
    return [line for line in normalized.split("\n") if line.strip()]


def _find_json_timestamp(value: Any, path: tuple[Any, ...] = ()) -> tuple[dt.datetime, dict[str, Any]] | None:
    if isinstance(value, dict):
        # Prefer semantically named timestamp keys before recursively scanning.
        for key, item in value.items():
            if str(key).lower() in TIMESTAMP_KEYS:
                parsed = parse_datetime(item)
                if parsed:
                    return parsed, {"kind": "json", "path": path + (key,), "original": item}
        for key, item in value.items():
            found = _find_json_timestamp(item, path + (key,))
            if found:
                return found
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            found = _find_json_timestamp(item, path + (idx,))
            if found:
                return found
    return None


def _find_raw_timestamp(text: str, reference: dt.datetime | None = None) -> tuple[dt.datetime, dict[str, Any]] | None:
    # RFC5424 places the timestamp after PRI and VERSION.
    m5424 = re.match(r"^(<\d{1,3}>1\s+)(\S+)", text)
    if m5424:
        parsed = parse_datetime(m5424.group(2), reference=reference)
        if parsed:
            return parsed, {
                "kind": "raw",
                "start": m5424.start(2),
                "end": m5424.end(2),
                "style": "iso",
                "original": m5424.group(2),
            }

    # RFC3164 timestamp normally follows PRI.
    mrfc = RFC3164_RE.search(text[:64])
    if mrfc:
        parsed = parse_datetime(mrfc.group("rfc3164"), reference=reference)
        if parsed:
            return parsed, {
                "kind": "raw",
                "start": mrfc.start("rfc3164"),
                "end": mrfc.end("rfc3164"),
                "style": "rfc3164",
                "original": mrfc.group("rfc3164"),
            }

    miso = ISO_RE.search(text)
    if miso:
        parsed = parse_datetime(miso.group("iso"), reference=reference)
        if parsed:
            return parsed, {
                "kind": "raw",
                "start": miso.start("iso"),
                "end": miso.end("iso"),
                "style": "iso",
                "original": miso.group("iso"),
            }

    mcef = CEF_RT_RE.search(text)
    if mcef:
        parsed = parse_datetime(mcef.group("value"), reference=reference)
        if parsed:
            original = mcef.group("value")
            style = "epoch_ms" if original.isdigit() and len(original) >= 13 else "epoch_s" if original.isdigit() else "iso"
            return parsed, {
                "kind": "raw",
                "start": mcef.start("value"),
                "end": mcef.end("value"),
                "style": style,
                "original": original,
            }
    return None


def make_event(value: Any, index: int, reference: dt.datetime | None = None) -> Event:
    found = _find_json_timestamp(value) if isinstance(value, (dict, list)) else _find_raw_timestamp(str(value), reference)
    if found:
        timestamp, hint = found
        return Event(value=value, index=index, timestamp=timestamp, timestamp_hint=hint)
    return Event(value=value, index=index)


def parse_events(text: str, fmt: str, boundary: str = "line") -> list[Event]:
    """Parse complete text. Invalid explicitly selected structured formats raise errors."""
    if fmt == "auto":
        fmt = detect_format(text)
    stripped = text.lstrip("\ufeff")
    events: list[Event] = []

    if fmt == "json":
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
        values = data if isinstance(data, list) else [data]
        return [make_event(value, idx) for idx, value in enumerate(values)]

    if fmt == "ndjson":
        for line_no, line in enumerate(stripped.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ParseError(f"Invalid NDJSON on line {line_no}: {exc.msg}") from exc
            events.append(make_event(value, len(events)))
        return events

    if fmt == "csv":
        try:
            reader = csv.DictReader(io.StringIO(stripped))
            if not reader.fieldnames or len(reader.fieldnames) < 2:
                raise ParseError("CSV input must contain a header row with at least two columns.")
            for row_no, row in enumerate(reader, start=2):
                if None in row:
                    raise ParseError(f"CSV row {row_no} contains more values than the header.")
                events.append(make_event(dict(row), len(events)))
        except csv.Error as exc:
            raise ParseError(f"Invalid CSV: {exc}") from exc
        return events

    records = split_records(stripped, boundary)
    return [make_event(record, idx) for idx, record in enumerate(records)]


def detect_file_format(path: str | os.PathLike[str], sample_size: int = 256 * 1024) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return detect_format(handle.read(sample_size))


def _iter_blank_blocks(handle: Iterable[str]) -> Iterator[str]:
    buffer: list[str] = []
    for line in handle:
        normalized = line.rstrip("\r\n")
        if normalized.strip():
            buffer.append(normalized)
        elif buffer:
            yield "\n".join(buffer)
            buffer.clear()
    if buffer:
        yield "\n".join(buffer)


def iter_file_events(path: str | os.PathLike[str], fmt: str, boundary: str = "line") -> Iterator[Event]:
    """Stream events from disk for line, block, NDJSON, and CSV sources."""
    path = str(path)
    if fmt == "auto":
        fmt = detect_file_format(path)
    if fmt == "json":
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            yield from parse_events(handle.read(), fmt, boundary)
        return
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        if fmt == "ndjson":
            index = 0
            for line_no, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ParseError(f"Invalid NDJSON on line {line_no}: {exc.msg}") from exc
                yield make_event(value, index)
                index += 1
            return
        if fmt == "csv":
            try:
                reader = csv.DictReader(handle)
                if not reader.fieldnames or len(reader.fieldnames) < 2:
                    raise ParseError("CSV input must contain a header row with at least two columns.")
                for row_no, row in enumerate(reader, start=2):
                    if None in row:
                        raise ParseError(f"CSV row {row_no} contains more values than the header.")
                    yield make_event(dict(row), row_no - 2)
            except csv.Error as exc:
                raise ParseError(f"Invalid CSV: {exc}") from exc
            return
        records: Iterable[str]
        if boundary == "blank":
            records = _iter_blank_blocks(handle)
        else:
            records = (line.rstrip("\r\n") for line in handle if line.strip())
        for index, record in enumerate(records):
            yield make_event(record, index)




def iter_exact_file_events(path: str | os.PathLike[str]) -> Iterator[Event]:
    """Yield opaque source bytes without decoding, trimming, or normalizing.

    Physical lines are used only as pacing units. Their original CR, LF, CRLF,
    blank lines, invalid UTF-8 bytes, and missing final terminator are retained.
    Concatenating all yielded values reproduces the source file byte-for-byte.
    """
    with open(path, "rb") as handle:
        index = 0
        while True:
            raw = handle.readline()
            if raw == b"":
                break
            yield Event(value=raw, index=index)
            index += 1


def iter_exact_bytes_events(payload: bytes) -> Iterator[Event]:
    """Yield typed UTF-8 payload bytes without changing their content.

    ``BytesIO.readline`` uses physical line endings only as replay/pacing
    boundaries. Concatenating all yielded values always reconstructs the
    original payload exactly, including CR, LF, CRLF, blank lines, leading or
    trailing spaces, and a missing final line terminator.
    """
    with io.BytesIO(payload) as handle:
        index = 0
        while True:
            raw = handle.readline()
            if raw == b"":
                break
            yield Event(value=raw, index=index)
            index += 1


def count_exact_file_records(path: str | os.PathLike[str]) -> int:
    return sum(1 for _ in iter_exact_file_events(path))


def count_exact_bytes_records(payload: bytes) -> int:
    return sum(1 for _ in iter_exact_bytes_events(payload))


def bytes_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

def file_sha256(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_source(config: dict[str, Any]) -> tuple[Callable[[], Iterator[Event]], int, dt.datetime | None, str, str]:
    """Return a repeatable event factory plus source metadata.

    File-backed line-oriented inputs are scanned and replayed without loading the
    entire source into memory. Pasted text is parsed once because it is already
    resident in the GUI or CLI process.
    """
    exact_passthrough = bool(config.get("exact_passthrough", True))
    fmt = config.get("format", "auto")
    boundary = config.get("boundary", "line")
    source_path = config.get("source_path")
    if exact_passthrough:
        source_bytes = config.get("source_bytes")
        if source_path:
            path = Path(source_path)
            if not path.is_file():
                raise ConfigurationError(f"Source file does not exist: {path}")
            count = count_exact_file_records(path)
            return (
                lambda: iter_exact_file_events(path),
                count,
                None,
                file_sha256(path),
                "exact-bytes",
            )
        if source_bytes is not None:
            if not isinstance(source_bytes, (bytes, bytearray, memoryview)):
                raise ConfigurationError("Typed source must be provided as UTF-8 bytes.")
            payload = bytes(source_bytes)
            count = count_exact_bytes_records(payload)
            return (
                lambda: iter_exact_bytes_events(payload),
                count,
                None,
                bytes_sha256(payload),
                "exact-typed-utf8",
            )
        raise ConfigurationError("Choose a source file or type log text to replay.")
    if source_path:
        path = Path(source_path)
        if not path.is_file():
            raise ConfigurationError(f"Source file does not exist: {path}")
        resolved_fmt = detect_file_format(path) if fmt == "auto" else fmt
        count = 0
        first_timestamp = None
        for event in iter_file_events(path, resolved_fmt, boundary):
            count += 1
            if first_timestamp is None and event.timestamp is not None:
                first_timestamp = event.timestamp
        return (
            lambda: iter_file_events(path, resolved_fmt, boundary),
            count,
            first_timestamp,
            file_sha256(path),
            resolved_fmt,
        )

    raw_text = config.get("raw_text", "")
    resolved_fmt = detect_format(raw_text) if fmt == "auto" else fmt
    base_events = parse_events(raw_text, resolved_fmt, boundary)
    first_timestamp = next((event.timestamp for event in base_events if event.timestamp is not None), None)

    def factory() -> Iterator[Event]:
        for event in base_events:
            yield Event(copy.deepcopy(event.value), event.index, event.timestamp, copy.deepcopy(event.timestamp_hint))

    return factory, len(base_events), first_timestamp, source_sha256(raw_text), resolved_fmt


def _format_shifted_timestamp(new_value: dt.datetime, hint: dict[str, Any]) -> Any:
    style = hint.get("style")
    original = hint.get("original")
    value = ensure_aware(new_value).astimezone(UTC)
    if style == "rfc3164":
        return f"{value.strftime('%b')} {value.day:2d} {value.strftime('%H:%M:%S')}"
    if style == "epoch_ms":
        return str(int(value.timestamp() * 1000))
    if style == "epoch_s":
        return str(int(value.timestamp()))
    if isinstance(original, (int, float)):
        return int(value.timestamp() * 1000) if float(original) > 10_000_000_000 else int(value.timestamp())
    if isinstance(original, str):
        if original.endswith("Z"):
            timespec = "microseconds" if "." in original and len(original.split(".", 1)[1].rstrip("Z")) > 3 else "milliseconds"
            return value.isoformat(timespec=timespec).replace("+00:00", "Z")
        if re.search(r"[+-]\d{2}:?\d{2}$", original):
            return value.isoformat(timespec="milliseconds")
        if " " in original and "T" not in original:
            return value.strftime("%Y-%m-%d %H:%M:%S")
    return iso_z(value)


def shifted_event(event: Event, offset: dt.timedelta) -> Event:
    """Return a deep-copied event with only its primary timestamp shifted."""
    if event.timestamp is None or not event.timestamp_hint:
        return Event(copy.deepcopy(event.value), event.index, None, None)
    new_timestamp = event.timestamp + offset
    hint = event.timestamp_hint
    value = copy.deepcopy(event.value)
    replacement = _format_shifted_timestamp(new_timestamp, hint)

    if hint["kind"] == "raw":
        text = str(value)
        value = text[: hint["start"]] + str(replacement) + text[hint["end"] :]
        new_hint = _find_raw_timestamp(value)
        return Event(value, event.index, new_timestamp, new_hint[1] if new_hint else None)

    cursor = value
    path = hint["path"]
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement
    return Event(value, event.index, new_timestamp, {**hint, "original": replacement})


def shift_events(events: Sequence[Event], base_now: dt.datetime | None = None) -> list[Event]:
    """Shift the complete source timeline by one constant offset."""
    first = next((event.timestamp for event in events if event.timestamp is not None), None)
    if first is None:
        return [Event(copy.deepcopy(e.value), e.index, e.timestamp, copy.deepcopy(e.timestamp_hint)) for e in events]
    offset = ensure_aware(base_now or utc_now()) - ensure_aware(first)
    return [shifted_event(event, offset) for event in events]


def event_wire_bytes(event: Event) -> bytes:
    """Return the transport payload.

    Byte-valued events are returned unchanged. This is the exact pass-through
    path and deliberately performs no decoding, newline handling, or encoding.
    """
    if isinstance(event.value, bytes):
        return event.value
    if isinstance(event.value, str):
        return event.value.encode("utf-8")
    return json.dumps(event.value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def event_wire_text(event: Event) -> str:
    if isinstance(event.value, bytes):
        return event.value.decode("utf-8", errors="backslashreplace")
    if isinstance(event.value, str):
        return event.value
    return json.dumps(event.value, ensure_ascii=False, separators=(",", ":"))


def event_rest_value(event: Event) -> Any:
    if isinstance(event.value, str):
        return {"raw": event.value}
    return event.value


def source_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class Transport:
    name = "transport"

    def send(self, events: Sequence[Event]) -> SendResult:
        raise NotImplementedError

    def test(self) -> SendResult:
        return SendResult(True, None, "No connection test is required.")

    def close(self) -> None:
        pass


class DryRunTransport(Transport):
    name = "dry-run"

    def send(self, events: Sequence[Event]) -> SendResult:
        return SendResult(True, 200, f"Dry run: accepted {len(events)} event(s).")




class WebhookTransport(Transport):
    """Send source records as unchanged HTTP request-body bytes.

    No delimiter, encoding conversion, serialization, compression, or other
    payload transformation is applied. When a batch contains multiple physical
    source records, their original byte sequences are concatenated in order.
    """

    name = "Webhook Collector"
    MAX_REQUEST_BYTES = 32 * 1024 * 1024

    def __init__(
        self,
        url: str,
        token: str,
        content_type: str = "application/octet-stream",
        timeout: int = 15,
        verify_tls: bool = True,
        ca_file: str = "",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("Webhook URL must be a valid http:// or https:// URL.")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ConfigurationError("Webhook URLs must use HTTPS except for local loopback testing.")
        if not token.strip():
            raise ConfigurationError("Webhook bearer token is required.")
        if not content_type.strip():
            raise ConfigurationError("Webhook Content-Type is required.")
        if ca_file and not Path(ca_file).is_file():
            raise ConfigurationError(f"CA certificate file does not exist: {ca_file}")
        self.url = url.strip()
        self.parsed = parsed
        self.token = token.strip()
        self.content_type = content_type.strip()
        self.timeout = max(1, int(timeout))
        self.verify_tls = bool(verify_tls)
        self.ca_file = ca_file
        self.extra_headers = extra_headers or {}

    def _ssl_context(self) -> ssl.SSLContext | None:
        if self.parsed.scheme != "https":
            return None
        if self.verify_tls:
            return ssl.create_default_context(cafile=self.ca_file or None)
        return ssl._create_unverified_context()  # explicitly selected by the operator

    def _connection(self) -> http.client.HTTPConnection:
        port = self.parsed.port
        if self.parsed.scheme == "https":
            return http.client.HTTPSConnection(
                self.parsed.hostname,
                port or 443,
                timeout=self.timeout,
                context=self._ssl_context(),
            )
        return http.client.HTTPConnection(self.parsed.hostname, port or 80, timeout=self.timeout)

    def _request_path(self) -> str:
        path = self.parsed.path or "/"
        if self.parsed.query:
            path += "?" + self.parsed.query
        return path

    def test(self) -> SendResult:
        conn = self._connection()
        started = time.monotonic()
        try:
            conn.connect()
            return SendResult(True, None, f"{self.parsed.scheme.upper()} connection succeeded in {time.monotonic() - started:.2f}s. No payload was sent.")
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            return SendResult(False, None, f"Connection failed: {exc}")
        finally:
            conn.close()

    def send(self, events: Sequence[Event]) -> SendResult:
        body = b"".join(event_wire_bytes(event) for event in events)
        if len(body) > self.MAX_REQUEST_BYTES:
            return SendResult(
                False,
                None,
                f"Webhook request body is {len(body):,} bytes; the supported maximum is {self.MAX_REQUEST_BYTES:,} bytes.",
            )
        authorization = self.token if self.token.lower().startswith("bearer ") else f"Bearer {self.token}"
        headers = {
            "Authorization": authorization,
            "Content-Type": self.content_type,
            "Accept": "application/json",
            "User-Agent": f"ExabeamReplay/{APP_VERSION}",
            **self.extra_headers,
        }
        conn = self._connection()
        try:
            conn.request("POST", self._request_path(), body=body, headers=headers)
            response = conn.getresponse()
            response_body = response.read(8192).decode("utf-8", errors="replace")
            ok = 200 <= response.status < 300
            return SendResult(ok, response.status, f"HTTP {response.status} {response.reason}", 1, response_body)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            return SendResult(False, None, f"Connection error: {exc}")
        finally:
            conn.close()


class RestTransport(Transport):
    name = "REST JSON"

    def __init__(
        self,
        url: str,
        api_key: str = "",
        source_type: str = "",
        timeout: int = 15,
        retries: int = 3,
        backoff: float = 1.0,
        extra_headers: dict[str, str] | None = None,
    ):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("REST URL must be a valid http:// or https:// URL.")
        self.url = url
        self.parsed = parsed
        self.api_key = api_key
        self.source_type = source_type
        self.timeout = timeout
        self.retries = max(0, retries)
        self.backoff = max(0.05, backoff)
        self.extra_headers = extra_headers or {}

    def _connection(self) -> http.client.HTTPConnection:
        port = self.parsed.port
        if self.parsed.scheme == "https":
            return http.client.HTTPSConnection(self.parsed.hostname, port or 443, timeout=self.timeout)
        return http.client.HTTPConnection(self.parsed.hostname, port or 80, timeout=self.timeout)

    def _request_path(self) -> str:
        path = self.parsed.path or "/"
        if self.parsed.query:
            path += "?" + self.parsed.query
        return path

    def test(self) -> SendResult:
        started = time.monotonic()
        try:
            with socket.create_connection(
                (self.parsed.hostname, self.parsed.port or (443 if self.parsed.scheme == "https" else 80)),
                timeout=self.timeout,
            ):
                pass
            return SendResult(True, None, f"TCP connection succeeded in {time.monotonic() - started:.2f}s.")
        except OSError as exc:
            return SendResult(False, None, f"Connection failed: {exc}")

    def send(self, events: Sequence[Event]) -> SendResult:
        payload = {
            "source_type": self.source_type or "replay:generic",
            "events": [event_rest_value(event) for event in events],
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"ExabeamReplay/{APP_VERSION}",
            **self.extra_headers,
        }
        if self.api_key:
            headers["Authorization"] = self.api_key if self.api_key.lower().startswith("bearer ") else f"Bearer {self.api_key}"
        if self.source_type:
            headers.setdefault("X-Source-Type", self.source_type)

        last = SendResult(False, None, "Request not attempted.")
        for attempt in range(1, self.retries + 2):
            conn = self._connection()
            try:
                conn.request("POST", self._request_path(), body=body, headers=headers)
                response = conn.getresponse()
                response_body = response.read(8192).decode("utf-8", errors="replace")
                ok = 200 <= response.status < 300
                last = SendResult(ok, response.status, f"HTTP {response.status} {response.reason}", attempt, response_body)
                if ok:
                    return last
                retryable = response.status in {408, 425, 429, 500, 502, 503, 504}
                if not retryable or attempt > self.retries:
                    return last
                retry_after = response.getheader("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else self.backoff * (2 ** (attempt - 1))
            except (OSError, http.client.HTTPException) as exc:
                last = SendResult(False, None, f"Connection error: {exc}", attempt)
                if attempt > self.retries:
                    return last
                delay = self.backoff * (2 ** (attempt - 1))
            finally:
                conn.close()
            time.sleep(min(delay, 30.0))
        return last


class SyslogTransport(Transport):
    MAX_EXABEAM_UDP_BYTES = 1024

    def __init__(
        self,
        host: str,
        port: int,
        protocol: str,
        timeout: int = 15,
        framing: str = "newline",
        verify_tls: bool = True,
        ca_file: str = "",
        retries: int = 3,
        backoff: float = 1.0,
    ):
        if not host.strip():
            raise ConfigurationError("Syslog host is required.")
        if not 1 <= int(port) <= 65535:
            raise ConfigurationError("Syslog port must be between 1 and 65535.")
        protocol = protocol.lower()
        if protocol not in {"udp", "tcp", "tls"}:
            raise ConfigurationError("Syslog protocol must be UDP, TCP, or TLS.")
        if framing not in {"none", "auto", "newline", "octet"}:
            raise ConfigurationError("Framing must be none, auto, newline, or octet-counting.")
        self.host = host.strip()
        self.port = int(port)
        self.protocol = protocol
        self.timeout = timeout
        self.framing = framing
        self.verify_tls = verify_tls
        self.ca_file = ca_file
        self.retries = max(0, retries)
        self.backoff = max(0.05, backoff)
        self._sock: socket.socket | ssl.SSLSocket | None = None
        self.name = f"Syslog {protocol.upper()}"

    def _connect(self) -> socket.socket | ssl.SSLSocket:
        if self.protocol == "udp":
            last_error: OSError | None = None
            for family, socktype, proto, _canonname, sockaddr in socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_DGRAM
            ):
                sock = socket.socket(family, socktype, proto)
                try:
                    sock.settimeout(self.timeout)
                    sock.connect(sockaddr)
                    return sock
                except OSError as exc:
                    last_error = exc
                    sock.close()
            raise last_error or OSError("No usable UDP address was found.")

        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if self.protocol == "tls":
            try:
                if self.verify_tls:
                    context = ssl.create_default_context(cafile=self.ca_file or None)
                else:
                    context = ssl._create_unverified_context()  # explicitly selected by the operator
                return context.wrap_socket(raw, server_hostname=self.host)
            except Exception:
                raw.close()
                raise
        return raw

    def _ensure_socket(self) -> socket.socket | ssl.SSLSocket:
        if self._sock is None:
            self._sock = self._connect()
        return self._sock

    def test(self) -> SendResult:
        try:
            sock = self._connect()
            sock.close()
            if self.protocol == "udp":
                return SendResult(True, None, "UDP socket and destination address are valid. UDP cannot confirm remote delivery.")
            return SendResult(True, None, f"Syslog {self.protocol.upper()} connection succeeded.")
        except (OSError, ssl.SSLError) as exc:
            return SendResult(False, None, f"Connection failed: {exc}")

    def _frame(self, event: Event) -> bytes:
        raw = event_wire_bytes(event)
        if self.framing == "none":
            return raw
        if self.framing == "auto":
            return raw if raw.endswith(b"\n") else raw + b"\n"
        if self.framing == "octet":
            return str(len(raw)).encode("ascii") + b" " + raw
        return raw.rstrip(b"\r\n") + b"\n"

    def close(self) -> None:
        if self._sock is not None:
            sock = self._sock
            self._sock = None
            if self.protocol == "tls" and isinstance(sock, ssl.SSLSocket):
                try:
                    sock.settimeout(min(float(self.timeout), 1.0))
                    raw = sock.unwrap()
                    raw.close()
                    return
                except (OSError, ssl.SSLError, ValueError):
                    pass
            elif self.protocol == "tcp":
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            try:
                sock.close()
            except OSError:
                pass

    def send(self, events: Sequence[Event]) -> SendResult:
        last = SendResult(False, None, "Send not attempted.")
        for attempt in range(1, self.retries + 2):
            try:
                sock = self._ensure_socket()
                for event in events:
                    payload = self._frame(event)
                    if self.protocol == "udp":
                        if len(payload) > self.MAX_EXABEAM_UDP_BYTES:
                            return SendResult(
                                False,
                                None,
                                f"UDP record {event.index + 1} is {len(payload):,} bytes; "
                                f"Exabeam Syslog UDP supports records up to {self.MAX_EXABEAM_UDP_BYTES:,} bytes. "
                                "Use Syslog TCP or TLS for larger records.",
                                attempt,
                            )
                        sent = sock.send(payload)
                        if sent != len(payload):
                            raise OSError(f"UDP sent {sent} of {len(payload)} bytes")
                    else:
                        sock.sendall(payload)
                return SendResult(True, None, f"Sent {len(events)} event(s) through {self.name}.", attempt)
            except (OSError, ssl.SSLError) as exc:
                last = SendResult(False, None, f"{self.name} socket error: {exc}", attempt)
                self.close()
                if attempt <= self.retries:
                    time.sleep(min(self.backoff * (2 ** (attempt - 1)), 30.0))
        return last


class TokenBucket:
    """Interruptible paced limiter with no large initial token burst."""

    def __init__(self, rate: float, stop_event: threading.Event, pause_event: threading.Event):
        self.rate = max(0.0, rate)
        self.next_slot = time.monotonic()
        self.stop_event = stop_event
        self.pause_event = pause_event

    def wait_for(self, amount: int) -> bool:
        if self.rate <= 0:
            while self.pause_event.is_set() and not self.stop_event.is_set():
                self.stop_event.wait(0.05)
            return not self.stop_event.is_set()
        target = max(time.monotonic(), self.next_slot)
        if not interruptible_wait(target, self.stop_event, self.pause_event):
            return False
        # Advance from the actual send slot to avoid catch-up bursts after pauses
        # or slow network requests. One batch may be sent immediately; subsequent
        # batches are spaced by their event cost.
        self.next_slot = time.monotonic() + (amount / self.rate)
        return True


def interruptible_wait(
    target_monotonic: float,
    stop_event: threading.Event,
    pause_event: threading.Event,
) -> bool:
    """Wait until a deadline while adjusting the deadline for paused duration."""
    while not stop_event.is_set():
        if pause_event.is_set():
            paused_at = time.monotonic()
            while pause_event.is_set() and not stop_event.is_set():
                time.sleep(0.05)
            target_monotonic += time.monotonic() - paused_at
            continue
        remaining = target_monotonic - time.monotonic()
        if remaining <= 0:
            return True
        stop_event.wait(min(remaining, 0.1))
    return False


def make_transport(config: dict[str, Any]) -> Transport:
    if config.get("dry_run"):
        return DryRunTransport()
    destination = config.get("destination", "syslog_tls")
    if config.get("exact_passthrough", True) and destination == "rest":
        raise ConfigurationError("REST JSON cannot provide byte-for-byte pass-through because it serializes an envelope.")
    common = {
        "timeout": int(config.get("timeout", 15)),
        "retries": int(config.get("retries", 3)),
        "backoff": float(config.get("retry_backoff", 1.0)),
    }
    if destination == "webhook":
        return WebhookTransport(
            config.get("webhook_url", ""),
            config.get("webhook_token", ""),
            "application/octet-stream",
            timeout=common["timeout"],
            verify_tls=True,
            ca_file="",
            extra_headers=config.get("extra_headers", {}),
        )
    if destination == "rest":
        return RestTransport(
            config.get("api_url", ""),
            config.get("api_key", ""),
            config.get("source_type", ""),
            extra_headers=config.get("extra_headers", {}),
            **common,
        )
    protocol = destination.removeprefix("syslog_")
    framing = config.get("framing", "newline")
    if config.get("exact_passthrough", True):
        # UDP datagrams preserve each physical record as the datagram payload.
        # TCP/TLS use RFC 6587 octet-counting so a message that begins with
        # digits and a space cannot be mistaken for its own length prefix.
        # The receiver removes the decimal length and space; the message bytes
        # that follow are the unchanged source record.
        framing = "octet" if protocol in {"tcp", "tls"} else "none"
    return SyslogTransport(
        config.get("host", ""),
        int(config.get("port", 6514 if protocol == "tls" else 514)),
        protocol,
        framing=framing,
        verify_tls=bool(config.get("verify_tls", True)),
        ca_file=config.get("ca_file", ""),
        **common,
    )


def validate_config(config: dict[str, Any]) -> None:
    source_path = config.get("source_path")
    source_bytes = config.get("source_bytes")
    raw_text = config.get("raw_text", "")
    exact = bool(config.get("exact_passthrough", True))
    if exact:
        if bool(source_path) == (source_bytes is not None):
            raise ConfigurationError("Choose exactly one source: a sample file or typed log text.")
        if source_bytes is not None and not isinstance(source_bytes, (bytes, bytearray, memoryview)):
            raise ConfigurationError("Typed source must be provided as UTF-8 bytes.")
        if source_bytes is not None and len(source_bytes) == 0:
            raise ConfigurationError("Type at least one character to replay.")
        if raw_text:
            raise ConfigurationError("Use source_bytes for exact typed-text replay.")
        if config.get("destination") == "rest":
            raise ConfigurationError("REST JSON destinations are unavailable in exact pass-through mode; use Webhook Collector for an unchanged HTTP request body.")
        if config.get("ts_rewrite"):
            raise ConfigurationError("Timestamp rewriting is unavailable in exact pass-through mode.")
        if config.get("framing") not in {None, "none"}:
            raise ConfigurationError("Additional framing is unavailable in exact pass-through mode.")
        if int(config.get("retries", 0)) != 0:
            raise ConfigurationError("Application-level retries are disabled in exact pass-through mode to prevent duplicate bytes after partial sends.")
        if not bool(config.get("stop_on_failure", True)):
            raise ConfigurationError("Exact pass-through must stop after the first failed batch to avoid sending an incomplete or reordered stream.")
    elif not source_path and not raw_text.strip():
        raise ConfigurationError("No source data was provided.")
    batch_size = int(config.get("batch_size", 1))
    if batch_size < 1 or batch_size > 5000:
        raise ConfigurationError("Batch size must be between 1 and 5000.")
    speed = float(config.get("speed", 1))
    if speed <= 0:
        raise ConfigurationError("Speed multiplier must be greater than zero.")
    if int(config.get("eps_cap", 0)) < 0:
        raise ConfigurationError("EPS cap cannot be negative.")
    loop_max = int(config.get("loop_max", 1))
    if loop_max < 1:
        raise ConfigurationError("Number of passes must be at least 1.")
    loop_interval = float(config.get("loop_interval", 0))
    if loop_interval < 0 or loop_interval > 86_400:
        raise ConfigurationError("Interval between passes must be between 0 and 86,400 seconds.")
    make_transport(config).close()


class ReplayEngine:
    """Threaded replay engine shared by GUI and tests."""

    def __init__(self, config: dict[str, Any], queue_out: queue.Queue | None = None):
        self.cfg = config
        self.q = queue_out or queue.Queue()
        self.run_id = str(config.get("run_id") or uuid.uuid4())
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._thread: threading.Thread | None = None
        self.summary: ReplaySummary | None = None

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.alive:
            raise ReplayError("Replay is already running.")
        self._stop.clear()
        self._pause.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"replay-{self.run_id[:8]}")
        self._thread.start()

    def run_sync(self) -> ReplaySummary:
        self._run()
        assert self.summary is not None
        return self.summary

    def pause(self) -> None:
        self._pause.set()

    def resume(self) -> None:
        self._pause.clear()

    def stop(self) -> None:
        self._stop.set()
        self._pause.clear()

    def join(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def _emit(self, kind: str, **kwargs: Any) -> None:
        self.q.put({"run_id": self.run_id, "kind": kind, **kwargs})

    def _write_report(self, summary: ReplaySummary, failed_path: Path | None) -> ReplaySummary:
        if not bool(self.cfg.get("save_reports", True)):
            return summary
        report_dir = Path(self.cfg.get("report_dir") or "reports")
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
            stem = f"replay-{self.run_id}"
            if failed_path and failed_path.exists():
                summary.failed_records_file = str(failed_path.resolve())
            report_path = report_dir / f"{stem}-report.json"
            summary.report_file = str(report_path.resolve())
            temporary = report_path.with_suffix(report_path.suffix + ".tmp")
            temporary.write_text(json.dumps(dataclasses.asdict(summary), indent=2), encoding="utf-8")
            temporary.replace(report_path)
        except OSError as exc:
            self._emit("log", level="warn", msg=f"Could not write run report: {exc}")
        return summary

    def _run(self) -> None:
        started_dt = utc_now()
        started_mono = time.monotonic()
        sent = failed_count = requests_failed = retries = loops_done = records_read = 0
        failed_path: Path | None = None
        source_hash = ""
        source_mode_name = "unknown"
        source_bytes = 0
        status = "failed"
        transport: Transport | None = None
        fatal_delivery_failure = False
        try:
            validate_config(self.cfg)
            fmt_requested = "exact bytes" if self.cfg.get("exact_passthrough", True) else self.cfg.get("format", "auto")
            self._emit("log", level="info", msg=f"Scanning source as {str(fmt_requested).upper()}…")
            source_factory, records_read, first_source_ts, source_hash, resolved_fmt = prepare_source(self.cfg)
            source_mode_name = resolved_fmt
            if self.cfg.get("source_path"):
                source_bytes = Path(self.cfg["source_path"]).stat().st_size
            elif self.cfg.get("source_bytes") is not None:
                source_bytes = len(bytes(self.cfg.get("source_bytes", b"")))
            else:
                source_bytes = len(self.cfg.get("raw_text", "").encode("utf-8", errors="replace"))
            if records_read == 0:
                raise ParseError("No events were found in the source.")
            self._emit("total", count=records_read)
            source_mode = "streaming file" if self.cfg.get("source_path") else "typed UTF-8 text"
            unit = "physical record" if self.cfg.get("exact_passthrough", True) else "event"
            self._emit("log", level="ok", msg=f"Validated {records_read:,} {unit}(s) as {resolved_fmt.upper()} ({source_mode}).")

            transport = make_transport(self.cfg)
            self._emit("log", level="info", msg=f"Destination: {transport.name}.")
            if isinstance(transport, WebhookTransport):
                self._emit("log", level="info", msg="Webhook payload: source bytes are sent without modification.")
            elif isinstance(transport, SyslogTransport) and transport.protocol in {"tcp", "tls"}:
                self._emit(
                    "log",
                    level="info",
                    msg=(
                        f"{transport.name} framing: RFC 6587 octet counting. "
                        "The collector receives the complete source record after removing the length prefix."
                    ),
                )
            elif isinstance(transport, SyslogTransport) and transport.protocol == "udp":
                self._emit(
                    "log",
                    level="info",
                    msg=f"UDP payload: each unchanged physical record is one datagram; maximum {transport.MAX_EXABEAM_UDP_BYTES:,} bytes.",
                )
            speed = float(self.cfg.get("speed", 1.0))
            eps_cap = int(self.cfg.get("eps_cap", 0))
            batch_size = int(self.cfg.get("batch_size", 1))
            loop_enabled = bool(self.cfg.get("loop", False))
            loop_max = int(self.cfg.get("loop_max", 1))
            loop_interval = float(self.cfg.get("loop_interval", 0))
            rewrite = bool(self.cfg.get("ts_rewrite", False)) and not bool(self.cfg.get("exact_passthrough", True))
            stop_on_failure = bool(self.cfg.get("stop_on_failure", True if self.cfg.get("exact_passthrough", True) else False))
            limiter = TokenBucket(eps_cap, self._stop, self._pause)
            recent_sends: deque[tuple[float, int]] = deque()

            while not self._stop.is_set():
                offset = ensure_aware(utc_now()) - ensure_aware(first_source_ts) if rewrite and first_source_ts else dt.timedelta(0)
                first_timeline_ts = first_source_ts + offset if first_source_ts else None
                source_iter: Iterator[Event] = source_factory()
                if rewrite and first_source_ts:
                    source_iter = (shifted_event(event, offset) for event in source_iter)
                pass_started = time.monotonic()
                idx = 0
                previewed = 0

                while idx < records_read and not self._stop.is_set():
                    batch = list(itertools.islice(source_iter, batch_size))
                    if not batch:
                        break
                    batch_ts = next((event.timestamp for event in batch if event.timestamp is not None), None)
                    if first_timeline_ts and batch_ts:
                        timeline_seconds = max(0.0, (batch_ts - first_timeline_ts).total_seconds()) / speed
                        if not interruptible_wait(pass_started + timeline_seconds, self._stop, self._pause):
                            break
                    if not limiter.wait_for(len(batch)):
                        break

                    if isinstance(transport, DryRunTransport) and previewed < 10:
                        for preview_event in batch[: 10 - previewed]:
                            preview = event_wire_text(preview_event).replace("\n", "\\n")
                            self._emit("log", level="dim", msg=f"Preview {preview_event.index + 1}: {preview[:500]}")
                            previewed += 1

                    result = transport.send(batch)
                    retries += max(0, result.attempts - 1)
                    if result.ok:
                        sent += len(batch)
                        now = time.monotonic()
                        recent_sends.append((now, len(batch)))
                    else:
                        failed_count += len(batch)
                        requests_failed += 1
                        if bool(self.cfg.get("save_reports", True)):
                            try:
                                if failed_path is None:
                                    report_dir = Path(self.cfg.get("report_dir") or "reports")
                                    report_dir.mkdir(parents=True, exist_ok=True)
                                    suffix = "raw" if self.cfg.get("exact_passthrough", True) else "ndjson"
                                    failed_path = report_dir / f"replay-{self.run_id}-failed.{suffix}"
                                if self.cfg.get("exact_passthrough", True):
                                    with failed_path.open("ab") as failed_handle:
                                        for failed_event in batch:
                                            failed_handle.write(event_wire_bytes(failed_event))
                                else:
                                    with failed_path.open("a", encoding="utf-8") as failed_handle:
                                        for failed_event in batch:
                                            failed_handle.write(json.dumps(event_rest_value(failed_event), ensure_ascii=False) + "\n")
                            except OSError as exc:
                                self._emit("log", level="warn", msg=f"Could not spool failed records: {exc}")
                        detail = f" — {result.response_body[:300]}" if result.response_body else ""
                        self._emit("log", level="err", msg=f"Batch {idx // batch_size + 1} failed: {result.message}{detail}")
                        if stop_on_failure:
                            fatal_delivery_failure = True
                            self._stop.set()
                            break

                    idx += len(batch)
                    now = time.monotonic()
                    while recent_sends and recent_sends[0][0] < now - 1.0:
                        recent_sends.popleft()
                    current_eps = sum(count for _, count in recent_sends)
                    self._emit(
                        "progress",
                        sent=sent,
                        errors=failed_count,
                        progress=min(idx / records_read, 1.0),
                        loops=loops_done,
                        current_index=idx,
                        total=records_read,
                    )
                    self._emit("eps", value=current_eps)

                if idx >= records_read:
                    loops_done += 1
                    self._emit("progress", sent=sent, errors=failed_count, progress=1.0, loops=loops_done, current_index=records_read, total=records_read)
                    self._emit("log", level="ok", msg=f"Pass {loops_done} complete: {sent:,} sent, {failed_count:,} failed.")
                if not loop_enabled or loops_done >= loop_max or self._stop.is_set():
                    break
                if loop_interval > 0:
                    self._emit(
                        "log",
                        level="info",
                        msg=f"Waiting {loop_interval:g} second(s) before pass {loops_done + 1}…",
                    )
                    if not interruptible_wait(
                        time.monotonic() + loop_interval,
                        self._stop,
                        self._pause,
                    ):
                        break
                self._emit("log", level="info", msg=f"Starting pass {loops_done + 1}…")

            if fatal_delivery_failure:
                status = "failed"
            else:
                status = "stopped" if self._stop.is_set() else "completed"
        except (ReplayError, OSError, ValueError) as exc:
            self._emit("log", level="err", msg=str(exc))
            status = "failed"
        except Exception as exc:  # defensive boundary for worker threads
            self._emit("log", level="err", msg=f"Unexpected failure: {type(exc).__name__}: {exc}")
            status = "failed"
        finally:
            if transport:
                transport.close()
            elapsed = max(time.monotonic() - started_mono, 0.000001)
            summary = ReplaySummary(
                run_id=self.run_id,
                status=status,
                started_at=iso_z(started_dt),
                completed_at=iso_z(utc_now()),
                source_sha256=(
                    source_hash
                    or (
                        bytes_sha256(bytes(self.cfg.get("source_bytes", b"")))
                        if self.cfg.get("source_bytes") is not None
                        else source_sha256(self.cfg.get("raw_text", ""))
                    )
                ),
                source_mode=source_mode_name,
                source_bytes=source_bytes,
                records_read=records_read,
                records_sent=sent,
                records_failed=failed_count,
                requests_failed=requests_failed,
                retries=retries,
                loops_completed=loops_done,
                average_eps=round(sent / elapsed, 2),
                destination=transport.name if transport else self.cfg.get("destination", "unknown"),
            )
            self.summary = self._write_report(summary, failed_path)
            self._emit("done", summary=dataclasses.asdict(self.summary))
