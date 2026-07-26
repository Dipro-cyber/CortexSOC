"""
CortexSOC — Log Collector Parsers
==================================
Three parser functions that normalise raw log strings into a consistent
structured dict.  Every returned dict always contains all six keys; any
field that cannot be extracted is set to ``None``.

Normalised dict schema
-----------------------
.. code-block:: python

    {
        "timestamp":      str | None,
        "source_ip":      str | None,
        "destination_ip": str | None,
        "event_type":     str | None,
        "severity":       str | None,
        "raw_payload":    str,          # always the original input
    }

Supported formats
-----------------
* **JSON syslog** — a JSON object with fields like ``timestamp``/``ts``,
  ``src_ip``/``source_ip``, ``dst_ip``/``destination_ip``,
  ``event_type``, ``severity``.
* **CEF** — ``CEF:<version>|<DeviceVendor>|<DeviceProduct>|<DeviceVersion>|
  <SignatureID>|<Name>|<Severity>|<Extensions>`` (RFC-4765 style).
* **Apache / Nginx Combined Log Format** —
  ``<IP> - - [<timestamp>] "<METHOD> <path> HTTP/<ver>" <status> <bytes>``.

Requirements: 8.1, 8.2
"""
from __future__ import annotations

import json
import re
from typing import Any

# ---------------------------------------------------------------------------
# Normalised-dict helpers
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = (
    "timestamp",
    "source_ip",
    "destination_ip",
    "event_type",
    "severity",
    "raw_payload",
)


def _empty_event(raw: str) -> dict[str, Any]:
    """Return an event dict with all fields set to ``None`` (except raw_payload)."""
    return {
        "timestamp": None,
        "source_ip": None,
        "destination_ip": None,
        "event_type": None,
        "severity": None,
        "raw_payload": raw,
    }


# ---------------------------------------------------------------------------
# Parser 1: JSON syslog
# ---------------------------------------------------------------------------

# Field aliases supported by this parser.
_JSON_TIMESTAMP_KEYS = ("timestamp", "ts", "time", "@timestamp")
_JSON_SRC_IP_KEYS = ("src_ip", "source_ip", "srcip", "sip", "src")
_JSON_DST_IP_KEYS = ("dst_ip", "destination_ip", "dstip", "dip", "dst")
_JSON_EVENT_TYPE_KEYS = ("event_type", "eventtype", "event", "type", "action")
_JSON_SEVERITY_KEYS = ("severity", "sev", "level", "priority")


def _first_matching(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Return the string value of the first key found in *data*, or ``None``."""
    for key in keys:
        if key in data:
            val = data[key]
            if val is not None:
                return str(val)
    return None


def parse_json_syslog(raw: str) -> dict[str, Any] | None:
    """Parse a JSON syslog entry into a normalised event dict.

    Accepts any JSON object containing log-like fields.  Returns ``None`` if
    *raw* is not valid JSON or does not parse to a mapping.

    Args:
        raw: The raw log string to parse.

    Returns:
        A normalised event dict, or ``None`` if *raw* is not a JSON object.
    """
    raw = raw.strip()
    if not raw.startswith("{"):
        return None
    try:
        data: Any = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    event = _empty_event(raw)
    event["timestamp"] = _first_matching(data, _JSON_TIMESTAMP_KEYS)
    event["source_ip"] = _first_matching(data, _JSON_SRC_IP_KEYS)
    event["destination_ip"] = _first_matching(data, _JSON_DST_IP_KEYS)
    event["event_type"] = _first_matching(data, _JSON_EVENT_TYPE_KEYS)
    event["severity"] = _first_matching(data, _JSON_SEVERITY_KEYS)
    return event


# ---------------------------------------------------------------------------
# Parser 2: CEF (Common Event Format)
# ---------------------------------------------------------------------------

# CEF header has exactly 8 pipe-delimited fields (the last being the extension KV string).
# Pattern: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
_CEF_PREFIX = re.compile(r"^CEF:\d+\|", re.IGNORECASE)
# Extension key=value pairs (values can contain spaces; next key starts at non-space\S+=)
_CEF_EXT_PATTERN = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)")

# CEF severity levels mapped to human-readable strings
_CEF_SEVERITY_MAP: dict[str, str] = {
    "0": "Unknown",
    "1": "Low",
    "2": "Low",
    "3": "Low",
    "4": "Medium",
    "5": "Medium",
    "6": "Medium",
    "7": "High",
    "8": "High",
    "9": "Very-High",
    "10": "Very-High",
}


def parse_cef(raw: str) -> dict[str, Any] | None:
    """Parse a CEF (Common Event Format) log line into a normalised event dict.

    Parses the 7-field CEF header and the key=value extension string.  Extracts
    ``src`` / ``sourceAddress`` as ``source_ip``, ``dst`` / ``destinationAddress``
    as ``destination_ip``, ``start`` / ``rt`` as ``timestamp``, the CEF *Name*
    field as ``event_type``, and the numeric CEF *Severity* mapped to a label.

    Args:
        raw: The raw log string to parse.

    Returns:
        A normalised event dict, or ``None`` if *raw* does not begin with the
        ``CEF:`` prefix or cannot be split into 8 pipe-delimited sections.
    """
    stripped = raw.strip()
    if not _CEF_PREFIX.match(stripped):
        return None

    # Split on unescaped pipes; CEF allows \| inside fields — handle naively for MVP.
    parts = stripped.split("|")
    if len(parts) < 8:
        return None

    # parts[0] = "CEF:version", [1]=DeviceVendor, [2]=DeviceProduct,
    # [3]=DeviceVersion, [4]=SignatureID, [5]=Name, [6]=Severity,
    # [7..] = Extension (join remainder in case extension contains |)
    name_field = parts[5].strip() or None
    severity_raw = parts[6].strip()
    extension_str = "|".join(parts[7:])

    # Map numeric severity
    severity: str | None = _CEF_SEVERITY_MAP.get(severity_raw, severity_raw or None)

    # Parse extension KV pairs
    ext: dict[str, str] = {}
    for m in _CEF_EXT_PATTERN.finditer(extension_str):
        ext[m.group(1)] = m.group(2).strip()

    # Extract fields from extension
    source_ip: str | None = ext.get("src") or ext.get("sourceAddress") or None
    destination_ip: str | None = ext.get("dst") or ext.get("destinationAddress") or None
    timestamp: str | None = ext.get("start") or ext.get("rt") or ext.get("end") or None

    event = _empty_event(raw)
    event["timestamp"] = timestamp
    event["source_ip"] = source_ip
    event["destination_ip"] = destination_ip
    event["event_type"] = name_field
    event["severity"] = severity
    return event


# ---------------------------------------------------------------------------
# Parser 3: Apache / Nginx Combined Log Format
# ---------------------------------------------------------------------------

# Combined Log Format:
# IP - - [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD /path HTTP/X.Y" status bytes
# Optional: "referrer" "user-agent"
_COMBINED_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)'            # client IP
    r'\s+\S+'                  # ident (usually -)
    r'\s+\S+'                  # auth user (usually -)
    r'\s+\[(?P<ts>[^\]]+)\]'  # [timestamp]
    r'\s+"(?P<request>[^"]*)"' # "request line"
    r'\s+(?P<status>\d{3})'   # HTTP status
    r'\s+(?P<bytes>\S+)'       # bytes sent (- or integer)
    r'(?:\s+"[^"]*")?'         # optional referrer
    r'(?:\s+"[^"]*")?'         # optional user agent
)

# HTTP status → approximate severity
def _http_status_to_severity(status: str) -> str:
    code = int(status)
    if code < 300:
        return "Info"
    if code < 400:
        return "Low"
    if code < 500:
        return "Medium"
    return "High"


def parse_apache_nginx(raw: str) -> dict[str, Any] | None:
    """Parse an Apache/Nginx Combined Log Format line into a normalised event dict.

    Extracts:
    - ``source_ip`` from the client IP field.
    - ``timestamp`` from the bracketed date/time field.
    - ``event_type`` from the HTTP method + path (e.g. ``"GET /index.html"``).
    - ``severity`` derived from the HTTP status code (Info/Low/Medium/High).
    - ``destination_ip`` is always ``None`` (not present in access log format).

    Args:
        raw: The raw log string to parse.

    Returns:
        A normalised event dict, or ``None`` if *raw* does not match the
        Combined Log Format pattern.
    """
    stripped = raw.strip()
    m = _COMBINED_LOG_PATTERN.match(stripped)
    if not m:
        return None

    ip = m.group("ip")
    timestamp = m.group("ts")
    request = m.group("request")
    status = m.group("status")

    # Derive event_type from HTTP method + path
    request_parts = request.split()
    if len(request_parts) >= 2:
        event_type: str | None = f"{request_parts[0]} {request_parts[1]}"
    elif request_parts:
        event_type = request_parts[0]
    else:
        event_type = None

    severity = _http_status_to_severity(status) if status else None

    event = _empty_event(raw)
    event["timestamp"] = timestamp
    event["source_ip"] = ip
    event["destination_ip"] = None
    event["event_type"] = event_type
    event["severity"] = severity
    return event
