"""
Utility functions for grumpwalk.

This module contains general-purpose utility functions for formatting,
parsing, and error handling.
"""

import sys
import re
from datetime import datetime, timezone
from typing import Optional, Dict, IO
from urllib.parse import urlparse, parse_qs


# Log file state -- configured via init_log_file(), used by log_stderr()
_log_file: Optional[IO] = None
_log_level: int = 1  # Default: INFO

# Log level constants
LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_ERROR = 2

LOG_LEVELS = {
    "DEBUG": LOG_LEVEL_DEBUG,
    "INFO": LOG_LEVEL_INFO,
    "ERROR": LOG_LEVEL_ERROR,
}

# Map every tag used in the codebase to a log level
_TAG_TO_LEVEL = {
    # ERROR level -- things that went wrong
    "ERROR": LOG_LEVEL_ERROR,
    "WARN": LOG_LEVEL_ERROR,
    "WARNING": LOG_LEVEL_ERROR,
    "!": LOG_LEVEL_ERROR,
    # ERROR level -- hints always accompany errors
    "HINT": LOG_LEVEL_ERROR,
    # INFO level -- operational messages
    "INFO": LOG_LEVEL_INFO,
    "DRY RUN": LOG_LEVEL_INFO,
    "ACL CLONE": LOG_LEVEL_INFO,
    "ACL REPORT": LOG_LEVEL_INFO,
    "ACL+OWNER/GROUP": LOG_LEVEL_INFO,
    "OWNER/GROUP": LOG_LEVEL_INFO,
    "SIMILARITY DETECTION": LOG_LEVEL_INFO,
    "BENCH": LOG_LEVEL_INFO,
    # DEBUG level -- internals
    "DEBUG": LOG_LEVEL_DEBUG,
}


def init_log_file(filepath: str, level: str = "INFO") -> None:
    """Open a log file for writing and set the log level.

    Writes a header with timezone information. The log file uses
    line buffering so entries are visible immediately.

    Args:
        filepath: Path to the log file (will be created or truncated)
        level: Minimum log level: DEBUG, INFO, or ERROR
    """
    global _log_file, _log_level

    _log_level = LOG_LEVELS.get(level.upper(), LOG_LEVEL_INFO)
    _log_file = open(filepath, "w", buffering=1)  # line-buffered

    # Write header with timezone info
    now = datetime.now().astimezone()
    tz_name = now.strftime("%Z")
    tz_offset = now.strftime("%z")
    _log_file.write(f"# grumpwalk log started {now.strftime('%Y-%m-%d %H:%M:%S')} {tz_name} (UTC{tz_offset})\n")
    _log_file.write(f"# All timestamps are local time ({tz_name})\n")
    _log_file.write(f"# Log level: {level.upper()}\n")
    _log_file.flush()


def close_log_file() -> None:
    """Close the log file if open."""
    global _log_file
    if _log_file:
        _log_file.close()
        _log_file = None


def log_to_file(message: str) -> None:
    """Write an untagged line to the log file (for banners/config).

    Only writes if a log file is open and log level is INFO or lower.
    """
    if _log_file and _log_level <= LOG_LEVEL_INFO:
        _log_file.write(message + "\n")


def log_stderr(tag: str, message: str, newline_before: bool = False):
    """Print a timestamped tagged message to stderr and optionally to a log file.

    Stderr format: [YYYY-MM-DD HH:MM:SS] [TAG] message
    Log file format: [YYYY-MM-DD HH:MM:SS TZ] [TAG] message

    Args:
        tag: Log level or category (e.g. ERROR, WARN, INFO, DEBUG)
        message: The log message
        newline_before: If True, print a blank line before the timestamped message

    Not intended for ephemeral progress lines that use \\r overwriting.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    prefix = "\n" if newline_before else ""
    print(f"{prefix}[{timestamp}] [{tag}] {message}", file=sys.stderr, flush=True)

    # Write to log file if open and tag meets level threshold
    if _log_file:
        tag_level = _TAG_TO_LEVEL.get(tag, LOG_LEVEL_INFO)
        if tag_level >= _log_level:
            now = datetime.now().astimezone()
            tz_abbrev = now.strftime("%Z")
            file_timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
            _log_file.write(f"[{file_timestamp} {tz_abbrev}] [{tag}] {message}\n")


def format_http_error(status: int, url: str, path: Optional[str] = None, host: Optional[str] = None) -> str:
    """Format HTTP error with helpful context and suggestions."""
    # Extract host from URL if not provided
    if not host:
        try:
            parsed = urlparse(url)
            host = parsed.hostname or "<cluster>"
        except Exception:
            host = "<cluster>"

    error_messages = {
        401: (
            "Authentication failed (401 Unauthorized)",
            f"Your credentials may have expired. Run: qq --host {host} login"
        ),
        403: (
            "Access denied (403 Forbidden)",
            f"You don't have permission to access: {path or url}"
        ),
        404: (
            "Not found (404)",
            f"Path does not exist: {path or url}"
        ),
        429: (
            "Too many requests (429)",
            "The cluster is rate-limiting requests. Try reducing --max-concurrent"
        ),
        500: (
            "Internal server error (500)",
            "The cluster encountered an error. Contact Qumulo support if this persists"
        ),
        503: (
            "Service unavailable (503)",
            "The cluster is temporarily unavailable. Please try again later"
        )
    }

    if status in error_messages:
        title, suggestion = error_messages[status]
        return f"\n[ERROR] {title}\n[HINT] {suggestion}"
    else:
        return f"\n[ERROR] HTTP {status}: {url}"


def extract_pagination_token(api_response: dict) -> Optional[str]:
    """Extract the pagination token from Qumulo API response."""
    if "paging" not in api_response:
        return None

    next_url = api_response["paging"].get("next")
    if not next_url:
        return None

    try:
        parsed = urlparse(next_url)
        query_params = parse_qs(parsed.query)

        if "after" in query_params:
            return query_params["after"][0]
        else:
            return None

    except Exception:
        return None


def parse_size_to_bytes(size_str: str) -> int:
    """Parse size string (e.g., '100MB', '1.5GiB') to bytes."""
    match = re.match(r"^([0-9]+\.?[0-9]*)([A-Za-z]*)$", size_str)
    if not match:
        raise ValueError(f"Invalid size format: {size_str}")

    size_num = float(match.group(1))
    size_unit = match.group(2).lower()

    multipliers = {
        "": 1,
        "b": 1,
        "kb": 1000,
        "mb": 1000000,
        "gb": 1000000000,
        "tb": 1000000000000,
        "pb": 1000000000000000,
        "kib": 1024,
        "mib": 1048576,
        "gib": 1073741824,
        "tib": 1099511627776,
        "pib": 1125899906842624,
    }

    if size_unit not in multipliers:
        raise ValueError(f"Unknown size unit: {size_unit}")

    return int(size_num * multipliers[size_unit])


def format_bytes(bytes_value: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} EB"


def format_time(seconds: float) -> str:
    """
    Format elapsed time in human-friendly format with total seconds.

    Examples:
        5.2s (5.2s)
        72.3s -> 1m 12s (72.3s)
        3665.7s -> 1h 1m 5s (3665.7s)
    """
    total_seconds = seconds

    if seconds < 60:
        # Less than a minute - just show seconds
        return f"{seconds:.1f}s"

    hours = int(seconds // 3600)
    seconds = seconds % 3600
    minutes = int(seconds // 60)
    secs = int(seconds % 60)

    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    friendly = " ".join(parts)
    return f"{friendly} ({total_seconds:.1f}s)"


def format_raw_id(details: dict, fallback: str = "") -> str:
    """Format raw identity ID without resolution.

    Args:
        details: owner_details or group_details dict with id_type and id_value
        fallback: fallback value if details are empty or missing keys

    Returns:
        Formatted string like UID:1001, GID:100, SID:S-1-5-21-..., or auth_id:<value>
    """
    if not details:
        return f"auth_id:{fallback}" if fallback else "Unknown"

    id_type = details.get("id_type", "")
    id_value = details.get("id_value", "")

    if id_type == "NFS_UID":
        return f"UID:{id_value}"
    elif id_type == "NFS_GID":
        return f"GID:{id_value}"
    elif id_type == "SMB_SID":
        return f"SID:{id_value}"
    elif id_value:
        return f"auth_id:{id_value}"
    elif fallback:
        return f"auth_id:{fallback}"
    else:
        return "Unknown"


def format_owner_name(identity: Dict) -> str:
    """Format owner name from resolved identity."""
    if not identity:
        return "Unknown"

    owner_name = identity.get("name", "Unknown")
    domain = identity.get("domain", "UNKNOWN")

    # For POSIX_USER domain, show UID if available
    if domain == "POSIX_USER" and "uid" in identity:
        uid = identity.get("uid")
        if owner_name and owner_name.startswith("Unknown"):
            return f"UID {uid}"
        elif owner_name:
            return f"{owner_name} (UID {uid})"
        else:
            return f"UID {uid}"

    # For POSIX_GROUP domain, show GID if available
    elif domain == "POSIX_GROUP" and "gid" in identity:
        gid = identity.get("gid")
        if owner_name and owner_name.startswith("Unknown"):
            return f"GID {gid}"
        elif owner_name:
            return f"{owner_name} (GID {gid})"
        else:
            return f"GID {gid}"

    return owner_name
