"""
Utility functions for grumpwalk.

This module contains general-purpose utility functions for formatting,
parsing, and error handling.
"""

import re
from typing import Optional, Dict
from urllib.parse import urlparse, parse_qs


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
