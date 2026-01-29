"""
Filtering logic for grumpwalk.

This module contains functions for creating and applying file filters
based on name patterns, time, size, owner, and type criteria.
"""

import fnmatch
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional, Set, TYPE_CHECKING, Callable

# Try to use aiohttp
try:
    import aiohttp
except ImportError:
    print(
        "[ERROR] aiohttp not installed. Install with: pip install aiohttp",
        file=sys.stderr,
    )
    sys.exit(1)

# Import from other modules
from .utils import parse_size_to_bytes

# TYPE_CHECKING imports to avoid circular dependencies
if TYPE_CHECKING:
    from .client import AsyncQumuloClient

async def resolve_owner_filters(
    client: "AsyncQumuloClient",
    session: aiohttp.ClientSession,
    args,
    parse_trustee: Callable
) -> Optional[Set[str]]:
    """
    Resolve owner filter arguments to a set of auth_ids to match.

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp ClientSession
        args: Command-line arguments
        parse_trustee: Function to parse trustee strings (from ACL module)

    Returns:
        None if no owner filter specified, otherwise a set of auth_ids
        (may be empty if resolution failed - filter will match nothing)
    """
    if not args.owners:
        return None

    # Determine owner type
    owner_type = "auto"
    if args.ad:
        owner_type = "ad"
    elif args.local:
        owner_type = "local"
    elif args.uid:
        owner_type = "uid"

    all_auth_ids = set()

    for owner in args.owners:
        # Parse the owner input based on type
        if owner_type == "uid":
            # UID - resolve by UID
            try:
                identity = await client.resolve_identity(session, owner, "uid")
                if identity.get("resolved") and identity.get("auth_id"):
                    all_auth_ids.add(identity["auth_id"])
            except Exception as e:
                print(f"[WARN] Failed to resolve UID {owner}: {e}", file=sys.stderr)
        elif owner_type == "ad":
            # Active Directory - resolve by name with AD domain
            payload_info = parse_trustee(f"ad:{owner}")
            payload = payload_info["payload"]

            url = f"{client.base_url}/v1/identity/find"
            try:
                async with session.post(
                    url, json=payload, ssl=client.ssl_context
                ) as response:
                    if response.status == 200:
                        identity = await response.json()
                        if identity.get("auth_id"):
                            all_auth_ids.add(identity["auth_id"])
            except Exception as e:
                print(f"[WARN] Failed to resolve AD user {owner}: {e}", file=sys.stderr)
        elif owner_type == "local":
            # Local - resolve by name with LOCAL domain
            payload_info = parse_trustee(f"local:{owner}")
            payload = payload_info["payload"]

            url = f"{client.base_url}/v1/identity/find"
            try:
                async with session.post(
                    url, json=payload, ssl=client.ssl_context
                ) as response:
                    if response.status == 200:
                        identity = await response.json()
                        if identity.get("auth_id"):
                            all_auth_ids.add(identity["auth_id"])
            except Exception as e:
                print(
                    f"[WARN] Failed to resolve local user {owner}: {e}", file=sys.stderr
                )
        else:
            # Auto-detect - parse and resolve
            payload_info = parse_trustee(owner)
            payload = payload_info["payload"]

            url = f"{client.base_url}/v1/identity/find"
            try:
                async with session.post(
                    url, json=payload, ssl=client.ssl_context
                ) as response:
                    if response.status == 200:
                        identity = await response.json()
                        if identity.get("auth_id"):
                            all_auth_ids.add(identity["auth_id"])
            except Exception as e:
                print(f"[WARN] Failed to resolve owner {owner}: {e}", file=sys.stderr)

    # If expand-identity is enabled, expand all auth_ids
    if args.expand_identity and all_auth_ids:
        expanded_ids = set()
        for auth_id in all_auth_ids:
            equivalent_ids = await client.expand_identity(session, auth_id)
            expanded_ids.update(equivalent_ids)
        return expanded_ids

    # Return the set even if empty - this ensures the filter is applied
    # and matches nothing when owner was specified but couldn't be resolved
    return all_auth_ids


def glob_to_regex(pattern: str) -> str:
    """
    Convert a glob pattern to a regex pattern.
    Supports common glob wildcards: *, ?, [seq], [!seq]

    If the pattern is already a valid regex (contains regex special chars
    that aren't glob chars), return it as-is.

    Args:
        pattern: Glob or regex pattern

    Returns:
        Regex pattern string
    """
    # Check if this looks like a regex pattern (contains regex-specific chars)
    # that aren't also glob chars. If so, assume it's already regex.
    regex_specific_chars = {'^', '$', '.', '+', '(', ')', '|', '{', '}', '\\'}

    # If pattern starts with common regex anchors or contains regex-specific syntax,
    # treat it as regex
    if pattern.startswith('^') or pattern.endswith('$'):
        return pattern

    # Check for regex-specific characters (excluding those used in globs)
    has_regex_chars = any(char in pattern for char in regex_specific_chars)

    # If it has regex chars, try to compile it as regex first
    if has_regex_chars:
        try:
            re.compile(pattern)
            # If it compiles successfully, it's likely a regex pattern
            return pattern
        except re.error:
            # If it fails, fall through to glob conversion
            pass

    # Convert glob to regex using fnmatch
    return fnmatch.translate(pattern)


def create_file_filter(args, owner_auth_ids: Optional[Set[str]] = None):
    """Create a file filter function based on command-line arguments."""

    # Calculate time thresholds (using current UTC time)
    now_utc = datetime.now(timezone.utc).replace(
        tzinfo=None
    )  # Convert to timezone-naive for comparison
    time_threshold_older = None
    time_threshold_newer = None

    if args.older_than:
        time_threshold_older = now_utc - timedelta(days=args.older_than)
    if args.newer_than:
        time_threshold_newer = now_utc - timedelta(days=args.newer_than)

    # Calculate field-specific time thresholds
    field_time_filters = {}

    if args.accessed_older_than or args.accessed_newer_than:
        field_time_filters["access_time"] = {
            "older": (
                now_utc - timedelta(days=args.accessed_older_than)
                if args.accessed_older_than
                else None
            ),
            "newer": (
                now_utc - timedelta(days=args.accessed_newer_than)
                if args.accessed_newer_than
                else None
            ),
        }

    if args.modified_older_than or args.modified_newer_than:
        field_time_filters["modification_time"] = {
            "older": (
                now_utc - timedelta(days=args.modified_older_than)
                if args.modified_older_than
                else None
            ),
            "newer": (
                now_utc - timedelta(days=args.modified_newer_than)
                if args.modified_newer_than
                else None
            ),
        }

    if args.created_older_than or args.created_newer_than:
        field_time_filters["creation_time"] = {
            "older": (
                now_utc - timedelta(days=args.created_older_than)
                if args.created_older_than
                else None
            ),
            "newer": (
                now_utc - timedelta(days=args.created_newer_than)
                if args.created_newer_than
                else None
            ),
        }

    if args.changed_older_than or args.changed_newer_than:
        field_time_filters["change_time"] = {
            "older": (
                now_utc - timedelta(days=args.changed_older_than)
                if args.changed_older_than
                else None
            ),
            "newer": (
                now_utc - timedelta(days=args.changed_newer_than)
                if args.changed_newer_than
                else None
            ),
        }

    # Parse size filters
    size_larger = None
    size_smaller = None
    include_metadata = args.include_metadata

    if args.larger_than:
        size_larger = parse_size_to_bytes(args.larger_than)
    if args.smaller_than:
        size_smaller = parse_size_to_bytes(args.smaller_than)

    # Determine time field
    time_field = args.time_field

    # Compile name patterns (OR logic)
    name_patterns_or = []
    if args.name_patterns:
        regex_flags = 0 if args.name_case_sensitive else re.IGNORECASE
        for pattern in args.name_patterns:
            try:
                # Convert glob to regex if needed
                regex_pattern = glob_to_regex(pattern)
                name_patterns_or.append(re.compile(regex_pattern, regex_flags))
            except re.error as e:
                print(f"[ERROR] Invalid pattern '{pattern}': {e}", file=sys.stderr)
                sys.exit(1)

    # Compile name patterns (AND logic)
    name_patterns_and = []
    if args.name_patterns_and:
        regex_flags = 0 if args.name_case_sensitive else re.IGNORECASE
        for pattern in args.name_patterns_and:
            try:
                # Convert glob to regex if needed
                regex_pattern = glob_to_regex(pattern)
                name_patterns_and.append(re.compile(regex_pattern, regex_flags))
            except re.error as e:
                print(f"[ERROR] Invalid pattern '{pattern}': {e}", file=sys.stderr)
                sys.exit(1)

    # Map type argument to Qumulo API type
    target_type = None
    if args.type:
        type_mapping = {
            'file': 'FS_FILE_TYPE_FILE',
            'f': 'FS_FILE_TYPE_FILE',
            'directory': 'FS_FILE_TYPE_DIRECTORY',
            'dir': 'FS_FILE_TYPE_DIRECTORY',
            'd': 'FS_FILE_TYPE_DIRECTORY',
            'symlink': 'FS_FILE_TYPE_SYMLINK',
            'link': 'FS_FILE_TYPE_SYMLINK',
            'l': 'FS_FILE_TYPE_SYMLINK',
        }
        target_type = type_mapping.get(args.type)

    def file_filter(entry: dict) -> bool:
        """Filter function that returns True if entry matches all criteria."""

        # Type filter
        if target_type and entry.get("type") != target_type:
            return False

        # Name pattern filters (OR logic - any pattern can match)
        if name_patterns_or:
            # Extract basename from path
            path = entry.get("path", "")
            name = path.rstrip('/').split('/')[-1] if '/' in path else path

            # Check if any pattern matches
            if not any(pattern.search(name) for pattern in name_patterns_or):
                return False

        # Name pattern filters (AND logic - all patterns must match)
        if name_patterns_and:
            # Extract basename from path
            path = entry.get("path", "")
            name = path.rstrip('/').split('/')[-1] if '/' in path else path

            # Check if all patterns match
            if not all(pattern.search(name) for pattern in name_patterns_and):
                return False

        # File-only filter (deprecated - use --type file instead)
        if args.file_only and entry.get("type") == "FS_FILE_TYPE_DIRECTORY":
            return False

        # Owner filter
        if owner_auth_ids is not None:
            # Get owner from entry - try owner_details first, then owner
            owner_details = entry.get("owner_details", {})
            file_owner_auth_id = owner_details.get("auth_id") or entry.get("owner")

            if not file_owner_auth_id:
                # No owner info, skip this file
                return False

            # Check if file owner matches any of our target auth_ids
            if file_owner_auth_id not in owner_auth_ids:
                return False

        # Size filters
        if size_larger is not None or size_smaller is not None:
            file_size = entry.get("size")
            if file_size is None:
                return False

            try:
                size_bytes = int(file_size)

                # Add metadata size if requested
                if include_metadata:
                    metablocks = entry.get("metablocks")
                    if metablocks:
                        try:
                            metadata_bytes = int(metablocks) * 4096
                            size_bytes += metadata_bytes
                        except (ValueError, TypeError):
                            pass  # If metablocks is invalid, just use file size

                if size_larger is not None and size_bytes <= size_larger:
                    return False
                if size_smaller is not None and size_bytes >= size_smaller:
                    return False
            except (ValueError, TypeError):
                return False

        # Time filters
        if time_threshold_older is not None or time_threshold_newer is not None:
            time_value = entry.get(time_field)
            if not time_value:
                return False

            try:
                # Parse Qumulo timestamp format: "2023-01-15T10:30:45.123456789Z"
                # Remove 'Z' and parse as timezone-naive for comparison
                file_time = datetime.fromisoformat(time_value.rstrip("Z").split(".")[0])

                if (
                    time_threshold_older is not None
                    and file_time >= time_threshold_older
                ):
                    return False
                if (
                    time_threshold_newer is not None
                    and file_time <= time_threshold_newer
                ):
                    return False
            except (ValueError, AttributeError):
                return False

        # Field-specific time filters (AND logic - all must match)
        for field_name, thresholds in field_time_filters.items():
            time_value = entry.get(field_name)
            if not time_value:
                return False  # If field is missing, reject the file

            try:
                # Parse Qumulo timestamp format
                file_time = datetime.fromisoformat(time_value.rstrip("Z").split(".")[0])

                # Check both older and newer thresholds if specified
                if thresholds["older"] is not None and file_time >= thresholds["older"]:
                    return False
                if thresholds["newer"] is not None and file_time <= thresholds["newer"]:
                    return False
            except (ValueError, AttributeError):
                return False  # If parsing fails, reject the file

        return True

    return file_filter
