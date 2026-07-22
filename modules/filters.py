"""
Filtering logic for grumpwalk.

This module contains functions for creating and applying file filters
based on name patterns, time, size, owner, type, and extended attribute criteria.
"""

import difflib
import fnmatch
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional, Set, List, TYPE_CHECKING, Callable

from .utils import log_stderr

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

# ---------------------------------------------------------------------------
# Extended attribute constants
# ---------------------------------------------------------------------------

FINDABLE_ATTRIBUTES = frozenset({
    "read_only", "hidden", "system", "archive",
    "temporary", "compressed", "not_content_indexed",
    "sparse_file", "offline",
})

SETTABLE_ATTRIBUTES = frozenset({
    "read_only", "hidden", "system", "archive",
})

ATTRIBUTE_ALIASES = {
    "sparse": "sparse_file",
    "readonly": "read_only",
    "nci": "not_content_indexed",
    "not_indexed": "not_content_indexed",
}


def parse_attribute_list(
    comma_str: str,
    allowed: frozenset,
    flag_name: str,
) -> List[str]:
    """
    Parse a comma-separated attribute list, resolve aliases, and validate.

    Args:
        comma_str: Comma-separated attribute names (e.g. "read_only,hidden,sparse")
        allowed: Set of valid canonical attribute names
        flag_name: CLI flag name for error messages

    Returns:
        Deduplicated list of canonical attribute names
    """
    seen = []
    for raw in comma_str.split(","):
        name = raw.strip().lower()
        if not name:
            continue

        canonical = ATTRIBUTE_ALIASES.get(name, name)

        if canonical not in allowed:
            close = difflib.get_close_matches(canonical, sorted(allowed), n=1, cutoff=0.5)
            hint = f" Did you mean '{close[0]}'?" if close else ""
            print(
                f"Error: Unknown attribute '{raw.strip()}' for {flag_name}.{hint}\n"
                f"  Valid attributes: {', '.join(sorted(allowed))}",
                file=sys.stderr,
            )
            sys.exit(1)

        if canonical not in seen:
            seen.append(canonical)

    return seen

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
                log_stderr("WARN", f"Failed to resolve UID {owner}: {e}")
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
                log_stderr("WARN", f"Failed to resolve AD user {owner}: {e}")
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
                log_stderr("WARN", f"Failed to resolve local user {owner}: {e}")
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
                log_stderr("WARN", f"Failed to resolve owner {owner}: {e}")

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


# Characters that mean something different in a regex than in a shell glob.
# Used both to auto-detect regex intent and to spot ambiguous patterns.
REGEX_SPECIFIC_CHARS = {'^', '$', '.', '+', '(', ')', '|', '{', '}', '\\'}

# Pattern interpretation modes, selected globally by --regex / --glob.
PATTERN_MODE_AUTO = "auto"
PATTERN_MODE_REGEX = "regex"
PATTERN_MODE_GLOB = "glob"


def resolve_pattern_mode(args) -> str:
    """Return the pattern interpretation mode selected by --regex / --glob."""
    if getattr(args, "force_regex", False):
        return PATTERN_MODE_REGEX
    if getattr(args, "force_glob", False):
        return PATTERN_MODE_GLOB
    return PATTERN_MODE_AUTO


def glob_to_regex(pattern: str, mode: str = PATTERN_MODE_AUTO) -> str:
    """
    Convert a glob pattern to a regex pattern.
    Supports common glob wildcards: *, ?, [seq], [!seq]

    Globs are anchored to the whole name (standard shell-glob semantics), so
    'file_*' matches names that begin with 'file_', not names that merely
    contain it. If the pattern is already a valid regex (contains regex special
    chars that aren't glob chars), it is returned as-is and stays unanchored so
    callers' re.search keeps its substring behavior.

    Args:
        pattern: Glob or regex pattern
        mode: PATTERN_MODE_AUTO detects which one was meant (the default, and
            grumpwalk's historical behavior); PATTERN_MODE_REGEX and
            PATTERN_MODE_GLOB skip detection and read every pattern the one way,
            as selected by --regex / --glob.

    Returns:
        Regex pattern string
    """
    if mode == PATTERN_MODE_REGEX:
        return pattern
    if mode == PATTERN_MODE_GLOB:
        return r"\A" + fnmatch.translate(pattern)

    # If pattern starts with common regex anchors or contains regex-specific syntax,
    # treat it as regex
    if pattern.startswith('^') or pattern.endswith('$'):
        return pattern

    # Check for regex-specific characters (excluding those used in globs)
    has_regex_chars = any(char in pattern for char in REGEX_SPECIFIC_CHARS)

    # If it has regex chars, try to compile it as regex first
    if has_regex_chars:
        try:
            re.compile(pattern)
            # If it compiles successfully, it's likely a regex pattern
            return pattern
        except re.error:
            # If it fails, fall through to glob conversion
            pass

    # Convert glob to regex using fnmatch. fnmatch.translate anchors only the
    # end (\Z); name filters match with re.search, so without a start anchor a
    # glob would match any name *containing* the pattern (e.g. 'file_*' would
    # match 'myfile_1'). Prepend \A so a glob matches the WHOLE name, matching
    # standard shell-glob semantics. User-written regexes (returned above,
    # unanchored) keep their re.search behavior.
    return r"\A" + fnmatch.translate(pattern)


def pattern_is_ambiguous(pattern: str) -> bool:
    """
    Return True if auto-detection reads this pattern as a regex when a shell
    glob would have been a reasonable reading too, and the two disagree.

    Only these patterns can surprise a user: they carry no explicit ^/$ anchor,
    so nothing signals regex intent, yet they compile as one. '.*' is the
    canonical case - as a regex it matches every name, as a glob it means "starts
    with a period". Patterns that cannot compile as a regex ('*.log') or that are
    explicitly anchored ('^[0-9]') have exactly one sensible reading, so they are
    never ambiguous.
    """
    if pattern.startswith('^') or pattern.endswith('$'):
        return False
    if not any(char in pattern for char in REGEX_SPECIFIC_CHARS):
        return False
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def warn_if_ambiguous(patterns: Optional[List[str]], mode: str, flag: str) -> None:
    """Warn once per ambiguous pattern that auto-detection had to guess.

    Silent when --regex or --glob was given: the user already said which they
    meant, so there is nothing to guess and nothing to warn about.
    """
    if not patterns or mode != PATTERN_MODE_AUTO:
        return
    for pattern in patterns:
        if pattern_is_ambiguous(pattern):
            log_stderr(
                "WARN",
                f"{flag} pattern '{pattern}' is ambiguous: it was read as a REGEX "
                "(unanchored, so '.' matches any character and the pattern may match "
                "part of a name). As a shell glob it would mean something different "
                "('.' would be a literal period and the match would cover the whole "
                "name). Pass --regex or --glob to say which you meant and silence "
                "this warning.",
            )


class OmitPatterns(list):
    """--omit-subdirs patterns plus the mode they should be matched with.

    A list subclass so every existing call site can keep passing it around as the
    plain list of strings it used to be. Directory omission has always been glob
    matching, and stays glob under auto-detection - reading '--omit-subdirs .*'
    as a regex would silently prune the entire tree. Only an explicit --regex
    switches it.
    """

    def __init__(self, patterns: Optional[List[str]] = None,
                 mode: str = PATTERN_MODE_AUTO):
        super().__init__(patterns or [])
        self.mode = mode
        self._regexes: Optional[List["re.Pattern"]] = None
        if mode == PATTERN_MODE_REGEX:
            self._regexes = []
            for pattern in self:
                try:
                    self._regexes.append(re.compile(pattern.rstrip("/")))
                except re.error as e:
                    log_stderr("ERROR", f"Invalid --omit-subdirs regex '{pattern}': {e}")
                    sys.exit(1)

    def matches(self, path: str, name: str) -> bool:
        """True if this directory should be omitted, by full path or by name."""
        if self._regexes is not None:
            stripped = path.rstrip("/")
            return any(r.search(stripped) or r.search(name) for r in self._regexes)
        for pattern in self:
            normalized = pattern.rstrip("/")
            if (fnmatch.fnmatch(path.rstrip("/"), normalized)
                    or fnmatch.fnmatch(name, normalized)):
                return True
        return False


def omit_matches(patterns, path: str, name: str) -> bool:
    """Match against --omit-subdirs patterns, accepting a plain list of globs."""
    if patterns is None:
        return False
    if isinstance(patterns, OmitPatterns):
        return patterns.matches(path, name)
    return OmitPatterns(patterns).matches(path, name)


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

    # Compile name patterns. --regex / --glob decide how every pattern is read;
    # by default each one is auto-detected as a glob or a regex.
    pattern_mode = resolve_pattern_mode(args)
    regex_flags = 0 if args.name_case_sensitive else re.IGNORECASE

    def compile_name_patterns(patterns, flag: str) -> List["re.Pattern"]:
        warn_if_ambiguous(patterns, pattern_mode, flag)
        compiled = []
        for pattern in patterns or []:
            try:
                compiled.append(
                    re.compile(glob_to_regex(pattern, pattern_mode), regex_flags)
                )
            except re.error as e:
                log_stderr("ERROR", f"Invalid pattern '{pattern}': {e}")
                sys.exit(1)
        return compiled

    # OR logic - any pattern can match
    name_patterns_or = compile_name_patterns(args.name_patterns, "--name")
    # AND logic - all patterns must match
    name_patterns_and = compile_name_patterns(args.name_patterns_and, "--name-and")
    # Exclusion - matching any pattern rejects the entry
    name_patterns_not = compile_name_patterns(
        getattr(args, "name_patterns_not", None), "--not-name"
    )

    # Extended attribute filters
    find_attr_true = getattr(args, 'find_attribute_true_parsed', None)
    find_attr_false = getattr(args, 'find_attribute_false_parsed', None)

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

        # Name pattern filters. All three match against the basename, never the
        # full path, so --not-name excludes an object by its own name and does
        # not exclude the contents of a directory it matched (use
        # --omit-subdirs for that).
        if name_patterns_or or name_patterns_and or name_patterns_not:
            path = entry.get("path", "")
            name = path.rstrip('/').split('/')[-1] if '/' in path else path

            # Exclusion first: matching any --not-name pattern rejects the entry
            if any(pattern.search(name) for pattern in name_patterns_not):
                return False

            # OR logic - any pattern can match
            if name_patterns_or and not any(
                pattern.search(name) for pattern in name_patterns_or
            ):
                return False

            # AND logic - all patterns must match
            if name_patterns_and and not all(
                pattern.search(name) for pattern in name_patterns_and
            ):
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

        # Extended attribute filters
        if find_attr_true:
            ext_attrs = entry.get("extended_attributes", {})
            if not all(ext_attrs.get(attr) is True for attr in find_attr_true):
                return False

        if find_attr_false:
            ext_attrs = entry.get("extended_attributes", {})
            if not all(ext_attrs.get(attr) is False for attr in find_attr_false):
                return False

        return True

    return file_filter
