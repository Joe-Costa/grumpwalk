#!/usr/bin/env python3

"""
Qumulo File Filter - Async Python version with aiohttp

High-performance async implementation using direct REST API calls instead of qq CLI.
Applies lessons learned from benchmark_async_aiohttp.py for 6-7x performance improvement.

Usage:
    ./qumulo_file_filter_async.py --host <cluster> --path <path> [OPTIONS]

Key improvements over bash version:
- Direct REST API calls via aiohttp (no subprocess overhead)
- Concurrent HTTP requests with asyncio
- Connection pooling for efficiency
- Progress reporting in real-time
- Multi-node support for load distribution
"""

import argparse
import asyncio
import fnmatch
import json
import ssl
import sys
import time
from pathlib import Path
from typing import List, Optional, Dict, Set
from urllib.parse import quote, urlparse, parse_qs
from datetime import datetime, timedelta, timezone

# Add the Qumulo CLI directory to path to import auth modules
CLI_PATH = Path(__file__).parent / 'cli' / 'cli'
sys.path.insert(0, str(CLI_PATH))

try:
    from qumulo.lib.auth import get_credentials, credential_store_filename
except ImportError as e:
    print(f"[ERROR] Failed to import Qumulo API modules: {e}", file=sys.stderr)
    print(f"[ERROR] Make sure the CLI directory exists at: {CLI_PATH}", file=sys.stderr)
    sys.exit(1)

try:
    import aiohttp
except ImportError:
    print("[ERROR] aiohttp not installed. Install with: pip install aiohttp", file=sys.stderr)
    sys.exit(1)

# Try to use ujson for faster parsing
try:
    import ujson as json_parser
    JSON_PARSER_NAME = "ujson"
except ImportError:
    import json as json_parser
    JSON_PARSER_NAME = "json"


class OwnerStats:
    """Track file ownership statistics for --owner-report."""

    def __init__(self):
        self.owner_data = {}  # auth_id -> {'bytes': int, 'files': int, 'dirs': int}
        self.lock = asyncio.Lock()

    async def add_file(self, owner_auth_id: str, size: int, is_dir: bool = False):
        """Add a file to the owner statistics."""
        async with self.lock:
            if owner_auth_id not in self.owner_data:
                self.owner_data[owner_auth_id] = {'bytes': 0, 'files': 0, 'dirs': 0}

            self.owner_data[owner_auth_id]['bytes'] += size
            if is_dir:
                self.owner_data[owner_auth_id]['dirs'] += 1
            else:
                self.owner_data[owner_auth_id]['files'] += 1

    def get_all_owners(self) -> List[str]:
        """Get list of all unique owner auth_ids."""
        return list(self.owner_data.keys())

    def get_stats(self, owner_auth_id: str) -> Dict:
        """Get statistics for a specific owner."""
        return self.owner_data.get(owner_auth_id, {'bytes': 0, 'files': 0, 'dirs': 0})


class ProgressTracker:
    """Track progress of async tree walking with real-time updates."""

    def __init__(self, verbose: bool = False):
        self.total_objects = 0
        self.total_dirs = 0
        self.matches = 0
        self.start_time = time.time()
        self.verbose = verbose
        self.last_update = time.time()
        self.lock = asyncio.Lock()

    async def update(self, objects: int, dirs: int = 0, matches: int = 0):
        """Update progress counters."""
        async with self.lock:
            self.total_objects += objects
            self.total_dirs += dirs
            self.matches += matches

            # Print progress every 0.5 seconds
            if self.verbose and time.time() - self.last_update > 0.5:
                elapsed = time.time() - self.start_time
                rate = self.total_objects / elapsed if elapsed > 0 else 0
                print(f"\r[PROGRESS] Objects: {self.total_objects:,} | "
                      f"Matches: {self.matches:,} | "
                      f"Rate: {rate:.1f} obj/sec",
                      end='', file=sys.stderr, flush=True)
                self.last_update = time.time()

    def final_report(self):
        """Print final progress report."""
        if self.verbose:
            elapsed = time.time() - self.start_time
            rate = self.total_objects / elapsed if elapsed > 0 else 0
            print(f"\r[PROGRESS] FINAL: {self.total_objects:,} objects processed | "
                  f"{self.matches:,} matches | "
                  f"{rate:.1f} obj/sec | "
                  f"{elapsed:.1f}s total",
                  file=sys.stderr)


class Profiler:
    """Track detailed performance metrics for profiling."""

    def __init__(self):
        self.timings = {}  # operation -> total time
        self.counts = {}   # operation -> call count
        self.lock = asyncio.Lock()

    async def record(self, operation: str, duration: float):
        """Record timing for an operation."""
        async with self.lock:
            if operation not in self.timings:
                self.timings[operation] = 0.0
                self.counts[operation] = 0
            self.timings[operation] += duration
            self.counts[operation] += 1

    def record_sync(self, operation: str, duration: float):
        """Record timing for an operation (synchronous version)."""
        if operation not in self.timings:
            self.timings[operation] = 0.0
            self.counts[operation] = 0
        self.timings[operation] += duration
        self.counts[operation] += 1

    def print_report(self, total_elapsed: float):
        """Print profiling report."""
        print("\n" + "=" * 80, file=sys.stderr)
        print("PROFILING REPORT", file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Calculate total accounted time
        total_accounted = sum(self.timings.values())

        # Sort by total time descending
        sorted_ops = sorted(self.timings.items(), key=lambda x: x[1], reverse=True)

        print(f"\n{'Operation':<30} {'Total Time':>12} {'Calls':>10} {'Avg Time':>12} {'% Total':>8}", file=sys.stderr)
        print("-" * 80, file=sys.stderr)

        for operation, total_time in sorted_ops:
            count = self.counts[operation]
            avg_time = total_time / count if count > 0 else 0
            pct_total = (total_time / total_elapsed * 100) if total_elapsed > 0 else 0

            print(f"{operation:<30} {total_time:>11.3f}s {count:>10,} {avg_time*1000:>11.2f}ms {pct_total:>7.1f}%",
                  file=sys.stderr)

        print("-" * 80, file=sys.stderr)
        print(f"{'Total Accounted':<30} {total_accounted:>11.3f}s", file=sys.stderr)
        print(f"{'Total Elapsed':<30} {total_elapsed:>11.3f}s", file=sys.stderr)

        unaccounted = total_elapsed - total_accounted
        if unaccounted > 0.01:
            pct_unaccounted = (unaccounted / total_elapsed * 100) if total_elapsed > 0 else 0
            print(f"{'Unaccounted (overhead)':<30} {unaccounted:>11.3f}s {pct_unaccounted:>7.1f}%", file=sys.stderr)

        # Identify bottlenecks
        print(f"\nTop 3 Bottlenecks:", file=sys.stderr)
        for i, (operation, total_time) in enumerate(sorted_ops[:3]):
            pct = (total_time / total_elapsed * 100) if total_elapsed > 0 else 0
            print(f"  {i+1}. {operation}: {pct:.1f}% of total time", file=sys.stderr)

        print("=" * 80, file=sys.stderr)


def extract_pagination_token(api_response: dict) -> Optional[str]:
    """Extract the pagination token from Qumulo API response."""
    if 'paging' not in api_response:
        return None

    next_url = api_response['paging'].get('next')
    if not next_url:
        return None

    try:
        parsed = urlparse(next_url)
        query_params = parse_qs(parsed.query)

        if 'after' in query_params:
            return query_params['after'][0]
        else:
            return None

    except Exception:
        return None


class AsyncQumuloClient:
    """Async Qumulo API client using aiohttp with optimized connection pooling."""

    def __init__(self, host: str, port: int, bearer_token: str,
                 max_concurrent: int = 100, connector_limit: int = 100):
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.bearer_token = bearer_token
        self.max_concurrent = max_concurrent

        # Create SSL context that doesn't verify certificates (for self-signed certs)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # Configure connection pooling
        self.connector_limit = connector_limit

        self.headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {bearer_token}'
        }

        # Semaphore to limit concurrent operations
        self.semaphore = asyncio.Semaphore(max_concurrent)

    def create_session(self) -> aiohttp.ClientSession:
        """Create optimized ClientSession with connection pooling."""
        connector = aiohttp.TCPConnector(
            limit=self.connector_limit,
            limit_per_host=self.connector_limit,
            ttl_dns_cache=300,
            ssl=self.ssl_context
        )
        return aiohttp.ClientSession(connector=connector, headers=self.headers)

    async def get_directory_page(self, session: aiohttp.ClientSession, path: str,
                                 limit: int = 1000, after_token: Optional[str] = None) -> dict:
        """
        Fetch a single page of directory contents from Qumulo API.

        Args:
            session: aiohttp ClientSession
            path: Directory path (must start with '/')
            limit: Maximum entries per page
            after_token: Pagination token from previous response

        Returns:
            Dictionary containing 'files' and 'paging' metadata
        """
        async with self.semaphore:
            if not path.startswith('/'):
                path = '/' + path

            encoded_path = quote(path, safe='')
            url = f"{self.base_url}/v1/files/{encoded_path}/entries/"

            params = {'limit': limit}
            if after_token:
                params['after'] = after_token

            async with session.get(url, params=params, ssl=self.ssl_context) as response:
                response.raise_for_status()
                return await response.json()

    async def enumerate_directory(self, session: aiohttp.ClientSession, path: str,
                                  max_entries: Optional[int] = None) -> List[dict]:
        """
        Enumerate all entries in a directory, following pagination.

        Args:
            session: aiohttp ClientSession
            path: Directory path
            max_entries: Optional limit on total entries to fetch

        Returns:
            List of all file/directory entries
        """
        all_entries = []
        after_token = None

        while True:
            response = await self.get_directory_page(session, path, limit=1000, after_token=after_token)

            files = response.get('files', [])
            all_entries.extend(files)

            # Check if we've reached the max entries limit
            if max_entries and len(all_entries) >= max_entries:
                all_entries = all_entries[:max_entries]
                break

            # Get next token
            after_token = extract_pagination_token(response)
            if not after_token:
                break

        return all_entries

    async def walk_tree_async(self, session: aiohttp.ClientSession, path: str,
                             max_depth: Optional[int] = None,
                             _current_depth: int = 0,
                             progress: Optional[ProgressTracker] = None,
                             file_filter=None,
                             owner_stats: Optional[OwnerStats] = None,
                             omit_subdirs: Optional[List[str]] = None,
                             collect_results: bool = True) -> List[dict]:
        """
        Recursively walk directory tree with concurrent directory enumeration.

        Args:
            session: aiohttp ClientSession
            path: Directory path to walk
            max_depth: Maximum depth to traverse (-1 or None for unlimited)
            _current_depth: Internal tracking of current depth
            progress: Optional ProgressTracker for reporting progress
            file_filter: Optional function to filter files
            owner_stats: Optional OwnerStats for collecting ownership data
            omit_subdirs: Optional list of wildcard patterns for directories to skip
            collect_results: If False, don't accumulate matching entries (saves memory for reports)

        Returns:
            List of matching file entries (empty if collect_results=False)
        """
        # Check depth limit
        if max_depth is not None and max_depth >= 0 and _current_depth >= max_depth:
            return []

        # Enumerate current directory
        entries = await self.enumerate_directory(session, path)

        # Filter entries and collect owner stats
        matching_entries = []
        match_count = 0

        for entry in entries:
            # Collect owner statistics if enabled
            if owner_stats:
                owner_details = entry.get('owner_details', {})
                owner_auth_id = owner_details.get('auth_id') or entry.get('owner')
                if owner_auth_id:
                    # Convert size to int (may be string from API)
                    try:
                        file_size = int(entry.get('size', 0))
                    except (ValueError, TypeError):
                        file_size = 0
                    is_dir = entry.get('type') == 'FS_FILE_TYPE_DIRECTORY'
                    await owner_stats.add_file(owner_auth_id, file_size, is_dir)

            # Apply filter and optionally collect results
            passes_filter = False
            if file_filter:
                if file_filter(entry):
                    passes_filter = True
                    match_count += 1
                    if collect_results:
                        matching_entries.append(entry)
            else:
                passes_filter = True
                match_count += 1
                if collect_results:
                    matching_entries.append(entry)

        # Find subdirectories and filter based on omit patterns
        subdirs = []
        omitted_count = 0

        for entry in entries:
            if entry.get('type') == 'FS_FILE_TYPE_DIRECTORY':
                subdir_path = entry['path']
                subdir_name = entry.get('name', '')

                # Check if this directory should be omitted
                should_omit = False
                if omit_subdirs:
                    for pattern in omit_subdirs:
                        if fnmatch.fnmatch(subdir_name, pattern):
                            should_omit = True
                            omitted_count += 1
                            break

                if not should_omit:
                    subdirs.append(subdir_path)

        # Update progress tracker
        if progress:
            await progress.update(len(entries), 1, match_count)

        # Recursively process subdirectories concurrently
        if subdirs and (max_depth is None or max_depth < 0 or _current_depth + 1 < max_depth):
            tasks = [
                self.walk_tree_async(session, subdir, max_depth, _current_depth + 1, progress, file_filter, owner_stats, omit_subdirs, collect_results)
                for subdir in subdirs
            ]

            # Process all subdirectories concurrently
            subdir_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Collect results from subdirectories (only if collect_results=True)
            if collect_results:
                for result in subdir_results:
                    if isinstance(result, list):
                        matching_entries.extend(result)

        return matching_entries

    async def resolve_identity(self, session: aiohttp.ClientSession,
                               identifier: str, id_type: str = "auth_id") -> Dict:
        """
        Resolve an identity using various identifier types.

        Args:
            session: aiohttp ClientSession
            identifier: The identifier value (auth_id, SID, UID, GID, or name)
            id_type: Type of identifier - "auth_id", "sid", "uid", "gid", or "name"

        Returns:
            Dictionary containing complete identity information
        """
        url = f"{self.base_url}/v1/identity/find"

        # Build the appropriate payload based on identifier type
        if id_type == "auth_id":
            payload = {"auth_id": str(identifier)}
        elif id_type == "sid":
            payload = {"sid": str(identifier)}
        elif id_type == "uid":
            # UID must be an integer
            try:
                payload = {"uid": int(identifier)}
            except (ValueError, TypeError):
                raise ValueError(f"UID must be a valid integer: {identifier}")
        elif id_type == "gid":
            # GID must be an integer
            try:
                payload = {"gid": int(identifier)}
            except (ValueError, TypeError):
                raise ValueError(f"GID must be a valid integer: {identifier}")
        elif id_type == "name":
            payload = {"name": str(identifier)}
        else:
            raise ValueError(f"Unknown id_type: {id_type}. Must be auth_id, sid, uid, gid, or name")

        try:
            async with session.post(url, json=payload, ssl=self.ssl_context) as response:
                if response.status == 200:
                    result = await response.json()
                    result["resolved"] = True
                    return result
                elif response.status == 404:
                    # Identity not found - return fallback
                    return {
                        "domain": "UNKNOWN",
                        id_type: identifier,
                        "name": f"Unknown ({id_type}: {identifier})",
                        "resolved": False
                    }
                else:
                    response.raise_for_status()
        except Exception as e:
            # Return fallback on error
            return {
                "domain": "ERROR",
                id_type: identifier,
                "name": f"Error resolving {id_type}: {identifier}",
                "error": str(e),
                "resolved": False
            }

    async def resolve_multiple_identities(self, session: aiohttp.ClientSession,
                                         auth_ids: List[str]) -> Dict[str, Dict]:
        """
        Resolve multiple identities in parallel.

        Args:
            session: aiohttp ClientSession
            auth_ids: List of auth_id values to resolve

        Returns:
            Dictionary mapping auth_id to resolved identity info
        """
        # Remove duplicates
        unique_ids = list(set(auth_ids))

        if not unique_ids:
            return {}

        # Create tasks for parallel resolution
        tasks = [
            self.resolve_identity(session, auth_id, "auth_id")
            for auth_id in unique_ids
        ]

        # Execute all resolutions in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Build cache mapping auth_id to result
        identity_cache = {}
        for auth_id, result in zip(unique_ids, results):
            if isinstance(result, Exception):
                identity_cache[auth_id] = {
                    "domain": "ERROR",
                    "auth_id": auth_id,
                    "name": f"Error: {auth_id}",
                    "error": str(result),
                    "resolved": False
                }
            else:
                identity_cache[auth_id] = result

        return identity_cache

    async def expand_identity(self, session: aiohttp.ClientSession,
                             auth_id: str) -> List[str]:
        """
        Expand an identity to all equivalent auth_ids.

        Args:
            session: aiohttp ClientSession
            auth_id: The auth_id to expand

        Returns:
            List of all equivalent auth_ids (including the original)
        """
        url = f"{self.base_url}/v1/identity/expand"

        payload = {"auth_id": auth_id}

        try:
            async with session.post(url, json=payload, ssl=self.ssl_context) as response:
                if response.status == 200:
                    result = await response.json()

                    # Extract all equivalent auth_ids
                    equivalent_ids = [auth_id]  # Include original

                    # Add from equivalent_ids array
                    for equiv in result.get('equivalent_ids', []):
                        equiv_auth_id = equiv.get('auth_id')
                        if equiv_auth_id and equiv_auth_id not in equivalent_ids:
                            equivalent_ids.append(equiv_auth_id)

                    # Add from nfs_id
                    nfs_auth_id = result.get('nfs_id', {}).get('auth_id')
                    if nfs_auth_id and nfs_auth_id not in equivalent_ids:
                        equivalent_ids.append(nfs_auth_id)

                    # Add from smb_id
                    smb_auth_id = result.get('smb_id', {}).get('auth_id')
                    if smb_auth_id and smb_auth_id not in equivalent_ids:
                        equivalent_ids.append(smb_auth_id)

                    # Add from id
                    id_auth_id = result.get('id', {}).get('auth_id')
                    if id_auth_id and id_auth_id not in equivalent_ids:
                        equivalent_ids.append(id_auth_id)

                    return equivalent_ids
                else:
                    # If expansion fails, return just the original
                    return [auth_id]
        except Exception:
            # If expansion fails, return just the original
            return [auth_id]


def parse_trustee(trustee_input: str) -> Dict:
    """
    Parse various trustee formats into an API payload.

    Supported formats:
        - SID: S-1-5-21-...
        - Auth ID: auth_id:500
        - UID: uid:1000 or just 1000
        - GID: gid:1001
        - Domain\\User: DOMAIN\\username
        - Email: user@domain.com
        - Plain name: username

    Returns:
        Dictionary suitable for /v1/identity/find endpoint with (payload, detected_type)
    """
    trustee = trustee_input.strip()

    # Windows SID format
    if trustee.startswith('S-') and len(trustee.split('-')) >= 3:
        return {"payload": {"sid": trustee}, "type": "sid"}

    # Explicit type prefixes
    if trustee.startswith('auth_id:'):
        return {"payload": {"auth_id": trustee[8:]}, "type": "auth_id"}

    if trustee.startswith('uid:'):
        try:
            return {"payload": {"uid": int(trustee[4:])}, "type": "uid"}
        except ValueError:
            return {"payload": {"name": trustee}, "type": "name"}

    if trustee.startswith('gid:'):
        try:
            return {"payload": {"gid": int(trustee[4:])}, "type": "gid"}
        except ValueError:
            return {"payload": {"name": trustee}, "type": "name"}

    # Pure numeric - assume UID
    if trustee.isdigit():
        return {"payload": {"uid": int(trustee)}, "type": "uid"}

    # NetBIOS domain format (DOMAIN\username)
    if '\\' in trustee:
        # Need to escape the backslash for JSON
        domain, username = trustee.split('\\', 1)
        return {"payload": {"name": f"{domain}\\\\{username}"}, "type": "name"}

    # Email or LDAP DN format
    if '@' in trustee or trustee.startswith('CN='):
        return {"payload": {"name": trustee}, "type": "name"}

    # Domain prefix formats (ad:user, local:user)
    if ':' in trustee and not trustee.startswith('S-'):
        prefix, name = trustee.split(':', 1)
        prefix = prefix.lower()

        if prefix in ['ad', 'active_directory']:
            return {"payload": {"name": name, "domain": "ACTIVE_DIRECTORY"}, "type": "name"}
        elif prefix == 'local':
            return {"payload": {"name": name, "domain": "LOCAL"}, "type": "name"}
        else:
            # Unknown prefix, treat as name
            return {"payload": {"name": trustee}, "type": "name"}

    # Default to name lookup
    return {"payload": {"name": trustee}, "type": "name"}


def parse_size_to_bytes(size_str: str) -> int:
    """Parse size string (e.g., '100MB', '1.5GiB') to bytes."""
    import re

    match = re.match(r'^([0-9]+\.?[0-9]*)([A-Za-z]*)$', size_str)
    if not match:
        raise ValueError(f"Invalid size format: {size_str}")

    size_num = float(match.group(1))
    size_unit = match.group(2).lower()

    multipliers = {
        '': 1, 'b': 1,
        'kb': 1000, 'mb': 1000000, 'gb': 1000000000, 'tb': 1000000000000, 'pb': 1000000000000000,
        'kib': 1024, 'mib': 1048576, 'gib': 1073741824, 'tib': 1099511627776, 'pib': 1125899906842624
    }

    if size_unit not in multipliers:
        raise ValueError(f"Unknown size unit: {size_unit}")

    return int(size_num * multipliers[size_unit])


async def resolve_owner_filters(client: AsyncQumuloClient, session: aiohttp.ClientSession, args) -> Optional[Set[str]]:
    """
    Resolve owner filter arguments to a set of auth_ids to match.

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp ClientSession
        args: Command-line arguments

    Returns:
        Set of auth_ids to match, or None if no owner filter specified
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
                if identity.get('resolved') and identity.get('auth_id'):
                    all_auth_ids.add(identity['auth_id'])
            except Exception as e:
                print(f"[WARN] Failed to resolve UID {owner}: {e}", file=sys.stderr)
        elif owner_type == "ad":
            # Active Directory - resolve by name with AD domain
            payload_info = parse_trustee(f"ad:{owner}")
            payload = payload_info['payload']

            url = f"{client.base_url}/v1/identity/find"
            try:
                async with session.post(url, json=payload, ssl=client.ssl_context) as response:
                    if response.status == 200:
                        identity = await response.json()
                        if identity.get('auth_id'):
                            all_auth_ids.add(identity['auth_id'])
            except Exception as e:
                print(f"[WARN] Failed to resolve AD user {owner}: {e}", file=sys.stderr)
        elif owner_type == "local":
            # Local - resolve by name with LOCAL domain
            payload_info = parse_trustee(f"local:{owner}")
            payload = payload_info['payload']

            url = f"{client.base_url}/v1/identity/find"
            try:
                async with session.post(url, json=payload, ssl=client.ssl_context) as response:
                    if response.status == 200:
                        identity = await response.json()
                        if identity.get('auth_id'):
                            all_auth_ids.add(identity['auth_id'])
            except Exception as e:
                print(f"[WARN] Failed to resolve local user {owner}: {e}", file=sys.stderr)
        else:
            # Auto-detect - parse and resolve
            payload_info = parse_trustee(owner)
            payload = payload_info['payload']

            url = f"{client.base_url}/v1/identity/find"
            try:
                async with session.post(url, json=payload, ssl=client.ssl_context) as response:
                    if response.status == 200:
                        identity = await response.json()
                        if identity.get('auth_id'):
                            all_auth_ids.add(identity['auth_id'])
            except Exception as e:
                print(f"[WARN] Failed to resolve owner {owner}: {e}", file=sys.stderr)

    # If expand-identity is enabled, expand all auth_ids
    if args.expand_identity and all_auth_ids:
        expanded_ids = set()
        for auth_id in all_auth_ids:
            equivalent_ids = await client.expand_identity(session, auth_id)
            expanded_ids.update(equivalent_ids)
        return expanded_ids

    return all_auth_ids if all_auth_ids else None


def create_file_filter(args, owner_auth_ids: Optional[Set[str]] = None):
    """Create a file filter function based on command-line arguments."""

    # Calculate time thresholds (using current UTC time)
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)  # Convert to timezone-naive for comparison
    time_threshold_older = None
    time_threshold_newer = None

    if args.older_than:
        time_threshold_older = now_utc - timedelta(days=args.older_than)
    if args.newer_than:
        time_threshold_newer = now_utc - timedelta(days=args.newer_than)

    # Calculate field-specific time thresholds
    field_time_filters = {}

    if args.accessed_older_than or args.accessed_newer_than:
        field_time_filters['access_time'] = {
            'older': now_utc - timedelta(days=args.accessed_older_than) if args.accessed_older_than else None,
            'newer': now_utc - timedelta(days=args.accessed_newer_than) if args.accessed_newer_than else None
        }

    if args.modified_older_than or args.modified_newer_than:
        field_time_filters['modification_time'] = {
            'older': now_utc - timedelta(days=args.modified_older_than) if args.modified_older_than else None,
            'newer': now_utc - timedelta(days=args.modified_newer_than) if args.modified_newer_than else None
        }

    if args.created_older_than or args.created_newer_than:
        field_time_filters['creation_time'] = {
            'older': now_utc - timedelta(days=args.created_older_than) if args.created_older_than else None,
            'newer': now_utc - timedelta(days=args.created_newer_than) if args.created_newer_than else None
        }

    if args.changed_older_than or args.changed_newer_than:
        field_time_filters['change_time'] = {
            'older': now_utc - timedelta(days=args.changed_older_than) if args.changed_older_than else None,
            'newer': now_utc - timedelta(days=args.changed_newer_than) if args.changed_newer_than else None
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

    def file_filter(entry: dict) -> bool:
        """Filter function that returns True if entry matches all criteria."""

        # File-only filter
        if args.file_only and entry.get('type') == 'FS_FILE_TYPE_DIRECTORY':
            return False

        # Owner filter
        if owner_auth_ids is not None:
            # Get owner from entry - try owner_details first, then owner
            owner_details = entry.get('owner_details', {})
            file_owner_auth_id = owner_details.get('auth_id') or entry.get('owner')

            if not file_owner_auth_id:
                # No owner info, skip this file
                return False

            # Check if file owner matches any of our target auth_ids
            if file_owner_auth_id not in owner_auth_ids:
                return False

        # Size filters
        if size_larger is not None or size_smaller is not None:
            file_size = entry.get('size')
            if file_size is None:
                return False

            try:
                size_bytes = int(file_size)

                # Add metadata size if requested
                if include_metadata:
                    metablocks = entry.get('metablocks')
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
                file_time = datetime.fromisoformat(time_value.rstrip('Z').split('.')[0])

                if time_threshold_older is not None and file_time >= time_threshold_older:
                    return False
                if time_threshold_newer is not None and file_time <= time_threshold_newer:
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
                file_time = datetime.fromisoformat(time_value.rstrip('Z').split('.')[0])

                # Check both older and newer thresholds if specified
                if thresholds['older'] is not None and file_time >= thresholds['older']:
                    return False
                if thresholds['newer'] is not None and file_time <= thresholds['newer']:
                    return False
            except (ValueError, AttributeError):
                return False  # If parsing fails, reject the file

        return True

    return file_filter


def format_bytes(bytes_value: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} EB"


async def generate_owner_report(client: AsyncQumuloClient, owner_stats: OwnerStats,
                                args, elapsed_time: float):
    """Generate and display ownership report."""
    print("\n" + "=" * 80, file=sys.stderr)
    print("OWNER REPORT", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    # Get all unique owners
    all_owners = owner_stats.get_all_owners()

    if not all_owners:
        print("No files found", file=sys.stderr)
        return

    print(f"\nResolving {len(all_owners)} unique owner identities...", file=sys.stderr)

    # Resolve all owners in parallel
    async with client.create_session() as session:
        identity_cache = await client.resolve_multiple_identities(session, all_owners)

    # Build report data
    report_rows = []
    total_bytes = 0
    total_files = 0
    total_dirs = 0

    for owner_auth_id in all_owners:
        stats = owner_stats.get_stats(owner_auth_id)
        identity = identity_cache.get(owner_auth_id, {})

        owner_name = identity.get('name', f'Unknown ({owner_auth_id})')
        domain = identity.get('domain', 'UNKNOWN')

        report_rows.append({
            'owner': owner_name,
            'domain': domain,
            'auth_id': owner_auth_id,
            'bytes': stats['bytes'],
            'files': stats['files'],
            'dirs': stats['dirs']
        })

        total_bytes += stats['bytes']
        total_files += stats['files']
        total_dirs += stats['dirs']

    # Sort by bytes descending
    report_rows.sort(key=lambda x: x['bytes'], reverse=True)

    # Print report
    print(f"\n{'Owner':<30} {'Domain':<20} {'Files':>10} {'Dirs':>8} {'Total Size':>15}", file=sys.stderr)
    print("-" * 90, file=sys.stderr)

    for row in report_rows:
        owner = row['owner'] or 'Unknown'
        domain = row['domain'] or 'UNKNOWN'
        print(f"{owner:<30} {domain:<20} {row['files']:>10,} {row['dirs']:>8,} {format_bytes(row['bytes']):>15}",
              file=sys.stderr)

    print("-" * 90, file=sys.stderr)
    print(f"{'TOTAL':<30} {'':<20} {total_files:>10,} {total_dirs:>8,} {format_bytes(total_bytes):>15}",
          file=sys.stderr)

    print(f"\nProcessing time: {elapsed_time:.2f}s", file=sys.stderr)
    rate = (total_files + total_dirs) / elapsed_time if elapsed_time > 0 else 0
    print(f"Processing rate: {rate:.1f} obj/sec", file=sys.stderr)
    print("=" * 80, file=sys.stderr)


async def main_async(args):
    """Main async function."""
    print("=" * 70, file=sys.stderr)
    print("Qumulo File Filter - Async Python (aiohttp)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"Cluster:          {args.host}", file=sys.stderr)
    print(f"Path:             {args.path}", file=sys.stderr)
    print(f"JSON parser:      {JSON_PARSER_NAME}", file=sys.stderr)
    print(f"Max concurrent:   {args.max_concurrent}", file=sys.stderr)
    print(f"Connection pool:  {args.connector_limit}", file=sys.stderr)
    if args.max_depth:
        print(f"Max depth:        {args.max_depth}", file=sys.stderr)
    if args.progress:
        print(f"Progress:         Enabled", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    # Load credentials
    if args.credentials_store:
        creds = get_credentials(args.credentials_store)
    else:
        creds = get_credentials(credential_store_filename())

    if not creds:
        print("\n[ERROR] No credentials found. Please run 'qq --host <cluster> login' first.",
              file=sys.stderr)
        sys.exit(1)

    bearer_token = creds.bearer_token

    # Create client
    client = AsyncQumuloClient(args.host, args.port, bearer_token,
                               args.max_concurrent, args.connector_limit)

    # Resolve owner filters if specified
    owner_auth_ids = None
    profiler = Profiler() if args.profile else None

    if args.owners:
        print("\nResolving owner identities...", file=sys.stderr)
        if profiler:
            resolve_start = time.time()

        async with client.create_session() as session:
            owner_auth_ids = await resolve_owner_filters(client, session, args)

        if profiler:
            profiler.record_sync('owner_identity_resolution', time.time() - resolve_start)

        if owner_auth_ids:
            print(f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr)
            if args.verbose:
                print(f"Owner auth_ids: {', '.join(owner_auth_ids)}", file=sys.stderr)
        else:
            print("[WARN] No valid owners resolved - no files will match!", file=sys.stderr)

    # Create file filter
    file_filter = create_file_filter(args, owner_auth_ids)

    # Create progress tracker
    progress = ProgressTracker(verbose=args.progress) if args.progress else None

    # Create owner stats tracker if owner-report enabled
    owner_stats = OwnerStats() if args.owner_report else None

    # Walk tree and collect matches
    start_time = time.time()

    if profiler:
        tree_walk_start = time.time()

    # For owner reports, don't collect matching files to save memory
    collect_results = not args.owner_report

    async with client.create_session() as session:
        matching_files = await client.walk_tree_async(
            session, args.path, args.max_depth, progress=progress,
            file_filter=file_filter, owner_stats=owner_stats,
            omit_subdirs=args.omit_subdirs, collect_results=collect_results
        )

    if profiler:
        tree_walk_time = time.time() - tree_walk_start
        profiler.record_sync('tree_walking', tree_walk_time)

    elapsed = time.time() - start_time

    # Final progress report
    if progress:
        progress.final_report()

    # Generate owner report if requested
    if args.owner_report and owner_stats:
        if profiler:
            report_start = time.time()
        await generate_owner_report(client, owner_stats, args, elapsed)
        if profiler:
            profiler.record_sync('owner_report_generation', time.time() - report_start)
            profiler.print_report(elapsed)
        return  # Exit after report, don't output file list

    # Apply limit if specified
    if args.limit and len(matching_files) > args.limit:
        if args.verbose:
            print(f"\n[INFO] Limiting results to {args.limit} files (found {len(matching_files)})", file=sys.stderr)
        matching_files = matching_files[:args.limit]

    # Output results
    if profiler:
        output_start = time.time()

    if args.csv_out:
        # CSV output
        import csv
        with open(args.csv_out, 'w', newline='') as csv_file:
            if not matching_files:
                if args.verbose:
                    print(f"[INFO] No matching files found, CSV file will be empty", file=sys.stderr)
                return

            if args.all_attributes:
                # Write all attributes
                fieldnames = sorted(matching_files[0].keys())
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for entry in matching_files:
                    writer.writerow(entry)
            else:
                # Write selective fields
                fieldnames = ['path']

                # Add time field if time filter was used
                if args.older_than or args.newer_than:
                    fieldnames.append(args.time_field)

                # Add owner if owner filter was used
                if args.owners:
                    fieldnames.append('owner')

                # Add size if size filter was used
                if args.larger_than or args.smaller_than:
                    fieldnames.append('size')

                writer = csv.DictWriter(csv_file, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for entry in matching_files:
                    writer.writerow(entry)

        if args.verbose:
            print(f"\n[INFO] Wrote {len(matching_files)} results to {args.csv_out}", file=sys.stderr)
    elif args.json or args.json_out:
        # JSON output
        output_handle = sys.stdout
        if args.json_out:
            output_handle = open(args.json_out, 'w')

        for entry in matching_files:
            if args.all_attributes:
                output_handle.write(json_parser.dumps(entry) + '\n')
            else:
                # Minimal output: path and filtered fields
                minimal_entry = {'path': entry['path']}
                if args.older_than or args.newer_than:
                    minimal_entry[args.time_field] = entry.get(args.time_field)
                if args.larger_than or args.smaller_than:
                    minimal_entry['size'] = entry.get('size')
                output_handle.write(json_parser.dumps(minimal_entry) + '\n')

        if args.json_out:
            output_handle.close()
            print(f"\n[INFO] Results written to {args.json_out}", file=sys.stderr)
    else:
        # Plain text output
        for entry in matching_files:
            print(entry['path'])

    # Record output timing
    if profiler:
        output_time = time.time() - output_start
        profiler.record_sync('output_generation', output_time)

    # Summary
    if args.verbose:
        print(f"\n[INFO] Processed {progress.total_objects if progress else 'N/A'} objects in {elapsed:.2f}s",
              file=sys.stderr)
        print(f"[INFO] Found {len(matching_files)} matching files", file=sys.stderr)
        rate = (progress.total_objects if progress else len(matching_files)) / elapsed if elapsed > 0 else 0
        print(f"[INFO] Processing rate: {rate:.1f} obj/sec", file=sys.stderr)

    # Print profiling report
    if profiler:
        profiler.print_report(elapsed)


def main():
    parser = argparse.ArgumentParser(
        description='Qumulo File Filter - Async Python implementation with aiohttp',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find files older than 30 days
  ./qumulo_file_filter_async.py --host cluster.example.com --path /home --older-than 30

  # Find large files with progress tracking
  ./qumulo_file_filter_async.py --host cluster.example.com --path /data --larger-than 1GB --progress

  # High-performance mode with increased concurrency
  ./qumulo_file_filter_async.py --host cluster.example.com --path /home --older-than 90 --max-concurrent 200 --connector-limit 200

  # Output to JSON file
  ./qumulo_file_filter_async.py --host cluster.example.com --path /home --older-than 30 --json-out results.json --all-attributes
        """
    )

    # Required arguments
    parser.add_argument('--host', required=True,
                       help='Qumulo cluster hostname or IP')
    parser.add_argument('--path', required=True,
                       help='Path to search')

    # Time filters
    parser.add_argument('--older-than', type=int,
                       help='Find files older than N days')
    parser.add_argument('--newer-than', type=int,
                       help='Find files newer than N days')

    # Time field selection
    parser.add_argument('--time-field', default='creation_time',
                       choices=['creation_time', 'modification_time', 'access_time', 'change_time'],
                       help='Time field to filter on (default: creation_time)')
    parser.add_argument('--created', action='store_const', const='creation_time', dest='time_field',
                       help='Filter by creation time')
    parser.add_argument('--modified', action='store_const', const='modification_time', dest='time_field',
                       help='Filter by modification time')
    parser.add_argument('--accessed', action='store_const', const='access_time', dest='time_field',
                       help='Filter by access time')
    parser.add_argument('--changed', action='store_const', const='change_time', dest='time_field',
                       help='Filter by change time')

    # Field-specific time filters (all use AND logic)
    parser.add_argument('--accessed-older-than', type=int,
                       help='Find files with access time older than N days')
    parser.add_argument('--accessed-newer-than', type=int,
                       help='Find files with access time newer than N days')
    parser.add_argument('--modified-older-than', type=int,
                       help='Find files with modification time older than N days')
    parser.add_argument('--modified-newer-than', type=int,
                       help='Find files with modification time newer than N days')
    parser.add_argument('--created-older-than', type=int,
                       help='Find files with creation time older than N days')
    parser.add_argument('--created-newer-than', type=int,
                       help='Find files with creation time newer than N days')
    parser.add_argument('--changed-older-than', type=int,
                       help='Find files with change time older than N days')
    parser.add_argument('--changed-newer-than', type=int,
                       help='Find files with change time newer than N days')

    # Size filters
    parser.add_argument('--larger-than',
                       help='Find files larger than specified size (e.g., 100MB, 1.5GiB)')
    parser.add_argument('--smaller-than',
                       help='Find files smaller than specified size')
    parser.add_argument('--include-metadata', action='store_true',
                       help='Include metadata blocks in size calculations (metablocks * 4KB)')

    # Owner filters
    parser.add_argument('--owner', action='append', dest='owners',
                       help='Filter by file owner (can be specified multiple times for OR logic)')
    parser.add_argument('--ad', action='store_true',
                       help='Owner(s) are Active Directory users')
    parser.add_argument('--local', action='store_true',
                       help='Owner(s) are local users')
    parser.add_argument('--uid', action='store_true',
                       help='Owner(s) are specified as UID numbers')
    parser.add_argument('--expand-identity', action='store_true',
                       help='Match all equivalent identities (e.g., AD user + NFS UID)')
    parser.add_argument('--owner-report', action='store_true',
                       help='Generate ownership report (file count and total bytes by owner)')

    # Search options
    parser.add_argument('--max-depth', type=int,
                       help='Maximum directory depth to search')
    parser.add_argument('--file-only', action='store_true',
                       help='Search files only (exclude directories)')
    parser.add_argument('--omit-subdirs', action='append',
                       help='Omit subdirectories matching pattern (supports wildcards, can be specified multiple times)')

    # Output options
    parser.add_argument('--json', action='store_true',
                       help='Output results as JSON to stdout')
    parser.add_argument('--json-out',
                       help='Write JSON results to file')
    parser.add_argument('--csv-out',
                       help='Write results to CSV file (mutually exclusive with --json/--json-out)')
    parser.add_argument('--all-attributes', action='store_true',
                       help='Include all file attributes in JSON output')
    parser.add_argument('--verbose', action='store_true',
                       help='Show detailed logging')
    parser.add_argument('--progress', action='store_true',
                       help='Show real-time progress stats')
    parser.add_argument('--limit', type=int,
                       help='Stop after finding N matching results')
    parser.add_argument('--profile', action='store_true',
                       help='Enable detailed performance profiling and timing metrics')

    # Connection options
    parser.add_argument('--port', type=int, default=8000,
                       help='Qumulo API port (default: 8000)')
    parser.add_argument('--credentials-store',
                       help='Path to credentials file (default: ~/.qfsd_cred)')

    # Performance tuning
    parser.add_argument('--max-concurrent', type=int, default=100,
                       help='Maximum concurrent operations (default: 100)')
    parser.add_argument('--connector-limit', type=int, default=100,
                       help='Maximum HTTP connections in pool (default: 100)')

    args = parser.parse_args()

    # Validate arguments
    if args.older_than and args.newer_than and args.newer_than >= args.older_than:
        print("Error: --newer-than must be less than --older-than for a valid time range",
              file=sys.stderr)
        sys.exit(1)

    # Check for mutually exclusive CSV and JSON output
    if args.csv_out and (args.json or args.json_out):
        print("Error: --csv-out cannot be used with --json or --json-out",
              file=sys.stderr)
        print("Please choose either CSV or JSON output format",
              file=sys.stderr)
        sys.exit(1)

    # Run async main
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
