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
import json
import ssl
import sys
import time
from pathlib import Path
from typing import List, Optional, Dict, Set
from urllib.parse import quote, urlparse, parse_qs
from datetime import datetime, timedelta

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
                             file_filter=None) -> List[dict]:
        """
        Recursively walk directory tree with concurrent directory enumeration.

        Args:
            session: aiohttp ClientSession
            path: Directory path to walk
            max_depth: Maximum depth to traverse (-1 or None for unlimited)
            _current_depth: Internal tracking of current depth
            progress: Optional ProgressTracker for reporting progress
            file_filter: Optional function to filter files

        Returns:
            List of matching file entries
        """
        # Check depth limit
        if max_depth is not None and max_depth >= 0 and _current_depth >= max_depth:
            return []

        # Enumerate current directory
        entries = await self.enumerate_directory(session, path)

        # Filter entries if filter function provided
        matching_entries = []
        if file_filter:
            for entry in entries:
                if file_filter(entry):
                    matching_entries.append(entry)
        else:
            matching_entries = entries

        # Find subdirectories
        subdirs = [
            entry['path'] for entry in entries
            if entry.get('type') == 'FS_FILE_TYPE_DIRECTORY'
        ]

        # Update progress tracker
        if progress:
            await progress.update(len(entries), 1, len(matching_entries))

        # Recursively process subdirectories concurrently
        if subdirs and (max_depth is None or max_depth < 0 or _current_depth + 1 < max_depth):
            tasks = [
                self.walk_tree_async(session, subdir, max_depth, _current_depth + 1, progress, file_filter)
                for subdir in subdirs
            ]

            # Process all subdirectories concurrently
            subdir_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Collect results from subdirectories
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


def create_file_filter(args):
    """Create a file filter function based on command-line arguments."""

    # Calculate time thresholds (timezone-aware)
    time_threshold_older = None
    time_threshold_newer = None

    if args.older_than:
        # Use timezone-naive datetime for comparison
        time_threshold_older = datetime.utcnow() - timedelta(days=args.older_than)
    if args.newer_than:
        # Use timezone-naive datetime for comparison
        time_threshold_newer = datetime.utcnow() - timedelta(days=args.newer_than)

    # Parse size filters
    size_larger = None
    size_smaller = None

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

        # Size filters
        if size_larger is not None or size_smaller is not None:
            file_size = entry.get('size')
            if file_size is None:
                return False

            try:
                size_bytes = int(file_size)
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

        return True

    return file_filter


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

    # Create file filter
    file_filter = create_file_filter(args)

    # Create client
    client = AsyncQumuloClient(args.host, args.port, bearer_token,
                               args.max_concurrent, args.connector_limit)

    # Create progress tracker
    progress = ProgressTracker(verbose=args.progress) if args.progress else None

    # Walk tree and collect matches
    start_time = time.time()

    async with client.create_session() as session:
        matching_files = await client.walk_tree_async(
            session, args.path, args.max_depth, progress=progress, file_filter=file_filter
        )

    elapsed = time.time() - start_time

    # Final progress report
    if progress:
        progress.final_report()

    # Output results
    if args.json or args.json_out:
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

    # Summary
    if args.verbose:
        print(f"\n[INFO] Processed {progress.total_objects if progress else 'N/A'} objects in {elapsed:.2f}s",
              file=sys.stderr)
        print(f"[INFO] Found {len(matching_files)} matching files", file=sys.stderr)
        rate = (progress.total_objects if progress else len(matching_files)) / elapsed if elapsed > 0 else 0
        print(f"[INFO] Processing rate: {rate:.1f} obj/sec", file=sys.stderr)


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

    # Size filters
    parser.add_argument('--larger-than',
                       help='Find files larger than specified size (e.g., 100MB, 1.5GiB)')
    parser.add_argument('--smaller-than',
                       help='Find files smaller than specified size')

    # Search options
    parser.add_argument('--max-depth', type=int,
                       help='Maximum directory depth to search')
    parser.add_argument('--file-only', action='store_true',
                       help='Search files only (exclude directories)')

    # Output options
    parser.add_argument('--json', action='store_true',
                       help='Output results as JSON to stdout')
    parser.add_argument('--json-out',
                       help='Write JSON results to file')
    parser.add_argument('--all-attributes', action='store_true',
                       help='Include all file attributes in JSON output')
    parser.add_argument('--verbose', action='store_true',
                       help='Show detailed logging')
    parser.add_argument('--progress', action='store_true',
                       help='Show real-time progress stats')

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
