"""
Async Qumulo API client for grumpwalk.

This module contains the AsyncQumuloClient class for interacting with
the Qumulo REST API using async/await patterns.
"""

import asyncio
import base64
import copy
import fnmatch
import json
import ssl
import sys
import time
from datetime import datetime
from typing import List, Optional, Dict, Set, Tuple
from urllib.parse import quote

from .utils import log_stderr

try:
    import aiohttp
except ImportError:
    log_stderr("ERROR", "aiohttp not installed. Install with: pip install aiohttp")
    sys.exit(1)

# Import from other modules
from .utils import (
    extract_pagination_token,
    format_bytes,
    format_time,
    parse_qumulo_version,
)
from .stats import OwnerStats
from .output import ProgressTracker

# Minimum Qumulo Core version that supports the skip-atime-update query
# parameter on read endpoints (entries/, data, streams data).
SKIP_ATIME_MIN_VERSION = (7, 9, 0)

class AsyncQumuloClient:
    """Async Qumulo API client using aiohttp with optimized connection pooling."""

    def __init__(
        self,
        host: str,
        port: int,
        bearer_token: str,
        max_concurrent: int = 100,
        connector_limit: int = 100,
        identity_cache: Optional[Dict] = None,
        verbose: bool = False,
        update_atime: bool = False,
    ):
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.bearer_token = bearer_token
        self.max_concurrent = max_concurrent
        self.verbose = verbose

        # atime handling. By default grumpwalk suppresses access-time updates on
        # reads (entries/data) when the cluster supports it. update_atime=True
        # opts back into normal atime behavior. supports_skip_atime is determined
        # at runtime by detect_capabilities(); until then we assume unsupported.
        self.update_atime = update_atime
        self.supports_skip_atime = False
        self.cluster_version: Optional[str] = None
        self.api_version: Optional[tuple] = None

        # Create SSL context that doesn't verify certificates (for self-signed certs)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # Configure connection pooling
        self.connector_limit = connector_limit

        self.headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {bearer_token}",
        }

        # Semaphore to limit concurrent operations
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Persistent identity cache for performance
        self.persistent_identity_cache = (
            identity_cache if identity_cache is not None else {}
        )
        self.cache_hits = 0
        self.cache_misses = 0

    def create_session(self, connect_timeout: int = 30) -> aiohttp.ClientSession:
        """Create optimized ClientSession with connection pooling and timeouts."""
        connector = aiohttp.TCPConnector(
            limit=self.connector_limit,
            limit_per_host=self.connector_limit,
            ttl_dns_cache=300,
            ssl=self.ssl_context,
        )
        # Set reasonable timeouts to fail fast on unreachable hosts
        timeout = aiohttp.ClientTimeout(
            total=None,  # No total timeout (allow long operations)
            connect=connect_timeout,  # Connection timeout
            sock_connect=connect_timeout,  # Socket connection timeout
            sock_read=60,  # Read timeout per chunk
        )
        return aiohttp.ClientSession(
            connector=connector,
            headers=self.headers,
            timeout=timeout
        )

    async def test_connection(self, timeout: int = 10) -> bool:
        """
        Test basic TCP connectivity to the cluster (no auth required).

        Args:
            timeout: Connection timeout in seconds

        Returns:
            True if connection succeeds

        Raises:
            asyncio.TimeoutError: If connection times out
            OSError: If connection refused or host unreachable
        """
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=self.ssl_context),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except asyncio.TimeoutError:
            raise
        except OSError:
            raise

    async def test_auth(self, session: aiohttp.ClientSession) -> bool:
        """
        Test authentication by making a lightweight API call.

        Args:
            session: aiohttp ClientSession with auth headers

        Returns:
            True if authentication succeeds

        Raises:
            aiohttp.ClientResponseError: If auth fails (401) or other HTTP error
        """
        # Use /v1/session/who-am-i as it requires auth and is lightweight
        url = f"{self.base_url}/v1/session/who-am-i"
        async with session.get(url, ssl=self.ssl_context) as response:
            if response.status == 401:
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=401,
                    message="Authentication failed"
                )
            response.raise_for_status()
            return True

    async def detect_capabilities(self, session: aiohttp.ClientSession) -> None:
        """Probe the cluster's API version to determine optional features.

        Queries GET /v1/version and records the parsed version. Sets
        self.supports_skip_atime when the cluster is new enough to accept the
        skip-atime-update query parameter on read endpoints.

        Failures are non-fatal: if the version cannot be read or parsed, the
        feature is simply treated as unsupported (safe default, no behavior
        change versus older grumpwalk releases).

        Args:
            session: aiohttp ClientSession with auth headers
        """
        url = f"{self.base_url}/v1/version"
        try:
            async with session.get(url, ssl=self.ssl_context) as response:
                if response.status == 200:
                    data = await response.json()
                    self.cluster_version = data.get("revision_id")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            self.cluster_version = None

        self.api_version = parse_qumulo_version(self.cluster_version)
        self.supports_skip_atime = (
            self.api_version is not None
            and self.api_version >= SKIP_ATIME_MIN_VERSION
        )

    def _atime_query_params(self) -> dict:
        """Query parameters to suppress atime updates on a read, when applicable.

        Returns {'skip-atime-update': 'true'} when the cluster supports the
        option and the user has not requested normal atime behavior via
        --update-atime; otherwise returns an empty dict.

        The value MUST be the literal string 'true'. The API rejects integer
        forms (skip-atime-update=1 -> HTTP 400), and aiohttp raises TypeError
        if a Python bool is passed as a query parameter value.
        """
        if self.supports_skip_atime and not self.update_atime:
            return {"skip-atime-update": "true"}
        return {}

    @staticmethod
    def _snapshot_query_params(snapshot_id) -> dict:
        """Query params to read in the context of a snapshot, or {} for live.

        Pass snapshot_id=None (the default everywhere) for a normal live read.
        The value is the snapshot's integer id as a string. NOTE: this only
        belongs on READ endpoints (entries/, info/attributes, aggregates/,
        info/acl, data) -- it must never be added to a write, and out-of-scope
        paths silently fall back to live data, so callers must confirm coverage
        first (see source_file_id containment).
        """
        return {"snapshot": str(snapshot_id)} if snapshot_id is not None else {}

    async def list_snapshots(self, session: aiohttp.ClientSession) -> List[dict]:
        """List all snapshots via GET /v2/snapshots/.

        Returns the list of snapshot objects (id, name, timestamp, expiration,
        source_file_id, directory_name, ...), or an empty list on error.
        """
        url = f"{self.base_url}/v2/snapshots/"
        try:
            async with session.get(url, ssl=self.ssl_context) as response:
                if response.status != 200:
                    return []
                data = await response.json()
                return data.get("entries", []) if isinstance(data, dict) else (data or [])
        except aiohttp.ClientError:
            return []

    async def get_snapshot(self, session: aiohttp.ClientSession, snapshot_id) -> Optional[dict]:
        """Fetch a single snapshot's metadata, or None if it does not exist."""
        url = f"{self.base_url}/v2/snapshots/{snapshot_id}"
        try:
            async with session.get(url, ssl=self.ssl_context) as response:
                return await response.json() if response.status == 200 else None
        except aiohttp.ClientError:
            return None

    async def resolve_id_to_path(self, session: aiohttp.ClientSession, file_id) -> Optional[str]:
        """Resolve a file ID to its current live path, or None if it no longer exists.

        Unlike get_file_attr (which assumes a path and prepends '/'), this uses the
        numeric id directly as the {ref}, so it works for snapshot source_file_ids.
        """
        url = f"{self.base_url}/v1/files/{quote(str(file_id), safe='')}/info/attributes"
        try:
            async with session.get(url, ssl=self.ssl_context) as response:
                return (await response.json()).get("path") if response.status == 200 else None
        except aiohttp.ClientError:
            return None

    async def create_snapshot(
        self,
        session: aiohttp.ClientSession,
        source_file_id,
        name: str = "grumpwalk-delta",
    ) -> Tuple[Optional[int], Optional[str]]:
        """Create a manual, non-expiring snapshot of source_file_id's subtree.

        Used by delta restore to capture the live ("now") state so a byte-range
        diff against the good snapshot can be computed. Returns (snapshot_id,
        error_message); snapshot_id is None on failure. Requires the
        PRIVILEGE_SNAPSHOT_WRITE privilege.
        """
        url = f"{self.base_url}/v3/snapshots/"
        body = {"source_file_id": str(source_file_id), "name": name, "expiration": ""}
        try:
            async with self.semaphore:
                async with session.post(url, json=body, ssl=self.ssl_context) as response:
                    text = await response.text()
                    if response.status in (200, 201):
                        try:
                            return (json.loads(text).get("id"), None)
                        except ValueError:
                            return (None, "could not parse create-snapshot response")
                    return (None, text[:200] or f"HTTP {response.status}")
        except aiohttp.ClientError as e:
            return (None, str(e))

    async def delete_snapshot(
        self, session: aiohttp.ClientSession, snapshot_id
    ) -> Tuple[bool, Optional[str]]:
        """Delete a snapshot by id. Used to clean up the temporary "now" snapshot
        that delta restore creates. Returns (success, error_message)."""
        url = f"{self.base_url}/v2/snapshots/{snapshot_id}"
        try:
            async with self.semaphore:
                async with session.delete(url, ssl=self.ssl_context) as response:
                    if response.status in (200, 204):
                        return (True, None)
                    text = await response.text()
                    return (False, text[:200] or f"HTTP {response.status}")
        except aiohttp.ClientError as e:
            return (False, str(e))

    async def get_directory_page(
        self,
        session: aiohttp.ClientSession,
        path: str,
        limit: int = 1000,
        after_token: Optional[str] = None,
        snapshot_id: Optional[int] = None,
    ) -> dict:
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
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/entries/"

            params = {"limit": limit}
            if after_token:
                params["after"] = after_token
            params.update(self._atime_query_params())
            params.update(self._snapshot_query_params(snapshot_id))

            async with session.get(
                url, params=params, ssl=self.ssl_context
            ) as response:
                response.raise_for_status()
                return await response.json()

    async def enumerate_directory(
        self,
        session: aiohttp.ClientSession,
        path: str,
        max_entries: Optional[int] = None,
        snapshot_id: Optional[int] = None,
    ) -> List[dict]:
        """
        Enumerate all entries in a directory, following pagination.

        Args:
            session: aiohttp ClientSession
            path: Directory path
            max_entries: Optional limit on total entries to fetch
            snapshot_id: If set, read the directory as of this snapshot

        Returns:
            List of all file/directory entries
        """
        all_entries = []
        after_token = None

        while True:
            response = await self.get_directory_page(
                session, path, limit=1000, after_token=after_token, snapshot_id=snapshot_id
            )

            files = response.get("files", [])
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

    async def enumerate_directory_streaming(
        self, session: aiohttp.ClientSession, path: str, callback, should_continue=None,
        snapshot_id: Optional[int] = None,
    ) -> int:
        """
        Stream directory entries without accumulating in memory.
        Calls callback with each page of results for processing.

        This is more memory-efficient for large directories (50k+ entries)
        as it processes entries page-by-page instead of accumulating them all.

        Args:
            session: aiohttp ClientSession
            path: Directory path
            callback: Async function that receives list of entries per page
                     Returns: (matching_entries, subdirs) tuple
            should_continue: Optional callable that returns False to stop enumeration early

        Returns:
            Total number of entries processed
        """
        total_entries = 0
        after_token = None

        while True:
            # Check if we should continue (for early exit on limit)
            if should_continue and not should_continue():
                break

            response = await self.get_directory_page(
                session, path, limit=1000, after_token=after_token, snapshot_id=snapshot_id
            )

            files = response.get("files", [])
            total_entries += len(files)

            # Process this page immediately via callback
            if callback and files:
                await callback(files)

            # Get next page token
            after_token = extract_pagination_token(response)
            if not after_token:
                break

        return total_entries

    async def get_directory_aggregates(
        self, session: aiohttp.ClientSession, path: str, snapshot_id: Optional[int] = None
    ) -> dict:
        """
        Get directory aggregate statistics.

        Returns RECURSIVE totals for the entire subtree under path (e.g.
        total_capacity, total_files, total_directories). All count/byte fields
        are returned as strings - use int() to convert.

        Args:
            session: aiohttp ClientSession
            path: Directory path

        Returns:
            Dictionary with aggregates data including total_files, total_directories, etc.
            Falls back to safe defaults if API call fails.
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/aggregates/"

            try:
                async with session.get(
                    url, params=self._snapshot_query_params(snapshot_id), ssl=self.ssl_context
                ) as response:
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientError as e:
                # Fall back gracefully if aggregates unavailable
                return {"total_files": "0", "total_directories": "0", "error": str(e)}

    async def get_directory_capacity(
        self, session: aiohttp.ClientSession, path: str
    ) -> dict:
        """
        Get directory capacity breakdown by owner.

        PHASE 3.3: Used for owner filter smart skipping to check if target owner
        has any files in the directory before enumeration.

        Args:
            session: aiohttp ClientSession
            path: Directory path

        Returns:
            Dictionary with capacity_by_owner data, or empty dict on error.
            Example: {"capacity_by_owner": [{"id": "500", "capacity_usage": 1073741824}]}
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/data/capacity/"

            params = {"path": path, "by_owner": "true"}

            try:
                async with session.get(
                    url, params=params, ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        # API may not be available or path may not exist
                        return {}
            except aiohttp.ClientError:
                # Fall back gracefully if capacity API unavailable
                return {}

    async def get_file_acl(
        self, session: aiohttp.ClientSession, path: str, snapshot_id: Optional[int] = None
    ) -> Optional[dict]:
        """
        Get the Access Control List (ACL) for a file or directory.
        Uses v2 API endpoint.

        Args:
            session: aiohttp ClientSession
            path: File or directory path
            snapshot_id: If set, read the ACL as of this snapshot

        Returns:
            Dictionary containing ACL data with 'aces', 'control', 'posix_special_permissions',
            or None if the ACL cannot be retrieved.
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v2/files/{encoded_path}/info/acl"

            try:
                async with session.get(
                    url, params=self._snapshot_query_params(snapshot_id), ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        if self.verbose:
                            log_stderr("WARN", f"Failed to get ACL for {path}: HTTP {response.status}")
                        return None
            except aiohttp.ClientError as e:
                if self.verbose:
                    log_stderr("WARN", f"Error getting ACL for {path}: {e}")
                return None

    async def set_file_acl(
        self,
        session: aiohttp.ClientSession,
        path: str,
        acl_data: dict,
        mark_inherited: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Apply ACL to a file or directory using v2 API.

        Performs 1:1 ACL replacement preserving all fields:
        - aces (Access Control Entries)
        - control flags
        - posix_special_permissions

        Args:
            session: aiohttp ClientSession
            path: Target file/directory path
            acl_data: Full ACL data structure from get_file_acl()
            mark_inherited: Add INHERITED flag to all ACEs

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v2/files/{encoded_path}/info/acl"

            # Deep copy to avoid mutating source
            acl_to_apply = copy.deepcopy(acl_data)

            # Extract nested 'acl' portion if present
            if 'acl' in acl_to_apply and 'aces' not in acl_to_apply:
                acl_payload = acl_to_apply['acl']
            else:
                acl_payload = acl_to_apply

            # Add INHERITED flag to all ACEs if requested
            if mark_inherited:
                for ace in acl_payload.get('aces', []):
                    flags = ace.get('flags', [])
                    if 'INHERITED' not in flags:
                        flags.append('INHERITED')
                    ace['flags'] = flags

            try:
                async with session.put(
                    url, json=acl_payload, ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        return (True, None)
                    else:
                        error_msg = f"HTTP {response.status}"
                        try:
                            error_detail = await response.json()
                            error_msg += f": {error_detail.get('description', '')}"
                        except:
                            pass
                        return (False, error_msg)
            except aiohttp.ClientError as e:
                return (False, str(e))

    async def get_file_attr(
        self,
        session: aiohttp.ClientSession,
        path: str,
        snapshot_id: Optional[int] = None,
    ) -> Optional[dict]:
        """
        Get file attributes including file ID using v1 attributes API.

        Args:
            session: aiohttp ClientSession
            path: Path to the file/directory
            snapshot_id: If set, read the attributes as of this snapshot

        Returns:
            Dictionary with file attributes including 'id', 'name', 'type', etc. or None if failed
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/info/attributes"

            try:
                async with session.get(
                    url, params=self._snapshot_query_params(snapshot_id), ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return None
            except aiohttp.ClientError:
                return None

    async def get_file_owner_group(
        self,
        session: aiohttp.ClientSession,
        path: str,
        snapshot_id: Optional[int] = None,
    ) -> Optional[dict]:
        """
        Get owner and group information for a file or directory using v1 attributes API.

        Args:
            session: aiohttp ClientSession
            path: Path to the file/directory
            snapshot_id: If set, read as of this snapshot

        Returns:
            Dictionary with 'owner', 'owner_details', 'group', 'group_details' or None if failed
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/info/attributes"

            try:
                async with session.get(
                    url, params=self._snapshot_query_params(snapshot_id), ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'owner': data.get('owner'),
                            'owner_details': data.get('owner_details'),
                            'group': data.get('group'),
                            'group_details': data.get('group_details')
                        }
                    else:
                        return None
            except aiohttp.ClientError:
                return None

    async def set_file_owner_group(
        self,
        session: aiohttp.ClientSession,
        path: str,
        owner: Optional[str] = None,
        group: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Set owner and/or group for a file or directory using v1 attributes PATCH API.

        Args:
            session: aiohttp ClientSession
            path: Path to the file/directory
            owner: Owner auth_id to set (if provided)
            group: Group auth_id to set (if provided)

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/info/attributes"

            # Build PATCH payload with only specified fields
            payload = {}
            if owner is not None:
                payload['owner'] = owner
            if group is not None:
                payload['group'] = group

            # Return success if nothing to update
            if not payload:
                return (True, None)

            try:
                async with session.patch(
                    url, json=payload, ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        return (True, None)
                    else:
                        error_msg = f"HTTP {response.status}"
                        try:
                            error_detail = await response.json()
                            error_msg += f": {error_detail.get('description', '')}"
                        except:
                            pass
                        return (False, error_msg)
            except aiohttp.ClientError as e:
                return (False, str(e))

    async def set_file_mode(
        self, session: aiohttp.ClientSession, path: str, mode: str
    ) -> Tuple[bool, Optional[str]]:
        """Set the POSIX mode on a file or directory (like chmod).

        PATCHes /info/attributes with the octal mode string (e.g. "0755"). The
        cluster maps the mode to the object's current owner/group/everyone, so
        chown the object first if you want the owner bits to apply to a new owner.
        Returns (success, error_message).
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path
            url = f"{self.base_url}/v1/files/{quote(path, safe='')}/info/attributes"
            try:
                async with session.patch(url, json={"mode": mode}, ssl=self.ssl_context) as response:
                    if response.status == 200:
                        return (True, None)
                    error_msg = f"HTTP {response.status}"
                    try:
                        error_msg += f": {(await response.json()).get('description', '')}"
                    except (aiohttp.ClientError, ValueError):
                        pass
                    return (False, error_msg)
            except aiohttp.ClientError as e:
                return (False, str(e))

    async def set_file_timestamps(
        self, session: aiohttp.ClientSession, path: str, times: dict
    ) -> Tuple[bool, Optional[str]]:
        """Set timestamp fields on a file or directory (like utimes).

        times may contain any of modification_time, access_time, creation_time
        as RFC 3339 strings. change_time (ctime) is not settable in a meaningful
        way because it reflects the last metadata change, so it is not accepted
        here. Returns (success, error_message).
        """
        payload = {k: v for k, v in (times or {}).items()
                   if k in ("modification_time", "access_time", "creation_time") and v}
        if not payload:
            return (True, None)
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path
            url = f"{self.base_url}/v1/files/{quote(path, safe='')}/info/attributes"
            try:
                async with session.patch(url, json=payload, ssl=self.ssl_context) as response:
                    if response.status == 200:
                        return (True, None)
                    error_msg = f"HTTP {response.status}"
                    try:
                        error_msg += f": {(await response.json()).get('description', '')}"
                    except (aiohttp.ClientError, ValueError):
                        pass
                    return (False, error_msg)
            except aiohttp.ClientError as e:
                return (False, str(e))

    async def get_file_user_metadata(
        self, session: aiohttp.ClientSession, path: str, snapshot_id: Optional[int] = None
    ) -> Optional[Dict[str, str]]:
        """
        Get all GENERIC user-metadata (custom tags) for a file or directory.

        Reads the v1 user-metadata list endpoint and Base64-decodes each value.
        Follows pagination via paging.next.

        Args:
            session: aiohttp ClientSession
            path: File or directory path
            snapshot_id: If set, read the tags as of this snapshot

        Returns:
            Dict mapping tag key to its decoded string value. An empty dict when
            the object has no GENERIC tags. None when the tags could not be read
            (callers treat None as an error, not as "no tags").
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/user-metadata/GENERIC/"
            snap_params = self._snapshot_query_params(snapshot_id)

            tags: Dict[str, str] = {}
            seen_urls: Set[str] = set()

            try:
                while url and url not in seen_urls:
                    seen_urls.add(url)
                    async with session.get(url, params=snap_params, ssl=self.ssl_context) as response:
                        if response.status == 404:
                            # Object exists but currently carries no GENERIC tags.
                            return tags
                        if response.status != 200:
                            if self.verbose:
                                log_stderr("WARN", f"Failed to read tags for {path}: HTTP {response.status}")
                            return None
                        data = await response.json()

                    for entry in data.get("entries", []):
                        key = entry.get("key")
                        if key is None:
                            continue
                        try:
                            tags[key] = base64.b64decode(entry.get("value", "")).decode("utf-8", "replace")
                        except (ValueError, TypeError):
                            # Value was not valid Base64; record it as empty rather than failing the read.
                            tags[key] = ""

                    next_url = (data.get("paging") or {}).get("next")
                    if next_url:
                        url = next_url if next_url.startswith("http") else f"{self.base_url}{next_url}"
                    else:
                        url = None

                return tags
            except aiohttp.ClientError as e:
                if self.verbose:
                    log_stderr("WARN", f"Error reading tags for {path}: {e}")
                return None

    async def set_file_user_metadata(
        self,
        session: aiohttp.ClientSession,
        path: str,
        key: str,
        value: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Create or update (upsert) a GENERIC user-metadata tag.

        Uses PUT, which creates the key or replaces its value. The value is
        Base64-encoded on the wire; the key is URL-encoded into the path.

        Args:
            session: aiohttp ClientSession
            path: Target file/directory path
            key: Tag key (arbitrary string)
            value: Tag value (arbitrary string)

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            encoded_key = quote(key, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/user-metadata/GENERIC/{encoded_key}"

            encoded_value = base64.b64encode(value.encode("utf-8")).decode("ascii")

            try:
                async with session.put(
                    url, json={"value": encoded_value}, ssl=self.ssl_context
                ) as response:
                    if 200 <= response.status < 300:
                        return (True, None)
                    error_msg = f"HTTP {response.status}"
                    try:
                        error_detail = await response.json()
                        error_msg += f": {error_detail.get('description', '')}"
                    except:
                        pass
                    return (False, error_msg)
            except aiohttp.ClientError as e:
                return (False, str(e))

    async def rename_entry(
        self,
        session: aiohttp.ClientSession,
        source_path: str,
        dest_parent: str,
        new_name: str,
        clobber: bool = False,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Move/rename an object to <dest_parent>/<new_name> via the RENAME action.

        A Qumulo move is a rename: POST to the destination parent's entries with
        action RENAME, the new name, and old_path pointing at the source. Works
        across directories within the cluster; moving a directory relocates its
        whole subtree. clobber=True overwrites an existing destination entry
        (the API returns fs_entry_exists_error otherwise).

        Args:
            session: aiohttp ClientSession
            source_path: Absolute path of the object to move/rename
            dest_parent: Absolute path of the destination directory
            new_name: Name the object will have in dest_parent
            clobber: Overwrite an existing destination entry

        Returns:
            Tuple of (success, error_class, error_message). error_class is the
            Qumulo error_class string when the API supplies one (e.g.
            'fs_entry_exists_error', 'fs_directory_cycle_error') so callers can
            tell a collision apart from a hard failure. (True, None, None) on
            success.
        """
        async with self.semaphore:
            if not source_path.startswith("/"):
                source_path = "/" + source_path
            if not dest_parent.startswith("/"):
                dest_parent = "/" + dest_parent

            encoded_parent = quote(dest_parent, safe="")
            url = f"{self.base_url}/v1/files/{encoded_parent}/entries/"
            payload = {
                "name": new_name,
                "action": "RENAME",
                "old_path": source_path,
                "clobber": bool(clobber),
            }

            try:
                async with session.post(url, json=payload, ssl=self.ssl_context) as response:
                    if 200 <= response.status < 300:
                        return (True, None, None)
                    error_class = None
                    description = ""
                    try:
                        detail = await response.json()
                        error_class = detail.get("error_class")
                        description = detail.get("description", "")
                    except (aiohttp.ClientError, ValueError):
                        pass
                    error_msg = f"HTTP {response.status}"
                    if error_class:
                        error_msg += f" {error_class}"
                    if description:
                        error_msg += f": {description}"
                    return (False, error_class, error_msg)
            except aiohttp.ClientError as e:
                return (False, None, str(e))

    async def create_entry(
        self,
        session: aiohttp.ClientSession,
        parent_path: str,
        name: str,
        action: str,
        old_path: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Create a file, directory, or symlink under parent_path.

        Thin wrapper over POST /v1/files/{parent}/entries/. action is one of
        CREATE_FILE, CREATE_DIRECTORY, CREATE_SYMLINK. For CREATE_SYMLINK,
        old_path is the link target.

        Returns (success, error_class, error_message); error_class is the
        Qumulo error_class when supplied (e.g. 'fs_entry_exists_error').
        """
        async with self.semaphore:
            if not parent_path.startswith("/"):
                parent_path = "/" + parent_path
            encoded_parent = quote(parent_path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_parent}/entries/"
            payload = {"name": name, "action": action}
            if old_path is not None:
                payload["old_path"] = old_path
            try:
                async with session.post(url, json=payload, ssl=self.ssl_context) as response:
                    if 200 <= response.status < 300:
                        return (True, None, None)
                    error_class, description = None, ""
                    try:
                        detail = await response.json()
                        error_class = detail.get("error_class")
                        description = detail.get("description", "")
                    except (aiohttp.ClientError, ValueError):
                        pass
                    msg = f"HTTP {response.status}"
                    if error_class:
                        msg += f" {error_class}"
                    if description:
                        msg += f": {description}"
                    return (False, error_class, msg)
            except aiohttp.ClientError as e:
                return (False, None, str(e))

    async def delete_entry(
        self, session: aiohttp.ClientSession, path: str
    ) -> Tuple[bool, Optional[str]]:
        """Delete a single file/empty-directory/symlink. Returns (ok, error)."""
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path
            url = f"{self.base_url}/v1/files/{quote(path, safe='')}"
            try:
                async with session.delete(url, ssl=self.ssl_context) as response:
                    if 200 <= response.status < 300 or response.status == 404:
                        return (True, None)
                    return (False, f"HTTP {response.status}")
            except aiohttp.ClientError as e:
                return (False, str(e))

    async def _copy_chunk(
        self, session: aiohttp.ClientSession, target_path: str, body: dict
    ) -> Tuple[int, Optional[dict], Optional[str]]:
        """One copy-chunk call. Returns (status, response_json_or_None, error)."""
        async with self.semaphore:
            url = f"{self.base_url}/v1/files/{quote(target_path, safe='')}/copy-chunk"
            try:
                async with session.post(url, json=body, ssl=self.ssl_context) as response:
                    text = await response.text()
                    data = None
                    if text:
                        try:
                            data = json.loads(text)
                        except ValueError:
                            data = None
                    return (response.status, data, None if response.status == 200 else text[:200])
            except aiohttp.ClientError as e:
                return (0, None, str(e))

    async def copy_file_data(
        self, session: aiohttp.ClientSession, source_path: str, target_path: str,
        source_snapshot: Optional[int] = None, on_progress=None,
    ) -> Tuple[bool, Optional[str]]:
        """Server-side copy of a file's data into an existing target file.

        Drives POST /v1/files/{target}/copy-chunk in a loop: the copy completes
        when the server returns HTTP 200 with an empty body. For files larger
        than the server's per-call limit, the response carries the remaining
        source_offset/length, which is fed back as the next request. The target
        file must already exist (a missing target returns fs_no_such_entry_error).

        source_snapshot (an int) reads the SOURCE from that snapshot version --
        the correct way to restore from a snapshot (works for modified and
        deleted files). Note: this is a BODY field; the ?snapshot= query parameter
        does NOT redirect copy-chunk's source (it reads live).

        Returns (success, error_message).
        """
        if not source_path.startswith("/"):
            source_path = "/" + source_path
        if not target_path.startswith("/"):
            target_path = "/" + target_path

        body = {"source_path": source_path, "source_offset": "0", "target_offset": "0"}
        if source_snapshot is not None:
            body["source_snapshot"] = int(source_snapshot)
        prev_offset = -1
        reported = 0  # cumulative bytes already passed to on_progress
        # Generous runaway guard; each iteration must advance the source offset.
        for _ in range(1_000_000):
            status, resp, err = await self._copy_chunk(session, target_path, body)
            if status != 200:
                return (False, err or f"copy-chunk HTTP {status}")
            if not isinstance(resp, dict) or int(resp.get("length") or 0) <= 0:
                # Done. The terminal response carries no usable offset, so the final
                # segment is reported by the caller (which knows the file size).
                return (True, None)
            offset = int(resp.get("source_offset") or 0)
            if offset <= prev_offset:
                return (False, "copy-chunk made no progress")
            if on_progress is not None and offset > reported:
                on_progress(offset - reported)
                reported = offset
            prev_offset = offset
            body = resp
        return (False, "copy-chunk did not converge")

    async def get_file_byte_diff(
        self,
        session: aiohttp.ClientSession,
        newer_snapshot_id,
        older_snapshot_id,
        file_id,
    ) -> Tuple[Optional[List[Tuple[int, int]]], Optional[str]]:
        """Changed byte regions of one file between two snapshots.

        GET /v2/snapshots/{newer}/changes-since/{older}/files/{ref} reports the
        regions that differ as FILE_REGION_DATA (changed data) or
        FILE_REGION_HOLE (sparse) entries, paginated. Returns
        (list_of_(offset, size)_data_regions, error_message). The list is the
        data regions only -- the overlapping byte ranges that must be re-copied
        from the good snapshot. A truncated tail (when the good version is larger
        than live) is NOT reported here and must be handled by the caller.
        """
        regions: List[Tuple[int, int]] = []
        url = (
            f"{self.base_url}/v2/snapshots/{newer_snapshot_id}"
            f"/changes-since/{older_snapshot_id}/files/{quote(str(file_id), safe='')}"
        )
        try:
            while url:
                async with self.semaphore:
                    async with session.get(url, ssl=self.ssl_context) as response:
                        if response.status != 200:
                            text = await response.text()
                            return (None, text[:200] or f"HTTP {response.status}")
                        data = await response.json()
                for entry in data.get("entries", []):
                    if entry.get("type") == "FILE_REGION_DATA":
                        regions.append((int(entry["offset"]), int(entry["size"])))
                nxt = (data.get("paging") or {}).get("next")
                if not nxt:
                    break
                url = nxt if nxt.startswith("http") else f"{self.base_url}{nxt}"
        except (aiohttp.ClientError, ValueError, KeyError) as e:
            return (None, str(e))
        return (regions, None)

    async def get_tree_diff(
        self,
        session: aiohttp.ClientSession,
        newer_snapshot_id,
        older_snapshot_id,
    ) -> Tuple[List[dict], Optional[str]]:
        """All path-level changes between two snapshots (changes-since at the tree
        level). Returns (entries, error) where each entry is
        {"op": "CREATE"|"MODIFY"|"DELETE", "path": str}, following pagination.

        Conventions reported by the API: directory paths carry a TRAILING SLASH
        (the file/dir discriminator), and a created or deleted directory is
        reported as a SINGLE entry -- its descendants are NOT listed, so a deleted
        directory must be repopulated from the snapshot subtree and a created
        directory removed recursively. The diff is a NET endpoint comparison, which
        is exactly right for "revert to snapshot": a file created and deleted
        between the two snapshots is absent from both and correctly reported as no
        change. `entries` holds whatever was collected even if a page later fails.
        """
        entries: List[dict] = []
        url = (
            f"{self.base_url}/v2/snapshots/{newer_snapshot_id}"
            f"/changes-since/{older_snapshot_id}?limit=1000"
        )
        try:
            while url:
                async with self.semaphore:
                    async with session.get(url, ssl=self.ssl_context) as response:
                        if response.status != 200:
                            text = await response.text()
                            return (entries, text[:200] or f"HTTP {response.status}")
                        data = await response.json()
                for e in data.get("entries", []):
                    path, op = e.get("path"), e.get("op")
                    if path and op:
                        entries.append({"op": op, "path": path})
                nxt = (data.get("paging") or {}).get("next")
                if not nxt:
                    break
                nxt = nxt if nxt.startswith("http") else f"{self.base_url}{nxt}"
                if nxt == url:           # guard against a self-referential final page
                    break
                url = nxt
        except (aiohttp.ClientError, ValueError) as e:
            return (entries, str(e))
        return (entries, None)

    async def set_file_size(
        self, session: aiohttp.ClientSession, path: str, size: int
    ) -> Tuple[bool, Optional[str]]:
        """Truncate or extend a file to `size` bytes via PATCH attributes.

        Extending creates a sparse (zero-filled) tail; delta restore then copies
        the real bytes over it. Returns (success, error_message)."""
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.base_url}/v1/files/{quote(path, safe='')}/info/attributes"
        try:
            async with self.semaphore:
                async with session.patch(
                    url, json={"size": str(size)}, ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        return (True, None)
                    text = await response.text()
                    return (False, text[:200] or f"HTTP {response.status}")
        except aiohttp.ClientError as e:
            return (False, str(e))

    async def copy_file_range(
        self,
        session: aiohttp.ClientSession,
        source_path: str,
        target_path: str,
        source_snapshot: int,
        offset: int,
        length: int,
    ) -> Tuple[bool, Optional[str]]:
        """Server-side copy of [offset, offset+length) from source_snapshot's
        source_path into target_path at the same offset.

        copy-chunk's `length` bounds the copy to a single region; the call is
        looped because the server may bound each chunk further. Both offsets are
        held equal so the byte range lands at the same place in the target.
        Returns (success, error_message)."""
        if not source_path.startswith("/"):
            source_path = "/" + source_path
        if not target_path.startswith("/"):
            target_path = "/" + target_path
        body = {
            "source_path": source_path,
            "source_snapshot": int(source_snapshot),
            "source_offset": str(offset),
            "target_offset": str(offset),
            "length": str(length),
        }
        prev_offset = -1
        for _ in range(1_000_000):
            status, resp, err = await self._copy_chunk(session, target_path, body)
            if status != 200:
                return (False, err or f"copy-chunk HTTP {status}")
            if not isinstance(resp, dict) or int(resp.get("length") or 0) <= 0:
                return (True, None)
            nxt = int(resp.get("source_offset") or 0)
            if nxt <= prev_offset:
                return (False, "copy-chunk range made no progress")
            prev_offset = nxt
            body = resp
        return (False, "copy-chunk range did not converge")

    async def delete_file_user_metadata(
        self,
        session: aiohttp.ClientSession,
        path: str,
        key: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Delete a GENERIC user-metadata tag.

        Idempotent: a missing key (HTTP 404) is treated as success.

        Args:
            session: aiohttp ClientSession
            path: Target file/directory path
            key: Tag key to delete

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            encoded_key = quote(key, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/user-metadata/GENERIC/{encoded_key}"

            try:
                async with session.delete(url, ssl=self.ssl_context) as response:
                    if 200 <= response.status < 300 or response.status == 404:
                        return (True, None)
                    error_msg = f"HTTP {response.status}"
                    try:
                        error_detail = await response.json()
                        error_msg += f": {error_detail.get('description', '')}"
                    except:
                        pass
                    return (False, error_msg)
            except aiohttp.ClientError as e:
                return (False, str(e))

    async def set_file_extended_attributes(
        self,
        session: aiohttp.ClientSession,
        path: str,
        attributes: dict,
        current_ext_attrs: Optional[dict] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Set extended (DOS) attributes on a file or directory.

        The Qumulo API requires the full extended_attributes object on PATCH,
        so this method reads the current attributes (unless provided), merges
        the requested changes, and sends the complete object.

        Args:
            session: aiohttp ClientSession
            path: Path to the file/directory
            attributes: Dict mapping attribute names to bool values,
                        e.g. {"read_only": True, "archive": False}
            current_ext_attrs: Optional pre-fetched extended_attributes dict
                               from the file entry (avoids an extra GET)

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/info/attributes"

            # Build full extended_attributes object by merging changes into current state
            if current_ext_attrs is not None:
                full_attrs = dict(current_ext_attrs)
            else:
                # Fetch current attributes
                try:
                    async with session.get(url, ssl=self.ssl_context) as response:
                        if response.status == 200:
                            data = await response.json()
                            full_attrs = dict(data.get("extended_attributes", {}))
                        else:
                            return (False, f"HTTP {response.status} reading current attributes")
                except aiohttp.ClientError as e:
                    return (False, f"Failed to read current attributes: {e}")

            full_attrs.update(attributes)
            payload = {"extended_attributes": full_attrs}

            try:
                async with session.patch(
                    url, json=payload, ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        return (True, None)
                    else:
                        error_msg = f"HTTP {response.status}"
                        try:
                            error_detail = await response.json()
                            error_msg += f": {error_detail.get('description', '')}"
                        except:
                            pass
                        return (False, error_msg)
            except aiohttp.ClientError as e:
                return (False, str(e))

    async def read_symlink(
        self, session: aiohttp.ClientSession, path: str, snapshot_id: Optional[int] = None
    ) -> Optional[str]:
        """
        Read the target of a symlink.

        Args:
            session: aiohttp ClientSession
            path: Path to the symlink
            snapshot_id: If set, read the symlink as of this snapshot

        Returns:
            The target path that the symlink points to, or None if read fails
        """
        async with self.semaphore:
            if not path.startswith('/'):
                path = '/' + path

            encoded_path = quote(path, safe='')
            url = f"{self.base_url}/v1/files/{encoded_path}/data"
            params = dict(self._atime_query_params())
            params.update(self._snapshot_query_params(snapshot_id))

            try:
                async with session.get(
                    url, params=params, ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        # Read the symlink target (returns as plain text)
                        target = await response.text()
                        return target.strip() if target else None
                    else:
                        return None
            except aiohttp.ClientError:
                return None

    async def read_file_chunk(
        self,
        session: aiohttp.ClientSession,
        path: str,
        offset: int,
        length: int
    ) -> Optional[bytes]:
        """
        Read a chunk of a file at a specific offset.

        Args:
            session: aiohttp ClientSession
            path: Path to the file
            offset: Byte offset to start reading from
            length: Number of bytes to read

        Returns:
            Bytes read from the file, or None if read fails
        """
        async with self.semaphore:
            if not path.startswith('/'):
                path = '/' + path

            encoded_path = quote(path, safe='')
            url = f"{self.base_url}/v1/files/{encoded_path}/data"

            params = {"offset": offset, "length": length}
            params.update(self._atime_query_params())

            try:
                async with session.get(
                    url, params=params, ssl=self.ssl_context
                ) as response:
                    if response.status == 200:
                        data = await response.read()
                        return data
                    else:
                        if self.verbose:
                            log_stderr("WARN", f"Failed to read chunk from {path} at offset {offset}: HTTP {response.status}")
                        return None
            except aiohttp.ClientError as e:
                if self.verbose:
                    log_stderr("WARN", f"Error reading chunk from {path}: {e}")
                return None

    async def enumerate_directory_adaptive(
        self,
        session: aiohttp.ClientSession,
        path: str,
        aggregates: dict,
        file_filter=None,
        owner_stats: Optional[OwnerStats] = None,
        collect_results: bool = True,
        verbose: bool = False,
        progress: Optional["ProgressTracker"] = None,
        output_callback=None,
        snapshot_id: Optional[int] = None,
    ) -> tuple:
        """
        Automatically choose between batch mode and streaming mode based on directory size.

        PHASE 3.2: Progressive streaming automatically switches to streaming mode for
        directories with 50k+ entries when collecting results to reduce memory usage.

        Decision logic:
        - < 50k entries: Use batch mode (existing behavior)
        - >= 50k entries AND collect_results=True: Use streaming mode
        - >= 50k entries AND collect_results=False: Use batch mode (already memory-efficient)

        Args:
            session: aiohttp ClientSession
            path: Directory path
            aggregates: Pre-fetched aggregates data with total_files/total_directories
            file_filter: Optional filter function
            owner_stats: Optional OwnerStats for collecting ownership data
            collect_results: If False, don't accumulate matching entries
            verbose: If True, log mode selection

        Returns:
            Tuple of (matching_entries, subdirs, match_count, total_entries_processed)
        """
        # Parse aggregates to determine directory size
        try:
            total_files = int(aggregates.get("total_files", 0))
            total_dirs = int(aggregates.get("total_directories", 0))
            total_entries = total_files + total_dirs
        except (ValueError, TypeError):
            total_entries = 0

        # Decide enumeration strategy
        # Use streaming for large directories when either:
        # 1. We're collecting results (to save memory)
        # 2. We have an output callback (for immediate output)
        use_streaming = total_entries >= 50000 and (collect_results or output_callback is not None)

        if verbose and use_streaming:
            print(
                f"\r[INFO] Progressive streaming: Using streaming mode for {path} ({total_entries:,} entries)",
                file=sys.stderr,
            )

        matching_entries = []
        subdirs = []
        match_count = 0
        total_processed = 0  # Track total entries processed (all files + dirs)

        if use_streaming:
            # Use streaming mode - process pages as they arrive
            async def process_page(page_entries):
                nonlocal match_count, total_processed
                page_size = len(page_entries)
                page_matches = 0

                total_processed += page_size
                for entry in page_entries:
                    # Collect owner statistics if enabled
                    if owner_stats:
                        owner_details = entry.get("owner_details", {})
                        owner_auth_id = owner_details.get("auth_id") or entry.get(
                            "owner"
                        )
                        if owner_auth_id:
                            try:
                                if owner_stats.use_capacity:
                                    datablocks = int(entry.get("datablocks", 0))
                                    metablocks = int(entry.get("metablocks", 0))
                                    file_size = (datablocks + metablocks) * 4096
                                else:
                                    file_size = int(entry.get("size", 0))
                            except (ValueError, TypeError):
                                file_size = 0
                            is_dir = entry.get("type") == "FS_FILE_TYPE_DIRECTORY"
                            await owner_stats.add_file(owner_auth_id, file_size, is_dir)

                    # Track subdirectories
                    if entry.get("type") == "FS_FILE_TYPE_DIRECTORY":
                        subdirs.append(entry["path"])

                    # Apply filter and collect results
                    is_match = False
                    if file_filter:
                        if file_filter(entry):
                            is_match = True
                            match_count += 1
                            page_matches += 1
                            if collect_results:
                                matching_entries.append(entry)
                    else:
                        is_match = True
                        match_count += 1
                        page_matches += 1
                        if collect_results:
                            matching_entries.append(entry)

                    # Output immediately if callback provided and entry matches
                    if is_match and output_callback:
                        # Check limit before outputting
                        if progress and not progress.can_output():
                            return  # Stop processing this page
                        await output_callback(entry)

                # Update progress after each page in streaming mode
                if progress:
                    await progress.update(page_size, 0, page_matches)

            # Stream directory entries with early exit check
            should_continue = lambda: not progress or progress.can_output()
            await self.enumerate_directory_streaming(
                session, path, process_page, should_continue, snapshot_id=snapshot_id)
        else:
            # Use batch mode - existing behavior
            entries = await self.enumerate_directory(session, path, snapshot_id=snapshot_id)
            total_processed = len(entries)

            for entry in entries:
                # Collect owner statistics if enabled
                if owner_stats:
                    owner_details = entry.get("owner_details", {})
                    owner_auth_id = owner_details.get("auth_id") or entry.get("owner")
                    if owner_auth_id:
                        try:
                            if owner_stats.use_capacity:
                                datablocks = int(entry.get("datablocks", 0))
                                metablocks = int(entry.get("metablocks", 0))
                                file_size = (datablocks + metablocks) * 4096
                            else:
                                file_size = int(entry.get("size", 0))
                        except (ValueError, TypeError):
                            file_size = 0
                        is_dir = entry.get("type") == "FS_FILE_TYPE_DIRECTORY"
                        await owner_stats.add_file(owner_auth_id, file_size, is_dir)

                # Track subdirectories
                if entry.get("type") == "FS_FILE_TYPE_DIRECTORY":
                    subdirs.append(entry["path"])

                # Apply filter and collect results
                is_match = False
                if file_filter:
                    if file_filter(entry):
                        is_match = True
                        match_count += 1
                        if collect_results:
                            matching_entries.append(entry)
                else:
                    is_match = True
                    match_count += 1
                    if collect_results:
                        matching_entries.append(entry)

                # Output immediately if callback provided and entry matches
                if is_match and output_callback:
                    # Check limit before outputting
                    if progress and not progress.can_output():
                        break  # Stop processing entries
                    await output_callback(entry)

        return (matching_entries, subdirs, match_count, total_processed)

    async def walk_tree_async(
        self,
        session: aiohttp.ClientSession,
        path: str,
        max_depth: Optional[int] = None,
        _current_depth: int = 0,
        progress: Optional[ProgressTracker] = None,
        file_filter=None,
        owner_stats: Optional[OwnerStats] = None,
        omit_subdirs: Optional[List[str]] = None,
        omit_paths: Optional[List[str]] = None,
        collect_results: bool = True,
        verbose: bool = False,
        max_entries_per_dir: Optional[int] = None,
        time_filter_info: Optional[Dict] = None,
        size_filter_info: Optional[Dict] = None,
        owner_filter_info: Optional[Dict] = None,
        output_callback=None,
        snapshot_id: Optional[int] = None,
    ) -> List[dict]:
        """
        Walk directory tree using bounded-memory BFS with async worker pool.

        Uses an asyncio.Queue with fixed-size worker pool instead of recursive
        coroutine expansion. Memory usage is O(queue_capacity) regardless of
        filesystem size, preventing OOM on large filesystems.

        Args:
            session: aiohttp ClientSession
            path: Directory path to walk
            max_depth: Maximum depth to traverse (-1 or None for unlimited)
            _current_depth: Ignored (kept for API compatibility)
            progress: Optional ProgressTracker for reporting progress
            file_filter: Optional function to filter files
            owner_stats: Optional OwnerStats for collecting ownership data
            omit_subdirs: Optional list of wildcard patterns for directories to skip
            omit_paths: Optional list of exact absolute paths to skip (no wildcards)
            collect_results: If False, don't accumulate matching entries (saves memory)
            verbose: If True, emit warnings to stderr for large directories
            max_entries_per_dir: If set, skip directories with more entries than this limit
            time_filter_info: Optional dict with time filter thresholds for smart skipping
            size_filter_info: Optional dict with size filter thresholds for smart skipping
            owner_filter_info: Optional dict with owner filter auth_ids for smart skipping
            output_callback: Optional async callback for streaming results

        Returns:
            List of matching file entries (empty if collect_results=False)
        """
        # Pre-normalize omit_paths once (avoid repeated work per directory)
        normalized_omit_paths = None
        if omit_paths:
            normalized_omit_paths = set(p.rstrip("/") for p in omit_paths)

        # Shared state for collect_results mode
        collected_results = [] if collect_results else None
        results_lock = asyncio.Lock()

        # If the root path is a single file or symlink (not a directory), operate on
        # just that object instead of trying to enumerate it as a directory (which
        # would match nothing). This lets --path point straight at a file.
        root_attr = await self.get_file_attr(session, path, snapshot_id=snapshot_id)
        if root_attr is not None and root_attr.get("type") != "FS_FILE_TYPE_DIRECTORY":
            root_attr.setdefault("path", path)
            root_attr.setdefault("name", path.rstrip("/").rsplit("/", 1)[-1])
            if file_filter is None or file_filter(root_attr):
                if output_callback is not None:
                    await output_callback(root_attr)
                if collected_results is not None:
                    collected_results.append(root_attr)
            return collected_results if collected_results is not None else []

        # Bounded work queue: (path, depth) tuples
        queue = asyncio.Queue(maxsize=50_000)
        await queue.put((path, 0))

        num_workers = min(self.max_concurrent, 200)

        async def _process_directory(dir_path: str, current_depth: int):
            """Process a single directory: smart skip, enumerate, filter, enqueue children."""
            # Check depth limit
            if max_depth is not None and max_depth >= 0 and current_depth >= max_depth:
                return

            # Early exit: Check if limit reached
            if progress and progress.should_stop():
                return

            # Get directory aggregates for pre-flight intelligence
            aggregates = await self.get_directory_aggregates(session, dir_path, snapshot_id=snapshot_id)

            # Check for errors in aggregates response
            has_aggregates_error = "error" in aggregates

            if not has_aggregates_error:
                try:
                    total_files = int(aggregates.get("total_files", 0))
                    total_directories = int(aggregates.get("total_directories", 0))
                    total_entries = total_files + total_directories

                    if verbose and total_entries > 100_000:
                        print(
                            f"\r[WARN] Large directory: {dir_path} ({total_entries:,} entries: "
                            f"{total_files:,} files, {total_directories:,} dirs)",
                            file=sys.stderr,
                        )

                    # Safety valve: skip directories exceeding max_entries_per_dir
                    if max_entries_per_dir and total_entries > max_entries_per_dir:
                        if progress:
                            await progress.increment_skipped(total_files, total_directories)
                        return

                    # Smart skipping: type-based
                    if file_filter:
                        test_dir = {"type": "FS_FILE_TYPE_DIRECTORY", "path": "/test", "name": "test"}
                        test_file = {"type": "FS_FILE_TYPE_FILE", "path": "/test", "name": "test"}

                        if not file_filter(test_dir) and file_filter(test_file):
                            if total_files == 0:
                                if progress:
                                    await progress.increment_skipped(total_files, total_directories)
                                return

                        if file_filter(test_dir) and not file_filter(test_file):
                            if total_directories == 0:
                                if progress:
                                    await progress.increment_skipped(total_files, total_directories)
                                return

                    # Smart skipping: time-based
                    if time_filter_info:
                        oldest_mod = aggregates.get("oldest_modification_time")
                        newest_mod = aggregates.get("newest_modification_time")
                        older_than_threshold = time_filter_info.get("older_than")
                        newer_than_threshold = time_filter_info.get("newer_than")
                        time_field = time_filter_info.get("time_field", "modification_time")

                        if time_field == "modification_time" and oldest_mod and newest_mod:
                            try:
                                oldest_time = datetime.fromisoformat(oldest_mod.rstrip("Z").split(".")[0])
                                newest_time = datetime.fromisoformat(newest_mod.rstrip("Z").split(".")[0])

                                if older_than_threshold and newest_time >= older_than_threshold:
                                    if progress:
                                        await progress.increment_skipped(total_files, total_directories)
                                    return

                                if newer_than_threshold and oldest_time <= newer_than_threshold:
                                    if progress:
                                        await progress.increment_skipped(total_files, total_directories)
                                    return
                            except (ValueError, AttributeError):
                                pass

                    # Smart skipping: size-based
                    if size_filter_info:
                        total_capacity = aggregates.get("total_capacity")
                        min_size = size_filter_info.get("min_size")
                        if min_size and total_capacity:
                            try:
                                if int(total_capacity) < min_size:
                                    if progress:
                                        await progress.increment_skipped(total_files, total_directories)
                                    return
                            except (ValueError, TypeError):
                                pass

                    # Smart skipping: owner-based
                    if owner_filter_info:
                        owner_auth_ids = owner_filter_info.get("auth_ids")
                        if owner_auth_ids:
                            capacity_data = await self.get_directory_capacity(session, dir_path)
                            if capacity_data and "capacity_by_owner" in capacity_data:
                                owners_with_files = set()
                                for entry in capacity_data.get("capacity_by_owner", []):
                                    owner_id = entry.get("id")
                                    if owner_id:
                                        owners_with_files.add(owner_id)
                                if not any(aid in owners_with_files for aid in owner_auth_ids):
                                    if progress:
                                        await progress.increment_skipped(total_files, total_directories)
                                    return

                except (ValueError, TypeError):
                    pass

            # Enumerate directory (adaptive: streaming for large dirs, batch for small)
            matching_entries, subdirs, match_count, total_processed = (
                await self.enumerate_directory_adaptive(
                    session, dir_path, aggregates,
                    file_filter, owner_stats, collect_results,
                    verbose, progress, output_callback,
                    snapshot_id=snapshot_id,
                )
            )

            # Filter subdirectories based on omit patterns
            if omit_subdirs:
                filtered_subdirs = []
                omitted_dirs_count = 0

                for subdir_path in subdirs:
                    subdir_name = (
                        subdir_path.rstrip("/").split("/")[-1]
                        if "/" in subdir_path else subdir_path
                    )
                    should_omit = False
                    for pattern in omit_subdirs:
                        normalized_pattern = pattern.rstrip("/")
                        if (fnmatch.fnmatch(subdir_path.rstrip("/"), normalized_pattern) or
                                fnmatch.fnmatch(subdir_name, normalized_pattern)):
                            should_omit = True
                            break
                    if should_omit:
                        omitted_dirs_count += 1
                    else:
                        filtered_subdirs.append(subdir_path)

                subdirs = filtered_subdirs

                if progress and omitted_dirs_count > 0:
                    await progress.increment_skipped(0, omitted_dirs_count)

                # Filter matching_entries for omitted directories
                if collect_results:
                    filtered_entries = []
                    for entry in matching_entries:
                        entry_path = entry.get('path', '')
                        entry_type = entry.get('type', '')
                        if entry_type == 'FS_FILE_TYPE_DIRECTORY':
                            entry_name = (
                                entry_path.rstrip("/").split("/")[-1]
                                if "/" in entry_path else entry_path
                            )
                            should_omit = False
                            for pattern in omit_subdirs:
                                normalized_pattern = pattern.rstrip("/")
                                if (fnmatch.fnmatch(entry_path.rstrip("/"), normalized_pattern) or
                                        fnmatch.fnmatch(entry_name, normalized_pattern)):
                                    should_omit = True
                                    break
                            if not should_omit:
                                filtered_entries.append(entry)
                        else:
                            filtered_entries.append(entry)
                    matching_entries = filtered_entries

            # Filter based on exact absolute paths (--omit-path)
            if normalized_omit_paths:
                filtered_subdirs = []
                omitted_paths_count = 0

                for subdir_path in subdirs:
                    if subdir_path.rstrip("/") in normalized_omit_paths:
                        omitted_paths_count += 1
                    else:
                        filtered_subdirs.append(subdir_path)

                subdirs = filtered_subdirs

                if progress and omitted_paths_count > 0:
                    await progress.increment_skipped(0, omitted_paths_count)

                if collect_results:
                    matching_entries = [
                        e for e in matching_entries
                        if e.get('path', '').rstrip("/") not in normalized_omit_paths
                    ]

            # Update progress for batch mode
            try:
                tf = int(aggregates.get("total_files", 0))
                td = int(aggregates.get("total_directories", 0))
                te = tf + td
                used_streaming = te >= 50000 and (collect_results or output_callback is not None)
            except (ValueError, TypeError):
                used_streaming = False

            if progress and not used_streaming:
                await progress.update(total_processed, 1, match_count)

            # Collect results if needed
            if collect_results and matching_entries:
                async with results_lock:
                    collected_results.extend(matching_entries)

            # Enqueue child subdirectories (or process inline if queue is full)
            if subdirs and (max_depth is None or max_depth < 0 or current_depth + 1 < max_depth):
                for subdir in subdirs:
                    if progress and progress.should_stop():
                        break
                    try:
                        queue.put_nowait((subdir, current_depth + 1))
                    except asyncio.QueueFull:
                        # Queue is full -- process inline to avoid deadlock.
                        # Recursion depth is bounded by filesystem depth (typically 10-30).
                        await _process_directory(subdir, current_depth + 1)

        async def _worker(worker_id: int):
            """Worker coroutine: pull directories from queue and process them."""
            while True:
                dir_path, depth = await queue.get()
                try:
                    await _process_directory(dir_path, depth)
                except Exception as e:
                    if verbose:
                        log_stderr("WARN", f"Error processing {dir_path}: {e}")
                finally:
                    queue.task_done()

        # Launch worker pool and wait for completion
        workers = [asyncio.create_task(_worker(i)) for i in range(num_workers)]

        await queue.join()

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        return collected_results if collected_results is not None else []

    async def resolve_identity(
        self, session: aiohttp.ClientSession, identifier: str, id_type: str = "auth_id"
    ) -> Dict:
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
            raise ValueError(
                f"Unknown id_type: {id_type}. Must be auth_id, sid, uid, gid, or name"
            )

        try:
            async with session.post(
                url, json=payload, ssl=self.ssl_context
            ) as response:
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
                        "resolved": False,
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
                "resolved": False,
            }

    async def resolve_multiple_identities(
        self,
        session: aiohttp.ClientSession,
        auth_ids: List[str],
        show_progress: bool = False,
    ) -> Dict[str, Dict]:
        """
        Resolve multiple identities in parallel, using identity expansion to find
        the best name for POSIX UIDs that are linked to AD users.

        Args:
            session: aiohttp ClientSession
            auth_ids: List of auth_id values to resolve
            show_progress: If True, display progress updates during resolution

        Returns:
            Dictionary mapping auth_id to resolved identity info
        """
        # Remove duplicates
        unique_ids = list(set(auth_ids))

        if not unique_ids:
            return {}

        # Track how many are already cached
        cached_count = sum(
            1 for auth_id in unique_ids if auth_id in self.persistent_identity_cache
        )
        to_resolve_count = len(unique_ids) - cached_count

        if show_progress:
            print(
                f"[INFO] Resolving {len(unique_ids)} unique owner identities ({cached_count} cached, {to_resolve_count} to fetch)...",
                file=sys.stderr,
            )

        start_time = time.time()

        # Create tasks for parallel resolution with expansion
        tasks = [
            self._resolve_identity_with_expansion(session, auth_id)
            for auth_id in unique_ids
        ]

        # Execute all resolutions in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        if show_progress:
            elapsed = time.time() - start_time
            avg_time = elapsed / len(unique_ids) if len(unique_ids) > 0 else 0
            print(
                f"[INFO] Identity resolution completed in {elapsed:.1f}s ({avg_time*1000:.1f}ms per identity)",
                file=sys.stderr,
            )
            print(
                f"[INFO] Cache stats - Hits: {self.cache_hits}, Misses: {self.cache_misses}, Hit rate: {self.cache_hits/(self.cache_hits+self.cache_misses)*100:.1f}%",
                file=sys.stderr,
            )

        # Build cache mapping auth_id to result
        identity_cache = {}
        for auth_id, result in zip(unique_ids, results):
            if isinstance(result, Exception):
                identity_cache[auth_id] = {
                    "domain": "ERROR",
                    "auth_id": auth_id,
                    "name": f"Error: {auth_id}",
                    "error": str(result),
                    "resolved": False,
                }
            else:
                identity_cache[auth_id] = result

        return identity_cache

    async def _resolve_identity_with_expansion(
        self, session: aiohttp.ClientSession, auth_id: str
    ) -> Dict:
        """
        Resolve an identity using expansion to find the best displayable name.

        This handles cases where a POSIX UID (like 2005) is linked to an AD user
        (like "mark") through POSIX extensions. We want to show the AD name.

        Checks persistent cache first to avoid redundant API calls.

        Args:
            session: aiohttp ClientSession
            auth_id: The auth_id to resolve

        Returns:
            Dictionary containing identity info with the best available name
        """
        # Check persistent cache first
        if auth_id in self.persistent_identity_cache:
            self.cache_hits += 1
            return self.persistent_identity_cache[auth_id]

        self.cache_misses += 1

        url = f"{self.base_url}/v1/identity/expand"

        # Build identity dict for the expand API
        # The expand API expects: {"id": {"auth_id": "12884903893"}}
        payload = {"id": {"auth_id": str(auth_id)}}

        try:
            async with session.post(
                url, json=payload, ssl=self.ssl_context
            ) as response:
                if response.status == 200:
                    expand_result = await response.json()

                    # Extract the primary identity (the one we queried for)
                    primary_identity = expand_result.get("id", {})

                    # Check if we got a name from the primary identity
                    best_identity = primary_identity.copy()
                    best_identity["auth_id"] = auth_id
                    best_identity["resolved"] = True

                    # If the primary identity doesn't have a name, check equivalent identities
                    if not primary_identity.get("name"):
                        # Look through equivalent identities to find one with a name
                        # Prefer AD identities over POSIX identities
                        equivalent_ids = expand_result.get("equivalent_ids", [])

                        # Sort equivalent identities by preference: AD > LOCAL > POSIX
                        def identity_preference(identity):
                            domain = identity.get("domain", "")
                            if domain == "ACTIVE_DIRECTORY":
                                return 0
                            elif domain == "LOCAL":
                                return 1
                            elif domain in ["POSIX_USER", "POSIX_GROUP"]:
                                return 2
                            else:
                                return 3

                        sorted_identities = sorted(
                            equivalent_ids, key=identity_preference
                        )

                        # Find the first equivalent identity with a name
                        for equiv_identity in sorted_identities:
                            if equiv_identity.get("name"):
                                # Found a better name - use this identity info
                                # But keep the original auth_id and domain info
                                best_identity["name"] = equiv_identity["name"]
                                # Keep track of both domains for display
                                if primary_identity.get("domain"):
                                    best_identity["domain"] = primary_identity["domain"]
                                best_identity["display_domain"] = equiv_identity.get(
                                    "domain"
                                )
                                break

                    # Store in cache for future use
                    self.persistent_identity_cache[auth_id] = best_identity

                    return best_identity

                elif response.status == 404:
                    # Identity not found - fall back to basic resolution
                    result = await self.resolve_identity(session, auth_id, "auth_id")
                    # Cache the result
                    self.persistent_identity_cache[auth_id] = result
                    return result
                else:
                    response.raise_for_status()

        except Exception:
            # Fall back to basic resolution on error
            result = await self.resolve_identity(session, auth_id, "auth_id")
            # Cache the fallback result
            self.persistent_identity_cache[auth_id] = result
            return result

    async def show_directory_stats(
        self,
        session: aiohttp.ClientSession,
        path: str,
        max_depth: int = 1,
        current_depth: int = 0,
    ) -> None:
        """
        Display directory statistics without enumerating entries.
        Uses aggregates API for fast exploration.

        Args:
            session: aiohttp ClientSession
            path: Directory path
            max_depth: Maximum depth to display (default: 1)
            current_depth: Current recursion depth
        """
        # Get aggregates
        aggregates = await self.get_directory_aggregates(session, path)

        if "error" in aggregates:
            print(f"\nDirectory: {path}")
            print("  (Unable to retrieve statistics)")
            return

        # Display statistics
        total_files = int(aggregates.get("total_files", 0))
        total_dirs = int(aggregates.get("total_directories", 0))
        total_entries = total_files + total_dirs
        total_capacity = int(aggregates.get("total_capacity", 0))
        oldest_time = aggregates.get("oldest_modification_time", "Unknown")
        newest_time = aggregates.get("newest_modification_time", "Unknown")

        # Format times
        if oldest_time != "Unknown":
            try:
                oldest_dt = datetime.fromisoformat(
                    oldest_time.rstrip("Z").split(".")[0]
                )
                oldest_time = oldest_dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass

        if newest_time != "Unknown":
            try:
                newest_dt = datetime.fromisoformat(
                    newest_time.rstrip("Z").split(".")[0]
                )
                newest_time = newest_dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass

        avg_size = total_capacity / total_files if total_files > 0 else 0

        # Print with indentation based on depth
        indent = "  " * current_depth
        print(f"\n{indent}Directory: {path}")
        print(
            f"{indent}  Total entries: {total_entries:,} ({total_files:,} files, {total_dirs:,} directories)"
        )
        print(f"{indent}  Total size: {format_bytes(total_capacity)}")
        print(f"{indent}  Modification time range: {oldest_time} to {newest_time}")
        if total_files > 0:
            print(f"{indent}  Average file size: {format_bytes(avg_size)}")

        # Recurse to subdirectories if depth permits.
        # Smart skip: total_dirs is the recursive count. If 0, there are no
        # subdirectories anywhere in this subtree -- no point enumerating.
        if current_depth < max_depth and total_dirs > 0:
            # Stream entries page-by-page, collecting only subdirectory paths.
            # This avoids loading millions of file entries into memory just to
            # filter them down to a handful of directories.
            subdirs = []

            async def extract_subdirs(page):
                for entry in page:
                    if entry.get("type") == "FS_FILE_TYPE_DIRECTORY":
                        subdirs.append(entry["path"])

            try:
                await self.enumerate_directory_streaming(
                    session, path, callback=extract_subdirs
                )
            except Exception as e:
                if self.verbose:
                    print(
                        f"{indent}  [ERROR] Failed to enumerate subdirectories: {e}",
                        file=sys.stderr,
                    )
                return

            for subdir_path in subdirs:
                await self.show_directory_stats(
                    session, subdir_path, max_depth, current_depth + 1
                )

    async def expand_identity(
        self, session: aiohttp.ClientSession, auth_id: str
    ) -> List[str]:
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
            async with session.post(
                url, json=payload, ssl=self.ssl_context
            ) as response:
                if response.status == 200:
                    result = await response.json()

                    # Extract all equivalent auth_ids
                    equivalent_ids = [auth_id]  # Include original

                    # Add from equivalent_ids array
                    for equiv in result.get("equivalent_ids", []):
                        equiv_auth_id = equiv.get("auth_id")
                        if equiv_auth_id and equiv_auth_id not in equivalent_ids:
                            equivalent_ids.append(equiv_auth_id)

                    # Add from nfs_id
                    nfs_auth_id = result.get("nfs_id", {}).get("auth_id")
                    if nfs_auth_id and nfs_auth_id not in equivalent_ids:
                        equivalent_ids.append(nfs_auth_id)

                    # Add from smb_id
                    smb_auth_id = result.get("smb_id", {}).get("auth_id")
                    if smb_auth_id and smb_auth_id not in equivalent_ids:
                        equivalent_ids.append(smb_auth_id)

                    # Add from id
                    id_auth_id = result.get("id", {}).get("auth_id")
                    if id_auth_id and id_auth_id not in equivalent_ids:
                        equivalent_ids.append(id_auth_id)

                    return equivalent_ids
                else:
                    # If expansion fails, return just the original
                    return [auth_id]
        except Exception:
            # If expansion fails, return just the original
            return [auth_id]
