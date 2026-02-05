"""
Async Qumulo API client for grumpwalk.

This module contains the AsyncQumuloClient class for interacting with
the Qumulo REST API using async/await patterns.
"""

import asyncio
import copy
import fnmatch
import ssl
import sys
import time
from datetime import datetime
from typing import List, Optional, Dict, Set, Tuple
from urllib.parse import quote

try:
    import aiohttp
except ImportError:
    print(
        "[ERROR] aiohttp not installed. Install with: pip install aiohttp",
        file=sys.stderr,
    )
    sys.exit(1)

# Import from other modules
from .utils import (
    extract_pagination_token,
    format_bytes,
    format_time,
)
from .stats import OwnerStats
from .output import ProgressTracker

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
    ):
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.bearer_token = bearer_token
        self.max_concurrent = max_concurrent
        self.verbose = verbose

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

    async def get_directory_page(
        self,
        session: aiohttp.ClientSession,
        path: str,
        limit: int = 1000,
        after_token: Optional[str] = None,
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
    ) -> List[dict]:
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
            response = await self.get_directory_page(
                session, path, limit=1000, after_token=after_token
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
        self, session: aiohttp.ClientSession, path: str, callback, should_continue=None
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
                session, path, limit=1000, after_token=after_token
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
        self, session: aiohttp.ClientSession, path: str
    ) -> dict:
        """
        Get directory aggregate statistics.

        Returns statistics for immediate children only (non-recursive).
        All count fields are returned as strings - use int() to convert.

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
                async with session.get(url, ssl=self.ssl_context) as response:
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
        self, session: aiohttp.ClientSession, path: str
    ) -> Optional[dict]:
        """
        Get the Access Control List (ACL) for a file or directory.
        Uses v2 API endpoint.

        Args:
            session: aiohttp ClientSession
            path: File or directory path

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
                async with session.get(url, ssl=self.ssl_context) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        if self.verbose:
                            print(
                                f"[WARN] Failed to get ACL for {path}: HTTP {response.status}",
                                file=sys.stderr,
                            )
                        return None
            except aiohttp.ClientError as e:
                if self.verbose:
                    print(f"[WARN] Error getting ACL for {path}: {e}", file=sys.stderr)
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
        path: str
    ) -> Optional[dict]:
        """
        Get file attributes including file ID using v1 attributes API.

        Args:
            session: aiohttp ClientSession
            path: Path to the file/directory

        Returns:
            Dictionary with file attributes including 'id', 'name', 'type', etc. or None if failed
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/info/attributes"

            try:
                async with session.get(url, ssl=self.ssl_context) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return None
            except aiohttp.ClientError:
                return None

    async def get_file_owner_group(
        self,
        session: aiohttp.ClientSession,
        path: str
    ) -> Optional[dict]:
        """
        Get owner and group information for a file or directory using v1 attributes API.

        Args:
            session: aiohttp ClientSession
            path: Path to the file/directory

        Returns:
            Dictionary with 'owner', 'owner_details', 'group', 'group_details' or None if failed
        """
        async with self.semaphore:
            if not path.startswith("/"):
                path = "/" + path

            encoded_path = quote(path, safe="")
            url = f"{self.base_url}/v1/files/{encoded_path}/info/attributes"

            try:
                async with session.get(url, ssl=self.ssl_context) as response:
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

    async def read_symlink(self, session: aiohttp.ClientSession, path: str) -> Optional[str]:
        """
        Read the target of a symlink.

        Args:
            session: aiohttp ClientSession
            path: Path to the symlink

        Returns:
            The target path that the symlink points to, or None if read fails
        """
        async with self.semaphore:
            if not path.startswith('/'):
                path = '/' + path

            encoded_path = quote(path, safe='')
            url = f"{self.base_url}/v1/files/{encoded_path}/data"

            try:
                async with session.get(url, ssl=self.ssl_context) as response:
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
            url = f"{self.base_url}/v1/files/{encoded_path}/data?offset={offset}&length={length}"

            try:
                async with session.get(url, ssl=self.ssl_context) as response:
                    if response.status == 200:
                        data = await response.read()
                        return data
                    else:
                        if self.verbose:
                            print(f"[WARN] Failed to read chunk from {path} at offset {offset}: HTTP {response.status}", file=sys.stderr)
                        return None
            except aiohttp.ClientError as e:
                if self.verbose:
                    print(f"[WARN] Error reading chunk from {path}: {e}", file=sys.stderr)
                return None

    def calculate_adaptive_concurrency(self, total_entries: int) -> int:
        """
        Calculate adaptive concurrency based on directory size.

        PHASE 3.2: Adaptive concurrency reduces concurrent operations for very large
        directories to prevent overwhelming the cluster and consuming excessive memory.

        Thresholds:
        - < 10k entries: Use full concurrency
        - 10k-50k entries: Reduce to 50% of base
        - 50k-100k entries: Reduce to 25% of base
        - > 100k entries: Reduce to 10% of base (min 5)

        Args:
            total_entries: Total entries in directory (files + directories)

        Returns:
            Adjusted concurrency level
        """
        if total_entries < 10000:
            return self.max_concurrent
        elif total_entries < 50000:
            return max(5, self.max_concurrent // 2)
        elif total_entries < 100000:
            return max(5, self.max_concurrent // 4)
        else:
            return max(5, self.max_concurrent // 10)

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
            await self.enumerate_directory_streaming(session, path, process_page, should_continue)
        else:
            # Use batch mode - existing behavior
            entries = await self.enumerate_directory(session, path)
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
    ) -> List[dict]:
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
            omit_paths: Optional list of exact absolute paths to skip (no wildcards)
            collect_results: If False, don't accumulate matching entries (saves memory for reports)
            verbose: If True, emit warnings to stderr for large directories
            max_entries_per_dir: If set, skip directories with more entries than this limit
            time_filter_info: Optional dict with time filter thresholds for smart skipping
            size_filter_info: Optional dict with size filter thresholds for smart skipping
            owner_filter_info: Optional dict with owner filter auth_ids for smart skipping

        Returns:
            List of matching file entries (empty if collect_results=False)
        """
        # Check depth limit
        if max_depth is not None and max_depth >= 0 and _current_depth >= max_depth:
            return []

        # Early exit: Check if limit reached
        if progress and progress.should_stop():
            return []

        # Get directory aggregates for pre-flight intelligence
        aggregates = await self.get_directory_aggregates(session, path)

        # Check for errors in aggregates response (API may not be available)
        has_aggregates_error = "error" in aggregates

        if not has_aggregates_error:
            # Parse aggregate statistics (API returns strings, convert to ints)
            try:
                total_files = int(aggregates.get("total_files", 0))
                total_directories = int(aggregates.get("total_directories", 0))
                total_entries = total_files + total_directories

                # Warn on large directories (100k+ entries)
                if verbose and total_entries > 100_000:
                    print(
                        f"\r[WARN] Large directory: {path} ({total_entries:,} entries: "
                        f"{total_files:,} files, {total_directories:,} dirs)",
                        file=sys.stderr,
                    )

                # Safety valve: skip directories exceeding max_entries_per_dir
                if max_entries_per_dir and total_entries > max_entries_per_dir:
                    # if verbose:
                    #     print(f"\r[SKIP] Directory exceeds limit: {path} "
                    #           f"({total_entries:,} entries > {max_entries_per_dir:,} limit)",
                    #           file=sys.stderr)
                    pass
                    if progress:
                        await progress.increment_skipped(total_files, total_directories)
                    return []

                # PHASE 2: Smart skipping - skip directories that can't possibly match filters
                # This saves API calls by not enumerating directories we know won't have matches
                if file_filter:
                    # Check if file_only filter is active (file_filter rejects all directories)
                    # We detect this by checking if args has file_only attribute
                    # Since we don't have access to args here, we check by testing the filter
                    # with a mock directory entry
                    test_dir = {
                        "type": "FS_FILE_TYPE_DIRECTORY",
                        "path": "/test",
                        "name": "test",
                    }
                    test_file = {
                        "type": "FS_FILE_TYPE_FILE",
                        "path": "/test",
                        "name": "test",
                    }

                    # If filter rejects directories but might accept files, check file count
                    if not file_filter(test_dir) and file_filter(test_file):
                        # This looks like --file-only filter
                        if total_files == 0:
                            # if verbose:
                            #     print(f"\r[SKIP] Smart skip: {path} (0 files, --file-only active)",
                            #           file=sys.stderr)
                            pass
                            if progress:
                                await progress.increment_skipped(
                                    total_files, total_directories
                                )
                            return []

                # PHASE 3: Enhanced smart skipping for time and size filters
                # Use aggregates data to skip directories that cannot possibly contain matching files

                # Time-based smart skipping
                if time_filter_info:
                    oldest_mod = aggregates.get("oldest_modification_time")
                    newest_mod = aggregates.get("newest_modification_time")

                    # Parse time filter info
                    older_than_threshold = time_filter_info.get("older_than")
                    newer_than_threshold = time_filter_info.get("newer_than")
                    time_field = time_filter_info.get("time_field", "modification_time")

                    # Only apply smart skipping for modification_time (since aggregates provides mod times)
                    if time_field == "modification_time" and (
                        oldest_mod and newest_mod
                    ):
                        try:
                            # Parse aggregates times
                            oldest_time = datetime.fromisoformat(
                                oldest_mod.rstrip("Z").split(".")[0]
                            )
                            newest_time = datetime.fromisoformat(
                                newest_mod.rstrip("Z").split(".")[0]
                            )

                            # Check --older-than filter
                            if older_than_threshold:
                                # If the NEWEST file is younger than threshold, NO files match
                                if newest_time >= older_than_threshold:
                                    # if verbose:
                                    #     print(f"\r[SKIP] Smart skip: {path} (all files newer than threshold)",
                                    #           file=sys.stderr)
                                    if progress:
                                        await progress.increment_skipped(
                                            total_files, total_directories
                                        )
                                    return []

                            # Check --newer-than filter
                            if newer_than_threshold:
                                # If the OLDEST file is older than threshold, NO files match
                                if oldest_time <= newer_than_threshold:
                                    # if verbose:
                                    #     print(f"\r[SKIP] Smart skip: {path} (all files older than threshold)",
                                    #           file=sys.stderr)
                                    if progress:
                                        await progress.increment_skipped(
                                            total_files, total_directories
                                        )
                                    return []

                        except (ValueError, AttributeError):
                            # If time parsing fails, continue without smart skipping
                            pass

                # Size-based smart skipping
                if size_filter_info:
                    total_capacity = aggregates.get("total_capacity")
                    min_size = size_filter_info.get("min_size")

                    # Check --larger-than filter (min_size)
                    if min_size and total_capacity:
                        try:
                            total_cap_bytes = int(total_capacity)
                            # If total directory capacity is less than min_size,
                            # NO individual files can be >= min_size
                            if total_cap_bytes < min_size:
                                # if verbose:
                                #     print(f"\r[SKIP] Smart skip: {path} "
                                #           f"(total capacity {total_cap_bytes} < min {min_size})",
                                #           file=sys.stderr)
                                if progress:
                                    await progress.increment_skipped(
                                        total_files, total_directories
                                    )
                                return []
                        except (ValueError, TypeError):
                            # If capacity parsing fails, continue without smart skipping
                            pass

                # PHASE 3.3: Owner-based smart skipping
                # Use capacity API to check if target owner has any files in this directory
                if owner_filter_info:
                    owner_auth_ids = owner_filter_info.get("auth_ids")
                    if owner_auth_ids:
                        # Get capacity breakdown by owner
                        capacity_data = await self.get_directory_capacity(session, path)
                        if capacity_data and "capacity_by_owner" in capacity_data:
                            # Extract owner IDs from capacity data
                            owners_with_files = set()
                            for entry in capacity_data.get("capacity_by_owner", []):
                                owner_id = entry.get("id")
                                if owner_id:
                                    owners_with_files.add(owner_id)

                            # Check if any of our target owners have files here
                            has_matching_owner = any(
                                auth_id in owners_with_files
                                for auth_id in owner_auth_ids
                            )

                            if not has_matching_owner:
                                # if verbose:
                                #     print(f"\r[SKIP] Smart skip: {path} (no files owned by target owner(s))",
                                #           file=sys.stderr)
                                if progress:
                                    await progress.increment_skipped(
                                        total_files, total_directories
                                    )
                                return []

            except (ValueError, TypeError):
                # If we can't parse aggregates, continue without the check
                pass

        # PHASE 3.2: Use adaptive enumeration (automatically chooses streaming vs batch mode)
        # Pass progress tracker for per-page updates in streaming mode
        matching_entries, subdirs, match_count, total_processed = (
            await self.enumerate_directory_adaptive(
                session,
                path,
                aggregates,
                file_filter,
                owner_stats,
                collect_results,
                verbose,
                progress,
                output_callback,
            )
        )

        # Filter subdirectories based on omit patterns
        if omit_subdirs:
            filtered_subdirs = []
            filtered_entries = []
            omitted_dirs_count = 0

            for subdir_path in subdirs:
                # Extract directory name (last component, handling trailing slashes)
                subdir_name = (
                    subdir_path.rstrip("/").split("/")[-1]
                    if "/" in subdir_path
                    else subdir_path
                )

                # Check if this directory should be omitted
                should_omit = False
                matched_pattern = None
                for pattern in omit_subdirs:
                    # Normalize pattern by stripping trailing slashes for matching
                    normalized_pattern = pattern.rstrip("/")

                    # Try matching against:
                    # 1. Full path (e.g., "/home/bob" matches "/home/bob")
                    # 2. Directory name only (e.g., "bob" matches "bob")
                    # 3. Pattern with wildcards (e.g., "bob*" matches "bob123")
                    if (fnmatch.fnmatch(subdir_path.rstrip("/"), normalized_pattern) or
                        fnmatch.fnmatch(subdir_name, normalized_pattern)):
                        should_omit = True
                        matched_pattern = pattern
                        break

                if should_omit:
                    omitted_dirs_count += 1
                else:
                    filtered_subdirs.append(subdir_path)

            subdirs = filtered_subdirs

            # Report omitted directories to progress tracker
            if progress and omitted_dirs_count > 0:
                # We count each omitted directory as 1 subdirectory skipped
                # We don't have file counts for omitted dirs without fetching their aggregates,
                # so we report 0 files (the subdirs count is what matters here)
                await progress.increment_skipped(0, omitted_dirs_count)

            # Also filter matching_entries to remove directories that match omit patterns
            for entry in matching_entries:
                entry_path = entry.get('path', '')
                entry_type = entry.get('type', '')

                # Only filter directories
                if entry_type == 'FS_FILE_TYPE_DIRECTORY':
                    entry_name = (
                        entry_path.rstrip("/").split("/")[-1]
                        if "/" in entry_path
                        else entry_path
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
                    # Keep all files
                    filtered_entries.append(entry)

            matching_entries = filtered_entries

        # Filter based on exact absolute paths (--omit-path)
        if omit_paths:
            filtered_subdirs = []
            filtered_entries = []
            omitted_paths_count = 0

            # Normalize omit_paths by stripping trailing slashes for consistent matching
            normalized_omit_paths = [p.rstrip("/") for p in omit_paths]

            # Filter subdirectories
            for subdir_path in subdirs:
                normalized_subdir = subdir_path.rstrip("/")
                if normalized_subdir in normalized_omit_paths:
                    omitted_paths_count += 1
                else:
                    filtered_subdirs.append(subdir_path)

            subdirs = filtered_subdirs

            # Report omitted paths to progress tracker
            if progress and omitted_paths_count > 0:
                await progress.increment_skipped(0, omitted_paths_count)

            # Also filter matching_entries to remove paths that match
            for entry in matching_entries:
                entry_path = entry.get('path', '')
                normalized_entry_path = entry_path.rstrip("/")

                # Check if this path should be omitted
                if normalized_entry_path not in normalized_omit_paths:
                    filtered_entries.append(entry)

            matching_entries = filtered_entries

        # Output matches immediately if callback provided
        # NOTE: Entries are already output during enumeration in enumerate_directory_adaptive
        # This section is kept for backwards compatibility but should not output duplicates
        # since output_callback is now called during enumeration

        # Update progress tracker for batch mode
        # In streaming mode, progress is already updated per-page inside enumerate_directory_adaptive
        # In batch mode, we update once with the total for this directory
        # We determine the mode by checking if total_entries >= 50000 (streaming threshold)
        try:
            total_files = int(aggregates.get("total_files", 0))
            total_dirs = int(aggregates.get("total_directories", 0))
            total_entries = total_files + total_dirs
            used_streaming = total_entries >= 50000 and (collect_results or output_callback is not None)
        except (ValueError, TypeError):
            used_streaming = False

        if progress and not used_streaming:
            # Batch mode: update progress once for this directory
            # Count ACTUAL entries processed (not recursive aggregates)
            await progress.update(total_processed, 1, match_count)

        # Recursively process subdirectories concurrently
        if subdirs and (
            max_depth is None or max_depth < 0 or _current_depth + 1 < max_depth
        ):
            # PHASE 3.2: Adaptive concurrency - process subdirectories in batches
            # Calculate batch size based on number of subdirectories
            num_subdirs = len(subdirs)
            batch_size = self.calculate_adaptive_concurrency(num_subdirs)

            # If limit is set, use smaller batch size for more responsive early exit
            if progress and progress.limit:
                batch_size = min(batch_size, 10)

            if verbose and batch_size < self.max_concurrent and num_subdirs > 0:
                print(
                    f"\r[INFO] Adaptive concurrency: Processing {num_subdirs} subdirs with batch size {batch_size} "
                    f"(reduced from {self.max_concurrent})",
                    file=sys.stderr,
                )

            # Process subdirectories in batches
            all_results = []

            # Track progress for large subdirectory sets
            show_batch_progress = progress and num_subdirs > 10000
            last_progress_time = time.time()
            batch_progress_interval = 10.0  # Show progress every 10 seconds

            for i in range(0, len(subdirs), batch_size):
                # Early exit: Check if limit reached before processing next batch
                if progress and progress.should_stop():
                    if verbose:
                        print(
                            f"\r[INFO] Early exit: Limit reached, skipping remaining {len(subdirs) - i} subdirectories",
                            file=sys.stderr,
                        )
                    break

                batch = subdirs[i : i + batch_size]
                tasks = [
                    self.walk_tree_async(
                        session,
                        subdir,
                        max_depth,
                        _current_depth + 1,
                        progress,
                        file_filter,
                        owner_stats,
                        omit_subdirs,
                        omit_paths,
                        collect_results,
                        verbose,
                        max_entries_per_dir,
                        time_filter_info,
                        size_filter_info,
                        owner_filter_info,
                        output_callback,
                    )
                    for subdir in batch
                ]

                # Process this batch concurrently
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                all_results.extend(batch_results)

                # Show batch progress for large directories
                if show_batch_progress:
                    current_time = time.time()
                    elapsed_since_last = current_time - last_progress_time
                    batch_num = (i // batch_size) + 1
                    total_batches = (num_subdirs + batch_size - 1) // batch_size

                    # Show progress every 100 batches or every 10 seconds
                    if (
                        batch_num % 100 == 0
                        or elapsed_since_last >= batch_progress_interval
                        or batch_num == total_batches
                    ):
                        percent = (i + batch_size) / num_subdirs * 100
                        subdirs_processed = min(i + batch_size, num_subdirs)

                        # Shorten path for display
                        display_path = path if len(path) <= 50 else "..." + path[-47:]

                        elapsed_total = current_time - progress.start_time
                        time_str = format_time(elapsed_total)

                        print(
                            f"\r[PROGRESS] Scanning subdirs in {display_path}: "
                            f"{subdirs_processed:,}/{num_subdirs:,} ({percent:.1f}%) | "
                            f"Run time: {time_str}",
                            end="",
                            file=sys.stderr,
                        )

                        last_progress_time = current_time

            # Clear the batch progress line if we showed it
            if show_batch_progress:
                print(file=sys.stderr)  # Newline to finish the progress line

            # Collect results from subdirectories (only if collect_results=True)
            if collect_results:
                # Optimize: At the top level, use efficient concatenation for large result sets
                # At deeper levels, use simple extend to avoid memory overhead
                if _current_depth == 0 and len(all_results) > 1000:
                    if verbose:
                        print(
                            f"\r[INFO] Collecting results from {len(all_results)} subdirectory batches...",
                            file=sys.stderr,
                        )

                    # Use itertools.chain for efficient concatenation
                    import itertools

                    result_lists = [
                        result for result in all_results if isinstance(result, list)
                    ]
                    if result_lists:
                        matching_entries.extend(
                            itertools.chain.from_iterable(result_lists)
                        )

                    if verbose:
                        print(
                            f"\r[INFO] Collection complete, {len(matching_entries)} total matches          ",
                            file=sys.stderr,
                        )
                else:
                    # For smaller result sets or nested levels, simple extend is fine
                    for result in all_results:
                        if isinstance(result, list):
                            matching_entries.extend(result)

        return matching_entries

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

        # Recurse to subdirectories if depth permits
        if current_depth < max_depth:
            # Enumerate immediate children only (just to get directory names)
            try:
                entries = await self.enumerate_directory(session, path)
                subdirs = [
                    e for e in entries if e.get("type") == "FS_FILE_TYPE_DIRECTORY"
                ]

                for subdir in subdirs:
                    subdir_path = subdir["path"]
                    await self.show_directory_stats(
                        session, subdir_path, max_depth, current_depth + 1
                    )
            except Exception as e:
                if self.verbose:
                    print(
                        f"{indent}  [ERROR] Failed to enumerate subdirectories: {e}",
                        file=sys.stderr,
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
