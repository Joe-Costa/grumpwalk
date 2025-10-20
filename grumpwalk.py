#!/usr/bin/env python3

"""
Qumulo File Filter and API Tree Walk Tool

Usage:
    ./grumpwalk.py --host <cluster> --path <path> [OPTIONS]

"""

import argparse
import asyncio
import copy
import fnmatch
import json
import os
import re
import ssl
import sys
import time
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple
from urllib.parse import quote
from datetime import datetime, timedelta, timezone

# Import modular components
from modules import (
    format_http_error,
    extract_pagination_token,
    parse_size_to_bytes,
    format_bytes,
    format_time,
    format_owner_name,
    ProgressTracker,
    BatchedOutputHandler,
    Profiler,
    CREDENTIALS_FILENAME,
    CREDENTIALS_VERSION,
    IDENTITY_CACHE_FILE,
    IDENTITY_CACHE_TTL,
    credential_store_filename,
    get_credentials,
    load_identity_cache,
    save_identity_cache,
    OwnerStats,
)

try:
    import aiohttp
except ImportError:
    print(
        "[ERROR] aiohttp not installed. Install with: pip install aiohttp",
        file=sys.stderr,
    )
    sys.exit(1)

# Try to use ujson for faster parsing
try:
    import ujson as json_parser

    JSON_PARSER_NAME = "ujson"
except ImportError:
    import json as json_parser

    JSON_PARSER_NAME = "json"

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

    def create_session(self) -> aiohttp.ClientSession:
        """Create optimized ClientSession with connection pooling."""
        connector = aiohttp.TCPConnector(
            limit=self.connector_limit,
            limit_per_host=self.connector_limit,
            ttl_dns_cache=300,
            ssl=self.ssl_context,
        )
        return aiohttp.ClientSession(connector=connector, headers=self.headers)

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
        self, session: aiohttp.ClientSession, path: str, callback
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

        Returns:
            Total number of entries processed
        """
        total_entries = 0
        after_token = None

        while True:
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
        use_streaming = total_entries >= 50000 and collect_results

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
                    if file_filter:
                        if file_filter(entry):
                            match_count += 1
                            page_matches += 1
                            if collect_results:
                                matching_entries.append(entry)
                    else:
                        match_count += 1
                        page_matches += 1
                        if collect_results:
                            matching_entries.append(entry)

                # Update progress after each page in streaming mode
                if progress:
                    await progress.update(page_size, 0, page_matches)

            # Stream directory entries
            await self.enumerate_directory_streaming(session, path, process_page)
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
                if file_filter:
                    if file_filter(entry):
                        match_count += 1
                        if collect_results:
                            matching_entries.append(entry)
                else:
                    match_count += 1
                    if collect_results:
                        matching_entries.append(entry)

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
        if output_callback and matching_entries:
            for entry in matching_entries:
                await output_callback(entry)

        # Update progress tracker for batch mode
        # In streaming mode, progress is already updated per-page inside enumerate_directory_adaptive
        # In batch mode, we update once with the total for this directory
        # We determine the mode by checking if total_entries >= 50000 (streaming threshold)
        try:
            total_files = int(aggregates.get("total_files", 0))
            total_dirs = int(aggregates.get("total_directories", 0))
            total_entries = total_files + total_dirs
            used_streaming = total_entries >= 50000 and collect_results
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


# ============================================================================
# ACL Conversion Functions (QACL to NFSv4-style shorthand)
# ============================================================================


def qacl_flags_to_nfsv4(flags: List[str]) -> str:
    """
    Convert Qumulo ACE flags to NFSv4-style flag string.

    Args:
        flags: List of Qumulo flags (e.g., ['OBJECT_INHERIT', 'CONTAINER_INHERIT', 'INHERITED'])

    Returns:
        NFSv4 flags string (e.g., 'fdI')
    """
    mapping = {
        'OBJECT_INHERIT': 'f',
        'CONTAINER_INHERIT': 'd',
        'NO_PROPAGATE_INHERIT': 'n',
        'INHERIT_ONLY': 'i',
        'INHERITED': 'I'
    }

    nfsv4_flags = []
    for flag in flags:
        if flag in mapping:
            nfsv4_flags.append(mapping[flag])

    return ''.join(nfsv4_flags)


def qacl_rights_to_nfsv4(rights: List[str], is_directory: bool = False) -> str:
    """
    Convert Qumulo QACL rights to NFSv4 permission string.

    Args:
        rights: List of Qumulo rights (e.g., ['READ', 'WRITE_ATTR', 'EXECUTE'])
        is_directory: Whether the file is a directory (affects DELETE_CHILD)

    Returns:
        NFSv4 permission string (e.g., 'rxtncy')
    """
    mapping = {
        'READ': 'r',
        'MODIFY': 'w',
        'EXTEND': 'a',
        'EXECUTE': 'x',
        'DELETE': 'd',
        'DELETE_CHILD': 'D',  # Only valid for directories
        'READ_ATTR': 't',
        'WRITE_ATTR': 'T',
        'READ_EA': 'n',
        'WRITE_EA': 'N',
        'READ_ACL': 'c',
        'WRITE_ACL': 'C',
        'CHANGE_OWNER': 'o',
        'SYNCHRONIZE': 'y'
    }

    perms = []
    for right in rights:
        if right in mapping:
            # Skip DELETE_CHILD if not a directory
            if right == 'DELETE_CHILD' and not is_directory:
                continue
            perms.append(mapping[right])

    # Return in canonical order: rwaxdDtTnNcCoy
    canonical_order = 'rwaxdDtTnNcCoy'
    return ''.join(p for p in canonical_order if p in perms)


def qacl_trustee_to_nfsv4(trustee: Dict, trustee_details: Optional[Dict] = None) -> str:
    """
    Convert Qumulo trustee to NFSv4-style principal format.

    Args:
        trustee: Qumulo trustee dict or auth_id string
        trustee_details: Optional trustee_details dict with id_type and id_value

    Returns:
        NFSv4 principal string (e.g., 'EVERYONE@', 'uid:1001', 'alice@corp.com')
    """
    # Handle legacy format (dict with domain, uid, gid, etc.)
    if isinstance(trustee, dict):
        domain = trustee.get('domain')
        uid = trustee.get('uid')
        gid = trustee.get('gid')
        name = trustee.get('name')

        if domain == 'WORLD':
            return 'EVERYONE@'
        elif domain == 'POSIX_USER':
            return f'uid:{uid}' if uid is not None else 'OWNER@'
        elif domain == 'POSIX_GROUP':
            return f'gid:{gid}' if gid is not None else 'GROUP@'
        elif domain == 'LOCAL_USER':
            return f'user:{name}' if name else f'uid:{uid}'
        elif domain == 'LOCAL_GROUP':
            return f'group:{name}' if name else f'gid:{gid}'
        elif domain in ('AD_USER', 'AD_GROUP'):
            return name if name else f'sid:{trustee.get("sid")}'
        else:
            return f'unknown:{trustee.get("auth_id")}'

    # Handle current API format (trustee is auth_id string, details in trustee_details)
    if trustee_details:
        id_type = trustee_details.get('id_type')
        id_value = trustee_details.get('id_value')

        if id_type == 'NFS_UID':
            return f'uid:{id_value}'
        elif id_type == 'NFS_GID':
            return f'gid:{id_value}'
        elif id_type == 'SMB_SID':
            # Check for well-known SIDs
            if id_value == 'S-1-1-0':
                return 'EVERYONE@'
            return f'sid:{id_value}'
        elif id_type == 'LOCAL_USER':
            return f'user:{id_value}'
        elif id_type == 'LOCAL_GROUP':
            return f'group:{id_value}'

    # Fallback: use auth_id
    return f'auth_id:{trustee}'


def extract_auth_ids_from_acl(qacl_data: Dict) -> set:
    """
    Extract all unique auth_ids from an ACL for identity resolution.

    Args:
        qacl_data: Full QACL dict

    Returns:
        Set of auth_id strings found in the ACL
    """
    auth_ids = set()

    if not qacl_data:
        return auth_ids

    # Handle nested structure
    if 'acl' in qacl_data and 'aces' not in qacl_data:
        qacl_data = qacl_data['acl']

    for ace in qacl_data.get('aces', []):
        trustee = ace.get('trustee')

        # Current API format: trustee is auth_id string
        if isinstance(trustee, str):
            auth_ids.add(trustee)
        # Legacy format: trustee is dict with auth_id
        elif isinstance(trustee, dict) and 'auth_id' in trustee:
            auth_ids.add(trustee['auth_id'])

    return auth_ids


def qacl_trustee_to_readable_name(trustee: Dict, trustee_details: Optional[Dict], identity_cache: Dict) -> str:
    """
    Convert Qumulo trustee to human-readable name using identity cache.
    Falls back to technical format if name not available.

    Args:
        trustee: Trustee value (auth_id string or dict)
        trustee_details: Trustee details dict
        identity_cache: Dictionary mapping auth_id to resolved identity info

    Returns:
        Human-readable trustee name or fallback technical format
    """
    # Get auth_id
    auth_id = None
    if isinstance(trustee, str):
        auth_id = trustee
    elif isinstance(trustee, dict):
        auth_id = trustee.get('auth_id')

    # Try to resolve from cache
    if auth_id and auth_id in identity_cache:
        identity = identity_cache[auth_id]
        name = identity.get('name', '')
        domain = identity.get('domain', '')

        # Format based on domain
        if domain == 'WORLD':
            return 'EVERYONE@'
        elif domain == 'POSIX_USER':
            uid = identity.get('uid')
            if name and not name.startswith('Unknown'):
                return f'{name} (UID {uid})' if uid else name
            return f'UID {uid}' if uid else 'OWNER@'
        elif domain == 'POSIX_GROUP':
            gid = identity.get('gid')
            if name and not name.startswith('Unknown'):
                return f'{name} (GID {gid})' if gid else name
            return f'GID {gid}' if gid else 'GROUP@'
        elif domain in ('ACTIVE_DIRECTORY', 'AD_USER', 'AD_GROUP'):
            return name if name else f'SID {identity.get("sid", auth_id)}'
        elif domain in ('LOCAL', 'LOCAL_USER', 'LOCAL_GROUP'):
            return name if name else f'Local {auth_id}'
        elif name:
            return name

    # Fallback to technical format
    return qacl_trustee_to_nfsv4(trustee, trustee_details)


def qacl_ace_to_readable(ace: Dict, is_directory: bool = False) -> str:
    """
    Convert a single Qumulo ACE to human-readable NFSv4-style format.

    Args:
        ace: Qumulo ACE dict with type, flags, trustee, rights
        is_directory: Whether this ACE is for a directory

    Returns:
        Readable ACE string in format: Allow/Deny:flags:principal:permissions
        Example: "Allow:fdI:uid:1001:rwxt"
    """
    # Convert type to human-readable form
    ace_type = 'Allow' if ace.get('type') == 'ALLOWED' else 'Deny'

    # Convert flags
    flags_str = qacl_flags_to_nfsv4(ace.get('flags', []))

    # Get trustee and trustee_details
    trustee = ace.get('trustee', {})
    trustee_details = ace.get('trustee_details')

    # Convert trustee to principal
    principal = qacl_trustee_to_nfsv4(trustee, trustee_details)

    # Add 'g' flag if trustee is a group (unless it's GROUP@)
    if trustee_details:
        id_type = trustee_details.get('id_type')
        if id_type in ('NFS_GID', 'LOCAL_GROUP', 'AD_GROUP'):
            if principal not in ('GROUP@',):
                flags_str = 'g' + flags_str
    elif isinstance(trustee, dict):
        domain = trustee.get('domain')
        if domain in ('POSIX_GROUP', 'LOCAL_GROUP', 'AD_GROUP'):
            if principal not in ('GROUP@',):
                flags_str = 'g' + flags_str

    # Convert rights
    permissions = qacl_rights_to_nfsv4(ace.get('rights', []), is_directory)

    return f'{ace_type}:{flags_str}:{principal}:{permissions}'


def qacl_to_readable_acl(qacl_data: Dict, is_directory: bool = False,
                         separator: str = '|') -> str:
    """
    Convert full Qumulo QACL to readable ACL string.

    Args:
        qacl_data: Full QACL dict - may have 'aces' directly or nested under 'acl'
        is_directory: Whether this is a directory ACL
        separator: Character to separate multiple ACEs (default: '|' for CSV)

    Returns:
        Separated ACL string suitable for CSV
        Example: "Allow:fdI:uid:1001:rwxt|Allow:fdI:GROUP@:rxt|Allow::OWNER@:rwatTnNcy"
    """
    if not qacl_data:
        return ''

    # Handle nested structure (get_file_acl returns {generated: bool, acl: {...}})
    if 'acl' in qacl_data and 'aces' not in qacl_data:
        qacl_data = qacl_data['acl']

    if 'aces' not in qacl_data:
        return ''

    readable_aces = []
    for ace in qacl_data.get('aces', []):
        readable_ace = qacl_ace_to_readable(ace, is_directory)
        readable_aces.append(readable_ace)

    return separator.join(readable_aces)


def qacl_to_readable_acl_with_names(qacl_data: Dict, is_directory: bool = False,
                                    separator: str = '|', identity_cache: Dict = None) -> str:
    """
    Convert full Qumulo QACL to readable ACL string with resolved names.

    Args:
        qacl_data: Full QACL dict - may have 'aces' directly or nested under 'acl'
        is_directory: Whether this is a directory ACL
        separator: Character to separate multiple ACEs (default: '|' for CSV)
        identity_cache: Dictionary mapping auth_id to resolved identity info

    Returns:
        Separated ACL string with human-readable names
        Example: "Allow:fdI:jsmith (UID 1001):rwxt|Allow:fdI:Domain Users:rxt"
    """
    if not qacl_data:
        return ''

    # Handle nested structure
    if 'acl' in qacl_data and 'aces' not in qacl_data:
        qacl_data = qacl_data['acl']

    if 'aces' not in qacl_data:
        return ''

    if not identity_cache:
        identity_cache = {}

    readable_aces = []
    for ace in qacl_data.get('aces', []):
        # Convert type
        ace_type = 'Allow' if ace.get('type') == 'ALLOWED' else 'Deny'

        # Convert flags
        flags_str = qacl_flags_to_nfsv4(ace.get('flags', []))

        # Get trustee and details
        trustee = ace.get('trustee', {})
        trustee_details = ace.get('trustee_details')

        # Resolve trustee name
        principal = qacl_trustee_to_readable_name(trustee, trustee_details, identity_cache)

        # Add 'g' flag for groups
        if trustee_details:
            id_type = trustee_details.get('id_type')
            if id_type in ('NFS_GID', 'LOCAL_GROUP', 'AD_GROUP'):
                if principal not in ('GROUP@',) and not principal.endswith(')'):  # Don't add 'g' if already formatted with GID
                    flags_str = 'g' + flags_str
        elif isinstance(trustee, dict):
            domain = trustee.get('domain')
            if domain in ('POSIX_GROUP', 'LOCAL_GROUP', 'AD_GROUP'):
                if principal not in ('GROUP@',):
                    flags_str = 'g' + flags_str

        # Convert rights
        permissions = qacl_rights_to_nfsv4(ace.get('rights', []), is_directory)

        readable_aces.append(f'{ace_type}:{flags_str}:{principal}:{permissions}')

    return separator.join(readable_aces)


def create_acl_fingerprint(qacl_data: Dict) -> str:
    """
    Create a unique fingerprint/hash for an ACL based on its content.
    Used for grouping files with identical ACLs.

    Args:
        qacl_data: Full QACL dict

    Returns:
        SHA-256 hash (first 16 chars) of the ACL structure
    """
    import hashlib
    import json

    if not qacl_data:
        return 'empty'

    # Handle nested structure
    if 'acl' in qacl_data and 'aces' not in qacl_data:
        qacl_data = qacl_data['acl']

    # Extract and normalize ACL components for hashing
    acl_to_hash = {
        'aces': [],
        'control': sorted(qacl_data.get('control', [])),
        'posix_special_permissions': sorted(qacl_data.get('posix_special_permissions', []))
    }

    # Normalize each ACE for consistent hashing
    for ace in qacl_data.get('aces', []):
        trustee = ace.get('trustee')
        trustee_details = ace.get('trustee_details', {})

        # Create normalized trustee representation
        if isinstance(trustee, dict):
            trustee_key = f"{trustee.get('domain')}:{trustee.get('uid')}:{trustee.get('gid')}:{trustee.get('sid')}"
        else:
            # Use trustee_details for current API format
            trustee_key = f"{trustee_details.get('id_type')}:{trustee_details.get('id_value')}"

        normalized_ace = {
            'type': ace.get('type'),
            'flags': sorted(ace.get('flags', [])),
            'trustee': trustee_key,
            'rights': sorted(ace.get('rights', []))
        }
        acl_to_hash['aces'].append(normalized_ace)

    # Create deterministic JSON and hash it
    acl_json = json.dumps(acl_to_hash, sort_keys=True)
    hash_digest = hashlib.sha256(acl_json.encode()).hexdigest()

    # Return first 16 characters for readability
    return hash_digest[:16]


def analyze_acl_structure(qacl_data: Dict) -> Dict:
    """
    Analyze ACL structure and extract useful metadata.

    Args:
        qacl_data: Full QACL dict

    Returns:
        Dict with analysis results:
        {
            'ace_count': int,
            'inherited_count': int,
            'explicit_count': int,
            'has_deny': bool,
            'has_everyone': bool,
            'trustees': list of principal strings,
            'fingerprint': str
        }
    """
    if not qacl_data:
        return {
            'ace_count': 0,
            'inherited_count': 0,
            'explicit_count': 0,
            'has_deny': False,
            'has_everyone': False,
            'trustees': [],
            'fingerprint': 'empty'
        }

    # Handle nested structure
    if 'acl' in qacl_data and 'aces' not in qacl_data:
        qacl_data = qacl_data['acl']

    aces = qacl_data.get('aces', [])

    ace_count = len(aces)
    inherited_count = 0
    explicit_count = 0
    has_deny = False
    has_everyone = False
    trustees = set()

    for ace in aces:
        # Check for DENY entries
        if ace.get('type') == 'DENIED':
            has_deny = True

        # Check for inherited ACEs
        if 'INHERITED' in ace.get('flags', []):
            inherited_count += 1
        else:
            explicit_count += 1

        # Extract trustee
        trustee = ace.get('trustee')
        trustee_details = ace.get('trustee_details')
        principal = qacl_trustee_to_nfsv4(trustee, trustee_details)
        trustees.add(principal)

        # Check for EVERYONE
        if principal == 'EVERYONE@':
            has_everyone = True

    return {
        'ace_count': ace_count,
        'inherited_count': inherited_count,
        'explicit_count': explicit_count,
        'has_deny': has_deny,
        'has_everyone': has_everyone,
        'trustees': sorted(list(trustees)),
        'fingerprint': create_acl_fingerprint(qacl_data)
    }


async def get_file_type(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    path: str
) -> Optional[str]:
    """
    Get the type of a file system object.

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp session
        path: Path to check

    Returns:
        'FS_FILE_TYPE_FILE', 'FS_FILE_TYPE_DIRECTORY', 'FS_FILE_TYPE_SYMLINK',
        or None if unable to determine
    """
    try:
        # Handle root directory special case
        if path == '/':
            return 'FS_FILE_TYPE_DIRECTORY'

        # Get parent directory and basename
        parent = os.path.dirname(path) or '/'
        name = os.path.basename(path)

        # List parent directory to get entry metadata
        entries = await client.enumerate_directory(session, parent, max_entries=1000)
        entry = next((e for e in entries if e['name'] == name), None)

        return entry.get('type') if entry else None
    except Exception as e:
        if client.verbose:
            print(f"[WARN] Could not determine type for {path}: {e}", file=sys.stderr)
        return None


async def check_acl_type_compatibility(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    source_path: str,
    target_path: str,
    propagate: bool
) -> bool:
    """
    Check ACL source/target type compatibility and warn user if needed.

    Warns when applying a file ACL to directories, as file ACLs may not have
    appropriate directory-specific permissions and inheritance settings.

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp session
        source_path: Path to ACL source
        target_path: Path to ACL target
        propagate: Whether ACL will be propagated to children

    Returns:
        True to proceed, False to abort
    """
    source_type = await get_file_type(client, session, source_path)
    target_type = await get_file_type(client, session, target_path)

    # Only warn if source is a file
    if source_type != 'FS_FILE_TYPE_FILE':
        return True

    # Warn if target is directory or propagating (might hit directories)
    should_warn = (
        target_type == 'FS_FILE_TYPE_DIRECTORY' or
        propagate
    )

    if not should_warn:
        return True

    # Display warning
    print("\n" + "=" * 70, file=sys.stderr)
    print("WARNING: Source ACL Type Mismatch", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"Source: {source_path} (FILE)", file=sys.stderr)

    if target_type == 'FS_FILE_TYPE_DIRECTORY':
        print(f"Target: {target_path} (DIRECTORY)", file=sys.stderr)
    else:
        print(f"Target: {target_path}", file=sys.stderr)

    print("\nFile ACLs may not be appropriate for directories because:", file=sys.stderr)
    print("  - Directories have different permission semantics", file=sys.stderr)
    print("  - Directory-specific rights (traverse, list, add files) may be missing", file=sys.stderr)
    print("  - Inheritance flags may not be configured correctly", file=sys.stderr)

    if propagate:
        print("\n[!] --propagate-acls is enabled. This will apply the file ACL to", file=sys.stderr)
        print("    all child objects including subdirectories.", file=sys.stderr)

    print("\n" + "=" * 70, file=sys.stderr)

    # Prompt user
    while True:
        response = input("Proceed? (Yes/No): ").strip().lower()
        if response in ['yes', 'y']:
            print("[INFO] Proceeding with ACL application...\n", file=sys.stderr)
            return True
        elif response in ['no', 'n']:
            print("[INFO] Operation cancelled by user.", file=sys.stderr)
            return False
        else:
            print("Please enter 'Yes' or 'No'.", file=sys.stderr)


def format_time_estimate(seconds: float) -> str:
    """Format seconds into human-readable time estimate."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"


async def apply_acl_to_tree(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    acl_data: dict,
    target_path: str,
    propagate: bool = False,
    file_filter = None,
    progress: bool = False,
    continue_on_error: bool = False,
    args = None,
    owner_group_data: Optional[dict] = None,
    copy_owner: bool = False,
    copy_group: bool = False,
    owner_group_only: bool = False
) -> dict:
    """
    Apply ACL and/or owner/group to target path, optionally propagating to filtered children.

    Applies to:
    1. Target path itself (no INHERITED flag modification for ACL)
    2. If propagate=True, all matching children (with INHERITED flag added to ACL)

    Children are filtered using the standard file_filter (Universal Filters).

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp session
        acl_data: Source ACL data (full structure with 'acl' nested)
        target_path: Target path to apply ACL
        propagate: If True, apply to all matching descendants
        file_filter: Filter function for matching objects
        progress: Show progress output
        continue_on_error: Continue on 401 errors after initial success
        args: Command line arguments for filter parameters
        owner_group_data: Owner/group data from source (optional)
        copy_owner: Copy owner from source
        copy_group: Copy group from source
        owner_group_only: Apply only owner/group, not ACL

    Returns:
        Statistics dict:
        {
            'objects_changed': int,
            'objects_failed': int,
            'objects_skipped': int,  # Didn't match filters
            'total_objects_processed': int,
            'errors': list[dict]  # [{path, error_code, message}]
        }
    """
    stats = {
        'objects_changed': 0,
        'objects_failed': 0,
        'objects_skipped': 0,
        'total_objects_processed': 0,
        'errors': []
    }

    start_time = time.time()

    # Step 1: Apply to target path
    if progress:
        if owner_group_only:
            print(f"[OWNER/GROUP] Applying owner/group to target: {target_path}", file=sys.stderr)
        elif copy_owner or copy_group:
            print(f"[ACL+OWNER/GROUP] Applying ACL and owner/group to target: {target_path}", file=sys.stderr)
        else:
            print(f"[ACL CLONE] Applying ACL to target: {target_path}", file=sys.stderr)

    # Apply ACL if not owner_group_only
    if not owner_group_only:
        success, error_msg = await client.set_file_acl(
            session, target_path, acl_data, mark_inherited=False
        )

        if not success:
            print(f"\n[ERROR] Failed to apply ACL to target path: {target_path}", file=sys.stderr)
            print(f"[ERROR] {error_msg}", file=sys.stderr)
            stats['objects_failed'] = 1
            stats['errors'].append({
                'path': target_path,
                'error_code': 'INITIAL_FAILURE',
                'message': error_msg
            })
            return stats

    # Apply owner/group if requested
    if (copy_owner or copy_group) and owner_group_data:
        owner_to_set = owner_group_data.get('owner') if copy_owner else None
        group_to_set = owner_group_data.get('group') if copy_group else None

        success, error_msg = await client.set_file_owner_group(
            session, target_path, owner=owner_to_set, group=group_to_set
        )

        if not success:
            print(f"\n[ERROR] Failed to apply owner/group to target path: {target_path}", file=sys.stderr)
            print(f"[ERROR] {error_msg}", file=sys.stderr)
            stats['objects_failed'] = 1
            stats['errors'].append({
                'path': target_path,
                'error_code': 'OWNER_GROUP_FAILURE',
                'message': error_msg
            })
            return stats

    stats['objects_changed'] = 1
    stats['total_objects_processed'] = 1

    # Step 2: Propagate to children if requested
    if not propagate:
        return stats

    # Walk the tree to get all objects
    if progress:
        print(f"[ACL CLONE] Scanning tree for child objects...", file=sys.stderr)

    matching_files = await client.walk_tree_async(
        session=session,
        path=target_path,
        max_depth=args.max_depth if args else None,
        progress=None,  # We'll handle progress ourselves
        file_filter=file_filter,
        collect_results=True
    )

    # Remove target path from list (already applied)
    matching_files = [f for f in matching_files if f['path'] != target_path]

    # Apply limit if specified
    if args and args.limit and len(matching_files) > args.limit:
        matching_files = matching_files[:args.limit]
        if progress:
            print(f"[ACL CLONE] Limiting to {args.limit:,} objects", file=sys.stderr)

    total_to_process = len(matching_files)
    processed = 0

    if progress:
        print(f"[ACL CLONE] Found {total_to_process:,} child objects to process", file=sys.stderr)

    # Batch size for parallel ACL application
    batch_size = 100

    # Helper async function to apply both ACL and owner/group to a single file
    async def apply_to_single_file(path: str):
        """Apply ACL and/or owner/group to a single file"""
        acl_success = True
        og_success = True
        error_msg = None

        # Apply ACL if not owner_group_only
        if not owner_group_only:
            acl_success, acl_error = await client.set_file_acl(
                session, path, acl_data, mark_inherited=True
            )
            if not acl_success:
                error_msg = acl_error

        # Apply owner/group if requested
        if (copy_owner or copy_group) and owner_group_data:
            owner_to_set = owner_group_data.get('owner') if copy_owner else None
            group_to_set = owner_group_data.get('group') if copy_group else None

            og_success, og_error = await client.set_file_owner_group(
                session, path, owner=owner_to_set, group=group_to_set
            )
            if not og_success:
                error_msg = og_error if not error_msg else f"{error_msg}; {og_error}"

        # Return combined result
        return (acl_success and og_success, error_msg)

    # Process files in batches for parallel application
    for i in range(0, total_to_process, batch_size):
        batch = matching_files[i:i + batch_size]

        # Create tasks for parallel execution
        tasks = []
        paths = []
        for entry in batch:
            path = entry['path']
            paths.append(path)
            task = apply_to_single_file(path)
            tasks.append(task)

        # Execute all tasks in this batch concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results from this batch
        for path, result in zip(paths, results):
            processed += 1
            stats['total_objects_processed'] += 1

            if isinstance(result, Exception):
                # Task raised an exception
                stats['objects_failed'] += 1
                error_msg = str(result)
                stats['errors'].append({
                    'path': path,
                    'error_code': 'EXCEPTION',
                    'message': error_msg
                })

                # Handle errors based on settings
                is_401 = '401' in error_msg or 'Unauthorized' in error_msg.lower()

                if is_401 and continue_on_error:
                    # Log and continue
                    if progress:
                        print(f"\n[WARN] 401 error on {path}, continuing...", file=sys.stderr)
                else:
                    # Pause and prompt
                    print(f"\n[ERROR] Failed to apply ACL to: {path}", file=sys.stderr)
                    print(f"[ERROR] {error_msg}", file=sys.stderr)

                    while True:
                        response = input("Continue? [C]ontinue / [A]bort: ").strip().lower()
                        if response in ['c', 'continue']:
                            break
                        elif response in ['a', 'abort']:
                            print("[INFO] Operation aborted by user.", file=sys.stderr)
                            return stats
                        print("Invalid response. Please enter 'c' or 'a'.")

            elif isinstance(result, tuple):
                # Normal return: (success: bool, error_msg: Optional[str])
                success, error_msg = result

                if success:
                    stats['objects_changed'] += 1
                else:
                    stats['objects_failed'] += 1
                    stats['errors'].append({
                        'path': path,
                        'error_code': 'APPLY_FAILURE',
                        'message': error_msg
                    })

                    # Handle errors based on settings
                    is_401 = '401' in error_msg or 'Unauthorized' in error_msg.lower()

                    if is_401 and continue_on_error:
                        # Log and continue
                        if progress:
                            print(f"\n[WARN] 401 error on {path}, continuing...", file=sys.stderr)
                    else:
                        # Pause and prompt
                        print(f"\n[ERROR] Failed to apply ACL to: {path}", file=sys.stderr)
                        print(f"[ERROR] {error_msg}", file=sys.stderr)

                        while True:
                            response = input("Continue? [C]ontinue / [A]bort: ").strip().lower()
                            if response in ['c', 'continue']:
                                break
                            elif response in ['a', 'abort']:
                                print("[INFO] Operation aborted by user.", file=sys.stderr)
                                return stats
                            print("Invalid response. Please enter 'c' or 'a'.")

        # Progress reporting after each batch
        if progress:
            elapsed = time.time() - start_time
            rate = processed / elapsed if elapsed > 0 else 0
            remaining = total_to_process - processed
            eta_seconds = remaining / rate if rate > 0 else 0
            eta_str = format_time_estimate(eta_seconds)

            print(
                f"\r[ACL CLONE] Changed: {stats['objects_changed']:,} | "
                f"Failed: {stats['objects_failed']:,} | "
                f"Remaining: {remaining:,} | "
                f"Est: {eta_str}",
                end='',
                file=sys.stderr
            )
            sys.stderr.flush()

    if progress:
        print()  # New line after progress

    return stats


async def generate_acl_report(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    files: List[Dict],
    show_progress: bool = False,
    resolve_names: bool = False,
    show_owner: bool = False,
    show_group: bool = False
) -> Dict:
    """
    Generate ACL report for a list of files.

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp session
        files: List of file dicts (with 'path' and 'type' keys)
        show_progress: Whether to show progress updates
        resolve_names: Whether to resolve auth_ids to human-readable names
        show_owner: Whether to resolve and display owner information
        show_group: Whether to resolve and display group information

    Returns:
        Dictionary containing:
        - file_acls: Dict mapping file path to ACL info
        - stats: Summary statistics
        - identity_cache: Dict mapping auth_id to resolved identity (if resolve_names=True or show_owner/show_group=True)
    """
    import sys
    import time

    file_acls = {}
    total_files = len(files)
    processed = 0
    start_time = time.time()

    # Batch size for ACL retrieval - increased for better throughput
    batch_size = 100

    for i in range(0, total_files, batch_size):
        batch = files[i:i + batch_size]

        # Fetch ACLs concurrently within batch
        tasks = []
        path_info = []
        for file_info in batch:
            path = file_info['path']
            is_directory = file_info.get('type') == 'FS_FILE_TYPE_DIRECTORY'
            owner = file_info.get('owner')
            owner_details = file_info.get('owner_details', {})
            group = file_info.get('group')
            group_details = file_info.get('group_details', {})
            task = client.get_file_acl(session, path)
            tasks.append(task)
            path_info.append((path, is_directory, owner, owner_details, group, group_details))

        # Wait for all tasks concurrently using gather
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for (path, is_directory, owner, owner_details, group, group_details), result in zip(path_info, results):
            if isinstance(result, Exception):
                # Task raised an exception
                if client.verbose:
                    print(f"[WARN] Error processing ACL for {path}: {result}", file=sys.stderr)
                file_acls[path] = {
                    'acl_data': None,
                    'is_directory': is_directory,
                    'owner': owner,
                    'owner_details': owner_details,
                    'group': group,
                    'group_details': group_details
                }
            elif result:
                # Successfully got ACL data
                file_acls[path] = {
                    'acl_data': result,
                    'is_directory': is_directory,
                    'owner': owner,
                    'owner_details': owner_details,
                    'group': group,
                    'group_details': group_details
                }
            else:
                # ACL retrieval returned None
                file_acls[path] = {
                    'acl_data': None,
                    'is_directory': is_directory,
                    'owner': owner,
                    'owner_details': owner_details,
                    'group': group,
                    'group_details': group_details
                }

            processed += 1

        # Progress update
        if show_progress and processed > 0:
            elapsed = time.time() - start_time
            rate = processed / elapsed if elapsed > 0 else 0
            remaining = total_files - processed

            # TTY-aware progress (use \r for overwrite on terminal)
            if sys.stderr.isatty():
                print(
                    f"\r[ACL REPORT] {processed:,} / {total_files:,} processed | "
                    f"{remaining:,} remaining | {rate:.1f} files/sec",
                    end='',
                    file=sys.stderr,
                    flush=True
                )
            else:
                # For non-TTY, print periodic updates
                if processed % 1000 == 0 or processed == total_files:
                    print(
                        f"[ACL REPORT] {processed:,} / {total_files:,} processed | "
                        f"{remaining:,} remaining | {rate:.1f} files/sec",
                        file=sys.stderr
                    )

    if show_progress:
        if sys.stderr.isatty():
            print(file=sys.stderr)  # New line after progress
        print(f"[ACL REPORT] Completed processing {total_files:,} files", file=sys.stderr)

    # Calculate statistics
    files_with_acls = sum(1 for info in file_acls.values() if info['acl_data'] is not None)

    stats = {
        'total_files': total_files,
        'files_with_acls': files_with_acls,
        'processing_time': time.time() - start_time
    }

    # Resolve names if requested (for ACLs, owners, or groups)
    identity_cache = {}
    if resolve_names or show_owner or show_group:
        # Collect all unique auth_ids
        all_auth_ids = set()

        # Collect from ACLs if resolve_names is enabled
        if resolve_names:
            for file_info in file_acls.values():
                acl_data = file_info.get('acl_data')
                if acl_data:
                    auth_ids = extract_auth_ids_from_acl(acl_data)
                    all_auth_ids.update(auth_ids)

        # Collect owner auth_ids if show_owner is enabled
        if show_owner:
            for file_info in file_acls.values():
                # Try to get auth_id from owner_details first, fallback to owner field
                owner_details = file_info.get('owner_details', {})
                owner_auth_id = owner_details.get('auth_id') or file_info.get('owner')
                if owner_auth_id:
                    all_auth_ids.add(owner_auth_id)

        # Collect group auth_ids if show_group is enabled
        if show_group:
            for file_info in file_acls.values():
                # Try to get auth_id from group_details first, fallback to group field
                group_details = file_info.get('group_details', {})
                group_auth_id = group_details.get('auth_id') or file_info.get('group')
                if group_auth_id:
                    all_auth_ids.add(group_auth_id)

        if all_auth_ids and show_progress:
            print(f"[ACL REPORT] Resolving {len(all_auth_ids)} unique identities...", file=sys.stderr)

        # Resolve identities using existing infrastructure
        if all_auth_ids:
            identity_cache = await client.resolve_multiple_identities(
                session,
                list(all_auth_ids),
                show_progress=show_progress
            )

    return {
        'file_acls': file_acls,
        'stats': stats,
        'identity_cache': identity_cache
    }


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
    if trustee.startswith("S-") and len(trustee.split("-")) >= 3:
        return {"payload": {"sid": trustee}, "type": "sid"}

    # Explicit type prefixes
    if trustee.startswith("auth_id:"):
        return {"payload": {"auth_id": trustee[8:]}, "type": "auth_id"}

    if trustee.startswith("uid:"):
        try:
            return {"payload": {"uid": int(trustee[4:])}, "type": "uid"}
        except ValueError:
            return {"payload": {"name": trustee}, "type": "name"}

    if trustee.startswith("gid:"):
        try:
            return {"payload": {"gid": int(trustee[4:])}, "type": "gid"}
        except ValueError:
            return {"payload": {"name": trustee}, "type": "name"}

    # Pure numeric - assume UID
    if trustee.isdigit():
        return {"payload": {"uid": int(trustee)}, "type": "uid"}

    # NetBIOS domain format (DOMAIN\username)
    if "\\" in trustee:
        # Need to escape the backslash for JSON
        domain, username = trustee.split("\\", 1)
        return {"payload": {"name": f"{domain}\\\\{username}"}, "type": "name"}

    # Email or LDAP DN format
    if "@" in trustee or trustee.startswith("CN="):
        return {"payload": {"name": trustee}, "type": "name"}

    # Domain prefix formats (ad:user, local:user)
    if ":" in trustee and not trustee.startswith("S-"):
        prefix, name = trustee.split(":", 1)
        prefix = prefix.lower()

        if prefix in ["ad", "active_directory"]:
            return {
                "payload": {"name": name, "domain": "ACTIVE_DIRECTORY"},
                "type": "name",
            }
        elif prefix == "local":
            return {"payload": {"name": name, "domain": "LOCAL"}, "type": "name"}
        else:
            # Unknown prefix, treat as name
            return {"payload": {"name": trustee}, "type": "name"}

    # Default to name lookup
    return {"payload": {"name": trustee}, "type": "name"}


def calculate_sample_points(
    file_size: int,
    sample_points: Optional[int] = None,
    sample_chunk_size: int = 65536
) -> List[int]:
    """
    Calculate adaptive sample points based on file size using stratified + random sampling.

    Uses a tiered approach:
    - Fixed points: start (0) and end
    - Stratified points: evenly distributed across file
    - Random points: deterministic pseudorandom offsets for better edge-case coverage

    This hybrid approach maximizes coverage and catches localized edits that purely
    evenly-spaced samples might miss.

    Args:
        file_size: Size of the file in bytes
        sample_points: Override number of sample points (3-11), or None for adaptive
        sample_chunk_size: Size of each sample chunk in bytes (default: 65536 / 64KB)

    Returns:
        List of byte offsets to sample from (non-overlapping, sorted)
    """
    import random

    SAMPLE_CHUNK_SIZE = sample_chunk_size

    # Special case: empty files
    if file_size == 0:
        return [0]  # Single sample at offset 0 (will read 0 bytes)

    # User override
    if sample_points is not None:
        num_points = max(3, min(11, sample_points))  # Clamp to 3-11
    else:
        # Adaptive based on file size
        if file_size < 1_000_000:  # < 1MB
            num_points = 3
        elif file_size < 100_000_000:  # < 100MB
            num_points = 5
        elif file_size < 1_000_000_000:  # < 1GB
            num_points = 7
        elif file_size < 10_000_000_000:  # < 10GB
            num_points = 9
        else:  # >= 10GB
            num_points = 11

    offsets = []

    def add_offset(pos):
        """Add offset if it doesn't overlap with existing offsets."""
        pos = max(0, min(max(0, file_size - SAMPLE_CHUNK_SIZE), pos))
        # Check for overlaps
        for existing in offsets:
            if not (pos + SAMPLE_CHUNK_SIZE <= existing or existing + SAMPLE_CHUNK_SIZE <= pos):
                return False
        offsets.append(pos)
        return True

    # Fixed points: start and end
    add_offset(0)
    if file_size >= SAMPLE_CHUNK_SIZE:
        add_offset(file_size - SAMPLE_CHUNK_SIZE)

    # Calculate how many stratified vs random points we need
    # Use 60% stratified, 40% random distribution
    remaining = num_points - len(offsets)
    num_stratified = max(1, int(remaining * 0.6))
    num_random = remaining - num_stratified

    # Stratified points: evenly distributed
    for i in range(1, num_stratified + 1):
        position = i / (num_stratified + 1)
        offset = int(position * file_size - SAMPLE_CHUNK_SIZE / 2)
        add_offset(offset)

    # Random points: deterministic based on file size
    # Use file_size as seed for reproducibility
    seed = file_size % (2**32)
    rng = random.Random(seed)

    tries = 0
    max_tries = 1000
    while len(offsets) < num_points and tries < max_tries:
        if file_size <= SAMPLE_CHUNK_SIZE:
            pos = 0
        else:
            pos = rng.randrange(0, file_size - SAMPLE_CHUNK_SIZE + 1)
        if add_offset(pos):
            continue
        tries += 1

    # Remove duplicates and sort
    return sorted(set(offsets))


async def compute_sample_hash(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    file_path: str,
    file_size: int,
    sample_points: Optional[int] = None,
    sample_chunk_size: int = 65536
) -> Optional[str]:
    """
    Compute a position-aware hash from multiple sample points in a file.

    Uses position-aware fingerprinting: includes offset and length metadata
    in the hash to prevent false positives when files have identical chunks
    at different positions.

    Format: hash(offset1 + length1 + data1 + offset2 + length2 + data2 + ...)

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp ClientSession
        file_path: Path to the file
        file_size: Size of the file in bytes
        sample_points: Optional override for number of sample points
        sample_chunk_size: Size of each sample chunk in bytes (default: 65536 / 64KB)

    Returns:
        SHA-256 hash of position-aware fingerprint, or None if failed
    """
    import hashlib
    import struct

    SAMPLE_CHUNK_SIZE = sample_chunk_size

    offsets = calculate_sample_points(file_size, sample_points, sample_chunk_size)

    # Read all sample points concurrently
    tasks = []
    for offset in offsets:
        task = client.read_file_chunk(session, file_path, offset, SAMPLE_CHUNK_SIZE)
        tasks.append(task)

    chunks = await asyncio.gather(*tasks)

    # Check if any reads failed
    if None in chunks:
        return None

    # Build position-aware fingerprint
    # Format: offset (8 bytes) + length (8 bytes) + data
    hasher = hashlib.sha256()
    for offset, chunk in zip(offsets, chunks):
        # Pack offset and length as little-endian 64-bit unsigned integers
        hasher.update(struct.pack('<Q', offset))
        hasher.update(struct.pack('<Q', len(chunk)))
        hasher.update(chunk)

    return hasher.hexdigest()


async def find_similar(
    client: AsyncQumuloClient,
    files: List[Dict],
    by_size_only: bool = False,
    sample_points: Optional[int] = None,
    sample_chunk_size: int = 65536,
    estimate_only: bool = False,
    progress: Optional['ProgressTracker'] = None
) -> Dict[str, List[Dict]]:
    """
    Find similar files using metadata filtering and sample hashing.

    Phase 1: Group by size + datablocks + sparse_file (instant)
    Phase 2: Compute sample hashes for potential similar files (fast)
    Phase 3: Return groups of similar files

    Args:
        client: AsyncQumuloClient instance
        files: List of file entries with metadata
        by_size_only: If True, only use size for similarity detection (no hashing)
        sample_points: Optional override for number of sample points
        sample_chunk_size: Size of each sample chunk in bytes (default: 65536 / 64KB)
        progress: Optional ProgressTracker for status updates

    Returns:
        Dictionary mapping fingerprint -> list of similar files
    """
    from collections import defaultdict

    if progress and progress.verbose:
        print(f"[SIMILARITY DETECTION] Phase 1: Metadata pre-filtering {len(files):,} files", file=sys.stderr)

    # Phase 1: Group by metadata (size, datablocks, sparse_file)
    metadata_groups = defaultdict(list)

    for entry in files:
        size = int(entry.get('size', 0))
        datablocks = entry.get('datablocks', 'unknown')
        sparse = entry.get('extended_attributes', {}).get('sparse_file', False)

        # Create metadata fingerprint
        fingerprint = f"{size}:{datablocks}:{sparse}"
        metadata_groups[fingerprint].append(entry)

    # Filter to only groups with 2+ files
    potential_duplicates = {k: v for k, v in metadata_groups.items() if len(v) >= 2}

    if progress and progress.verbose:
        total_potential = sum(len(v) for v in potential_duplicates.values())
        print(f"[SIMILARITY DETECTION] Found {total_potential:,} potential similar files in {len(potential_duplicates):,} groups", file=sys.stderr)

    # If estimate-only mode, calculate and display data transfer estimate, then exit
    if estimate_only:
        total_files = sum(len(v) for v in potential_duplicates.values())
        total_file_size = 0
        total_data_to_read = 0

        # Calculate estimates for each size group
        for fingerprint, group in potential_duplicates.items():
            size_str = fingerprint.split(':')[0]
            file_size = int(size_str)
            total_file_size += file_size * len(group)

            # Calculate sample points for this file size
            sample_offsets = calculate_sample_points(file_size, sample_points, sample_chunk_size)
            num_points = len(sample_offsets)

            # Data to read per file
            data_per_file = min(num_points * sample_chunk_size, file_size)
            total_data_to_read += data_per_file * len(group)

        # Calculate coverage percentage
        if total_file_size > 0:
            coverage_pct = (total_data_to_read / total_file_size) * 100
        else:
            coverage_pct = 0

        # Format human-readable sizes
        def format_bytes(b):
            if b >= 1_000_000_000_000:
                return f"{b / 1_000_000_000_000:.2f} TB"
            elif b >= 1_000_000_000:
                return f"{b / 1_000_000_000:.2f} GB"
            elif b >= 1_000_000:
                return f"{b / 1_000_000:.2f} MB"
            elif b >= 1_000:
                return f"{b / 1_000:.2f} KB"
            else:
                return f"{b} bytes"

        # Human-readable chunk size
        if sample_chunk_size >= 1048576:
            chunk_str = f"{sample_chunk_size / 1048576:.1f}MB".rstrip('0').rstrip('.')
        elif sample_chunk_size >= 1024:
            chunk_str = f"{sample_chunk_size / 1024:.0f}KB"
        else:
            chunk_str = f"{sample_chunk_size}B"

        print(f"\n{'=' * 70}", file=sys.stderr)
        print(f"SIMILARITY DETECTION - DATA TRANSFER ESTIMATE", file=sys.stderr)
        print(f"{'=' * 70}", file=sys.stderr)
        print(f"Files to scan:        {total_files:,}", file=sys.stderr)
        print(f"Total file size:      {format_bytes(total_file_size)}", file=sys.stderr)
        print(f"Sample chunk size:    {chunk_str}", file=sys.stderr)
        print(f"Data to read:         {format_bytes(total_data_to_read)}", file=sys.stderr)
        print(f"Coverage:             {coverage_pct:.2f}%", file=sys.stderr)
        print(f"{'=' * 70}\n", file=sys.stderr)

        return {}  # Return empty dict to exit without doing actual hashing

    # If size-only mode, return now
    if by_size_only:
        return potential_duplicates

    # Phase 2: Compute sample hashes for potential similar files
    if progress and progress.verbose:
        print(f"[SIMILARITY DETECTION] Phase 2: Computing sample hashes", file=sys.stderr)

    hash_groups = defaultdict(list)
    BATCH_SIZE = 1000  # Process files in batches to avoid overwhelming the system

    # Limit concurrent hash operations to avoid overwhelming connection pool
    # Each hash operation does N API calls (where N = sample points)
    # Connection pool size is ~100, so we want: concurrent_hashes * sample_points ≤ 80
    # This leaves some headroom for other operations
    # Calculate based on actual sample_points being used
    avg_sample_points = sample_points if sample_points else 7  # Default adaptive is ~7
    MAX_CONCURRENT_HASHES = max(10, min(80, 80 // avg_sample_points))

    # Track progress across all groups
    total_files_to_hash = sum(len(group) for group in potential_duplicates.values())
    files_hashed = 0
    hash_start_time = time.time()
    last_progress_update = time.time()
    is_tty = sys.stderr.isatty() if progress else False

    # Create semaphore to limit concurrent hash operations
    hash_semaphore = asyncio.Semaphore(MAX_CONCURRENT_HASHES)

    async def hash_with_limit(entry, file_path, file_size, sample_points_arg):
        """Wrapper to limit concurrent hash operations."""
        async with hash_semaphore:
            return await compute_sample_hash(client, session, file_path, file_size, sample_points_arg, sample_chunk_size)

    async with client.create_session() as session:
        for fingerprint, group in potential_duplicates.items():
            # Extract size from fingerprint
            size_str = fingerprint.split(':')[0]
            file_size = int(size_str)

            # Process files in batches
            for i in range(0, len(group), BATCH_SIZE):
                batch = group[i:i + BATCH_SIZE]

                # Compute hashes for this batch with concurrency limit
                tasks = []
                for entry in batch:
                    file_path = entry['path']
                    task = hash_with_limit(entry, file_path, file_size, sample_points)
                    tasks.append((entry, task))

                # Wait for all hashes in this batch to complete
                results = await asyncio.gather(*[task for _, task in tasks])

                # Group by hash
                for (entry, _), sample_hash in zip(tasks, results):
                    if sample_hash:
                        # Create combined fingerprint: metadata + hash
                        combined_fingerprint = f"{fingerprint}:{sample_hash}"
                        hash_groups[combined_fingerprint].append(entry)

                # Update progress
                files_hashed += len(batch)

                if progress:
                    current_time = time.time()
                    elapsed = current_time - hash_start_time
                    rate = files_hashed / elapsed if elapsed > 0 else 0
                    remaining = total_files_to_hash - files_hashed

                    progress_msg = (f"[DUPLICATE DETECTION] {files_hashed:,} / {total_files_to_hash:,} hashed | "
                                  f"{remaining:,} remaining | {rate:.1f} files/sec")

                    # Only update progress display every 0.5 seconds
                    if is_tty:
                        # Always overwrite in TTY mode
                        print(f"\r{progress_msg}", end='', file=sys.stderr, flush=True)
                    elif progress.verbose and (current_time - last_progress_update) > 0.5:
                        # Only print on new line when redirected AND enough time has passed
                        print(progress_msg, file=sys.stderr, flush=True)
                        last_progress_update = current_time

    # Print final summary
    if progress and is_tty:
        elapsed = time.time() - hash_start_time
        rate = files_hashed / elapsed if elapsed > 0 else 0
        print(f"\r[SIMILARITY DETECTION] FINAL: {files_hashed:,} files hashed | {rate:.1f} files/sec | {elapsed:.1f}s", file=sys.stderr)
    elif progress and progress.verbose:
        elapsed = time.time() - hash_start_time
        rate = files_hashed / elapsed if elapsed > 0 else 0
        print(f"[SIMILARITY DETECTION] FINAL: {files_hashed:,} files hashed | {rate:.1f} files/sec | {elapsed:.1f}s", file=sys.stderr)

    # Filter to only groups with 2+ files (actual similar files)
    similar_groups = {k: v for k, v in hash_groups.items() if len(v) >= 2}

    if progress and progress.verbose:
        total_similar = sum(len(v) for v in similar_groups.values())
        print(f"[SIMILARITY DETECTION] Found {total_similar:,} confirmed similar files in {len(similar_groups):,} groups", file=sys.stderr)

    return similar_groups


async def resolve_owner_filters(
    client: AsyncQumuloClient, session: aiohttp.ClientSession, args
) -> Optional[Set[str]]:
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

    return all_auth_ids if all_auth_ids else None


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


async def generate_owner_report(
    client: AsyncQumuloClient, owner_stats: OwnerStats, args, elapsed_time: float
):
    """Generate and display ownership report."""
    print("\n" + "=" * 80, file=sys.stderr)
    print("OWNER REPORT", file=sys.stderr)
    print("=" * 80, file=sys.stderr)

    # Get all unique owners
    all_owners = owner_stats.get_all_owners()

    if not all_owners:
        print("No files found", file=sys.stderr)
        return

    # Resolve all owners in parallel
    async with client.create_session() as session:
        identity_cache = await client.resolve_multiple_identities(
            session, all_owners, show_progress=True
        )

    # Build report data
    report_rows = []
    total_bytes = 0
    total_files = 0
    total_dirs = 0

    for owner_auth_id in all_owners:
        stats = owner_stats.get_stats(owner_auth_id)
        identity = identity_cache.get(owner_auth_id, {})

        # Extract owner name, including UID/GID for POSIX users
        owner_name = identity.get("name", f"Unknown ({owner_auth_id})")
        domain = identity.get("domain", "UNKNOWN")

        # For POSIX_USER domain, show UID if available
        if domain == "POSIX_USER" and "uid" in identity:
            uid = identity.get("uid")
            # If name is generic "Unknown", replace with UID
            if owner_name and owner_name.startswith("Unknown"):
                owner_name = f"UID {uid}"
            elif owner_name:
                # Append UID to name
                owner_name = f"{owner_name} (UID {uid})"
            else:
                # No name at all, use UID
                owner_name = f"UID {uid}"

        # For POSIX_GROUP domain, show GID if available
        elif domain == "POSIX_GROUP" and "gid" in identity:
            gid = identity.get("gid")
            if owner_name and owner_name.startswith("Unknown"):
                owner_name = f"GID {gid}"
            elif owner_name:
                owner_name = f"{owner_name} (GID {gid})"
            else:
                # No name at all, use GID
                owner_name = f"GID {gid}"

        report_rows.append(
            {
                "owner": owner_name,
                "domain": domain,
                "auth_id": owner_auth_id,
                "bytes": stats["bytes"],
                "files": stats["files"],
                "dirs": stats["dirs"],
            }
        )

        total_bytes += stats["bytes"]
        total_files += stats["files"]
        total_dirs += stats["dirs"]

    # Sort by bytes descending
    report_rows.sort(key=lambda x: x["bytes"], reverse=True)

    # Print report
    print(
        f"\n{'Owner':<30} {'Domain':<20} {'Files':>10} {'Dirs':>8} {'Total Size':>15}",
        file=sys.stderr,
    )
    print("-" * 90, file=sys.stderr)

    for row in report_rows:
        owner = row["owner"] or "Unknown"
        domain = row["domain"] or "UNKNOWN"
        print(
            f"{owner:<30} {domain:<20} {row['files']:>10,} {row['dirs']:>8,} {format_bytes(row['bytes']):>15}",
            file=sys.stderr,
        )

    print("-" * 90, file=sys.stderr)
    print(
        f"{'TOTAL':<30} {'':<20} {total_files:>10,} {total_dirs:>8,} {format_bytes(total_bytes):>15}",
        file=sys.stderr,
    )

    print(f"\nProcessing time: {elapsed_time:.2f}s", file=sys.stderr)
    rate = (total_files + total_dirs) / elapsed_time if elapsed_time > 0 else 0
    print(f"Processing rate: {rate:.1f} obj/sec", file=sys.stderr)

    # Print cache statistics
    total_lookups = client.cache_hits + client.cache_misses
    if total_lookups > 0:
        hit_rate = (client.cache_hits / total_lookups) * 100
        print(
            f"\nIdentity cache: {client.cache_hits} hits, {client.cache_misses} misses ({hit_rate:.1f}% hit rate)",
            file=sys.stderr,
        )

    print("=" * 80, file=sys.stderr)


async def main_async(args):
    """Main async function."""
    # Determine if we're in ACL cloning mode
    acl_cloning_mode = args.source_acl and args.acl_target

    print("=" * 70, file=sys.stderr)
    if acl_cloning_mode:
        print("GrumpWalk - ACL Cloning Mode", file=sys.stderr)
    else:
        print("GrumpWalk - Qumulo Directory Tree Walk", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"Cluster:          {args.host}", file=sys.stderr)

    if acl_cloning_mode:
        print(f"Source ACL:       {args.source_acl}", file=sys.stderr)
        print(f"Target path:      {args.acl_target}", file=sys.stderr)
        if args.propagate_acls:
            print(f"Propagate:        Enabled", file=sys.stderr)
    else:
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
        bearer_token = get_credentials(args.credentials_store)
    else:
        bearer_token = get_credentials(credential_store_filename())

    if not bearer_token:
        print(
            "\n[ERROR] No credentials found. Please run 'qq --host <cluster> login' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Load persistent identity cache
    identity_cache = load_identity_cache(verbose=args.verbose)

    # Create client with identity cache
    client = AsyncQumuloClient(
        args.host,
        args.port,
        bearer_token,
        args.max_concurrent,
        args.connector_limit,
        identity_cache=identity_cache,
        verbose=args.verbose,
    )

    # ACL Cloning Mode
    if args.source_acl or args.acl_target:
        # Validate: both flags must be provided together
        if not (args.source_acl and args.acl_target):
            print("[ERROR] Both --source-acl and --acl-target must be specified together", file=sys.stderr)
            sys.exit(1)

        async with client.create_session() as session:
            # Step 1: Retrieve source ACL
            if args.verbose:
                print(f"[INFO] Retrieving ACL from: {args.source_acl}", file=sys.stderr)

            source_acl = await client.get_file_acl(session, args.source_acl)

            if not source_acl:
                print(f"[ERROR] Could not retrieve ACL from {args.source_acl}", file=sys.stderr)
                sys.exit(1)

            if args.verbose:
                ace_count = len(source_acl.get('acl', {}).get('aces', []))
                print(f"[INFO] Retrieved ACL with {ace_count} ACEs", file=sys.stderr)

            # Step 1b: Retrieve owner/group if requested
            owner_group_data = None
            if args.copy_owner or args.copy_group:
                if args.verbose:
                    print(f"[INFO] Retrieving owner/group from: {args.source_acl}", file=sys.stderr)

                owner_group_data = await client.get_file_owner_group(session, args.source_acl)

                if not owner_group_data:
                    print(f"[ERROR] Could not retrieve owner/group from {args.source_acl}", file=sys.stderr)
                    sys.exit(1)

                if args.verbose:
                    if args.copy_owner:
                        print(f"[INFO] Source owner: {owner_group_data.get('owner')}", file=sys.stderr)
                    if args.copy_group:
                        print(f"[INFO] Source group: {owner_group_data.get('group')}", file=sys.stderr)

            # Step 2: Check ACL type compatibility and warn if needed
            proceed = await check_acl_type_compatibility(
                client=client,
                session=session,
                source_path=args.source_acl,
                target_path=args.acl_target,
                propagate=args.propagate_acls
            )

            if not proceed:
                sys.exit(0)

            # Step 3: Build file filter from Universal Filters (reuse existing logic)
            owner_auth_ids = None
            if args.owners:
                print("\nResolving owner identities...", file=sys.stderr)
                owner_auth_ids = await resolve_owner_filters(client, session, args)
                if owner_auth_ids:
                    print(f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr)

            file_filter = create_file_filter(args, owner_auth_ids)

            # Step 4: Apply ACL and/or owner/group to target tree
            stats = await apply_acl_to_tree(
                client=client,
                session=session,
                acl_data=source_acl,
                target_path=args.acl_target,
                propagate=args.propagate_acls,
                file_filter=file_filter,
                progress=args.progress,
                continue_on_error=args.continue_on_error,
                args=args,
                owner_group_data=owner_group_data,
                copy_owner=args.copy_owner,
                copy_group=args.copy_group,
                owner_group_only=args.owner_group_only
            )

            # Step 5: Print summary
            if args.owner_group_only:
                print("\nOWNER/GROUP COPY SUMMARY", file=sys.stderr)
            elif args.copy_owner or args.copy_group:
                print("\nACL + OWNER/GROUP COPY SUMMARY", file=sys.stderr)
            else:
                print("\nACL CLONING SUMMARY", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Source:            {args.source_acl}", file=sys.stderr)
            print(f"Target path:       {args.acl_target}", file=sys.stderr)

            # Show what was copied
            copied_items = []
            if not args.owner_group_only:
                copied_items.append("ACL")
            if args.copy_owner:
                copied_items.append("Owner")
            if args.copy_group:
                copied_items.append("Group")
            print(f"Copied:            {', '.join(copied_items)}", file=sys.stderr)

            print(f"Objects changed:   {stats['objects_changed']:,}", file=sys.stderr)
            print(f"Objects failed:    {stats['objects_failed']:,}", file=sys.stderr)
            if file_filter:
                print(f"Objects skipped:   {stats['objects_skipped']:,} (filter mismatch)", file=sys.stderr)

            if stats['errors']:
                print("\nErrors encountered:", file=sys.stderr)
                for error in stats['errors'][:10]:  # Show first 10
                    print(f"  {error['path']}: {error['message']}", file=sys.stderr)
                if len(stats['errors']) > 10:
                    print(f"  ... and {len(stats['errors']) - 10} more", file=sys.stderr)

            # Exit with error code if any failures
            if stats['objects_failed'] > 0:
                sys.exit(1)

        return  # Exit after ACL operation

    # PHASE 3: Directory statistics exploration mode
    if args.show_dir_stats:
        print("\n[INFO] Directory statistics mode (exploration)", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        start_time = time.time()

        # Use max_depth from args, default to 1 if not specified
        depth = args.max_depth if args.max_depth else 1

        async with client.create_session() as session:
            await client.show_directory_stats(session, args.path, max_depth=depth)

        elapsed = time.time() - start_time
        print(f"\n{'=' * 70}", file=sys.stderr)
        print(f"Exploration completed in {elapsed:.2f}s", file=sys.stderr)
        return

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
            profiler.record_sync(
                "owner_identity_resolution", time.time() - resolve_start
            )

        if owner_auth_ids:
            print(
                f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr
            )
            if args.verbose:
                print(f"Owner auth_ids: {', '.join(owner_auth_ids)}", file=sys.stderr)
        else:
            print(
                "[WARN] No valid owners resolved - no files will match!",
                file=sys.stderr,
            )

    # Create file filter
    file_filter = create_file_filter(args, owner_auth_ids)

    # PHASE 3: Prepare filter info for smart skipping
    # Build time filter info for aggregates-based smart skipping
    time_filter_info = None
    if args.older_than or args.newer_than:
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        time_filter_info = {
            "time_field": args.time_field,
            "older_than": (
                now_utc - timedelta(days=args.older_than) if args.older_than else None
            ),
            "newer_than": (
                now_utc - timedelta(days=args.newer_than) if args.newer_than else None
            ),
        }

    # Build size filter info for aggregates-based smart skipping
    size_filter_info = None
    if args.larger_than:
        # Only support --larger-than for smart skipping (min size threshold)
        size_filter_info = {"min_size": parse_size_to_bytes(args.larger_than)}

    # PHASE 3.3: Build owner filter info for aggregates-based smart skipping
    owner_filter_info = None
    if owner_auth_ids:
        owner_filter_info = {"auth_ids": owner_auth_ids}

    # Create progress tracker with optional limit for early exit
    progress = (
        ProgressTracker(verbose=args.progress, limit=args.limit)
        if args.progress
        else None
    )

    # Fetch and display directory aggregates to inform user of search scope
    async with client.create_session() as session:
        try:
            aggregates = await client.get_directory_aggregates(session, args.path)
            total_files = aggregates.get('total_files', 'unknown')
            total_dirs = aggregates.get('total_directories', 'unknown')

            # Format numbers with commas
            if isinstance(total_files, str):
                files_str = total_files
            else:
                files_str = f"{int(total_files):,}"

            if isinstance(total_dirs, str):
                dirs_str = total_dirs
            else:
                dirs_str = f"{int(total_dirs):,}"

            # Add note if traversal filters are active
            filter_note = ""
            if args.max_depth or args.omit_subdirs:
                filter_note = " (before filters)"

            print(f"Searching directory {args.path} ({dirs_str} subdirectories, {files_str} files){filter_note}",
                  file=sys.stderr)
        except Exception as e:
            # If aggregates fail, just continue without displaying them
            if args.verbose:
                print(f"[WARN] Could not fetch directory aggregates: {e}", file=sys.stderr)

    # Create owner stats tracker if owner-report enabled
    # Use capacity-based calculation (actual disk usage) by default to handle sparse files correctly
    owner_stats = (
        OwnerStats(use_capacity=args.use_capacity) if args.owner_report else None
    )

    # Walk tree and collect matches
    start_time = time.time()

    if profiler:
        tree_walk_start = time.time()

    # For owner reports and ACL reports, don't collect matching files to save memory
    # Also collect results if we need to resolve symlinks, generate ACL reports, or find similar files
    collect_results = not args.owner_report or args.resolve_links or args.acl_report or args.find_similar

    # Create output callback for streaming results to stdout (plain text mode only)
    # Disable streaming if --resolve-links is enabled (need to resolve after collection)
    # Disable streaming if --acl-report is enabled (generates its own report)
    # Disable streaming if --find-similar is enabled (need to collect all files first)
    output_callback = None
    batched_handler = None

    if not args.owner_report and not args.acl_report and not args.csv_out and not args.json_out and not args.resolve_links and not args.find_similar:
        if args.show_owner or args.show_group:
            # Use batched output handler for streaming with identity resolution
            output_format = "json" if args.json else "text"
            batched_handler = BatchedOutputHandler(
                client,
                batch_size=100,
                show_owner=args.show_owner,
                show_group=args.show_group,
                output_format=output_format,
            )

            async def output_callback(entry):
                await batched_handler.add_entry(entry)

        else:
            # Direct streaming output (no owner resolution needed)
            if args.json:
                # JSON to stdout
                async def output_callback(entry):
                    print(json_parser.dumps(entry))
                    sys.stdout.flush()

            else:
                # Plain text to stdout
                async def output_callback(entry):
                    print(entry["path"])
                    sys.stdout.flush()

    async with client.create_session() as session:
        matching_files = await client.walk_tree_async(
            session,
            args.path,
            args.max_depth,
            progress=progress,
            file_filter=file_filter,
            owner_stats=owner_stats,
            omit_subdirs=args.omit_subdirs,
            omit_paths=args.omit_path,
            collect_results=collect_results,
            verbose=args.verbose,
            max_entries_per_dir=args.max_entries_per_dir,
            time_filter_info=time_filter_info,
            size_filter_info=size_filter_info,
            owner_filter_info=owner_filter_info,
            output_callback=output_callback,
        )

    if profiler:
        tree_walk_time = time.time() - tree_walk_start
        profiler.record_sync("tree_walking", tree_walk_time)

    elapsed = time.time() - start_time

    # Final progress report
    if progress:
        progress.final_report()

    # Add diagnostic timing
    if args.progress or args.verbose:
        print(
            f"[INFO] Tree walk completed, collected {len(matching_files)} matching files",
            file=sys.stderr,
        )

    # Flush any remaining batched output
    if batched_handler:
        await batched_handler.flush()

    # Resolve owner and group identities if --show-owner or --show-group is enabled (for non-streaming modes only)
    # Skip if batched_handler was used (streaming mode)
    identity_cache_for_output = {}
    if (args.show_owner or args.show_group) and matching_files and not batched_handler:
        # Collect unique auth_ids (owners and/or groups) from matching files
        unique_auth_ids = set()

        if args.show_owner:
            for entry in matching_files:
                owner_details = entry.get("owner_details", {})
                owner_auth_id = owner_details.get("auth_id") or entry.get("owner")
                if owner_auth_id:
                    unique_auth_ids.add(owner_auth_id)

        if args.show_group:
            for entry in matching_files:
                group_details = entry.get("group_details", {})
                group_auth_id = group_details.get("auth_id") or entry.get("group")
                if group_auth_id:
                    unique_auth_ids.add(group_auth_id)

        if unique_auth_ids:
            async with client.create_session() as session:
                identity_cache_for_output = await client.resolve_multiple_identities(
                    session,
                    list(unique_auth_ids),
                    show_progress=args.verbose or args.progress,
                )

    # Resolve symlinks if --resolve-links is enabled
    if args.resolve_links and matching_files and not batched_handler:
        async with client.create_session() as session:
            for entry in matching_files:
                if entry.get("type") == "FS_FILE_TYPE_SYMLINK":
                    target = await client.read_symlink(session, entry["path"])
                    if target:
                        # Convert relative paths to absolute paths
                        if not target.startswith('/'):
                            # Relative path - resolve relative to symlink's directory
                            import os.path
                            symlink_dir = os.path.dirname(entry["path"])
                            # Normalize path to handle .. and . components
                            absolute_target = os.path.normpath(os.path.join(symlink_dir, target))
                            entry["symlink_target"] = absolute_target
                        else:
                            # Already absolute
                            entry["symlink_target"] = target
                    else:
                        entry["symlink_target"] = "(unreadable)"

    # Generate owner report if requested
    if args.owner_report and owner_stats:
        if profiler:
            report_start = time.time()
        await generate_owner_report(client, owner_stats, args, elapsed)
        if profiler:
            profiler.record_sync("owner_report_generation", time.time() - report_start)
            profiler.print_report(elapsed)

        # Save identity cache before exiting
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
        return  # Exit after report, don't output file list

    # Generate ACL report if requested
    if args.acl_report and matching_files:
        print("\n" + "=" * 70, file=sys.stderr)
        print("ACL REPORT", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

        # Generate ACL report
        async with client.create_session() as session:
            acl_report = await generate_acl_report(
                client,
                session,
                matching_files,
                show_progress=args.progress,
                resolve_names=args.acl_resolve_names,
                show_owner=args.show_owner,
                show_group=args.show_group
            )

        # Get identity cache
        identity_cache = acl_report.get('identity_cache', {})

        # Display summary statistics
        stats = acl_report['stats']
        print("\n" + "=" * 70, file=sys.stderr)
        print("ACL REPORT SUMMARY", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(f"Total files analyzed:        {stats['total_files']:,}", file=sys.stderr)
        print(f"Files with ACLs:             {stats['files_with_acls']:,}", file=sys.stderr)
        print(f"Processing time:             {stats['processing_time']:.2f}s", file=sys.stderr)
        if args.acl_resolve_names:
            print(f"Identities resolved:         {len(identity_cache):,}", file=sys.stderr)

        # Export to CSV if requested
        if args.acl_csv:
            import csv

            file_acls = acl_report['file_acls']

            # First pass: collect all ACL data and find max number of ACEs
            acl_rows = []
            max_aces = 0

            for path, acl_info in file_acls.items():
                acl_data = acl_info['acl_data']
                is_directory = acl_info['is_directory']
                owner_details = acl_info.get('owner_details', {})
                group_details = acl_info.get('group_details', {})

                # Skip if no ACL data
                if not acl_data:
                    continue

                # Generate readable ACL with names if requested
                if args.acl_resolve_names and identity_cache:
                    readable_acl = qacl_to_readable_acl_with_names(
                        acl_data,
                        is_directory=is_directory,
                        identity_cache=identity_cache
                    )
                else:
                    readable_acl = qacl_to_readable_acl(acl_data, is_directory=is_directory)

                # Extract ACE counts from acl_data
                acl_dict = acl_data.get('acl', acl_data) if 'acl' in acl_data else acl_data
                aces = acl_dict.get('aces', [])
                ace_count = len(aces)
                inherited_count = sum(1 for ace in aces if ace.get('flags', []) and 'INHERITED' in ace['flags'])
                explicit_count = ace_count - inherited_count

                # Split trustees
                trustees = readable_acl.split('|') if readable_acl else []
                max_aces = max(max_aces, len(trustees))

                # Resolve owner and group names if requested
                owner_name = None
                group_name = None

                if args.show_owner:
                    # Use the numeric owner field as the auth_id
                    owner_auth_id = acl_info.get('owner')
                    if owner_auth_id and owner_auth_id in identity_cache:
                        owner_name = format_owner_name(identity_cache[owner_auth_id])
                    elif owner_auth_id:
                        owner_name = f"auth_id:{owner_auth_id}"
                    else:
                        owner_name = "Unknown"

                if args.show_group:
                    # Use the numeric group field as the auth_id
                    group_auth_id = acl_info.get('group')
                    if group_auth_id and group_auth_id in identity_cache:
                        group_name = format_owner_name(identity_cache[group_auth_id])
                    elif group_auth_id:
                        group_name = f"auth_id:{group_auth_id}"
                    else:
                        group_name = "Unknown"

                acl_rows.append({
                    'path': path,
                    'ace_count': ace_count,
                    'inherited_count': inherited_count,
                    'explicit_count': explicit_count,
                    'trustees': trustees,
                    'owner': owner_name,
                    'group': group_name
                })

            # Create CSV with dynamic trustee columns
            with open(args.acl_csv, 'w', newline='') as csv_file:
                fieldnames = ['path']

                # Add owner and group columns if requested
                if args.show_owner:
                    fieldnames.append('owner')
                if args.show_group:
                    fieldnames.append('group')

                # Add ACL count columns
                fieldnames.extend([
                    'ace_count',
                    'inherited_count',
                    'explicit_count'
                ])

                # Add trustee columns dynamically
                for i in range(1, max_aces + 1):
                    fieldnames.append(f'trustee_{i}')

                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()

                # Write rows with trustees in separate columns
                for row_data in acl_rows:
                    row = {'path': row_data['path']}

                    # Add owner and group if requested
                    if args.show_owner:
                        row['owner'] = row_data['owner']
                    if args.show_group:
                        row['group'] = row_data['group']

                    # Add ACL counts
                    row['ace_count'] = row_data['ace_count']
                    row['inherited_count'] = row_data['inherited_count']
                    row['explicit_count'] = row_data['explicit_count']

                    # Add each trustee to its own column
                    for i, trustee in enumerate(row_data['trustees'], start=1):
                        row[f'trustee_{i}'] = trustee.strip()

                    writer.writerow(row)

            print(f"\n[INFO] ACL CSV exported to: {args.acl_csv}", file=sys.stderr)

        # Export to JSON if requested
        if args.json or args.json_out:
            output_handle = sys.stdout
            if args.json_out:
                output_handle = open(args.json_out, 'w')

            file_acls = acl_report['file_acls']

            # Generate JSON output for ACLs - one entry per file
            for path, acl_info in file_acls.items():
                acl_data = acl_info['acl_data']
                is_directory = acl_info['is_directory']
                owner_details = acl_info.get('owner_details', {})
                group_details = acl_info.get('group_details', {})

                # Skip if no ACL data
                if not acl_data:
                    continue

                # Generate readable ACL with names if requested
                if args.acl_resolve_names and identity_cache:
                    readable_acl = qacl_to_readable_acl_with_names(
                        acl_data,
                        is_directory=is_directory,
                        identity_cache=identity_cache
                    )
                else:
                    readable_acl = qacl_to_readable_acl(acl_data, is_directory=is_directory)

                # Extract ACE counts from acl_data
                acl_dict = acl_data.get('acl', acl_data) if 'acl' in acl_data else acl_data
                aces = acl_dict.get('aces', [])
                ace_count = len(aces)
                inherited_count = sum(1 for ace in aces if ace.get('flags', []) and 'INHERITED' in ace['flags'])
                explicit_count = ace_count - inherited_count

                # Split the readable ACL by pipe to get individual ACEs
                ace_entries = readable_acl.split('|') if readable_acl else []
                trustees = [ace_entry.strip() for ace_entry in ace_entries]

                # Write one JSON entry per file with trustees as array
                json_entry = {'path': path}

                # Add owner and group if requested
                if args.show_owner:
                    # Use the numeric owner field as the auth_id
                    owner_auth_id = acl_info.get('owner')
                    if owner_auth_id and owner_auth_id in identity_cache:
                        json_entry['owner'] = format_owner_name(identity_cache[owner_auth_id])
                    elif owner_auth_id:
                        json_entry['owner'] = f"auth_id:{owner_auth_id}"
                    else:
                        json_entry['owner'] = "Unknown"

                if args.show_group:
                    # Use the numeric group field as the auth_id
                    group_auth_id = acl_info.get('group')
                    if group_auth_id and group_auth_id in identity_cache:
                        json_entry['group'] = format_owner_name(identity_cache[group_auth_id])
                    elif group_auth_id:
                        json_entry['group'] = f"auth_id:{group_auth_id}"
                    else:
                        json_entry['group'] = "Unknown"

                # Add ACL info
                json_entry.update({
                    'ace_count': ace_count,
                    'inherited_count': inherited_count,
                    'explicit_count': explicit_count,
                    'trustees': trustees
                })

                # Use ensure_ascii=False and escape_forward_slashes=False for cleaner output
                if JSON_PARSER_NAME == "ujson":
                    output_handle.write(json_parser.dumps(json_entry, ensure_ascii=False, escape_forward_slashes=False) + '\n')
                else:
                    output_handle.write(json_parser.dumps(json_entry, ensure_ascii=False) + '\n')

            if args.json_out:
                output_handle.close()
                print(f"\n[INFO] ACL JSON exported to: {args.json_out}", file=sys.stderr)

        print("\n" + "=" * 70, file=sys.stderr)

        # Save identity cache before exiting
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
        return  # Exit after ACL report

    # Find similar files if requested
    if args.find_similar:
        if profiler:
            dup_start = time.time()

        print(f"\n{'=' * 70}", file=sys.stderr)
        print(f"SIMILARITY DETECTION", file=sys.stderr)
        print(f"{'=' * 70}", file=sys.stderr)
        print(f"WARNING: Results are ADVISORY ONLY.", file=sys.stderr)
        print(f"Perform additional verification (e.g., full checksums) before deleting files.", file=sys.stderr)
        print(f"{'=' * 70}", file=sys.stderr)

        similar_files = await find_similar(
            client,
            matching_files,
            by_size_only=args.by_size,
            sample_points=args.sample_points,
            sample_chunk_size=args.sample_size if args.sample_size else 65536,
            estimate_only=args.estimate_size,
            progress=progress
        )

        if profiler:
            profiler.record_sync("similarity_detection", time.time() - dup_start)

        # If estimate-only, we're done (report was already printed)
        if args.estimate_size:
            return

        # Report results
        if not similar_files:
            print("\nNo similar files found.", file=sys.stderr)
            # No similar files found, but may still need to create empty CSV or JSON
            if args.csv_out:
                import csv
                with open(args.csv_out, "w", newline="") as csv_file:
                    writer = csv.DictWriter(csv_file, fieldnames=["similar_group", "path", "size", "coverage"])
                    writer.writeheader()
                if args.verbose:
                    print(f"\n[INFO] Created empty CSV file: {args.csv_out}", file=sys.stderr)
            elif args.json_out:
                # Create empty JSON file
                with open(args.json_out, "w") as json_file:
                    pass  # Empty file
                if args.verbose:
                    print(f"\n[INFO] Created empty JSON file: {args.json_out}", file=sys.stderr)
        else:
            total_groups = len(similar_files)
            total_similar = sum(len(group) for group in similar_files.values())

            # Calculate detection method info
            if args.by_size:
                confidence_msg = "Detection method: Size+metadata only (may have false positives)"
                confidence_value = "Low (size+metadata only)"
            else:
                # Get sample point count and calculate coverage from first group (representative)
                first_file = next(iter(similar_files.values()))[0]
                file_size = int(first_file.get('size', 0))
                chunk_size = args.sample_size if args.sample_size else 65536
                sample_offsets = calculate_sample_points(file_size, args.sample_points, chunk_size)
                num_points = len(sample_offsets)

                # Calculate actual coverage percentage
                if file_size > 0:
                    total_sampled = num_points * chunk_size
                    coverage_pct = min(100.0, (total_sampled / file_size) * 100)
                    coverage_str = f"{coverage_pct:.1f}%" if coverage_pct < 100 else "100%"
                else:
                    coverage_str = "N/A"

                # Human-readable chunk size
                if chunk_size >= 1048576:
                    chunk_str = f"{chunk_size / 1048576:.1f}MB".rstrip('0').rstrip('.')
                elif chunk_size >= 1024:
                    chunk_str = f"{chunk_size / 1024:.0f}KB"
                else:
                    chunk_str = f"{chunk_size}B"

                confidence_msg = f"Detection method: {num_points}-point sampling ({chunk_str} chunks, {coverage_str} coverage)"
                confidence_value = coverage_str

            print(f"\nFound {total_similar:,} similar files in {total_groups:,} groups", file=sys.stderr)
            print(f"{confidence_msg}", file=sys.stderr)
            print(f"{'=' * 70}\n", file=sys.stderr)

            # Handle CSV output for similar files
            if args.csv_out:
                import csv
                with open(args.csv_out, "w", newline="") as csv_file:
                    fieldnames = ["similar_group", "path", "size", "coverage"]
                    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                    writer.writeheader()

                    for group_id, (fingerprint, files) in enumerate(similar_files.items(), 1):
                        # Extract size from fingerprint
                        size_str = fingerprint.split(':')[0]
                        file_size = int(size_str)

                        for f in files:
                            writer.writerow({
                                "similar_group": group_id,
                                "path": f['path'],
                                "size": file_size,
                                "coverage": confidence_value
                            })

                if args.verbose:
                    print(f"\n[INFO] Wrote {total_similar:,} similar files ({total_groups:,} groups) to {args.csv_out}", file=sys.stderr)
            elif args.json_out or args.json:
                # Handle JSON output for similar files
                output_handle = open(args.json_out, 'w') if args.json_out else sys.stdout

                try:
                    for group_id, (fingerprint, files) in enumerate(similar_files.items(), 1):
                        # Extract size from fingerprint
                        size_str = fingerprint.split(':')[0]
                        file_size = int(size_str)

                        for f in files:
                            entry = {
                                "similar_group": group_id,
                                "path": f['path'],
                                "size": file_size,
                                "coverage": confidence_value
                            }

                            # Use ensure_ascii=False and escape_forward_slashes=False for cleaner output
                            if JSON_PARSER_NAME == "ujson":
                                output_handle.write(json_parser.dumps(entry, ensure_ascii=False, escape_forward_slashes=False) + '\n')
                            else:
                                output_handle.write(json_parser.dumps(entry, ensure_ascii=False) + '\n')
                finally:
                    if args.json_out:
                        output_handle.close()
                        if args.verbose:
                            print(f"\n[INFO] Wrote {total_similar:,} similar files ({total_groups:,} groups) to {args.json_out}", file=sys.stderr)
            else:
                # Output similar file groups to stderr (text mode)
                for group_id, (fingerprint, files) in enumerate(similar_files.items(), 1):
                    # Extract size from fingerprint
                    size_str = fingerprint.split(':')[0]
                    file_size = int(size_str)

                    print(f"Group {group_id}: {len(files)} files ({file_size:,} bytes each)", file=sys.stderr)
                    for f in files:
                        print(f"  {f['path']}", file=sys.stderr)
                    print(file=sys.stderr)

        if profiler:
            profiler.print_report(elapsed)

        # Save identity cache before exiting
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
        return  # Exit after similarity detection

    # Apply limit if specified
    if args.limit and len(matching_files) > args.limit:
        if args.verbose:
            print(
                f"\n[INFO] Limiting results to {args.limit} files (found {len(matching_files)})",
                file=sys.stderr,
            )
        matching_files = matching_files[: args.limit]

    # Output results
    if profiler:
        output_start = time.time()

    if args.csv_out:
        # CSV output
        import csv

        with open(args.csv_out, "w", newline="") as csv_file:
            if not matching_files:
                if args.verbose:
                    print(
                        f"[INFO] No matching files found, CSV file will be empty",
                        file=sys.stderr,
                    )
                return

            if args.all_attributes:
                # Add resolved owner name to entries if --show-owner is enabled
                if args.show_owner:
                    for entry in matching_files:
                        owner_details = entry.get("owner_details", {})
                        owner_auth_id = owner_details.get("auth_id") or entry.get(
                            "owner"
                        )
                        if owner_auth_id and owner_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[owner_auth_id]
                            entry["owner_name"] = format_owner_name(identity)
                        else:
                            entry["owner_name"] = "Unknown"

                # Add resolved group name to entries if --show-group is enabled
                if args.show_group:
                    for entry in matching_files:
                        group_details = entry.get("group_details", {})
                        group_auth_id = group_details.get("auth_id") or entry.get(
                            "group"
                        )
                        if group_auth_id and group_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[group_auth_id]
                            entry["group_name"] = format_owner_name(identity)
                        else:
                            entry["group_name"] = "Unknown"

                # Write all attributes
                fieldnames = sorted(matching_files[0].keys())
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for entry in matching_files:
                    writer.writerow(entry)
            else:
                # Write selective fields
                fieldnames = ["path"]

                # Add time field if time filter was used
                if args.older_than or args.newer_than:
                    fieldnames.append(args.time_field)

                # Add size if size filter was used
                if args.larger_than or args.smaller_than:
                    fieldnames.append("size")

                # Add owner if --show-owner is enabled
                if args.show_owner:
                    fieldnames.append("owner")

                # Add group if --show-group is enabled
                if args.show_group:
                    fieldnames.append("group")

                # Add symlink_target if --resolve-links is enabled
                if args.resolve_links:
                    fieldnames.append("symlink_target")

                writer = csv.DictWriter(
                    csv_file, fieldnames=fieldnames, extrasaction="ignore"
                )
                writer.writeheader()
                for entry in matching_files:
                    row = {"path": entry["path"]}
                    if args.older_than or args.newer_than:
                        row[args.time_field] = entry.get(args.time_field)
                    if args.larger_than or args.smaller_than:
                        row["size"] = entry.get("size")
                    if args.show_owner:
                        owner_details = entry.get("owner_details", {})
                        owner_auth_id = owner_details.get("auth_id") or entry.get(
                            "owner"
                        )
                        if owner_auth_id and owner_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[owner_auth_id]
                            row["owner"] = format_owner_name(identity)
                        else:
                            row["owner"] = "Unknown"
                    if args.show_group:
                        group_details = entry.get("group_details", {})
                        group_auth_id = group_details.get("auth_id") or entry.get(
                            "group"
                        )
                        if group_auth_id and group_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[group_auth_id]
                            row["group"] = format_owner_name(identity)
                        else:
                            row["group"] = "Unknown"
                    if args.resolve_links and "symlink_target" in entry:
                        row["symlink_target"] = entry["symlink_target"]
                    writer.writerow(row)

        if args.verbose:
            print(
                f"\n[INFO] Wrote {len(matching_files)} results to {args.csv_out}",
                file=sys.stderr,
            )
    elif args.json or args.json_out:
        # JSON output
        # Skip if batched_handler was used (already output via streaming)
        if batched_handler:
            pass  # Already handled by batched streaming
        else:
            output_handle = sys.stdout
            if args.json_out:
                output_handle = open(args.json_out, "w")

            for entry in matching_files:
                if args.all_attributes:
                    # Add resolved owner name to entry if --show-owner is enabled
                    if args.show_owner:
                        owner_details = entry.get("owner_details", {})
                        owner_auth_id = owner_details.get("auth_id") or entry.get(
                            "owner"
                        )
                        if owner_auth_id and owner_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[owner_auth_id]
                            entry["owner_name"] = format_owner_name(identity)
                        else:
                            entry["owner_name"] = "Unknown"

                    # Add resolved group name to entry if --show-group is enabled
                    if args.show_group:
                        group_details = entry.get("group_details", {})
                        group_auth_id = group_details.get("auth_id") or entry.get(
                            "group"
                        )
                        if group_auth_id and group_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[group_auth_id]
                            entry["group_name"] = format_owner_name(identity)
                        else:
                            entry["group_name"] = "Unknown"

                    output_handle.write(json_parser.dumps(entry) + "\n")
                else:
                    # Minimal output: path and filtered fields
                    minimal_entry = {"path": entry["path"]}
                    if args.older_than or args.newer_than:
                        minimal_entry[args.time_field] = entry.get(args.time_field)
                    if args.larger_than or args.smaller_than:
                        minimal_entry["size"] = entry.get("size")
                    if args.show_owner:
                        owner_details = entry.get("owner_details", {})
                        owner_auth_id = owner_details.get("auth_id") or entry.get(
                            "owner"
                        )
                        if owner_auth_id and owner_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[owner_auth_id]
                            minimal_entry["owner"] = format_owner_name(identity)
                        else:
                            minimal_entry["owner"] = "Unknown"
                    if args.show_group:
                        group_details = entry.get("group_details", {})
                        group_auth_id = group_details.get("auth_id") or entry.get(
                            "group"
                        )
                        if group_auth_id and group_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[group_auth_id]
                            minimal_entry["group"] = format_owner_name(identity)
                        else:
                            minimal_entry["group"] = "Unknown"
                    if args.resolve_links and "symlink_target" in entry:
                        minimal_entry["symlink_target"] = entry["symlink_target"]
                    output_handle.write(json_parser.dumps(minimal_entry) + "\n")

            if args.json_out:
                output_handle.close()
                print(f"\n[INFO] Results written to {args.json_out}", file=sys.stderr)
    else:
        # Plain text output
        # Only output if we didn't use streaming callback (which already printed results)
        if output_callback is None:
            for entry in matching_files:
                output_line = entry["path"]

                # Add symlink target if --resolve-links is enabled and this is a symlink
                if args.resolve_links and "symlink_target" in entry:
                    output_line = f"{output_line} → {entry['symlink_target']}"

                # Add owner information if --show-owner is enabled
                if args.show_owner:
                    owner_details = entry.get("owner_details", {})
                    owner_auth_id = owner_details.get("auth_id") or entry.get("owner")
                    if owner_auth_id and owner_auth_id in identity_cache_for_output:
                        identity = identity_cache_for_output[owner_auth_id]
                        owner_name = format_owner_name(identity)
                        output_line = f"{output_line}\t{owner_name}"
                    else:
                        output_line = f"{output_line}\tUnknown"

                # Add group information if --show-group is enabled
                if args.show_group:
                    group_details = entry.get("group_details", {})
                    group_auth_id = group_details.get("auth_id") or entry.get("group")
                    if group_auth_id and group_auth_id in identity_cache_for_output:
                        identity = identity_cache_for_output[group_auth_id]
                        group_name = format_owner_name(identity)
                        output_line = f"{output_line}\t{group_name}"
                    else:
                        output_line = f"{output_line}\tUnknown"

                print(output_line)

    # Record output timing
    if profiler:
        output_time = time.time() - output_start
        profiler.record_sync("output_generation", output_time)

    # Summary
    if args.verbose:
        print(
            f"\n[INFO] Processed {progress.total_objects if progress else 'N/A'} objects in {elapsed:.2f}s",
            file=sys.stderr,
        )
        print(f"[INFO] Found {len(matching_files)} matching files", file=sys.stderr)
        rate = (
            (progress.total_objects if progress else len(matching_files)) / elapsed
            if elapsed > 0
            else 0
        )
        print(f"[INFO] Processing rate: {rate:.1f} obj/sec", file=sys.stderr)

    # Print profiling report
    if profiler:
        profiler.print_report(elapsed)

    # Save identity cache before exiting
    save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)


def main():
    parser = argparse.ArgumentParser(
        description="Qumulo File Filter and Directory Tree Walker Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find files older than 30 days
  ./grumpwalk.py --host cluster.example.com --path /home --older-than 30

  # Find large files with progress tracking
  ./grumpwalk.py --host cluster.example.com --path /data --larger-than 1GB --progress

  # Search for log files or temporary files (OR logic, glob wildcards)
  ./grumpwalk.py --host cluster.example.com --path /var --name '*.log' --name '*.tmp'

  # Search for backup files from 2024 (AND logic)
  ./grumpwalk.py --host cluster.example.com --path /backups --name-and '*backup*' --name-and '*2024*'

  # Find all Python test files (glob pattern)
  ./grumpwalk.py --host cluster.example.com --path /code --name 'test_*.py' --type file

  # Find all directories starting with "temp" (regex pattern)
  ./grumpwalk.py --host cluster.example.com --path /data --name '^temp.*' --type directory

  # Case-sensitive search for README files
  ./grumpwalk.py --host cluster.example.com --path /docs --name '^README$' --name-case-sensitive

  # High-performance mode with increased concurrency
  ./grumpwalk.py --host cluster.example.com --path /home --older-than 90 --max-concurrent 200 --connector-limit 200

  # Output to JSON file
  ./grumpwalk.py --host cluster.example.com --path /home --older-than 30 --json-out results.json --all-attributes

  # Clone ACL from one directory to another
  ./grumpwalk.py --host cluster.example.com --source-acl /source/dir --acl-target /target/dir

  # Clone ACL and propagate to all children
  ./grumpwalk.py --host cluster.example.com --source-acl /source/dir --acl-target /target/dir --propagate-acls --progress

  # Copy owner and group (with ACL) from source to target
  ./grumpwalk.py --host cluster.example.com --source-acl /source/dir --acl-target /target/dir --copy-owner --copy-group --propagate-acls

  # Copy only owner and group (no ACL changes)
  ./grumpwalk.py --host cluster.example.com --source-acl /source/dir --acl-target /target/dir --copy-owner --copy-group --owner-group-only --propagate-acls

  # Clone ACL to filtered files (e.g., only files older than 30 days)
  ./grumpwalk.py --host cluster.example.com --source-acl /source/dir --acl-target /target/dir --propagate-acls --older-than 30 --type file --progress
        """,
    )

    # ============================================================================
    # REQUIRED ARGUMENTS
    # ============================================================================
    required = parser.add_argument_group('Required Arguments')
    required.add_argument("--host", required=True, help="Qumulo cluster hostname or IP")
    required.add_argument("--path", help="Path to search (not required for ACL cloning with --source-acl/--acl-target)")

    # ============================================================================
    # UNIVERSAL FILTERS - TIME
    # Filters that work with any feature (regular search, reports, etc.)
    # ============================================================================
    time_filters = parser.add_argument_group('Universal Filters - Time',
        'Time-based filters that work with all features')

    time_filters.add_argument("--older-than", type=int, help="Find files older than N days")
    time_filters.add_argument("--newer-than", type=int, help="Find files newer than N days")

    time_filters.add_argument(
        "--time-field",
        default="creation_time",
        choices=["creation_time", "modification_time", "access_time", "change_time"],
        help="Time field to filter on (default: creation_time)",
    )
    time_filters.add_argument(
        "--created",
        action="store_const",
        const="creation_time",
        dest="time_field",
        help="Shortcut for --time-field creation_time",
    )
    time_filters.add_argument(
        "--modified",
        action="store_const",
        const="modification_time",
        dest="time_field",
        help="Shortcut for --time-field modification_time",
    )
    time_filters.add_argument(
        "--accessed",
        action="store_const",
        const="access_time",
        dest="time_field",
        help="Shortcut for --time-field access_time",
    )
    time_filters.add_argument(
        "--changed",
        action="store_const",
        const="change_time",
        dest="time_field",
        help="Shortcut for --time-field change_time",
    )
    time_filters.add_argument(
        "--accessed-older-than",
        type=int,
        help="Find files with access time older than N days (AND logic)",
    )
    time_filters.add_argument(
        "--accessed-newer-than",
        type=int,
        help="Find files with access time newer than N days (AND logic)",
    )
    time_filters.add_argument(
        "--modified-older-than",
        type=int,
        help="Find files with modification time older than N days (AND logic)",
    )
    time_filters.add_argument(
        "--modified-newer-than",
        type=int,
        help="Find files with modification time newer than N days (AND logic)",
    )
    time_filters.add_argument(
        "--created-older-than",
        type=int,
        help="Find files with creation time older than N days (AND logic)",
    )
    time_filters.add_argument(
        "--created-newer-than",
        type=int,
        help="Find files with creation time newer than N days (AND logic)",
    )
    time_filters.add_argument(
        "--changed-older-than",
        type=int,
        help="Find files with change time older than N days (AND logic)",
    )
    time_filters.add_argument(
        "--changed-newer-than",
        type=int,
        help="Find files with change time newer than N days (AND logic)",
    )

    # ============================================================================
    # UNIVERSAL FILTERS - SIZE
    # ============================================================================
    size_filters = parser.add_argument_group('Universal Filters - Size',
        'Size-based filters that work with all features')

    size_filters.add_argument(
        "--larger-than",
        help="Find files larger than specified size (e.g., 100MB, 1.5GiB)",
    )
    size_filters.add_argument(
        "--smaller-than",
        help="Find files smaller than specified size (e.g., 50MB, 500KiB)",
    )
    size_filters.add_argument(
        "--include-metadata",
        action="store_true",
        help="Include metadata blocks in size calculations (metablocks * 4KB)",
    )

    # ============================================================================
    # UNIVERSAL FILTERS - NAME AND TYPE
    # ============================================================================
    name_filters = parser.add_argument_group('Universal Filters - Name and Type',
        'Name pattern and type filters that work with all features')

    name_filters.add_argument(
        "--name",
        action="append",
        dest="name_patterns",
        help="Filter by name pattern (supports glob wildcards and regex, repeatable for OR logic). "
             "Glob: --name '*.log' | Regex: --name '.*\\.log$'",
    )
    name_filters.add_argument(
        "--name-and",
        action="append",
        dest="name_patterns_and",
        help="Filter by name pattern using AND logic (all patterns must match, repeatable). "
             "Example: --name-and '*backup*' --name-and '*2024*'",
    )
    name_filters.add_argument(
        "--name-case-sensitive",
        action="store_true",
        help="Make name pattern matching case-sensitive (default: case-insensitive)",
    )
    name_filters.add_argument(
        "--type",
        choices=["file", "f", "directory", "dir", "d", "symlink", "link", "l"],
        help="Filter by object type: file/f, directory/dir/d, or symlink/link/l",
    )

    # ============================================================================
    # UNIVERSAL FILTERS - OWNER
    # ============================================================================
    owner_filters = parser.add_argument_group('Universal Filters - Owner',
        'Owner-based filters that work with all features')

    owner_filters.add_argument(
        "--owner",
        action="append",
        dest="owners",
        help="Filter by file owner (repeatable for OR logic)",
    )
    owner_filters.add_argument(
        "--ad",
        action="store_true",
        help="Owner(s) are Active Directory users",
    )
    owner_filters.add_argument(
        "--local",
        action="store_true",
        help="Owner(s) are local users",
    )
    owner_filters.add_argument(
        "--uid",
        action="store_true",
        help="Owner(s) are specified as UID numbers",
    )
    owner_filters.add_argument(
        "--expand-identity",
        action="store_true",
        help="Match all equivalent identities (e.g., AD user + NFS UID)",
    )

    # ============================================================================
    # UNIVERSAL FILTERS - DIRECTORY SCOPE
    # ============================================================================
    dir_filters = parser.add_argument_group('Universal Filters - Directory Scope',
        'Directory traversal filters that work with all features')

    dir_filters.add_argument(
        "--max-depth",
        type=int,
        help="Maximum directory depth to search",
    )
    dir_filters.add_argument(
        "--file-only",
        action="store_true",
        help="Search files only, exclude directories (deprecated, use --type file)",
    )
    dir_filters.add_argument(
        "--omit-subdirs",
        action="append",
        help="Omit subdirectories matching pattern (supports wildcards, repeatable)",
    )
    dir_filters.add_argument(
        "--omit-path",
        action="append",
        help="Omit specific absolute paths (exact match, repeatable)",
    )
    dir_filters.add_argument(
        "--max-entries-per-dir",
        type=int,
        help="Skip directories with more than N entries",
    )

    # ============================================================================
    # OUTPUT OPTIONS
    # ============================================================================
    output = parser.add_argument_group('Output Options',
        'Control output format and verbosity')

    output.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON to stdout",
    )
    output.add_argument(
        "--json-out",
        help="Write JSON results to file",
    )
    output.add_argument(
        "--csv-out",
        help="Write results to CSV file",
    )
    output.add_argument(
        "--all-attributes",
        action="store_true",
        help="Include all file attributes in JSON output",
    )
    output.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed logging",
    )
    output.add_argument(
        "--progress",
        action="store_true",
        help="Show real-time progress statistics",
    )
    output.add_argument(
        "--limit",
        type=int,
        help="Stop after finding N matching results",
    )
    output.add_argument(
        "--profile",
        action="store_true",
        help="Enable performance profiling and timing metrics",
    )

    # ============================================================================
    # FEATURE: OWNER REPORTS
    # ============================================================================
    owner_report = parser.add_argument_group('Feature: Owner Reports',
        'Generate storage capacity reports by owner')

    owner_report.add_argument(
        "--owner-report",
        action="store_true",
        help="Generate ownership report (file count and capacity by owner)",
    )
    owner_report.add_argument(
        "--show-owner",
        action="store_true",
        help="Display owner information in output (works with all features)",
    )
    owner_report.add_argument(
        "--show-group",
        action="store_true",
        help="Display group information in output (works with all features)",
    )
    owner_report.add_argument(
        "--use-capacity",
        action="store_true",
        default=True,
        help="Use actual disk capacity (datablocks + metablocks) instead of logical size (default: True)",
    )
    owner_report.add_argument(
        "--report-logical-size",
        dest="use_capacity",
        action="store_false",
        help="Report logical file size instead of actual disk capacity",
    )

    # ============================================================================
    # FEATURE: ACL REPORTS
    # ============================================================================
    acl_report = parser.add_argument_group('Feature: ACL Reports',
        'Generate ACL and permissions inventory reports')

    acl_report.add_argument(
        "--acl-report",
        action="store_true",
        help="Generate ACL inventory report showing unique ACLs and affected files",
    )
    acl_report.add_argument(
        "--acl-csv",
        help="Export per-file ACL data to CSV file (requires --acl-report)",
    )
    acl_report.add_argument(
        "--acl-resolve-names",
        action="store_true",
        help="Resolve auth_ids and SIDs to human-readable names in ACL report",
    )

    # ============================================================================
    # FEATURE: ACL AND OWNER/GROUP MANAGEMENT
    # ============================================================================
    acl_management = parser.add_argument_group('Feature: ACL and Owner/Group Management',
        'Copy ACLs, owner, and group between objects')

    acl_management.add_argument(
        "--source-acl",
        help="Source object path",
        metavar="PATH"
    )

    acl_management.add_argument(
        "--acl-target",
        help="Target object/directory path",
        metavar="PATH"
    )

    acl_management.add_argument(
        "--propagate-acls",
        action="store_true",
        help="Apply to all child objects recursively"
    )

    acl_management.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue on permission errors"
    )

    acl_management.add_argument(
        "--copy-owner",
        action="store_true",
        help="Copy owner from source"
    )

    acl_management.add_argument(
        "--copy-group",
        action="store_true",
        help="Copy group from source"
    )

    acl_management.add_argument(
        "--owner-group-only",
        action="store_true",
        help="Copy only owner/group, skip ACL"
    )

    # ============================================================================
    # FEATURE: SIMILARITY DETECTION
    # ============================================================================
    similarity = parser.add_argument_group('Feature: Similarity Detection',
        'Find similar files using adaptive sampling (results are advisory)')

    similarity.add_argument(
        "--find-similar",
        action="store_true",
        help="Find similar files using metadata + sample hashing",
    )
    similarity.add_argument(
        "--by-size",
        action="store_true",
        help="Match by size+metadata only, skip hashing (fast but less accurate)",
    )
    similarity.add_argument(
        "--sample-points",
        type=int,
        choices=range(3, 12),
        metavar="N",
        help="Number of sample points to hash (3-11, default: adaptive based on size)",
    )
    similarity.add_argument(
        "--sample-size",
        type=parse_size_to_bytes,
        metavar="SIZE",
        help="Sample chunk size (e.g., 64KB, 256KB, 1MB, default: 64KB)",
    )
    similarity.add_argument(
        "--estimate-size",
        action="store_true",
        help="Show data transfer estimate and exit without hashing",
    )

    # ============================================================================
    # FEATURE: DIRECTORY EXPLORATION
    # ============================================================================
    exploration = parser.add_argument_group('Feature: Directory Exploration',
        'Explore directory structure without enumerating files')

    exploration.add_argument(
        "--show-dir-stats",
        action="store_true",
        help="Show directory statistics only (no file enumeration)",
    )

    # ============================================================================
    # FEATURE: SYMLINK RESOLUTION
    # ============================================================================
    symlinks = parser.add_argument_group('Feature: Symlink Resolution',
        'Resolve and display symlink targets')

    symlinks.add_argument(
        "--resolve-links",
        action="store_true",
        help="Resolve and display symlink targets (shows 'link -> target')",
    )

    # ============================================================================
    # CONNECTION OPTIONS
    # ============================================================================
    connection = parser.add_argument_group('Connection Options',
        'Configure connection to Qumulo cluster')

    connection.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Qumulo API port (default: 8000)",
    )
    connection.add_argument(
        "--credentials-store",
        help="Path to credentials file (default: ~/.qfsd_cred)",
    )

    # ============================================================================
    # PERFORMANCE TUNING
    # ============================================================================
    performance = parser.add_argument_group('Performance Tuning',
        'Tune concurrency and connection pool settings')

    performance.add_argument(
        "--max-concurrent",
        type=int,
        default=100,
        help="Maximum concurrent operations (default: 100)",
    )
    performance.add_argument(
        "--connector-limit",
        type=int,
        default=100,
        help="Maximum HTTP connections in pool (default: 100)",
    )

    args = parser.parse_args()

    # Validate arguments
    # Check that either --path OR (--source-acl + --acl-target) are provided
    acl_cloning_mode = args.source_acl and args.acl_target
    if not args.path and not acl_cloning_mode:
        print(
            "Error: Either --path is required OR both --source-acl and --acl-target for ACL cloning",
            file=sys.stderr,
        )
        sys.exit(1)

    # Validate owner/group flags
    if (args.copy_owner or args.copy_group) and not args.source_acl:
        print(
            "Error: --copy-owner and --copy-group require --source-acl",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.owner_group_only and not (args.copy_owner or args.copy_group):
        print(
            "Error: --owner-group-only requires at least one of --copy-owner or --copy-group",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.older_than and args.newer_than and args.newer_than >= args.older_than:
        print(
            "Error: --newer-than must be less than --older-than for a valid time range",
            file=sys.stderr,
        )
        sys.exit(1)

    # Check for mutually exclusive CSV and JSON output
    if args.csv_out and (args.json or args.json_out):
        print(
            "Error: --csv-out cannot be used with --json or --json-out", file=sys.stderr
        )
        print("Please choose either CSV or JSON output format", file=sys.stderr)
        sys.exit(1)

    # Run async main
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user", file=sys.stderr)
        sys.exit(130)
    except aiohttp.ClientResponseError as e:
        # HTTP error with detailed message
        path_for_error = args.path if args.path else (args.acl_target if hasattr(args, 'acl_target') else 'N/A')
        error_msg = format_http_error(e.status, str(e.request_info.url), path_for_error)
        print(error_msg, file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    except aiohttp.ClientConnectorError as e:
        print(f"\n[ERROR] Cannot connect to cluster: {args.host}:{args.port}", file=sys.stderr)
        print(f"[HINT] Check that the cluster is reachable and the hostname/port are correct", file=sys.stderr)
        if args.verbose:
            print(f"[DEBUG] {e}", file=sys.stderr)
        sys.exit(1)
    except aiohttp.ClientError as e:
        print(f"\n[ERROR] Network error: {e}", file=sys.stderr)
        print(f"[HINT] Check your network connection to the cluster", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
