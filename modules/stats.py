"""
Statistics tracking classes for grumpwalk.

This module contains classes for tracking file ownership statistics
and generating reports.
"""

import asyncio
from typing import List, Dict


class OwnerStats:
    """Track file ownership statistics for --owner-report."""

    def __init__(self, use_capacity: bool = False):
        """
        Initialize owner statistics tracker.

        Args:
            use_capacity: If True, use actual disk usage (datablocks + metablocks).
                         If False, use logical file size. Set to True to handle sparse files correctly.
        """
        self.owner_data = {}  # auth_id -> {'bytes': int, 'files': int, 'dirs': int}
        self.lock = asyncio.Lock()
        self.use_capacity = use_capacity

    async def add_file(self, owner_auth_id: str, size: int, is_dir: bool = False):
        """Add a file to the owner statistics."""
        async with self.lock:
            if owner_auth_id not in self.owner_data:
                self.owner_data[owner_auth_id] = {"bytes": 0, "files": 0, "dirs": 0}

            self.owner_data[owner_auth_id]["bytes"] += size
            if is_dir:
                self.owner_data[owner_auth_id]["dirs"] += 1
            else:
                self.owner_data[owner_auth_id]["files"] += 1

    def get_all_owners(self) -> List[str]:
        """Get list of all unique owner auth_ids."""
        return list(self.owner_data.keys())

    def get_stats(self, owner_auth_id: str) -> Dict:
        """Get statistics for a specific owner."""
        return self.owner_data.get(owner_auth_id, {"bytes": 0, "files": 0, "dirs": 0})
