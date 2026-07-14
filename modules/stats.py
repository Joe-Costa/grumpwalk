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


class DirectoryMatchStats:
    """Aggregate filtered matches per directory for --per-directory-matches.

    Fed one matched entry at a time from the tree walk. For each match, every
    ancestor directory between the search root and the object's parent is
    credited (recursive, du-style rollup), so a directory's totals include all
    matches anywhere in its subtree. A grand total across the whole tree is
    tracked separately.

    Capacity is actual on-disk usage -- (datablocks + metablocks) * 4096 --
    which reflects what admins care about (allocated space, correct for sparse
    files), falling back to logical size when block counts are absent.
    """

    BLOCK_SIZE = 4096

    def __init__(self, root_path: str):
        """
        Args:
            root_path: The --path search root that all matches live under.
        """
        self.root = self._normalize(root_path)
        # dir_path -> {"files": int, "capacity": int, "depth": int}
        self.dirs: Dict[str, Dict] = {}
        self.total_files = 0
        self.total_capacity = 0

    @staticmethod
    def _normalize(p: str) -> str:
        p = (p or "/").rstrip("/")
        return p or "/"

    def _capacity(self, entry: dict) -> int:
        """On-disk used capacity of an entry, in bytes."""
        datablocks = entry.get("datablocks")
        metablocks = entry.get("metablocks")
        if datablocks is not None or metablocks is not None:
            return (int(datablocks or 0) + int(metablocks or 0)) * self.BLOCK_SIZE
        return int(entry.get("size", 0) or 0)

    def add(self, entry: dict) -> None:
        """Credit one matched entry to the grand total and its ancestor dirs.

        Runs inside the async walk's single-threaded event loop with no awaits,
        so it is atomic with respect to other callbacks (no lock needed).
        """
        path = entry.get("path")
        if not path:
            return

        cap = self._capacity(entry)
        self.total_files += 1
        self.total_capacity += cap

        p = path.rstrip("/")
        if self.root == "/":
            rel = p[1:] if p.startswith("/") else p
        else:
            prefix = self.root + "/"
            if not p.startswith(prefix):
                # Entry equals the root itself or lies outside it: counts toward
                # the grand total only, no intermediate directory bucket.
                return
            rel = p[len(prefix):]

        components = rel.split("/") if rel else []
        # Ancestor directories are the prefixes excluding the final component
        # (the matched object itself). depth == number of components below root.
        for depth in range(1, len(components)):
            if self.root == "/":
                dir_path = "/" + "/".join(components[:depth])
            else:
                dir_path = self.root + "/" + "/".join(components[:depth])
            bucket = self.dirs.get(dir_path)
            if bucket is None:
                self.dirs[dir_path] = {"files": 1, "capacity": cap, "depth": depth}
            else:
                bucket["files"] += 1
                bucket["capacity"] += cap

    def rows(self, subdir_report: bool = False) -> List[Dict]:
        """Return per-directory rows to display.

        Without subdir_report: only the immediate children of the root
        (depth 1), each a rollup of its whole subtree (du -d1 style).
        With subdir_report: every directory that contains matches, at every
        depth reached by the walk (du style).
        """
        rows = []
        for dir_path, bucket in self.dirs.items():
            if not subdir_report and bucket["depth"] != 1:
                continue
            rows.append({
                "path": dir_path,
                "files": bucket["files"],
                "capacity": bucket["capacity"],
                "depth": bucket["depth"],
            })
        return rows
