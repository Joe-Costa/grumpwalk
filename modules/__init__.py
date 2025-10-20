"""
Grumpwalk modules package.

This package contains modular components for the grumpwalk file search tool.
"""

# Import utility functions
from .utils import (
    format_http_error,
    extract_pagination_token,
    parse_size_to_bytes,
    format_bytes,
    format_time,
    format_owner_name,
)

# Import output/progress classes
from .output import (
    ProgressTracker,
    BatchedOutputHandler,
    Profiler,
)

# Import credentials and cache handling
from .credentials import (
    CREDENTIALS_FILENAME,
    CREDENTIALS_VERSION,
    IDENTITY_CACHE_FILE,
    IDENTITY_CACHE_TTL,
    credential_store_filename,
    get_credentials,
    load_identity_cache,
    save_identity_cache,
)

# Import statistics classes
from .stats import (
    OwnerStats,
)

# Import async Qumulo API client
from .client import (
    AsyncQumuloClient,
)

# Import filtering functions
from .filters import (
    resolve_owner_filters,
    glob_to_regex,
    create_file_filter,
)

__all__ = [
    # Utils
    "format_http_error",
    "extract_pagination_token",
    "parse_size_to_bytes",
    "format_bytes",
    "format_time",
    "format_owner_name",
    # Output
    "ProgressTracker",
    "BatchedOutputHandler",
    "Profiler",
    # Credentials
    "CREDENTIALS_FILENAME",
    "CREDENTIALS_VERSION",
    "IDENTITY_CACHE_FILE",
    "IDENTITY_CACHE_TTL",
    "credential_store_filename",
    "get_credentials",
    "load_identity_cache",
    "save_identity_cache",
    # Stats
    "OwnerStats",
    # Client
    "AsyncQumuloClient",
    # Filters
    "resolve_owner_filters",
    "glob_to_regex",
    "create_file_filter",
]
