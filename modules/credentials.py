"""
Credentials and identity cache management for grumpwalk.

This module contains functions for loading Qumulo credentials and managing
the identity resolution cache.
"""

import json
import os
import sys
import time
from typing import Optional, Dict

# Try to use ujson for faster parsing
try:
    import ujson as json_parser
except ImportError:
    import json as json_parser

# Standalone credential management (no cli/cli/ dependencies)
CREDENTIALS_FILENAME = '.qfsd_cred'
CREDENTIALS_VERSION = 1

# Identity cache configuration
IDENTITY_CACHE_FILE = "file_filter_resolved_identities"
IDENTITY_CACHE_TTL = 15 * 60  # 15 minutes in seconds


def credential_store_filename(creds_file_name: str = CREDENTIALS_FILENAME) -> str:
    """Get the path to the credentials store file."""
    if os.path.isabs(creds_file_name):
        return creds_file_name

    home = os.path.expanduser('~')
    if home == '~':
        home = os.environ.get('HOME')

    if home is None or home == '~':
        raise OSError('Could not find home directory for credentials store')

    path = os.path.join(home, creds_file_name)
    if os.path.isdir(path):
        raise OSError('Credentials store is a directory: %s' % path)
    return path


def get_credentials(path: str) -> Optional[str]:
    """
    Load credentials from file and return bearer token.
    Returns None if file doesn't exist or is empty.
    """
    if not os.path.isfile(path):
        return None

    try:
        with open(path) as store:
            if os.fstat(store.fileno()).st_size == 0:
                return None
            contents = json.load(store)

        # Extract bearer_token from the credentials file
        if 'bearer_token' not in contents:
            return None

        bearer_token = contents['bearer_token']
        if not isinstance(bearer_token, str):
            return None

        return bearer_token
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def load_identity_cache(verbose: bool = False) -> Dict:
    """Load identity cache from file, removing expired entries."""
    cache = {}
    cache_timestamp = int(time.time())

    try:
        if os.path.exists(IDENTITY_CACHE_FILE):
            with open(IDENTITY_CACHE_FILE, "r") as f:
                cache_data = json_parser.load(f)

                # Remove expired entries
                expired_count = 0
                for auth_id, entry in list(cache_data.items()):
                    if cache_timestamp - entry.get("timestamp", 0) > IDENTITY_CACHE_TTL:
                        expired_count += 1
                        del cache_data[auth_id]
                    else:
                        # Store full identity data, not just name
                        cache[auth_id] = entry.get("identity", {})

                # Write cleaned cache back to file if entries were expired
                if expired_count > 0:
                    save_identity_cache(cache, verbose=False)

            if verbose and cache:
                print(
                    f"[INFO] Loaded {len(cache)} cached identities from {IDENTITY_CACHE_FILE}",
                    file=sys.stderr,
                )
                if expired_count > 0:
                    print(
                        f"[INFO] Removed {expired_count} expired cache entries",
                        file=sys.stderr,
                    )
    except Exception as e:
        if verbose:
            print(f"[WARN] Failed to load identity cache: {e}", file=sys.stderr)

    return cache


def save_identity_cache(identity_cache: Dict, verbose: bool = False):
    """Save identity cache to file."""
    try:
        cache_data = {}
        cache_timestamp = int(time.time())

        for auth_id, identity in identity_cache.items():
            cache_data[auth_id] = {"identity": identity, "timestamp": cache_timestamp}

        with open(IDENTITY_CACHE_FILE, "w") as f:
            json_parser.dump(cache_data, f, indent=2)

        if verbose:
            print(
                f"[INFO] Saved {len(identity_cache)} identities to cache file",
                file=sys.stderr,
            )
    except Exception as e:
        if verbose:
            print(f"[WARN] Failed to save identity cache: {e}", file=sys.stderr)
