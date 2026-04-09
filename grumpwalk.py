#!/usr/bin/env python3

"""
Qumulo File Filter and API Tree Walk Tool

Usage:
    ./grumpwalk.py --host <cluster> --path <path> [OPTIONS]

"""

__version__ = "2.6.1"

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

# Optional argcomplete support for bash completion
try:
    import argcomplete
    ARGCOMPLETE_AVAILABLE = True
except ImportError:
    ARGCOMPLETE_AVAILABLE = False

# Import modular components
from modules import (
    log_stderr,
    log_to_file,
    init_log_file,
    close_log_file,
    LOG_LEVELS,
    format_http_error,
    extract_pagination_token,
    parse_size_to_bytes,
    format_bytes,
    format_time,
    format_raw_id,
    format_owner_name,
    ProgressTracker,
    BatchedOutputHandler,
    StreamingFileOutputHandler,
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
    AsyncQumuloClient,
    resolve_owner_filters,
    glob_to_regex,
    create_file_filter,
    FINDABLE_ATTRIBUTES,
    SETTABLE_ATTRIBUTES,
    parse_attribute_list,
    parse_field_specs,
    extract_fields,
    convert_timestamps_to_epoch,
)
from modules.tuning import (
    load_tuning_profile,
    save_tuning_profile,
    generate_tuning_profile,
    format_profile_summary,
    format_benchmark_results,
    suggest_from_benchmark,
    get_profile_path,
    BENCHMARK_CONCURRENCY_LEVELS,
    BENCHMARK_FILE_LIMIT,
)

try:
    import aiohttp
except ImportError:
    log_stderr("ERROR", "aiohttp not installed. Install with: pip install aiohttp")
    sys.exit(1)

# Try to use ujson for faster parsing
try:
    import ujson as json_parser

    JSON_PARSER_NAME = "ujson"
except ImportError:
    import json as json_parser

    JSON_PARSER_NAME = "json"

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
        elif domain in ('AD_USER', 'AD_GROUP', 'ACTIVE_DIRECTORY'):
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


# ============================================================================
# ACE MANIPULATION FUNCTIONS
# ============================================================================

# Reverse mapping: NFSv4 shorthand -> Qumulo rights
NFSV4_TO_QACL_RIGHTS = {
    'r': 'READ',
    'w': 'MODIFY',
    'a': 'EXTEND',
    'x': 'EXECUTE',
    'd': 'DELETE',
    'D': 'DELETE_CHILD',
    't': 'READ_ATTR',
    'T': 'WRITE_ATTR',
    'n': 'READ_EA',
    'N': 'WRITE_EA',
    'c': 'READ_ACL',
    'C': 'WRITE_ACL',
    'o': 'CHANGE_OWNER',
    'y': 'SYNCHRONIZE',
}

# Reverse mapping: NFSv4 shorthand -> Qumulo flags
NFSV4_TO_QACL_FLAGS = {
    'f': 'OBJECT_INHERIT',
    'd': 'CONTAINER_INHERIT',
    'n': 'NO_PROPAGATE_INHERIT',
    'i': 'INHERIT_ONLY',
    'I': 'INHERITED',
}

# Windows Explorer-style permission presets
# These map to Qumulo rights to match Windows behavior
WINDOWS_PERMISSION_PRESETS = {
    # Read: View files/folders and their attributes
    'read': [
        'READ', 'READ_EA', 'READ_ATTR', 'READ_ACL', 'EXECUTE', 'SYNCHRONIZE'
    ],
    'r': None,  # Single 'r' handled by NFSv4 mapping

    # Write: Create files/folders, modify attributes (but not delete or read)
    # Note: DELETE_CHILD is only in Full Control
    'write': [
        'MODIFY', 'EXTEND', 'WRITE_EA', 'WRITE_ATTR', 'SYNCHRONIZE'
    ],

    # Read+Execute: Same as Read (Execute is included in Read for traversal)
    'readexecute': [
        'READ', 'READ_EA', 'READ_ATTR', 'READ_ACL', 'EXECUTE', 'SYNCHRONIZE'
    ],
    'rx': None,  # Handled by NFSv4

    # Modify: Read + Write + Delete (everything except DELETE_CHILD, change permissions/ownership)
    # Note: DELETE_CHILD ("Delete subfolders and files") is only in Full Control, not Modify
    'modify': [
        'READ', 'MODIFY', 'EXTEND', 'EXECUTE', 'DELETE',
        'READ_ATTR', 'WRITE_ATTR', 'READ_EA', 'WRITE_EA', 'READ_ACL', 'SYNCHRONIZE'
    ],

    # Full Control: All rights including permission and ownership changes
    'fullcontrol': [
        'READ', 'MODIFY', 'EXTEND', 'EXECUTE', 'DELETE', 'DELETE_CHILD',
        'READ_ATTR', 'WRITE_ATTR', 'READ_EA', 'WRITE_EA',
        'READ_ACL', 'WRITE_ACL', 'CHANGE_OWNER', 'SYNCHRONIZE'
    ],
    'full': [
        'READ', 'MODIFY', 'EXTEND', 'EXECUTE', 'DELETE', 'DELETE_CHILD',
        'READ_ATTR', 'WRITE_ATTR', 'READ_EA', 'WRITE_EA',
        'READ_ACL', 'WRITE_ACL', 'CHANGE_OWNER', 'SYNCHRONIZE'
    ],
}

# Well-known trustee names that map to specific identities
WELL_KNOWN_TRUSTEES = {
    'everyone': {'sid': 'S-1-1-0', 'name': 'Everyone'},
    'everyone@': {'sid': 'S-1-1-0', 'name': 'Everyone'},
    'owner@': {'special': 'OWNER'},
    'group@': {'special': 'GROUP'},
}


def nfsv4_rights_to_qacl(rights_str: str) -> List[str]:
    """
    Convert rights specification to Qumulo rights list.

    Supports:
    - NFSv4 shorthand: 'rwx', 'rwaxdDtTnNcCoy'
    - Windows presets: 'Read', 'Write', 'Modify', 'FullControl', 'Full'
    - Combined: 'Read+Write' or 'Modify+Co' (preset plus NFSv4 extras)

    Args:
        rights_str: Rights specification string

    Returns:
        List of Qumulo rights like ['READ', 'MODIFY', 'EXECUTE']
    """
    rights = set()  # Use set to avoid duplicates

    # Check for Windows preset first (case-insensitive)
    rights_lower = rights_str.lower().replace(' ', '').replace('_', '')

    # Handle combined presets like "Read+Write" or "Modify+Co"
    if '+' in rights_str:
        parts = rights_str.split('+')
        for part in parts:
            part_rights = nfsv4_rights_to_qacl(part.strip())
            rights.update(part_rights)
        return list(rights)

    # Check for Windows preset
    if rights_lower in WINDOWS_PERMISSION_PRESETS:
        preset = WINDOWS_PERMISSION_PRESETS[rights_lower]
        if preset is not None:
            return preset.copy()
        # If preset is None, fall through to NFSv4 handling

    # NFSv4 shorthand parsing
    for char in rights_str:
        if char in NFSV4_TO_QACL_RIGHTS:
            rights.add(NFSV4_TO_QACL_RIGHTS[char])
        elif char in ' +':
            continue  # Skip separators
        else:
            log_stderr("WARN", f"Unknown right character '{char}' in pattern")

    return list(rights)


def nfsv4_flags_to_qacl(flags_str: str) -> List[str]:
    """
    Convert NFSv4 flags shorthand to Qumulo flags list.

    Args:
        flags_str: String like 'fd' or 'fdI'

    Returns:
        List of Qumulo flags like ['OBJECT_INHERIT', 'CONTAINER_INHERIT']
    """
    flags = []
    for char in flags_str:
        if char in NFSV4_TO_QACL_FLAGS:
            flags.append(NFSV4_TO_QACL_FLAGS[char])
        elif char == 'g':
            pass  # 'g' is group indicator, not a flag
        else:
            log_stderr("WARN", f"Unknown flag character '{char}' in pattern")
    return flags


def parse_ace_pattern(pattern: str, pattern_type: str = 'remove') -> dict:
    """
    Parse ACE pattern strings into structured dict.

    Formats:
    - 'Type:Trustee' for removal (e.g., 'Allow:Everyone')
    - 'Type:Trustee:Rights' for rights modification (e.g., 'Allow:Everyone:rx')
    - 'Type:Flags:Trustee:Rights' for adding (e.g., 'Allow:fd:jsmith:rwx')

    Args:
        pattern: The pattern string to parse
        pattern_type: One of 'remove', 'add', 'add_rights', 'remove_rights'

    Returns:
        Dict with keys: type, flags, trustee, rights, raw_trustee
        Returns None if pattern is invalid
    """
    parts = pattern.split(':')

    result = {
        'type': None,
        'flags': [],
        'trustee': None,
        'rights': [],
        'raw_trustee': None,
    }

    # Parse ACE type (Allow/Deny)
    if len(parts) < 2:
        log_stderr("ERROR", f"Invalid ACE pattern '{pattern}': expected at least Type:Trustee")
        return None

    ace_type = parts[0].upper()
    if ace_type in ('ALLOW', 'ALLOWED', 'A'):
        result['type'] = 'ALLOWED'
    elif ace_type in ('DENY', 'DENIED', 'D'):
        result['type'] = 'DENIED'
    else:
        log_stderr("ERROR", f"Invalid ACE type '{parts[0]}': expected Allow or Deny")
        return None

    if pattern_type == 'remove':
        # Format: Type:Trustee
        if len(parts) != 2:
            log_stderr("ERROR", f"Invalid remove pattern '{pattern}': expected Type:Trustee")
            return None
        result['raw_trustee'] = parts[1]

    elif pattern_type in ('add_rights', 'remove_rights'):
        # Format: Type:Trustee:Rights
        if len(parts) != 3:
            log_stderr("ERROR", f"Invalid rights pattern '{pattern}': expected Type:Trustee:Rights")
            return None
        result['raw_trustee'] = parts[1]
        result['rights'] = nfsv4_rights_to_qacl(parts[2])

    elif pattern_type == 'add':
        # Format: Type:Flags:Trustee:Rights
        if len(parts) != 4:
            log_stderr("ERROR", f"Invalid add pattern '{pattern}': expected Type:Flags:Trustee:Rights")
            return None
        result['flags'] = nfsv4_flags_to_qacl(parts[1])
        result['raw_trustee'] = parts[2]
        result['rights'] = nfsv4_rights_to_qacl(parts[3])

    return result


def normalize_trustee_for_match(trustee_info: dict) -> str:
    """
    Create a normalized string representation of a trustee for matching.

    Handles both API formats:
    - Current: trustee is auth_id string, trustee_details has id_type/id_value
    - Legacy: trustee is dict with domain, sid, uid, gid, name

    Args:
        trustee_info: Dict with 'trustee' and optionally 'trustee_details'

    Returns:
        Normalized string for comparison (lowercase)
    """
    trustee = trustee_info.get('trustee')
    details = trustee_info.get('trustee_details', {})

    # Check for well-known SID (Everyone)
    if details.get('id_value') == 'S-1-1-0':
        return 'everyone'
    if isinstance(trustee, dict) and trustee.get('sid') == 'S-1-1-0':
        return 'everyone'

    # Try id_value from details
    id_type = details.get('id_type', '')
    id_value = details.get('id_value', '')

    if id_type == 'NFS_UID':
        return f'uid:{id_value}'.lower()
    elif id_type == 'NFS_GID':
        return f'gid:{id_value}'.lower()
    elif id_type == 'SMB_SID':
        return f'sid:{id_value}'.lower()
    elif id_type in ('LOCAL_USER', 'LOCAL_GROUP'):
        return id_value.lower() if id_value else str(trustee).lower()

    # Legacy format handling
    if isinstance(trustee, dict):
        domain = trustee.get('domain', '')
        name = trustee.get('name', '')
        sid = trustee.get('sid', '')
        uid = trustee.get('uid')
        gid = trustee.get('gid')

        if domain == 'WORLD':
            return 'everyone'
        elif domain == 'POSIX_USER' and uid is not None:
            return f'uid:{uid}'
        elif domain == 'POSIX_GROUP' and gid is not None:
            return f'gid:{gid}'
        elif name:
            return name.lower()
        elif sid:
            return f'sid:{sid}'.lower()

    # Fallback to auth_id
    return str(trustee).lower()


def normalize_pattern_trustee(raw_trustee: str) -> str:
    """
    Normalize a user-provided trustee pattern for matching.

    Args:
        raw_trustee: User input like 'Everyone', 'uid:1001', 'DOMAIN\\user'

    Returns:
        Normalized string for comparison (lowercase)
    """
    trustee = raw_trustee.strip().lower()

    # Handle well-known names
    if trustee in ('everyone', 'everyone@'):
        return 'everyone'

    # Handle prefixed formats
    if trustee.startswith('uid:') or trustee.startswith('gid:') or trustee.startswith('sid:'):
        return trustee

    # Handle domain\\user format (normalize backslash)
    if '\\' in trustee:
        return trustee.replace('\\\\', '\\')

    return trustee


def match_ace(ace: dict, pattern: dict) -> bool:
    """
    Check if an ACE matches a pattern (by type and trustee).

    Args:
        ace: ACE dict from API with type, trustee, trustee_details
        pattern: Parsed pattern dict with type, raw_trustee, and optionally resolved_auth_id

    Returns:
        True if ACE matches the pattern
    """
    # Check type match
    if ace.get('type') != pattern.get('type'):
        return False

    # If pattern has resolved auth_id, compare directly
    if pattern.get('resolved_auth_id'):
        # Extract auth_id from ACE trustee (may be dict or string)
        ace_trustee = ace.get('trustee')
        if isinstance(ace_trustee, dict):
            ace_auth_id = str(ace_trustee.get('auth_id', ''))
        else:
            ace_auth_id = str(ace_trustee) if ace_trustee else ''
        # Ensure both are strings for comparison
        pattern_auth_id = str(pattern['resolved_auth_id'])
        return ace_auth_id == pattern_auth_id

    # Fall back to normalized string comparison
    ace_trustee = normalize_trustee_for_match({
        'trustee': ace.get('trustee'),
        'trustee_details': ace.get('trustee_details', {})
    })
    pattern_trustee = normalize_pattern_trustee(pattern.get('raw_trustee', ''))

    return ace_trustee == pattern_trustee


async def resolve_pattern_trustees(
    client: 'AsyncQumuloClient',
    session: 'aiohttp.ClientSession',
    patterns: List[dict],
    verbose: bool = False
) -> None:
    """
    Resolve trustees in patterns to auth_ids for accurate matching.

    Modifies patterns in-place, adding 'resolved_auth_id' field.
    Uses the client's persistent_identity_cache for performance.

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp session
        patterns: List of parsed patterns with 'raw_trustee' field
        verbose: Whether to print verbose output
    """
    for pattern in patterns:
        raw_trustee = pattern.get('raw_trustee')
        if not raw_trustee:
            continue

        # Check for well-known trustees that don't need resolution
        trustee_lower = raw_trustee.lower()
        if trustee_lower in ('everyone', 'everyone@'):
            # Everyone has well-known auth_id
            pattern['resolved_auth_id'] = '8589934592'  # Well-known Everyone auth_id
            if verbose:
                log_stderr("INFO", f"'{raw_trustee}' -> auth_id 8589934592 (Everyone)")
            continue

        # Use parse_trustee to get the right format for identity resolution
        trustee_spec = parse_trustee(raw_trustee)
        payload = trustee_spec['payload']
        id_type = trustee_spec['type']

        # Extract identifier from payload
        if id_type == 'uid':
            identifier = payload.get('uid')
        elif id_type == 'gid':
            identifier = payload.get('gid')
        elif id_type == 'sid':
            identifier = payload.get('sid')
        elif id_type == 'auth_id':
            identifier = payload.get('auth_id')
            # If already an auth_id, use it directly
            pattern['resolved_auth_id'] = str(identifier)
            if verbose:
                log_stderr("INFO", f"'{raw_trustee}' is already auth_id {identifier}")
            continue
        else:  # name
            identifier = payload.get('name')

        # Resolve to auth_id using identity API
        if verbose:
            log_stderr("INFO", f"Resolving trustee '{raw_trustee}' ({id_type})...")

        resolved = await client.resolve_identity(session, identifier, id_type)

        if resolved and resolved.get('auth_id'):
            auth_id = str(resolved['auth_id'])
            pattern['resolved_auth_id'] = auth_id
            # Always show resolution result
            log_stderr("INFO", f"Resolved '{raw_trustee}' -> auth_id {auth_id}")

            # Cache the resolved identity for future use
            if auth_id not in client.persistent_identity_cache:
                client.persistent_identity_cache[auth_id] = resolved
        else:
            log_stderr("WARN", f"Could not resolve trustee '{raw_trustee}' - matching may fail")


def normalize_acl_for_put(acl: dict) -> dict:
    """
    Normalize ACL for PUT request to Qumulo API v2.

    The v2 API accepts trustee as either:
    - Full object: {"auth_id": "123", "name": "...", ...}
    - Simple string: "123" (auth_id only)

    This function removes internal marker fields and read-only fields,
    but preserves trustee format from the source.

    Args:
        acl: ACL dict (possibly with nested 'acl' key)

    Returns:
        Normalized ACL ready for PUT request
    """
    import copy
    result = copy.deepcopy(acl)

    # Handle nested structure
    if 'acl' in result and 'aces' not in result:
        inner = result['acl']
    else:
        inner = result

    # Clean each ACE - remove internal marker fields but keep trustee format
    for ace in inner.get('aces', []):
        # Remove internal marker fields
        ace.pop('_needs_resolution', None)
        ace.pop('trustee_details', None)

    # Remove 'generated' field if present (read-only field from GET response)
    result.pop('generated', None)
    if 'acl' in result:
        result['acl'].pop('generated', None)

    return result


def sort_aces_canonical(aces: List[dict]) -> List[dict]:
    """
    Sort ACEs into Windows canonical order.

    Order:
    1. Explicit DENY (no INHERITED flag)
    2. Explicit ALLOW (no INHERITED flag)
    3. Inherited DENY (with INHERITED flag)
    4. Inherited ALLOW (with INHERITED flag)

    Args:
        aces: List of ACE dicts

    Returns:
        Sorted list of ACE dicts
    """
    def ace_sort_key(ace: dict) -> tuple:
        is_inherited = 'INHERITED' in ace.get('flags', [])
        is_deny = ace.get('type') == 'DENIED'
        # Sort order: (inherited?, not deny?) -> (0,0), (0,1), (1,0), (1,1)
        return (is_inherited, not is_deny)

    return sorted(aces, key=ace_sort_key)


def break_acl_inheritance(acl: dict) -> dict:
    """
    Break inheritance at this path by converting inherited ACEs to explicit.

    This:
    1. Removes 'INHERITED' flag from all ACEs
    2. Adds 'PROTECTED' to control flags (blocks parent inheritance)
    3. Removes 'AUTO_INHERIT' from control flags
    4. Keeps 'PRESENT' in control flags

    Args:
        acl: ACL dict (may have nested 'acl' structure)

    Returns:
        Modified ACL dict with inheritance broken
    """
    import copy
    result = copy.deepcopy(acl)

    # Handle nested structure
    if 'acl' in result and 'aces' not in result:
        inner = result['acl']
    else:
        inner = result

    # Remove INHERITED flag from all ACEs
    for ace in inner.get('aces', []):
        flags = ace.get('flags', [])
        if 'INHERITED' in flags:
            flags.remove('INHERITED')
            ace['flags'] = flags

    # Update control flags
    control = set(inner.get('control', []))
    control.add('PRESENT')
    control.add('PROTECTED')
    control.discard('AUTO_INHERIT')
    inner['control'] = list(control)

    return result


def needs_inheritance_break(acl: dict, patterns: List[dict]) -> bool:
    """
    Check if any pattern targets an inherited ACE.

    Args:
        acl: ACL dict
        patterns: List of parsed patterns

    Returns:
        True if any pattern matches an inherited ACE
    """
    # Handle nested structure
    if 'acl' in acl and 'aces' not in acl:
        aces = acl['acl'].get('aces', [])
    else:
        aces = acl.get('aces', [])

    for ace in aces:
        if 'INHERITED' in ace.get('flags', []):
            for pattern in patterns:
                if match_ace(ace, pattern):
                    return True
    return False


def apply_ace_modifications(
    acl: dict,
    remove_patterns: List[dict],
    add_aces: List[dict],
    add_rights_patterns: List[dict],
    remove_rights_patterns: List[dict],
    replace_aces: List[Tuple[dict, dict]] = None,
    clone_patterns: List[dict] = None,
    migrate_patterns: List[dict] = None,
    sync_cloned_aces: bool = False,
    verbose: bool = False
) -> Tuple[dict, dict]:
    """
    Apply all ACE modifications to an ACL in memory.

    Processing order:
    1. Check if inheritance break needed, apply if so
    2. Remove matching ACEs
    3. Remove rights from matching ACEs (delete if empty)
    4. Add rights to matching ACEs (merge)
    5. Replace ACEs (full replacement or type-changing replacement)
    6. Add new ACEs (merge if same type+trustee exists)
    7. Migrate trustees (in-place replacement from source to target)
    8. Clone ACEs from source trustee to target trustee (or sync if exists)
    9. Re-sort into canonical order

    Args:
        acl: ACL dict to modify
        remove_patterns: Patterns for ACEs to remove
        add_aces: Patterns for ACEs to add (merge rights if exists)
        add_rights_patterns: Patterns for rights to add
        remove_rights_patterns: Patterns for rights to remove
        replace_aces: List of tuples (find_pattern, new_ace_pattern).
                      If new_ace_pattern is None, in-place replacement.
                      If new_ace_pattern is provided, full replacement (can change type).
        clone_patterns: List of dicts with source_auth_id, target_auth_id, target_trustee
                       for cloning ACEs from one trustee to another.
        migrate_patterns: List of dicts with source_auth_id, target_trustee for in-place
                         trustee replacement (domain migration).
        sync_cloned_aces: If True, update existing target ACEs to match source rights.
                         If False (default), skip if target ACE already exists.

    Returns:
        Tuple of (modified_acl, stats_dict)
        stats_dict has keys: removed, added, modified, cloned, synced, migrated, inheritance_broken
    """
    import copy
    result = copy.deepcopy(acl)

    if replace_aces is None:
        replace_aces = []
    if clone_patterns is None:
        clone_patterns = []
    if migrate_patterns is None:
        migrate_patterns = []

    stats = {
        'removed': 0,
        'added': 0,
        'modified': 0,
        'replaced': 0,
        'cloned': 0,
        'synced': 0,
        'migrated': 0,
        'inheritance_broken': False,
    }

    # Handle nested structure
    if 'acl' in result and 'aces' not in result:
        inner = result['acl']
    else:
        inner = result

    aces = inner.get('aces', [])

    # Collect all patterns that might affect inherited ACEs
    # Flatten replace_aces tuples - only need find_patterns for inheritance check
    replace_find_patterns = [find_pat for find_pat, _ in replace_aces]
    all_patterns = remove_patterns + add_rights_patterns + remove_rights_patterns + replace_find_patterns
    if needs_inheritance_break(acl, all_patterns):
        result = break_acl_inheritance(result)
        stats['inheritance_broken'] = True
        # Re-get inner after breaking inheritance
        if 'acl' in result and 'aces' not in result:
            inner = result['acl']
        else:
            inner = result
        aces = inner.get('aces', [])

    # 1. Remove matching ACEs
    new_aces = []
    for ace in aces:
        should_remove = False
        for pattern in remove_patterns:
            ace_type = ace.get('type')
            ace_trustee = ace.get('trustee')
            # Extract auth_id from trustee (may be dict or string)
            if isinstance(ace_trustee, dict):
                ace_auth_id = str(ace_trustee.get('auth_id', ''))
            else:
                ace_auth_id = str(ace_trustee) if ace_trustee else ''
            pat_type = pattern.get('type')
            pat_auth_id = pattern.get('resolved_auth_id')
            if verbose:
                log_stderr("DEBUG", f"ACE type='{ace_type}' auth_id='{ace_auth_id}' vs pattern type='{pat_type}' auth_id='{pat_auth_id}'")
            if match_ace(ace, pattern):
                should_remove = True
                stats['removed'] += 1
                if verbose:
                    log_stderr("DEBUG", "  -> MATCH - will remove")
                break
        if not should_remove:
            new_aces.append(ace)
    aces = new_aces

    # 2. Remove rights from matching ACEs
    for pattern in remove_rights_patterns:
        for ace in aces:
            if match_ace(ace, pattern):
                rights_to_remove = set(pattern.get('rights', []))
                current_rights = set(ace.get('rights', []))
                new_rights = current_rights - rights_to_remove
                if new_rights != current_rights:
                    stats['modified'] += 1
                ace['rights'] = list(new_rights)

    # Remove ACEs with no rights left
    aces = [ace for ace in aces if ace.get('rights')]

    # 3. Add rights to matching ACEs
    for pattern in add_rights_patterns:
        matched = False
        for ace in aces:
            if match_ace(ace, pattern):
                rights_to_add = set(pattern.get('rights', []))
                current_rights = set(ace.get('rights', []))
                new_rights = current_rights | rights_to_add
                if new_rights != current_rights:
                    stats['modified'] += 1
                ace['rights'] = list(new_rights)
                matched = True
        if not matched:
            log_stderr("WARN", "No matching ACE found for --add-rights pattern")

    # 4. Replace ACEs (full replacement or type-changing replacement)
    for find_pattern, new_ace_pattern in replace_aces:
        matching_indices = []

        if verbose:
            log_stderr("DEBUG", f"Looking for ACE: type={find_pattern.get('type')} trustee={find_pattern.get('raw_trustee')} resolved_auth_id={find_pattern.get('resolved_auth_id')}")

        # First pass: find ALL matching ACEs
        for i, ace in enumerate(aces):
            if verbose:
                ace_trustee = ace.get('trustee')
                if isinstance(ace_trustee, dict):
                    ace_auth_id = ace_trustee.get('auth_id', '')
                else:
                    ace_auth_id = ace_trustee
                log_stderr("DEBUG", f"  Checking ACE[{i}]: type={ace.get('type')} auth_id={ace_auth_id}")
            if match_ace(ace, find_pattern):
                matching_indices.append(i)
                if verbose:
                    log_stderr("DEBUG", f"  -> MATCH at index {i}")

        if matching_indices:
            # Replace first match, remove any duplicates
            first_idx = matching_indices[0]
            if new_ace_pattern is not None:
                # Paired mode: replace with entirely new ACE (can change type)
                new_ace = {
                    'type': new_ace_pattern['type'],
                    'flags': new_ace_pattern.get('flags', []),
                    'trustee': new_ace_pattern.get('raw_trustee'),
                    'rights': new_ace_pattern.get('rights', []),
                    '_needs_resolution': True,
                }
                aces[first_idx] = new_ace
                if verbose:
                    log_stderr("DEBUG", f"Replaced ACE[{first_idx}] {find_pattern.get('type')}:{find_pattern.get('raw_trustee')} with {new_ace_pattern.get('type')}:{new_ace_pattern.get('raw_trustee')}")
            else:
                # In-place mode: update flags and rights only (same type+trustee)
                aces[first_idx]['flags'] = find_pattern.get('flags', [])
                aces[first_idx]['rights'] = find_pattern.get('rights', [])
                if verbose:
                    log_stderr("DEBUG", f"Replaced ACE[{first_idx}] in-place for {find_pattern.get('raw_trustee')}")
            stats['replaced'] += 1

            # Remove duplicate matching ACEs (in reverse order to preserve indices)
            if len(matching_indices) > 1:
                for dup_idx in reversed(matching_indices[1:]):
                    if verbose:
                        log_stderr("DEBUG", f"Removing duplicate ACE at index {dup_idx}")
                    del aces[dup_idx]
                    stats['removed'] += 1

        if not matching_indices:
            # No matching ACE found
            if new_ace_pattern is not None:
                # Paired mode (--replace-ace X --new-ace Y): Don't create if X not found
                # This is a transformation operation, not "ensure exists"
                log_stderr("WARN", f"No matching {find_pattern.get('type')} ACE found for trustee '{find_pattern.get('raw_trustee')}' - skipping (nothing to replace)")
            else:
                # Non-paired mode (--replace-ace only): Create new ACE if not found
                log_stderr("WARN", f"No matching {find_pattern.get('type')} ACE found for trustee '{find_pattern.get('raw_trustee')}' - creating new ACE")
                new_ace = {
                    'type': find_pattern['type'],
                    'flags': find_pattern.get('flags', []),
                    'trustee': find_pattern.get('raw_trustee'),
                    'rights': find_pattern.get('rights', []),
                    '_needs_resolution': True,
                }
                aces.append(new_ace)
                stats['added'] += 1
                if verbose:
                    log_stderr("DEBUG", f"Adding new ACE for {find_pattern.get('raw_trustee')}")

    # 6. Add new ACEs (merge if same type+trustee exists)
    for pattern in add_aces:
        merged = False
        for ace in aces:
            if match_ace(ace, pattern):
                # Merge rights into existing ACE
                existing_rights = set(ace.get('rights', []))
                new_rights = set(pattern.get('rights', []))
                ace['rights'] = list(existing_rights | new_rights)
                stats['modified'] += 1
                merged = True
                break

        if not merged:
            # Create new ACE (trustee will need to be resolved to auth_id later)
            new_ace = {
                'type': pattern['type'],
                'flags': pattern.get('flags', []),
                'trustee': pattern.get('raw_trustee'),  # Will be resolved later
                'rights': pattern.get('rights', []),
                '_needs_resolution': True,  # Marker for trustee resolution
            }
            aces.append(new_ace)
            stats['added'] += 1

    # 7. Migrate trustees (in-place replacement from source to target)
    for mp in migrate_patterns:
        source_auth_id = mp.get('source_auth_id')
        target_trustee = mp.get('target_trustee')
        target_auth_id = mp.get('target_auth_id')

        if not source_auth_id or not target_trustee:
            if verbose:
                log_stderr("DEBUG", f"Skipping migrate pattern - missing auth_id or target: source={source_auth_id}, target={target_trustee}")
            continue

        # Find all ACEs matching the source trustee and migrate them
        aces_to_remove = []
        for ace in aces:
            ace_trustee = ace.get('trustee')
            if isinstance(ace_trustee, dict):
                ace_auth_id = str(ace_trustee.get('auth_id', ''))
            else:
                ace_auth_id = str(ace_trustee) if ace_trustee else ''

            if ace_auth_id == str(source_auth_id):
                ace_type = ace.get('type')

                # Check if target already has an ACE of the same type (by auth_id)
                existing_target_ace = None
                if target_auth_id:
                    for other_ace in aces:
                        if other_ace is ace:
                            continue
                        if other_ace in aces_to_remove:
                            continue  # Skip ACEs we're already removing
                        other_type = other_ace.get('type')
                        if other_type != ace_type:
                            continue
                        other_trustee = other_ace.get('trustee')
                        if isinstance(other_trustee, dict):
                            other_auth_id = str(other_trustee.get('auth_id', ''))
                        else:
                            other_auth_id = str(other_trustee) if other_trustee else ''
                        if other_auth_id == target_auth_id:
                            existing_target_ace = other_ace
                            break

                if existing_target_ace:
                    # Merge rights into existing target ACE
                    existing_rights = set(existing_target_ace.get('rights', []))
                    source_rights = set(ace.get('rights', []))
                    merged_rights = existing_rights | source_rights
                    existing_target_ace['rights'] = list(merged_rights)
                    aces_to_remove.append(ace)
                    stats['migrated'] += 1
                    if verbose:
                        log_stderr("DEBUG", f"Merged {ace_type} ACE rights from {source_auth_id} into existing {target_trustee} ACE")
                else:
                    # No existing target - replace trustee in-place
                    ace['trustee'] = target_trustee
                    ace['_needs_resolution'] = True
                    stats['migrated'] += 1
                    if verbose:
                        log_stderr("DEBUG", f"Migrated {ace_type} ACE from {source_auth_id} to {target_trustee}")

        # Remove ACEs that were merged into existing targets
        for ace in aces_to_remove:
            aces.remove(ace)

    # 8. Clone ACEs from source trustee to target trustee (or sync if exists)
    for cp in clone_patterns:
        source_auth_id = cp.get('source_auth_id')
        target_auth_id = cp.get('target_auth_id')

        if not source_auth_id or not target_auth_id:
            if verbose:
                log_stderr("DEBUG", f"Skipping clone pattern - missing auth_id: source={source_auth_id}, target={target_auth_id}")
            continue

        # Find all ACEs matching the source trustee (any type)
        cloned_count = 0
        synced_count = 0
        for ace in aces[:]:  # Iterate over copy since we're appending
            # Get the auth_id from the ACE trustee
            ace_trustee = ace.get('trustee')
            if isinstance(ace_trustee, dict):
                ace_auth_id = str(ace_trustee.get('auth_id', ''))
            else:
                ace_auth_id = str(ace_trustee) if ace_trustee else ''

            # Match by source auth_id
            if ace_auth_id == str(source_auth_id):
                # Check if a target ACE already exists (same type)
                target_ace = None
                for existing_ace in aces:
                    existing_trustee = existing_ace.get('trustee')
                    if isinstance(existing_trustee, dict):
                        existing_auth_id = str(existing_trustee.get('auth_id', ''))
                    else:
                        existing_auth_id = str(existing_trustee) if existing_trustee else ''

                    if (existing_auth_id == str(target_auth_id) and
                            existing_ace.get('type') == ace.get('type')):
                        target_ace = existing_ace
                        break

                if target_ace is not None:
                    # Target ACE exists
                    if sync_cloned_aces:
                        # Sync mode: update existing target ACE with source rights and flags
                        target_ace['rights'] = list(ace.get('rights', []))
                        target_ace['flags'] = list(ace.get('flags', []))
                        synced_count += 1
                        if verbose:
                            log_stderr("DEBUG", f"Synced {ace.get('type')} ACE for {target_auth_id} with rights from {source_auth_id}")
                    else:
                        # Default: skip if target already exists
                        if verbose:
                            log_stderr("DEBUG", f"Clone skipped - {ace.get('type')} ACE already exists for target trustee {target_auth_id}")
                else:
                    # Target ACE does not exist - create a clone
                    # Use raw trustee name and _needs_resolution marker
                    # so it gets resolved like other new ACEs
                    cloned_ace = {
                        'type': ace.get('type'),
                        'flags': list(ace.get('flags', [])),  # Copy flags
                        'trustee': cp.get('target_trustee'),  # Raw trustee name
                        'rights': list(ace.get('rights', [])),  # Copy rights
                        '_needs_resolution': True,  # Will be resolved before PUT
                    }
                    aces.append(cloned_ace)
                    cloned_count += 1
                    if verbose:
                        log_stderr("DEBUG", f"Cloned {ace.get('type')} ACE from {source_auth_id} to {cp.get('target_trustee')}")

        stats['cloned'] += cloned_count
        stats['synced'] += synced_count
        if verbose:
            if cloned_count > 0:
                log_stderr("DEBUG", f"Cloned {cloned_count} ACE(s) from {cp.get('source_trustee')} to {cp.get('target_trustee')}")
            if synced_count > 0:
                log_stderr("DEBUG", f"Synced {synced_count} ACE(s) for {cp.get('target_trustee')} from {cp.get('source_trustee')}")

    # 9. Re-sort into canonical order
    aces = sort_aces_canonical(aces)

    inner['aces'] = aces
    return result, stats


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
            log_stderr("WARN", f"Could not determine type for {path}: {e}")
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
        log_stderr("!", "--propagate-acls is enabled. This will apply the file ACL to\n    all child objects including subdirectories.", newline_before=True)

    print("\n" + "=" * 70, file=sys.stderr)

    # Prompt user
    while True:
        response = input("Proceed? (Yes/No): ").strip().lower()
        if response in ['yes', 'y']:
            log_stderr("INFO", "Proceeding with ACL application...\n")
            return True
        elif response in ['no', 'n']:
            log_stderr("INFO", "Operation cancelled by user.")
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


async def display_scope_aggregates(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    path: str,
    label: str = "Processing",
    verbose: bool = False,
    max_depth: int = None,
    omit_subdirs: list = None,
):
    """Fetch and display directory aggregate counts before a tree operation.

    Shows the total number of subdirectories and files under the given path
    so the user knows the scope of work before a propagation begins.
    Failures are non-fatal -- the operation proceeds without the display.
    """
    try:
        aggregates = await client.get_directory_aggregates(session, path)
        total_files = aggregates.get('total_files', 'unknown')
        total_dirs = aggregates.get('total_directories', 'unknown')

        if isinstance(total_files, str):
            files_str = total_files
        else:
            files_str = f"{int(total_files):,}"

        if isinstance(total_dirs, str):
            dirs_str = total_dirs
        else:
            dirs_str = f"{int(total_dirs):,}"

        filter_note = ""
        if max_depth or omit_subdirs:
            filter_note = " (before filters)"

        print(
            f"{label} {path} ({dirs_str} subdirectories, {files_str} files){filter_note}",
            file=sys.stderr,
        )
    except Exception as e:
        if verbose:
            log_stderr("WARN", f"Could not fetch directory aggregates: {e}")


async def collect_stats(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    path: str,
    results: list,
    max_depth: int = None,
    omit_subdirs: list = None,
    omit_paths: list = None,
    _current_depth: int = 0,
):
    """Collect directory aggregate statistics without performing a tree walk.

    Fetches aggregates from the Qumulo API for the given path and appends
    a stats dict to the results list. Optionally recurses into subdirectories
    up to max_depth levels, respecting omit patterns.

    Uses streaming enumeration to find subdirectories without loading all
    entries into memory -- safe for directories with millions of files.

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp ClientSession
        path: Directory path to query
        results: List to append stat dicts to
        max_depth: Maximum recursion depth (None = no recursion)
        omit_subdirs: Glob patterns for subdirectory names to skip
        omit_paths: Exact absolute paths to skip
        _current_depth: Internal recursion tracker
    """
    aggregates = await client.get_directory_aggregates(session, path)

    if "error" in aggregates:
        results.append({
            "path": path,
            "error": aggregates["error"],
        })
        return

    total_files = int(aggregates.get("total_files", 0))
    total_dirs = int(aggregates.get("total_directories", 0))
    total_capacity = int(aggregates.get("total_capacity", 0))

    results.append({
        "path": path,
        "files": total_files,
        "subdirectories": total_dirs,
        "total_size": total_capacity,
    })

    # Recurse into subdirectories if depth permits
    if max_depth is not None and _current_depth < max_depth:
        # Normalize omit paths once
        normalized_omit_paths = (
            {p.rstrip("/") for p in omit_paths} if omit_paths else set()
        )

        # Stream directory entries page by page, collecting only subdirectories.
        # This avoids loading millions of file entries into memory.
        subdirs = []

        async def extract_subdirs(page):
            for entry in page:
                if entry.get("type") != "FS_FILE_TYPE_DIRECTORY":
                    continue
                subdir_path = entry["path"]
                subdir_name = subdir_path.rstrip("/").split("/")[-1]

                if subdir_path.rstrip("/") in normalized_omit_paths:
                    continue
                if omit_subdirs and any(
                    fnmatch.fnmatch(subdir_name, pat.rstrip("/"))
                    for pat in omit_subdirs
                ):
                    continue
                subdirs.append(subdir_path)

        try:
            await client.enumerate_directory_streaming(
                session, path, callback=extract_subdirs
            )
        except Exception as e:
            log_stderr("WARN", f"Could not enumerate {path}: {e}")
            return

        for subdir_path in subdirs:
            await collect_stats(
                client, session, subdir_path,
                results=results,
                max_depth=max_depth,
                omit_subdirs=omit_subdirs,
                omit_paths=omit_paths,
                _current_depth=_current_depth + 1,
            )


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
    owner_group_only: bool = False,
    acl_concurrency: int = 100,
    dry_run: bool = False
) -> dict:
    """
    Apply ACL and/or owner/group to target path, optionally propagating to filtered children.

    If dry_run is True, walks the tree and reports what would change without
    calling any write APIs.

    Applies to:
    1. Target path itself (no INHERITED flag modification for ACL)
    2. If propagate=True, all matching children (with INHERITED flag added to ACL)

    Children are filtered using the standard file_filter (Universal Filters).

    Uses streaming mode with bounded queue for memory efficiency on large trees.

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp session
        acl_data: Source ACL data (full structure with 'acl' nested)
        target_path: Target path to apply ACL
        propagate: If True, apply to all matching descendants
        file_filter: Filter function for matching objects
        progress: Show progress output
        continue_on_error: Continue on errors without prompting
        args: Command line arguments for filter parameters
        owner_group_data: Owner/group data from source (optional)
        copy_owner: Copy owner from source
        copy_group: Copy group from source
        owner_group_only: Apply only owner/group, not ACL
        acl_concurrency: Number of concurrent ACL operations (default 100)

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
    if dry_run:
        if owner_group_only:
            log_stderr("DRY RUN", f"Would apply owner/group to target: {target_path}")
        elif copy_owner or copy_group:
            log_stderr("DRY RUN", f"Would apply ACL and owner/group to target: {target_path}")
        else:
            log_stderr("DRY RUN", f"Would apply ACL to target: {target_path}")
        stats['objects_changed'] = 1
    else:
        if progress:
            if owner_group_only:
                log_stderr("OWNER/GROUP", f"Applying owner/group to target: {target_path}")
            elif copy_owner or copy_group:
                log_stderr("ACL+OWNER/GROUP", f"Applying ACL and owner/group to target: {target_path}")
            else:
                log_stderr("ACL CLONE", f"Applying ACL to target: {target_path}")

        # Apply ACL if not owner_group_only
        if not owner_group_only:
            success, error_msg = await client.set_file_acl(
                session, target_path, acl_data, mark_inherited=False
            )

            if not success:
                log_stderr("ERROR", f"Failed to apply ACL to target path: {target_path}", newline_before=True)
                log_stderr("ERROR", f"{error_msg}")
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
                log_stderr("ERROR", f"Failed to apply owner/group to target path: {target_path}", newline_before=True)
                log_stderr("ERROR", f"{error_msg}")
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

    # Create a ProgressTracker to count examined vs matched objects
    walk_progress = ProgressTracker(verbose=False, limit=args.limit if args else None)

    # Bounded queue for memory-efficient streaming (max 10K entries = ~15-20MB)
    # This allows tree walk to run ahead while ACL application catches up
    entry_queue = asyncio.Queue(maxsize=10000)

    # Shared state for producer/consumer coordination
    producer_done = asyncio.Event()
    abort_requested = asyncio.Event()
    limit_reached = asyncio.Event()
    entries_queued = [0]  # Use list for mutability in nested function

    # Helper async function to apply both ACL and owner/group to a single file
    async def apply_to_single_file(path: str):
        """Apply ACL and/or owner/group to a single file. In dry-run mode, just report."""
        if dry_run:
            return (True, None)

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

    # Output callback for streaming - adds entries to queue
    async def queue_entry(entry):
        """Callback to add matching entries to the processing queue."""
        # Skip if abort requested or limit reached
        if abort_requested.is_set() or limit_reached.is_set():
            return

        # Skip target path (already applied)
        if entry.get('path') == target_path:
            return

        # Check limit
        if args and args.limit and entries_queued[0] >= args.limit:
            limit_reached.set()
            return

        # Add to queue (blocks if queue is full, providing backpressure)
        await entry_queue.put(entry)
        entries_queued[0] += 1

    # Producer: walk tree and stream entries to queue
    async def producer():
        """Walk tree and stream matching entries to queue."""
        try:
            await client.walk_tree_async(
                session=session,
                path=target_path,
                max_depth=args.max_depth if args else None,
                progress=walk_progress,
                file_filter=file_filter,
                collect_results=False,  # Memory-efficient streaming mode
                output_callback=queue_entry,
            )
        except Exception as e:
            if progress:
                log_stderr("ERROR", f"Tree walk failed: {e}", newline_before=True)
        finally:
            producer_done.set()

    # Consumer: process entries from queue in batches
    async def consumer():
        """Process entries from queue, applying ACLs in batches."""
        batch_size = acl_concurrency
        batch = []
        processed = 0

        while True:
            # Check for abort
            if abort_requested.is_set():
                break

            # Try to fill batch
            try:
                # Use timeout to periodically check if producer is done
                entry = await asyncio.wait_for(entry_queue.get(), timeout=0.1)
                batch.append(entry)

                # Continue filling batch if more entries available
                while len(batch) < batch_size:
                    try:
                        entry = entry_queue.get_nowait()
                        batch.append(entry)
                    except asyncio.QueueEmpty:
                        break

            except asyncio.TimeoutError:
                # No entry available, check if producer is done
                if producer_done.is_set() and entry_queue.empty():
                    break
                # Process partial batch if we have entries
                if not batch:
                    continue

            # Process batch if we have entries
            if batch:
                # Create tasks for parallel execution
                tasks = []
                paths = []
                for entry in batch:
                    path = entry['path']
                    paths.append(path)
                    tasks.append(apply_to_single_file(path))

                # Execute all tasks in this batch concurrently
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Process results
                for path, result in zip(paths, results):
                    processed += 1
                    stats['total_objects_processed'] += 1

                    if isinstance(result, Exception):
                        stats['objects_failed'] += 1
                        error_msg = str(result)
                        stats['errors'].append({
                            'path': path,
                            'error_code': 'EXCEPTION',
                            'message': error_msg
                        })

                        if continue_on_error:
                            if progress:
                                log_stderr("WARN", f"Error on {path}: {error_msg}, continuing...", newline_before=True)
                        else:
                            log_stderr("ERROR", f"Failed to apply ACL to: {path}", newline_before=True)
                            log_stderr("ERROR", f"{error_msg}")

                            while True:
                                response = input("Continue? [C]ontinue / [A]bort: ").strip().lower()
                                if response in ['c', 'continue']:
                                    break
                                elif response in ['a', 'abort']:
                                    log_stderr("INFO", "Operation aborted by user.")
                                    abort_requested.set()
                                    return
                                print("Invalid response. Please enter 'c' or 'a'.")

                    elif isinstance(result, tuple):
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

                            if continue_on_error:
                                if progress:
                                    log_stderr("WARN", f"Error on {path}: {error_msg}, continuing...", newline_before=True)
                            else:
                                log_stderr("ERROR", f"Failed to apply ACL to: {path}", newline_before=True)
                                log_stderr("ERROR", f"{error_msg}")

                                while True:
                                    response = input("Continue? [C]ontinue / [A]bort: ").strip().lower()
                                    if response in ['c', 'continue']:
                                        break
                                    elif response in ['a', 'abort']:
                                        log_stderr("INFO", "Operation aborted by user.")
                                        abort_requested.set()
                                        return
                                    print("Invalid response. Please enter 'c' or 'a'.")

                # Progress reporting after each batch
                if progress:
                    elapsed = time.time() - start_time
                    rate = processed / elapsed if elapsed > 0 else 0
                    queue_size = entry_queue.qsize()

                    # Show queue size to indicate backpressure
                    progress_label = "DRY RUN" if dry_run else "ACL CLONE"
                    changed_label = "Would change" if dry_run else "Changed"
                    print(
                        f"\r[{progress_label}] {changed_label}: {stats['objects_changed']:,} | "
                        f"Failed: {stats['objects_failed']:,} | "
                        f"Processed: {processed:,} | "
                        f"Queue: {queue_size:,} | "
                        f"Rate: {rate:.0f}/s",
                        end='',
                        file=sys.stderr
                    )
                    sys.stderr.flush()

                # Clear batch for next iteration
                batch = []

    # Run producer and consumer concurrently
    await asyncio.gather(producer(), consumer())

    # Calculate skipped objects from progress tracker
    stats['objects_skipped'] = walk_progress.total_objects - walk_progress.matches

    if progress:
        print()  # New line after progress
        elapsed = time.time() - start_time
        complete_label = "DRY RUN" if dry_run else "ACL CLONE"
        log_stderr(complete_label, f"Completed in {elapsed:.1f}s")

    return stats


async def generate_acl_report(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    files: List[Dict],
    show_progress: bool = False,
    resolve_names: bool = False,
    show_owner: bool = False,
    show_group: bool = False,
    dont_resolve_ids: bool = False
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
                    log_stderr("WARN", f"Error processing ACL for {path}: {result}")
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
                    log_stderr("ACL REPORT", f"{processed:,} / {total_files:,} processed | {remaining:,} remaining | {rate:.1f} files/sec")

    if show_progress:
        if sys.stderr.isatty():
            print(file=sys.stderr)  # New line after progress
        log_stderr("ACL REPORT", f"Completed processing {total_files:,} files")

    # Calculate statistics
    files_with_acls = sum(1 for info in file_acls.values() if info['acl_data'] is not None)

    stats = {
        'total_files': total_files,
        'files_with_acls': files_with_acls,
        'processing_time': time.time() - start_time
    }

    # Resolve names if requested (for ACLs, owners, or groups)
    # When dont_resolve_ids is set, skip owner/group resolution but still resolve ACL trustee names
    identity_cache = {}
    need_owner_resolution = show_owner and not dont_resolve_ids
    need_group_resolution = show_group and not dont_resolve_ids
    if resolve_names or need_owner_resolution or need_group_resolution:
        # Collect all unique auth_ids
        all_auth_ids = set()

        # Collect from ACLs if resolve_names is enabled
        if resolve_names:
            for file_info in file_acls.values():
                acl_data = file_info.get('acl_data')
                if acl_data:
                    auth_ids = extract_auth_ids_from_acl(acl_data)
                    all_auth_ids.update(auth_ids)

        # Collect owner auth_ids if show_owner is enabled (and not skipping resolution)
        if need_owner_resolution:
            for file_info in file_acls.values():
                # Try to get auth_id from owner_details first, fallback to owner field
                owner_details = file_info.get('owner_details', {})
                owner_auth_id = owner_details.get('auth_id') or file_info.get('owner')
                if owner_auth_id:
                    all_auth_ids.add(owner_auth_id)

        # Collect group auth_ids if show_group is enabled (and not skipping resolution)
        if need_group_resolution:
            for file_info in file_acls.values():
                # Try to get auth_id from group_details first, fallback to group field
                group_details = file_info.get('group_details', {})
                group_auth_id = group_details.get('auth_id') or file_info.get('group')
                if group_auth_id:
                    all_auth_ids.add(group_auth_id)

        if all_auth_ids and show_progress:
            log_stderr("ACL REPORT", f"Resolving {len(all_auth_ids)} unique identities...")

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


def load_trustee_mappings(filepath: str, verbose: bool = False) -> List[dict]:
    """
    Load trustee mappings from a CSV file.

    CSV format: source,target (header row optional)

    Supports all trustee formats:
    - DOMAIN\\username (NetBIOS)
    - user@domain.com (UPN)
    - uid:1001, gid:100 (NFS)
    - S-1-5-21-... (SID)
    - username (plain name)

    Args:
        filepath: Path to CSV file
        verbose: Print debug info

    Returns:
        List of dicts: [{'source': '...', 'target': '...', 'line': N}, ...]

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If CSV format is invalid
    """
    import csv

    mappings = []

    try:
        with open(filepath, 'r', newline='', encoding='utf-8') as f:
            # Detect if first row is a header
            first_line = f.readline().strip()
            f.seek(0)

            # Check if first row looks like a header (common header names)
            has_header = False
            if first_line:
                first_parts = first_line.lower().split(',')
                if len(first_parts) >= 2:
                    header_keywords = ['source', 'target', 'from', 'to', 'old', 'new']
                    if any(kw in first_parts[0] for kw in header_keywords) or \
                       any(kw in first_parts[1] for kw in header_keywords):
                        has_header = True

            reader = csv.reader(f)
            line_num = 0

            for row in reader:
                line_num += 1

                # Skip header row
                if line_num == 1 and has_header:
                    if verbose:
                        log_stderr("DEBUG", f"Skipping header row: {row}")
                    continue

                # Skip empty rows
                if not row or all(cell.strip() == '' for cell in row):
                    continue

                # Validate row has at least 2 columns
                if len(row) < 2:
                    raise ValueError(
                        f"Line {line_num}: Expected at least 2 columns (source,target), "
                        f"got {len(row)}: {row}"
                    )

                source = row[0].strip()
                target = row[1].strip()

                # Validate non-empty values
                if not source:
                    raise ValueError(f"Line {line_num}: Empty source value")
                if not target:
                    raise ValueError(f"Line {line_num}: Empty target value")

                mappings.append({
                    'source': source,
                    'target': target,
                    'line': line_num,
                })

        if verbose:
            log_stderr("DEBUG", f"Loaded {len(mappings)} trustee mappings from {filepath}")

        return mappings

    except FileNotFoundError:
        raise FileNotFoundError(f"Mapping file not found: {filepath}")
    except csv.Error as e:
        raise ValueError(f"CSV parsing error in {filepath}: {e}")


def parse_owner_change_pattern(pattern: str) -> dict:
    """
    Parse 'SOURCE:TARGET' pattern for owner/group changes.

    Handles trustees that contain colons (uid:N, gid:N) by smart splitting.

    Handles:
    - DOMAIN\\user:DOMAIN\\other
    - uid:1001:uid:2001
    - gid:100:gid:200
    - olduser:newuser

    Args:
        pattern: The owner/group change pattern

    Returns:
        {'source': str, 'target': str}

    Raises:
        ValueError if pattern is invalid
    """
    if ':' not in pattern:
        raise ValueError(
            f"Invalid owner change pattern '{pattern}'. "
            f"Expected format: 'SOURCE:TARGET' (e.g., 'olduser:newuser', 'uid:1001:uid:2001')"
        )

    # Handle special prefixed formats that contain colons
    # uid:N:uid:M -> split after first uid:N
    # gid:N:gid:M -> split after first gid:N
    # auth_id:N:auth_id:M -> split after first auth_id:N

    lower_pattern = pattern.lower()

    # Check for uid:N:target
    if lower_pattern.startswith('uid:'):
        rest = pattern[4:]  # after 'uid:'
        if ':' in rest:
            colon_pos = rest.index(':')
            uid_part = rest[:colon_pos]
            if uid_part.isdigit():
                source = pattern[:4 + colon_pos]  # uid:N
                target = rest[colon_pos + 1:]     # everything after
                if target:
                    return {'source': source, 'target': target}

    # Check for gid:N:target
    if lower_pattern.startswith('gid:'):
        rest = pattern[4:]  # after 'gid:'
        if ':' in rest:
            colon_pos = rest.index(':')
            gid_part = rest[:colon_pos]
            if gid_part.isdigit():
                source = pattern[:4 + colon_pos]  # gid:N
                target = rest[colon_pos + 1:]     # everything after
                if target:
                    return {'source': source, 'target': target}

    # Check for auth_id:N:target
    if lower_pattern.startswith('auth_id:'):
        rest = pattern[8:]  # after 'auth_id:'
        if ':' in rest:
            colon_pos = rest.index(':')
            auth_part = rest[:colon_pos]
            if auth_part.isdigit():
                source = pattern[:8 + colon_pos]  # auth_id:N
                target = rest[colon_pos + 1:]     # everything after
                if target:
                    return {'source': source, 'target': target}

    # Default: split on the last colon (handles DOMAIN\user:DOMAIN\other, simple:names)
    last_colon = pattern.rfind(':')
    if last_colon <= 0 or last_colon >= len(pattern) - 1:
        raise ValueError(
            f"Invalid owner change pattern '{pattern}'. "
            f"Expected format: 'SOURCE:TARGET' (e.g., 'olduser:newuser')"
        )

    source = pattern[:last_colon].strip()
    target = pattern[last_colon + 1:].strip()

    if not source:
        raise ValueError(f"Invalid pattern '{pattern}': source cannot be empty")
    if not target:
        raise ValueError(f"Invalid pattern '{pattern}': target cannot be empty")

    return {'source': source, 'target': target}


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
        # Keep single backslash - aiohttp handles JSON encoding
        domain, username = trustee.split("\\", 1)
        return {"payload": {"name": f"{domain}\\{username}"}, "type": "name"}

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
        xxHash or SHA-256 hash of position-aware fingerprint, or None if failed
    """
    import struct

    # Try to use xxhash if available (much faster than SHA-256)
    try:
        import xxhash
        hasher = xxhash.xxh128()
    except ImportError:
        import hashlib
        hasher = hashlib.sha256()

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

    # Check if xxhash is available and inform user
    try:
        import xxhash
        hash_lib = "xxHash (fast)"
    except ImportError:
        hash_lib = "SHA-256 (slow - install xxhash for 10x speedup: pip install xxhash)"

    if progress and progress.verbose:
        log_stderr("SIMILARITY DETECTION", f"Using {hash_lib} for file hashing")
        log_stderr("SIMILARITY DETECTION", f"Phase 1: Metadata pre-filtering {len(files):,} files")

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
        log_stderr("SIMILARITY DETECTION", f"Found {total_potential:,} potential similar files in {len(potential_duplicates):,} groups")

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
        log_stderr("SIMILARITY DETECTION", "Phase 2: Computing sample hashes")

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
        log_stderr("SIMILARITY DETECTION", f"FINAL: {files_hashed:,} files hashed | {rate:.1f} files/sec | {elapsed:.1f}s")

    # Filter to only groups with 2+ files (actual similar files)
    similar_groups = {k: v for k, v in hash_groups.items() if len(v) >= 2}

    if progress and progress.verbose:
        total_similar = sum(len(v) for v in similar_groups.values())
        log_stderr("SIMILARITY DETECTION", f"Found {total_similar:,} confirmed similar files in {len(similar_groups):,} groups")

    return similar_groups


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


def validate_attribute_args(args):
    """
    Validate --find-attribute-* and --set-attribute-* arguments.

    Parses comma-separated lists, resolves aliases, validates attribute names,
    enforces pairing rules (same-boolean = error, opposite pairs must be
    positionally adjacent in sys.argv), and stores parsed results on args.
    """
    has_find_true = bool(args.find_attribute_true)
    has_find_false = bool(args.find_attribute_false)
    has_set_true = bool(args.set_attribute_true)
    has_set_false = bool(args.set_attribute_false)

    # Nothing to validate
    if not any([has_find_true, has_find_false, has_set_true, has_set_false]):
        args.find_attribute_true_parsed = None
        args.find_attribute_false_parsed = None
        args.set_attribute_true_parsed = None
        args.set_attribute_false_parsed = None
        return

    # Parse and validate attribute names
    args.find_attribute_true_parsed = None
    args.find_attribute_false_parsed = None
    args.set_attribute_true_parsed = None
    args.set_attribute_false_parsed = None

    if has_find_true:
        merged = ",".join(args.find_attribute_true)
        args.find_attribute_true_parsed = parse_attribute_list(
            merged, FINDABLE_ATTRIBUTES, "--find-attribute-true")

    if has_find_false:
        merged = ",".join(args.find_attribute_false)
        args.find_attribute_false_parsed = parse_attribute_list(
            merged, FINDABLE_ATTRIBUTES, "--find-attribute-false")

    if has_set_true:
        merged = ",".join(args.set_attribute_true)
        args.set_attribute_true_parsed = parse_attribute_list(
            merged, SETTABLE_ATTRIBUTES, "--set-attribute-true")

    if has_set_false:
        merged = ",".join(args.set_attribute_false)
        args.set_attribute_false_parsed = parse_attribute_list(
            merged, SETTABLE_ATTRIBUTES, "--set-attribute-false")

    # Positional pairing validation via sys.argv scan.
    # Rules:
    #   - A find/set pair with the SAME boolean that are adjacent = error
    #   - A find/set pair with OPPOSITE booleans must be adjacent (no flags between)
    #   - Both opposite-boolean pairs may coexist in one command
    attr_flags = {
        "--find-attribute-true", "--find-attribute-false",
        "--set-attribute-true", "--set-attribute-false",
    }

    has_any_set = has_set_true or has_set_false
    has_any_find = has_find_true or has_find_false

    if has_any_find and has_any_set:
        # Build ordered list of (position, flag_name) from sys.argv
        flag_positions = []
        argv = sys.argv
        for i, arg in enumerate(argv):
            bare_arg = arg.split("=", 1)[0] if "=" in arg else arg
            if bare_arg in attr_flags:
                flag_positions.append((i, bare_arg))

        # Walk through flag_positions looking for find->set adjacency
        for idx, (pos, name) in enumerate(flag_positions):
            if not name.startswith("--find-attribute-"):
                continue

            # Check if the next attribute flag is a --set-attribute-*
            if idx + 1 < len(flag_positions):
                next_pos, next_name = flag_positions[idx + 1]
                if next_name.startswith("--set-attribute-"):
                    find_bool = "true" if name.endswith("-true") else "false"
                    set_bool = "true" if next_name.endswith("-true") else "false"

                    # Same-boolean pair = error
                    if find_bool == set_bool:
                        print(
                            f"Error: {name} and {next_name} cannot be paired (same boolean).\n"
                            f"  A find/set pair must use opposite booleans.\n"
                            f"  Use --find-attribute-true with --set-attribute-false, or\n"
                            f"  use --find-attribute-false with --set-attribute-true.",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    # Opposite-boolean pair: check no other flags between them
                    find_value_end = pos + 1
                    if "=" in argv[pos]:
                        find_value_end = pos  # value embedded in flag

                    for j in range(find_value_end + 1, next_pos):
                        candidate = argv[j]
                        bare = candidate.split("=", 1)[0] if "=" in candidate else candidate
                        if bare.startswith("--") and bare not in attr_flags:
                            print(
                                f"Error: {name} and {next_name} must be positionally adjacent.\n"
                                f"  Found '{bare}' between them.\n"
                                f"  Place {next_name} immediately after {name} and its value.",
                                file=sys.stderr,
                            )
                            sys.exit(1)

        # Also reject same-boolean pairs that are not adjacent but where no
        # opposite pair accounts for them. If find-true and set-true both
        # exist, they must each be part of a separate opposite-boolean pair.
        # The only way that works is if find-false and set-false also exist
        # (i.e., both dual pairs are present). If not, it's an error.
        if has_find_true and has_set_true and not (has_find_false and has_set_false):
            print(
                "Error: --find-attribute-true and --set-attribute-true cannot be used together (same boolean).\n"
                "  A find/set pair must use opposite booleans.\n"
                "  Use --find-attribute-true with --set-attribute-false, or\n"
                "  use --find-attribute-false with --set-attribute-true.",
                file=sys.stderr,
            )
            sys.exit(1)

        if has_find_false and has_set_false and not (has_find_true and has_set_true):
            print(
                "Error: --find-attribute-false and --set-attribute-false cannot be used together (same boolean).\n"
                "  A find/set pair must use opposite booleans.\n"
                "  Use --find-attribute-false with --set-attribute-true, or\n"
                "  use --find-attribute-true with --set-attribute-false.",
                file=sys.stderr,
            )
            sys.exit(1)

    # Require --path when using attribute flags
    if not args.path:
        print(
            "Error: --find-attribute-* and --set-attribute-* require --path",
            file=sys.stderr,
        )
        sys.exit(1)


async def main_async(args):
    """Main async function."""
    # Backward compatibility: consolidate old propagation flags into unified flag
    if getattr(args, 'propagate_ace_changes', False) or getattr(args, 'propagate_owner_changes', False):
        args.propagate_changes = True

    # Determine if we're in ACL cloning mode
    acl_cloning_mode = (args.source_acl or args.source_acl_file) and args.acl_target

    # Helper to print a line to both stderr and log file
    def banner_line(line: str):
        print(line, file=sys.stderr)
        log_to_file(line)

    banner_line("=" * 70)
    if acl_cloning_mode:
        banner_line("GrumpWalk - ACL Cloning Mode")
    else:
        banner_line("GrumpWalk - Qumulo Directory Tree Walk")
    banner_line("=" * 70)
    banner_line(f"Cluster:          {args.host}")

    if acl_cloning_mode:
        if args.source_acl_file:
            banner_line(f"Source ACL:       {args.source_acl_file} (file)")
        else:
            banner_line(f"Source ACL:       {args.source_acl}")
        banner_line(f"Target path:      {args.acl_target}")
        if args.propagate_acls:
            banner_line(f"Propagate:        Enabled")
        banner_line(f"ACL concurrency:  {args.acl_concurrency}")
    else:
        banner_line(f"Path:             {args.path}")

    banner_line(f"JSON parser:      {JSON_PARSER_NAME}")
    banner_line(f"Walk concurrency: {args.max_concurrent}")
    banner_line(f"Connection pool:  {args.connector_limit}")
    if args.max_depth:
        banner_line(f"Max depth:        {args.max_depth}")
    if args.progress:
        banner_line(f"Progress:         Enabled")
    if args.log_file:
        banner_line(f"Log file:         {args.log_file} (level: {args.log_level})")
    banner_line("=" * 70)

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

    # Test basic TCP connectivity to cluster before proceeding
    print("Verifying cluster connection...", file=sys.stderr, end=" ", flush=True)
    try:
        await client.test_connection(timeout=10)
        print("OK", file=sys.stderr)
    except asyncio.TimeoutError:
        print("FAILED", file=sys.stderr)
        log_stderr("ERROR", f"Connection timed out to {args.host}:{args.port}", newline_before=True)
        log_stderr("HINT", "Check that the cluster is powered on and reachable")
        log_stderr("HINT", "Verify the hostname/IP and port are correct")
        sys.exit(1)
    except OSError as e:
        print("FAILED", file=sys.stderr)
        log_stderr("ERROR", f"Cannot connect to {args.host}:{args.port}", newline_before=True)
        err_str = str(e).lower()
        if "refused" in err_str or "errno 61" in err_str or "errno 111" in err_str:
            log_stderr("HINT", "Connection refused - verify host and port are correct")
        elif "no route" in err_str or "unreachable" in err_str:
            log_stderr("HINT", "Host unreachable - check network connectivity")
        elif "nodename" in err_str or "name or service not known" in err_str or "errno 8" in err_str:
            log_stderr("HINT", "DNS resolution failed - check hostname spelling")
        else:
            log_stderr("HINT", f"{e}")
        sys.exit(1)

    # Test authentication before proceeding
    print("Verifying credentials...", file=sys.stderr, end=" ", flush=True)
    async with client.create_session() as session:
        try:
            await client.test_auth(session)
            print("OK", file=sys.stderr)
        except aiohttp.ClientResponseError as e:
            print("FAILED", file=sys.stderr)
            if e.status == 401:
                log_stderr("ERROR", "Authentication failed (401 Unauthorized)", newline_before=True)
                log_stderr("HINT", "Your bearer token may be expired or invalid")
                log_stderr("HINT", f"Generate a new token: qq --host {args.host} login")
            else:
                log_stderr("ERROR", f"HTTP {e.status}: {e.message}", newline_before=True)
            sys.exit(1)

    # Display scope aggregates for --path (universal, all modes)
    if args.path:
        async with client.create_session() as session:
            aggregates = await client.get_directory_aggregates(session, args.path)
            if "error" not in aggregates:
                total_files = int(aggregates.get("total_files", 0))
                total_dirs = int(aggregates.get("total_directories", 0))
                print(
                    f"Searching {total_dirs:,} directories and {total_files:,} files",
                    file=sys.stderr,
                )

    # ACL Cloning Mode
    if args.source_acl or args.source_acl_file or args.acl_target:
        # Validate: need a source and a target
        if not ((args.source_acl or args.source_acl_file) and args.acl_target):
            log_stderr("ERROR", "Both a source (--source-acl or --source-acl-file) and --acl-target must be specified")
            sys.exit(1)

        # Validate: can't specify both source types
        if args.source_acl and args.source_acl_file:
            log_stderr("ERROR", "Cannot specify both --source-acl and --source-acl-file")
            sys.exit(1)

        async with client.create_session() as session:
            # Step 1: Get source ACL (from file or cluster)
            if args.source_acl_file:
                # Load ACL from local JSON file
                try:
                    with open(args.source_acl_file, 'r') as f:
                        source_acl = json.load(f)
                    if args.verbose:
                        ace_count = len(source_acl.get('acl', {}).get('aces', []))
                        log_stderr("INFO", f"Loaded ACL from file with {ace_count} ACEs")
                except FileNotFoundError:
                    log_stderr("ERROR", f"ACL file not found: {args.source_acl_file}")
                    sys.exit(1)
                except json.JSONDecodeError as e:
                    log_stderr("ERROR", f"Invalid JSON in ACL file: {e}")
                    sys.exit(1)
            else:
                # Retrieve ACL from cluster
                if args.verbose:
                    log_stderr("INFO", f"Retrieving ACL from: {args.source_acl}")

                source_acl = await client.get_file_acl(session, args.source_acl)

                if not source_acl:
                    log_stderr("ERROR", f"Could not retrieve ACL from {args.source_acl}")
                    sys.exit(1)

                if args.verbose:
                    ace_count = len(source_acl.get('acl', {}).get('aces', []))
                    log_stderr("INFO", f"Retrieved ACL with {ace_count} ACEs")

            # Step 1b: Retrieve owner/group if requested
            owner_group_data = None
            if args.copy_owner or args.copy_group:
                if args.source_acl_file:
                    log_stderr("ERROR", "Cannot use --copy-owner or --copy-group with --source-acl-file")
                    sys.exit(1)

                if args.verbose:
                    log_stderr("INFO", f"Retrieving owner/group from: {args.source_acl}")

                owner_group_data = await client.get_file_owner_group(session, args.source_acl)

                if not owner_group_data:
                    log_stderr("ERROR", f"Could not retrieve owner/group from {args.source_acl}")
                    sys.exit(1)

                if args.verbose:
                    if args.copy_owner:
                        log_stderr("INFO", f"Source owner: {owner_group_data.get('owner')}")
                    if args.copy_group:
                        log_stderr("INFO", f"Source group: {owner_group_data.get('group')}")

            # Step 2: Check ACL type compatibility and warn if needed (skip if using file)
            if not args.source_acl_file:
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
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)
                if owner_auth_ids:
                    print(f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr)

            file_filter = create_file_filter(args, owner_auth_ids)

            # Display scope before propagation
            if args.propagate_acls:
                await display_scope_aggregates(
                    client, session, args.acl_target,
                    label="Propagating to",
                    verbose=args.verbose,
                    max_depth=args.max_depth,
                    omit_subdirs=args.omit_subdirs,
                )

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
                owner_group_only=args.owner_group_only,
                acl_concurrency=args.acl_concurrency,
                dry_run=args.dry_run
            )

            # Step 5: Print summary
            dry_label = " (DRY RUN)" if args.dry_run else ""
            if args.owner_group_only:
                print(f"\nOWNER/GROUP COPY SUMMARY{dry_label}", file=sys.stderr)
            elif args.copy_owner or args.copy_group:
                print(f"\nACL + OWNER/GROUP COPY SUMMARY{dry_label}", file=sys.stderr)
            else:
                print(f"\nACL CLONING SUMMARY{dry_label}", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            if args.source_acl_file:
                print(f"Source:            {args.source_acl_file} (file)", file=sys.stderr)
            else:
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
            if args.dry_run:
                print(f"Would copy:        {', '.join(copied_items)}", file=sys.stderr)
            else:
                print(f"Copied:            {', '.join(copied_items)}", file=sys.stderr)

            changed_label = "Would change:" if args.dry_run else "Objects changed:"
            print(f"{changed_label:19}{stats['objects_changed']:,}", file=sys.stderr)
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

    # ACE RESTORE MODE
    # Restore ACLs from a backup file created by --ace-backup
    if args.ace_restore:
        import json

        log_stderr("INFO", "ACE Restore Mode", newline_before=True)
        print("=" * 70, file=sys.stderr)
        print(f"Backup file:       {args.ace_restore}", file=sys.stderr)

        # Load the backup file
        try:
            with open(args.ace_restore, 'r') as f:
                backup_data = json.load(f)
        except FileNotFoundError:
            log_stderr("ERROR", f"Backup file not found: {args.ace_restore}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            log_stderr("ERROR", f"Invalid JSON in backup file: {e}")
            sys.exit(1)

        # Extract backup data
        backup_path = backup_data.get('path')
        backup_file_id = backup_data.get('file_id')
        backup_acl = backup_data.get('original_acl')
        backup_timestamp = backup_data.get('timestamp')

        if not backup_path or not backup_acl:
            log_stderr("ERROR", "Backup file is missing required fields (path, original_acl)")
            sys.exit(1)

        print(f"Original path:     {backup_path}", file=sys.stderr)
        if backup_file_id:
            print(f"File ID:           {backup_file_id}", file=sys.stderr)
        if backup_timestamp:
            print(f"Backup timestamp:  {backup_timestamp}", file=sys.stderr)

        # Determine target path (use --path if provided, otherwise use backup path)
        target_path = args.path if args.path else backup_path
        print(f"Target path:       {target_path}", file=sys.stderr)

        # Count ACEs in backup
        acl_inner = backup_acl.get('acl', backup_acl)
        backup_aces = acl_inner.get('aces', [])
        print(f"ACEs to restore:   {len(backup_aces)}", file=sys.stderr)

        if args.dry_run:
            print(f"Dry run:           Enabled (no changes will be made)", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

        async with client.create_session() as session:
            # Get current file attributes to verify file_id
            current_attr = await client.get_file_attr(session, target_path)

            if not current_attr:
                log_stderr("ERROR", f"Could not retrieve attributes from {target_path}")
                print("        The path may not exist or you may not have permission to access it.", file=sys.stderr)
                sys.exit(1)

            current_file_id = current_attr.get('id')

            # Verify file_id matches (safety check)
            if backup_file_id and current_file_id:
                if str(backup_file_id) != str(current_file_id):
                    log_stderr("WARNING", "File ID mismatch detected!", newline_before=True)
                    print(f"          Backup file ID:  {backup_file_id}", file=sys.stderr)
                    print(f"          Current file ID: {current_file_id}", file=sys.stderr)
                    print(f"          This may indicate the path now refers to a different file.", file=sys.stderr)

                    if not args.force_restore:
                        log_stderr("ERROR", "Refusing to restore due to file ID mismatch.", newline_before=True)
                        print(f"        Use --force-restore to override this safety check.", file=sys.stderr)
                        sys.exit(1)
                    else:
                        log_stderr("WARNING", "Proceeding with restore due to --force-restore flag.", newline_before=True)
                else:
                    log_stderr("INFO", f"File ID verified: {current_file_id}")
            elif backup_file_id and not current_file_id:
                log_stderr("WARNING", "Could not verify file ID (current file has no ID)")
            elif not backup_file_id:
                log_stderr("WARNING", "Backup does not contain file_id (older backup format)")

            # Dry run: show what would be restored
            if args.dry_run:
                log_stderr("DRY RUN", "Would restore the following ACL:", newline_before=True)
                print("-" * 60, file=sys.stderr)
                for i, ace in enumerate(backup_aces):
                    ace_str = qacl_ace_to_readable(ace, is_dir=True)
                    print(f"  {i+1}. {ace_str}", file=sys.stderr)
                print("-" * 60, file=sys.stderr)
                log_stderr("DRY RUN", "No changes were made.")
                return

            # Apply the backed-up ACL
            log_stderr("INFO", f"Restoring ACL to: {target_path}", newline_before=True)
            success, error = await client.set_file_acl(session, target_path, backup_acl, mark_inherited=False)

            if not success:
                log_stderr("ERROR", f"Failed to restore ACL: {error}")
                sys.exit(1)

            log_stderr("INFO", f"ACL restored successfully ({len(backup_aces)} ACEs)")

            # Propagate if requested
            if args.propagate_changes:
                log_stderr("INFO", f"Propagating restored ACL to children of: {target_path}", newline_before=True)
                await display_scope_aggregates(
                    client, session, target_path,
                    label="Propagating to",
                    verbose=args.verbose,
                    max_depth=args.max_depth,
                    omit_subdirs=args.omit_subdirs,
                )

                # Resolve owner filters if any
                owner_auth_ids = None
                if args.owners:
                    owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)

                file_filter = create_file_filter(args, owner_auth_ids)

                propagate_stats = await apply_acl_to_tree(
                    client=client,
                    session=session,
                    acl_data=backup_acl,
                    target_path=target_path,
                    propagate=True,
                    file_filter=file_filter,
                    progress=args.progress,
                    continue_on_error=args.continue_on_error,
                    args=args,
                    acl_concurrency=args.acl_concurrency
                )

                log_stderr("INFO", "Propagation complete:", newline_before=True)
                print(f"  Objects changed:  {propagate_stats['objects_changed']:,}", file=sys.stderr)
                print(f"  Objects failed:   {propagate_stats['objects_failed']:,}", file=sys.stderr)

        log_stderr("INFO", "ACE restore complete", newline_before=True)
        return  # Exit after ACE restore

    # ACE MANIPULATION MODE
    # Check if any ACE manipulation flags are specified
    ace_manipulation_mode = (
        args.remove_aces or args.add_aces or args.replace_aces or
        args.add_rights or args.remove_rights or args.clone_ace_sources or
        args.migrate_trustees or args.clone_ace_map
    )

    # Check for mutually exclusive flags: ACL cloning vs ACE manipulation
    acl_cloning_mode = args.source_acl or args.source_acl_file
    if ace_manipulation_mode and acl_cloning_mode:
        log_stderr("ERROR", "ACL cloning (--source-acl, --source-acl-file, --acl-target) cannot be combined with")
        print("        ACE manipulation (--add-ace, --remove-ace, --replace-ace, --add-rights, --remove-rights, --clone-ace-*)", file=sys.stderr)
        print("", file=sys.stderr)
        print("        Use ACL cloning to copy an entire ACL from one path to another.", file=sys.stderr)
        print("        Use ACE manipulation to surgically modify individual ACEs.", file=sys.stderr)
        sys.exit(1)

    if ace_manipulation_mode:
        if not args.path:
            log_stderr("ERROR", "--path is required for ACE manipulation")
            sys.exit(1)

        # Auto-convert --propagate-acls to --propagate-changes for ACE manipulation
        # This provides better UX since users naturally try --propagate-acls
        if args.propagate_acls and not args.propagate_changes:
            args.propagate_changes = True
            log_stderr("INFO", "Using --propagate-changes for ACE manipulation (--propagate-acls also accepted)")

        # Validate --replace-ace / --new-ace pairing
        replace_count = len(args.replace_aces) if args.replace_aces else 0
        new_ace_count = len(args.new_aces) if args.new_aces else 0

        if new_ace_count > 0 and replace_count == 0:
            log_stderr("ERROR", "--new-ace requires --replace-ace to specify which ACE to replace")
            sys.exit(1)

        if new_ace_count > 0 and new_ace_count != replace_count:
            log_stderr("ERROR", "--replace-ace and --new-ace must be paired 1:1")
            print(f"        Found {replace_count} --replace-ace and {new_ace_count} --new-ace", file=sys.stderr)
            sys.exit(1)

        # Validate positional pairing by checking sys.argv order
        if new_ace_count > 0:
            replace_positions = []
            new_ace_positions = []
            for i, arg in enumerate(sys.argv):
                if arg == '--replace-ace':
                    replace_positions.append(i)
                elif arg == '--new-ace':
                    new_ace_positions.append(i)

            # Each --new-ace should immediately follow a --replace-ace (with its value in between)
            for j, new_pos in enumerate(new_ace_positions):
                if j >= len(replace_positions):
                    log_stderr("ERROR", f"--new-ace at position {new_pos} has no matching --replace-ace")
                    sys.exit(1)
                replace_pos = replace_positions[j]
                # --new-ace should be 2 positions after --replace-ace (--replace-ace VALUE --new-ace)
                if new_pos != replace_pos + 2:
                    log_stderr("ERROR", "--new-ace must immediately follow --replace-ace 'PATTERN'")
                    print(f"        Expected: --replace-ace 'FIND' --new-ace 'REPLACE'", file=sys.stderr)
                    sys.exit(1)

        # Validate --clone-ace-source / --clone-ace-target pairing
        clone_source_count = len(args.clone_ace_sources) if args.clone_ace_sources else 0
        clone_target_count = len(args.clone_ace_targets) if args.clone_ace_targets else 0

        if clone_source_count > 0 and clone_target_count == 0:
            log_stderr("ERROR", "--clone-ace-source requires --clone-ace-target")
            sys.exit(1)

        if clone_target_count > 0 and clone_source_count == 0:
            log_stderr("ERROR", "--clone-ace-target requires --clone-ace-source")
            sys.exit(1)

        if clone_source_count != clone_target_count:
            log_stderr("ERROR", "--clone-ace-source and --clone-ace-target must be paired 1:1")
            print(f"        Found {clone_source_count} --clone-ace-source and {clone_target_count} --clone-ace-target", file=sys.stderr)
            sys.exit(1)

        log_stderr("INFO", "ACE Manipulation Mode", newline_before=True)
        print("=" * 70, file=sys.stderr)

        # Parse all patterns
        remove_patterns = []
        add_patterns = []
        replace_patterns = []
        add_rights_patterns = []
        remove_rights_patterns = []
        clone_patterns = []  # List of (source_trustee, target_trustee) tuples

        if args.remove_aces:
            for pattern in args.remove_aces:
                parsed = parse_ace_pattern(pattern, 'remove')
                if parsed:
                    remove_patterns.append(parsed)
                else:
                    sys.exit(1)

        if args.add_aces:
            for pattern in args.add_aces:
                parsed = parse_ace_pattern(pattern, 'add')
                if parsed:
                    add_patterns.append(parsed)
                else:
                    sys.exit(1)

        if args.replace_aces:
            # Check if we have paired --new-ace arguments
            has_new_aces = args.new_aces and len(args.new_aces) == len(args.replace_aces)

            for i, pattern in enumerate(args.replace_aces):
                if has_new_aces:
                    # Paired mode: --replace-ace is the search pattern, --new-ace is replacement
                    # Parse search pattern (can be Type:Trustee or full format)
                    find_parsed = parse_ace_pattern(pattern, 'remove')  # Flexible matching
                    if not find_parsed:
                        sys.exit(1)
                    # Parse replacement pattern (must be full format)
                    replace_parsed = parse_ace_pattern(args.new_aces[i], 'add')
                    if not replace_parsed:
                        sys.exit(1)
                    # Store as tuple (find_pattern, new_ace_pattern)
                    replace_patterns.append((find_parsed, replace_parsed))
                else:
                    # Non-paired mode: in-place replacement (same type+trustee)
                    parsed = parse_ace_pattern(pattern, 'add')  # Same format as add
                    if parsed:
                        # Store as tuple with None for new_ace (in-place replacement)
                        replace_patterns.append((parsed, None))
                    else:
                        sys.exit(1)

        if args.add_rights:
            for pattern in args.add_rights:
                parsed = parse_ace_pattern(pattern, 'add_rights')
                if parsed:
                    add_rights_patterns.append(parsed)
                else:
                    sys.exit(1)

        if args.remove_rights:
            for pattern in args.remove_rights:
                parsed = parse_ace_pattern(pattern, 'remove_rights')
                if parsed:
                    remove_rights_patterns.append(parsed)
                else:
                    sys.exit(1)

        if args.clone_ace_sources:
            for i, source in enumerate(args.clone_ace_sources):
                target = args.clone_ace_targets[i]
                # Store as dict with source and target trustees (will be resolved later)
                clone_patterns.append({
                    'source_trustee': source,
                    'target_trustee': target,
                })

        # Load --clone-ace-map CSV and add to clone_patterns
        if args.clone_ace_map:
            try:
                csv_mappings = load_trustee_mappings(args.clone_ace_map, verbose=args.verbose)
                for mapping in csv_mappings:
                    clone_patterns.append({
                        'source_trustee': mapping['source'],
                        'target_trustee': mapping['target'],
                        'line': mapping['line'],  # For error reporting
                    })
                log_stderr("INFO", f"Loaded {len(csv_mappings)} clone mappings from {args.clone_ace_map}")
            except FileNotFoundError as e:
                log_stderr("ERROR", f"{e}")
                sys.exit(1)
            except ValueError as e:
                log_stderr("ERROR", f"{e}")
                sys.exit(1)

        # Load --migrate-trustees CSV
        migrate_patterns = []
        if args.migrate_trustees:
            try:
                csv_mappings = load_trustee_mappings(args.migrate_trustees, verbose=args.verbose)
                for mapping in csv_mappings:
                    migrate_patterns.append({
                        'source_trustee': mapping['source'],
                        'target_trustee': mapping['target'],
                        'line': mapping['line'],  # For error reporting
                    })
                log_stderr("INFO", f"Loaded {len(csv_mappings)} migration mappings from {args.migrate_trustees}")
            except FileNotFoundError as e:
                log_stderr("ERROR", f"{e}")
                sys.exit(1)
            except ValueError as e:
                log_stderr("ERROR", f"{e}")
                sys.exit(1)

        # Show what will be done
        if remove_patterns:
            print(f"ACEs to remove:    {len(remove_patterns)}", file=sys.stderr)
        if add_patterns:
            print(f"ACEs to add:       {len(add_patterns)}", file=sys.stderr)
        if replace_patterns:
            # Check if paired or in-place replacements
            paired_count = sum(1 for _, new_pat in replace_patterns if new_pat is not None)
            inplace_count = len(replace_patterns) - paired_count
            if paired_count > 0:
                print(f"ACEs to replace:   {paired_count} (with --new-ace)", file=sys.stderr)
            if inplace_count > 0:
                print(f"ACEs to replace:   {inplace_count} (in-place)", file=sys.stderr)
        if add_rights_patterns:
            print(f"Rights to add:     {len(add_rights_patterns)}", file=sys.stderr)
        if remove_rights_patterns:
            print(f"Rights to remove:  {len(remove_rights_patterns)}", file=sys.stderr)
        if clone_patterns:
            print(f"ACEs to clone:     {len(clone_patterns)}", file=sys.stderr)
            for cp in clone_patterns:
                print(f"                   {cp['source_trustee']} -> {cp['target_trustee']}", file=sys.stderr)
            if args.sync_cloned_aces:
                print(f"Sync mode:         Enabled (existing target ACEs will be updated)", file=sys.stderr)
        if migrate_patterns:
            print(f"Trustees to migrate: {len(migrate_patterns)}", file=sys.stderr)
            for mp in migrate_patterns:
                print(f"                   {mp['source_trustee']} -> {mp['target_trustee']}", file=sys.stderr)
        if args.propagate_changes:
            print(f"Propagate:         Enabled", file=sys.stderr)
        if args.dry_run:
            print(f"Dry run:           Enabled (no changes will be made)", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

        async with client.create_session() as session:
            # Step 1: Resolve all pattern trustees to auth_ids
            # Flatten replace_patterns tuples for resolution
            replace_flat = []
            for find_pat, new_pat in replace_patterns:
                replace_flat.append(find_pat)
                if new_pat is not None:
                    replace_flat.append(new_pat)
            all_patterns = remove_patterns + add_rights_patterns + remove_rights_patterns + add_patterns + replace_flat

            # Resolve clone pattern trustees (both source and target)
            if clone_patterns:
                log_stderr("INFO", "Resolving clone trustee identities...", newline_before=True)
                for cp in clone_patterns:
                    # Resolve source trustee
                    source = cp['source_trustee']
                    log_stderr("INFO", f"Resolving source trustee '{source}'...")

                    # Use parse_trustee to get the right format for identity resolution
                    source_spec = parse_trustee(source)
                    source_payload = source_spec['payload']
                    source_id_type = source_spec['type']

                    # Extract identifier from payload
                    if source_id_type == 'uid':
                        source_identifier = source_payload.get('uid')
                    elif source_id_type == 'gid':
                        source_identifier = source_payload.get('gid')
                    elif source_id_type == 'sid':
                        source_identifier = source_payload.get('sid')
                    elif source_id_type == 'auth_id':
                        source_identifier = source_payload.get('auth_id')
                    else:  # name
                        source_identifier = source_payload.get('name')

                    result = await client.resolve_identity(session, source_identifier, source_id_type)
                    if result and result.get('auth_id'):
                        cp['source_auth_id'] = str(result['auth_id'])
                        log_stderr("INFO", f"Resolved source '{source}' -> auth_id {cp['source_auth_id']}")
                    else:
                        log_stderr("ERROR", f"Could not resolve source trustee: {source}")
                        sys.exit(1)

                    # Resolve target trustee
                    target = cp['target_trustee']
                    log_stderr("INFO", f"Resolving target trustee '{target}'...")

                    # Use parse_trustee to get the right format for identity resolution
                    target_spec = parse_trustee(target)
                    target_payload = target_spec['payload']
                    target_id_type = target_spec['type']

                    # Extract identifier from payload
                    if target_id_type == 'uid':
                        target_identifier = target_payload.get('uid')
                    elif target_id_type == 'gid':
                        target_identifier = target_payload.get('gid')
                    elif target_id_type == 'sid':
                        target_identifier = target_payload.get('sid')
                    elif target_id_type == 'auth_id':
                        target_identifier = target_payload.get('auth_id')
                    else:  # name
                        target_identifier = target_payload.get('name')

                    result = await client.resolve_identity(session, target_identifier, target_id_type)
                    if result and result.get('auth_id'):
                        cp['target_auth_id'] = str(result['auth_id'])
                        cp['target_identity'] = result  # Store full identity for ACE creation
                        log_stderr("INFO", f"Resolved target '{target}' -> auth_id {cp['target_auth_id']}")
                    else:
                        log_stderr("ERROR", f"Could not resolve target trustee: {target}")
                        sys.exit(1)

            # Resolve migrate pattern trustees (both source and target need auth_id)
            if migrate_patterns:
                if args.verbose:
                    log_stderr("INFO", "Resolving migrate trustee identities...", newline_before=True)
                for mp in migrate_patterns:
                    # Resolve source trustee to get auth_id for matching
                    source = mp['source_trustee']
                    if args.verbose:
                        log_stderr("INFO", f"Resolving source trustee '{source}'...")

                    # Use parse_trustee to get the right format for identity resolution
                    source_spec = parse_trustee(source)
                    source_payload = source_spec['payload']
                    source_id_type = source_spec['type']

                    # Extract identifier from payload
                    if source_id_type == 'uid':
                        source_identifier = source_payload.get('uid')
                    elif source_id_type == 'gid':
                        source_identifier = source_payload.get('gid')
                    elif source_id_type == 'sid':
                        source_identifier = source_payload.get('sid')
                    elif source_id_type == 'auth_id':
                        source_identifier = source_payload.get('auth_id')
                    else:  # name
                        source_identifier = source_payload.get('name')

                    result = await client.resolve_identity(session, source_identifier, source_id_type)
                    if result and result.get('auth_id'):
                        mp['source_auth_id'] = str(result['auth_id'])
                        if args.verbose:
                            log_stderr("INFO", f"Resolved source '{source}' -> auth_id {mp['source_auth_id']}")
                    else:
                        log_stderr("ERROR", f"Could not resolve source trustee: {source}")
                        sys.exit(1)

                    # Resolve target trustee to get auth_id for duplicate detection
                    target = mp['target_trustee']
                    if args.verbose:
                        log_stderr("INFO", f"Resolving target trustee '{target}'...")

                    target_spec = parse_trustee(target)
                    target_payload = target_spec['payload']
                    target_id_type = target_spec['type']

                    if target_id_type == 'uid':
                        target_identifier = target_payload.get('uid')
                    elif target_id_type == 'gid':
                        target_identifier = target_payload.get('gid')
                    elif target_id_type == 'sid':
                        target_identifier = target_payload.get('sid')
                    elif target_id_type == 'auth_id':
                        target_identifier = target_payload.get('auth_id')
                    else:  # name
                        target_identifier = target_payload.get('name')

                    result = await client.resolve_identity(session, target_identifier, target_id_type)
                    if result and result.get('auth_id'):
                        mp['target_auth_id'] = str(result['auth_id'])
                        if args.verbose:
                            log_stderr("INFO", f"Resolved target '{target}' -> auth_id {mp['target_auth_id']}")
                    else:
                        log_stderr("ERROR", f"Could not resolve target trustee: {target}")
                        sys.exit(1)

            if all_patterns:
                log_stderr("INFO", "Resolving trustee identities...", newline_before=True)
                await resolve_pattern_trustees(client, session, all_patterns, verbose=args.verbose)

            # Step 2: Get current ACL and file attributes from path
            log_stderr("INFO", f"Retrieving ACL from: {args.path}")
            current_acl = await client.get_file_acl(session, args.path)
            file_attr = await client.get_file_attr(session, args.path)

            if not current_acl:
                log_stderr("ERROR", f"Could not retrieve ACL from {args.path}")
                sys.exit(1)

            # Extract file_id for backup safety (allows restore even if path is renamed)
            file_id = file_attr.get('id') if file_attr else None

            # Show current ACL summary
            acl_inner = current_acl.get('acl', current_acl)
            current_aces = acl_inner.get('aces', [])
            inherited_count = sum(1 for ace in current_aces if 'INHERITED' in ace.get('flags', []))
            log_stderr("INFO", f"Current ACL has {len(current_aces)} ACEs ({inherited_count} inherited)")

            # Step 3: Apply modifications in memory
            modified_acl, stats = apply_ace_modifications(
                current_acl,
                remove_patterns,
                add_patterns,
                add_rights_patterns,
                remove_rights_patterns,
                replace_aces=replace_patterns,
                clone_patterns=clone_patterns,
                migrate_patterns=migrate_patterns,
                sync_cloned_aces=args.sync_cloned_aces,
                verbose=args.verbose
            )

            # Show modification summary
            log_stderr("INFO", "Modifications:", newline_before=True)
            print(f"  ACEs removed:         {stats['removed']}", file=sys.stderr)
            print(f"  ACEs added:           {stats['added']}", file=sys.stderr)
            print(f"  ACEs replaced:        {stats['replaced']}", file=sys.stderr)
            print(f"  ACEs modified:        {stats['modified']}", file=sys.stderr)
            print(f"  ACEs cloned:          {stats['cloned']}", file=sys.stderr)
            print(f"  ACEs synced:          {stats['synced']}", file=sys.stderr)
            print(f"  ACEs migrated:        {stats['migrated']}", file=sys.stderr)
            if stats['inheritance_broken']:
                print(f"  Inheritance:          BROKEN (converted to explicit)", file=sys.stderr)

            # Show resulting ACL summary
            mod_inner = modified_acl.get('acl', modified_acl)
            new_aces = mod_inner.get('aces', [])
            print(f"  Resulting ACE count:  {len(new_aces)}", file=sys.stderr)

            # Dry run: show what would happen and exit
            if args.dry_run:
                log_stderr("DRY RUN", "Would apply the following ACL:", newline_before=True)
                print("-" * 60, file=sys.stderr)

                # Show each ACE in readable format
                is_dir = True  # Assume directory for display purposes
                for i, ace in enumerate(new_aces):
                    ace_str = qacl_ace_to_readable(ace, is_dir)
                    marker = ""
                    if ace.get('_needs_resolution'):
                        marker = " [NEW - trustee needs resolution]"
                    print(f"  {i+1}. {ace_str}{marker}", file=sys.stderr)

                print("-" * 60, file=sys.stderr)
                log_stderr("DRY RUN", "No changes were made.")
                # Save identity cache before exiting (trustees were resolved)
                save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
                return

            # Step 3: Save backup if requested
            if args.ace_backup:
                import json
                backup_data = {
                    'path': args.path,
                    'file_id': file_id,
                    'original_acl': current_acl,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                try:
                    with open(args.ace_backup, 'w') as f:
                        json.dump(backup_data, f, indent=2)
                    log_stderr("INFO", f"Backup saved to: {args.ace_backup}")
                    if file_id:
                        log_stderr("INFO", f"File ID {file_id} recorded for safety verification")
                except Exception as e:
                    log_stderr("ERROR", f"Failed to save backup: {e}")
                    sys.exit(1)

            # Step 4: Resolve any new trustees that need auth_id
            for ace in new_aces:
                if ace.get('_needs_resolution'):
                    raw_trustee = ace.get('trustee')
                    if args.verbose:
                        log_stderr("INFO", f"Resolving trustee: {raw_trustee}")

                    # Use parse_trustee to get the right format for identity resolution
                    trustee_spec = parse_trustee(raw_trustee)
                    payload = trustee_spec['payload']
                    id_type = trustee_spec['type']

                    # Extract identifier from payload
                    if id_type == 'uid':
                        identifier = payload.get('uid')
                    elif id_type == 'gid':
                        identifier = payload.get('gid')
                    elif id_type == 'sid':
                        identifier = payload.get('sid')
                    elif id_type == 'auth_id':
                        identifier = payload.get('auth_id')
                    else:  # name
                        identifier = payload.get('name')

                    # Resolve to auth_id using identity API
                    resolved = await client.resolve_identity(session, identifier, id_type)

                    if resolved and resolved.get('auth_id'):
                        # Build full trustee object for v2 API
                        ace['trustee'] = {
                            'auth_id': str(resolved['auth_id']),
                            'domain': resolved.get('domain', 'UNKNOWN'),
                            'name': resolved.get('name', raw_trustee),
                            'sid': resolved.get('sid'),
                            'uid': resolved.get('uid'),
                            'gid': resolved.get('gid'),
                        }
                        del ace['_needs_resolution']
                        if args.verbose:
                            log_stderr("INFO", f"Resolved '{raw_trustee}' to auth_id {resolved['auth_id']}")
                    else:
                        log_stderr("ERROR", f"Could not resolve trustee: {raw_trustee}")
                        sys.exit(1)

            # Step 5: Apply modified ACL to target path
            log_stderr("INFO", f"Applying modified ACL to: {args.path}", newline_before=True)
            # Normalize ACL for PUT request (convert trustee objects to auth_id strings)
            normalized_acl = normalize_acl_for_put(modified_acl)
            success, error = await client.set_file_acl(session, args.path, normalized_acl, mark_inherited=False)

            if not success:
                log_stderr("ERROR", f"Failed to apply ACL: {error}")
                sys.exit(1)

            log_stderr("INFO", "ACL applied successfully")

            # Step 6: Propagate to children if requested
            if args.propagate_changes:
                log_stderr("INFO", f"Propagating ACL to children of: {args.path}", newline_before=True)
                await display_scope_aggregates(
                    client, session, args.path,
                    label="Propagating to",
                    verbose=args.verbose,
                    max_depth=args.max_depth,
                    omit_subdirs=args.omit_subdirs,
                )

                # Resolve owner filters if any
                owner_auth_ids = None
                if args.owners:
                    owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)

                file_filter = create_file_filter(args, owner_auth_ids)

                # Use existing apply_acl_to_tree for propagation
                # The modified ACL will be inherited (mark_inherited=True for children)
                propagate_stats = await apply_acl_to_tree(
                    client=client,
                    session=session,
                    acl_data=normalized_acl,
                    target_path=args.path,
                    propagate=True,
                    file_filter=file_filter,
                    progress=args.progress,
                    continue_on_error=args.continue_on_error,
                    args=args,
                    acl_concurrency=args.acl_concurrency
                )

                log_stderr("INFO", "Propagation complete:", newline_before=True)
                print(f"  Objects changed:  {propagate_stats['objects_changed']:,}", file=sys.stderr)
                print(f"  Objects failed:   {propagate_stats['objects_failed']:,}", file=sys.stderr)
                if file_filter:
                    print(f"  Objects skipped:  {propagate_stats['objects_skipped']:,}", file=sys.stderr)

                if propagate_stats['objects_failed'] > 0:
                    sys.exit(1)

        log_stderr("INFO", "ACE manipulation complete", newline_before=True)
        # Save identity cache before exiting
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
        return  # Exit after ACE manipulation

    # OWNER/GROUP CHANGE MODE
    # Selective ownership change - find files by current owner/group and change to new owner/group
    change_owner_mode = (args.change_owner or args.change_group or
                         args.change_owners_file or args.change_groups_file)

    if change_owner_mode:
        if args.verbose:
            log_stderr("INFO", "Owner/Group Change Mode", newline_before=True)
            print("=" * 70, file=sys.stderr)

        # Parse all owner change patterns from CLI and CSV
        owner_change_patterns = []
        group_change_patterns = []

        # Parse --change-owner patterns
        if args.change_owner:
            for pattern in args.change_owner:
                try:
                    parsed = parse_owner_change_pattern(pattern)
                    owner_change_patterns.append({
                        'source': parsed['source'],
                        'target': parsed['target'],
                        'source_trustee': parse_trustee(parsed['source']),
                        'target_trustee': parse_trustee(parsed['target']),
                    })
                except ValueError as e:
                    log_stderr("ERROR", f"{e}")
                    sys.exit(1)

        # Parse --change-group patterns
        if args.change_group:
            for pattern in args.change_group:
                try:
                    parsed = parse_owner_change_pattern(pattern)
                    group_change_patterns.append({
                        'source': parsed['source'],
                        'target': parsed['target'],
                        'source_trustee': parse_trustee(parsed['source']),
                        'target_trustee': parse_trustee(parsed['target']),
                    })
                except ValueError as e:
                    log_stderr("ERROR", f"{e}")
                    sys.exit(1)

        # Load CSV files
        if args.change_owners_file:
            try:
                csv_mappings = load_trustee_mappings(args.change_owners_file, verbose=args.verbose)
                for mapping in csv_mappings:
                    owner_change_patterns.append({
                        'source': mapping['source'],
                        'target': mapping['target'],
                        'source_trustee': parse_trustee(mapping['source']),
                        'target_trustee': parse_trustee(mapping['target']),
                        'line': mapping.get('line'),
                    })
            except (FileNotFoundError, ValueError) as e:
                log_stderr("ERROR", f"Failed to load owner mappings file: {e}")
                sys.exit(1)

        if args.change_groups_file:
            try:
                csv_mappings = load_trustee_mappings(args.change_groups_file, verbose=args.verbose)
                for mapping in csv_mappings:
                    group_change_patterns.append({
                        'source': mapping['source'],
                        'target': mapping['target'],
                        'source_trustee': parse_trustee(mapping['source']),
                        'target_trustee': parse_trustee(mapping['target']),
                        'line': mapping.get('line'),
                    })
            except (FileNotFoundError, ValueError) as e:
                log_stderr("ERROR", f"Failed to load group mappings file: {e}")
                sys.exit(1)

        # Display summary of mappings
        if args.verbose:
            if owner_change_patterns:
                print(f"Owner changes:    {len(owner_change_patterns)} mapping(s)", file=sys.stderr)
                for p in owner_change_patterns:
                    print(f"                  {p['source']} -> {p['target']}", file=sys.stderr)

            if group_change_patterns:
                print(f"Group changes:    {len(group_change_patterns)} mapping(s)", file=sys.stderr)
                for p in group_change_patterns:
                    print(f"                  {p['source']} -> {p['target']}", file=sys.stderr)

        if args.dry_run:
            log_stderr("DRY RUN", "Preview mode - no changes will be made")

        if args.verbose:
            print("=" * 70, file=sys.stderr)
            log_stderr("INFO", "Resolving identities...", newline_before=True)

        # Helper to extract identifier and type from parsed trustee
        def get_identifier_and_type(trustee_spec):
            payload = trustee_spec['payload']
            id_type = trustee_spec['type']
            if id_type == 'uid':
                return payload.get('uid'), id_type
            elif id_type == 'gid':
                return payload.get('gid'), id_type
            elif id_type == 'sid':
                return payload.get('sid'), id_type
            elif id_type == 'auth_id':
                return payload.get('auth_id'), id_type
            else:  # name
                return payload.get('name'), 'name'

        async with client.create_session() as session:
            # Resolve owner change patterns
            for p in owner_change_patterns:
                # Resolve source
                source_name = p['source']
                if args.verbose:
                    log_stderr("INFO", f"Resolving source owner '{source_name}'...")
                source_identifier, source_id_type = get_identifier_and_type(p['source_trustee'])
                result = await client.resolve_identity(session, source_identifier, source_id_type)
                if result and result.get('auth_id'):
                    p['source_auth_id'] = str(result['auth_id'])
                    if args.verbose:
                        log_stderr("INFO", f"Resolved source '{source_name}' -> auth_id {p['source_auth_id']}")
                else:
                    log_stderr("WARN", f"Could not resolve source owner '{source_name}' - may not exist")
                    p['source_auth_id'] = None

                # Resolve target - MUST succeed
                target_name = p['target']
                if args.verbose:
                    log_stderr("INFO", f"Resolving target owner '{target_name}'...")
                target_identifier, target_id_type = get_identifier_and_type(p['target_trustee'])
                result = await client.resolve_identity(session, target_identifier, target_id_type)
                if result and result.get('auth_id'):
                    p['target_auth_id'] = str(result['auth_id'])
                    if args.verbose:
                        log_stderr("INFO", f"Resolved target '{target_name}' -> auth_id {p['target_auth_id']}")
                else:
                    log_stderr("ERROR", f"Could not resolve target owner '{target_name}'")
                    log_stderr("ERROR", "Target must exist before changing ownership")
                    sys.exit(1)

            # Resolve group change patterns
            for p in group_change_patterns:
                # Resolve source
                source_name = p['source']
                if args.verbose:
                    log_stderr("INFO", f"Resolving source group '{source_name}'...")
                source_identifier, source_id_type = get_identifier_and_type(p['source_trustee'])
                result = await client.resolve_identity(session, source_identifier, source_id_type)
                if result and result.get('auth_id'):
                    p['source_auth_id'] = str(result['auth_id'])
                    if args.verbose:
                        log_stderr("INFO", f"Resolved source '{source_name}' -> auth_id {p['source_auth_id']}")
                else:
                    log_stderr("WARN", f"Could not resolve source group '{source_name}' - may not exist")
                    p['source_auth_id'] = None

                # Resolve target - MUST succeed
                target_name = p['target']
                if args.verbose:
                    log_stderr("INFO", f"Resolving target group '{target_name}'...")
                target_identifier, target_id_type = get_identifier_and_type(p['target_trustee'])
                result = await client.resolve_identity(session, target_identifier, target_id_type)
                if result and result.get('auth_id'):
                    p['target_auth_id'] = str(result['auth_id'])
                    if args.verbose:
                        log_stderr("INFO", f"Resolved target '{target_name}' -> auth_id {p['target_auth_id']}")
                else:
                    log_stderr("ERROR", f"Could not resolve target group '{target_name}'")
                    log_stderr("ERROR", "Target must exist before changing group")
                    sys.exit(1)

        # Build lookup dicts for fast matching
        owner_source_to_target = {}
        for p in owner_change_patterns:
            if p.get('source_auth_id'):
                owner_source_to_target[p['source_auth_id']] = {
                    'target_auth_id': p['target_auth_id'],
                    'source_name': p['source'],
                    'target_name': p['target'],
                }

        group_source_to_target = {}
        for p in group_change_patterns:
            if p.get('source_auth_id'):
                group_source_to_target[p['source_auth_id']] = {
                    'target_auth_id': p['target_auth_id'],
                    'source_name': p['source'],
                    'target_name': p['target'],
                }

        if not owner_source_to_target and not group_source_to_target:
            log_stderr("WARN", "No valid source identities could be resolved. No files will be changed.", newline_before=True)
            return

        # Initialize statistics
        change_stats = {
            'files_scanned': 0,
            'owners_changed': 0,
            'groups_changed': 0,
            'owner_change_failed': 0,
            'group_change_failed': 0,
            'files_skipped': 0,
            'errors': [],
        }

        # Resolve any owner filters for the file filter
        owner_auth_ids = None
        async with client.create_session() as session:
            if args.owners:
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)

        # Create file filter
        file_filter = create_file_filter(args, owner_auth_ids)

        # Build filter info for smart directory skipping
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

        size_filter_info = None
        if args.larger_than:
            size_filter_info = {"min_size": parse_size_to_bytes(args.larger_than)}

        owner_filter_info = None
        if owner_auth_ids:
            owner_filter_info = {"auth_ids": owner_auth_ids}

        # Create progress tracker
        progress = (
            ProgressTracker(verbose=args.progress)
            if args.progress
            else None
        )

        if args.verbose:
            if args.propagate_changes:
                log_stderr("INFO", f"Processing {args.path} and all children...", newline_before=True)
            else:
                log_stderr("INFO", f"Processing {args.path} only (use --propagate-changes for children)...", newline_before=True)
        start_time = time.time()

        # Helper function to process a single file/directory for ownership change
        async def process_file_for_ownership_change(session, entry):
            change_stats['files_scanned'] += 1
            file_path = entry.get('path')
            file_owner = entry.get('owner')
            file_group = entry.get('group')

            new_owner = None
            new_group = None
            owner_change_info = None
            group_change_info = None

            # Check if owner matches any source
            if file_owner and file_owner in owner_source_to_target:
                owner_change_info = owner_source_to_target[file_owner]
                new_owner = owner_change_info['target_auth_id']

            # Check if group matches any source
            if file_group and file_group in group_source_to_target:
                group_change_info = group_source_to_target[file_group]
                new_group = group_change_info['target_auth_id']

            # If no changes needed, skip
            if not new_owner and not new_group:
                return

            # Dry run - just log what would change
            if args.dry_run:
                if new_owner:
                    log_stderr("DRY RUN", f"Would change owner: {file_path}")
                    print(f"          {owner_change_info['source_name']} (auth_id: {file_owner}) -> "
                          f"{owner_change_info['target_name']} (auth_id: {new_owner})", file=sys.stderr)
                    change_stats['owners_changed'] += 1
                if new_group:
                    log_stderr("DRY RUN", f"Would change group: {file_path}")
                    print(f"          {group_change_info['source_name']} (auth_id: {file_group}) -> "
                          f"{group_change_info['target_name']} (auth_id: {new_group})", file=sys.stderr)
                    change_stats['groups_changed'] += 1
                return

            # Apply the change
            success, error_msg = await client.set_file_owner_group(
                session,
                file_path,
                owner=new_owner,
                group=new_group
            )

            if success:
                if new_owner:
                    change_stats['owners_changed'] += 1
                    if args.verbose:
                        log_stderr("INFO", f"Changed owner: {file_path}")
                if new_group:
                    change_stats['groups_changed'] += 1
                    if args.verbose:
                        log_stderr("INFO", f"Changed group: {file_path}")
            else:
                if new_owner:
                    change_stats['owner_change_failed'] += 1
                if new_group:
                    change_stats['group_change_failed'] += 1
                change_stats['errors'].append({
                    'path': file_path,
                    'error': error_msg
                })
                if args.verbose:
                    log_stderr("ERROR", f"Failed to change ownership: {file_path}: {error_msg}")

        async with client.create_session() as session:
            if args.propagate_changes:
                await display_scope_aggregates(
                    client, session, args.path,
                    label="Changing ownership in",
                    verbose=args.verbose,
                    max_depth=args.max_depth,
                    omit_subdirs=args.omit_subdirs,
                )

                # Walk the tree and change ownership for all matching files
                async def tree_walk_callback(entry):
                    await process_file_for_ownership_change(session, entry)

                await client.walk_tree_async(
                    session,
                    args.path,
                    args.max_depth,
                    progress=progress,
                    file_filter=file_filter,
                    omit_subdirs=args.omit_subdirs,
                    omit_paths=args.omit_path,
                    collect_results=False,
                    verbose=args.verbose,
                    max_entries_per_dir=args.max_entries_per_dir,
                    time_filter_info=time_filter_info,
                    size_filter_info=size_filter_info,
                    owner_filter_info=owner_filter_info,
                    output_callback=tree_walk_callback,
                )
            else:
                # Only process the target path itself
                owner_group_info = await client.get_file_owner_group(session, args.path)
                if owner_group_info:
                    # Build an entry dict compatible with the processing function
                    entry = {
                        'path': args.path,
                        'owner': owner_group_info.get('owner'),
                        'group': owner_group_info.get('group'),
                        'owner_details': owner_group_info.get('owner_details'),
                        'group_details': owner_group_info.get('group_details'),
                    }
                    await process_file_for_ownership_change(session, entry)
                else:
                    log_stderr("ERROR", f"Could not get attributes for: {args.path}")
                    change_stats['errors'].append({
                        'path': args.path,
                        'error': 'Could not get file attributes'
                    })

        elapsed = time.time() - start_time

        # Final progress report
        if progress:
            progress.final_report()

        # Display summary
        print("\n" + "=" * 70, file=sys.stderr)
        if args.dry_run:
            print("OWNER/GROUP CHANGE PREVIEW (DRY RUN)", file=sys.stderr)
        else:
            print("OWNER/GROUP CHANGE SUMMARY", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(f"Path:               {args.path}", file=sys.stderr)
        print(f"Files scanned:      {change_stats['files_scanned']:,}", file=sys.stderr)
        print(f"Owners changed:     {change_stats['owners_changed']:,}", file=sys.stderr)
        print(f"Groups changed:     {change_stats['groups_changed']:,}", file=sys.stderr)
        if change_stats['owner_change_failed'] > 0 or change_stats['group_change_failed'] > 0:
            print(f"Owner changes failed: {change_stats['owner_change_failed']:,}", file=sys.stderr)
            print(f"Group changes failed: {change_stats['group_change_failed']:,}", file=sys.stderr)
        print(f"Elapsed time:       {elapsed:.2f}s", file=sys.stderr)
        if change_stats['files_scanned'] > 0:
            rate = change_stats['files_scanned'] / elapsed if elapsed > 0 else 0
            print(f"Processing rate:    {rate:.0f} files/sec", file=sys.stderr)

        if change_stats['errors']:
            print("\nErrors encountered:", file=sys.stderr)
            for error in change_stats['errors'][:10]:
                print(f"  {error['path']}: {error['error']}", file=sys.stderr)
            if len(change_stats['errors']) > 10:
                print(f"  ... and {len(change_stats['errors']) - 10} more", file=sys.stderr)

        # Save identity cache
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)

        # Exit with error code if any failures
        if change_stats['owner_change_failed'] > 0 or change_stats['group_change_failed'] > 0:
            sys.exit(1)

        return  # Exit after owner/group change mode

    # ========================================================================
    # EXTENDED ATTRIBUTE MODIFICATION MODE
    # ========================================================================
    set_attribute_mode = (args.set_attribute_true_parsed or args.set_attribute_false_parsed)

    if set_attribute_mode:
        if args.verbose:
            log_stderr("INFO", "Extended Attribute Modification Mode", newline_before=True)
            print("=" * 70, file=sys.stderr)

        # Build the attributes dict to PATCH
        attrs_to_set = {}
        if args.set_attribute_true_parsed:
            for attr in args.set_attribute_true_parsed:
                attrs_to_set[attr] = True
        if args.set_attribute_false_parsed:
            for attr in args.set_attribute_false_parsed:
                attrs_to_set[attr] = False

        if args.verbose:
            for attr, val in attrs_to_set.items():
                log_stderr("INFO", f"  Will set {attr} = {val}")

        if args.dry_run:
            log_stderr("DRY RUN", "Preview mode - no changes will be made")

        if args.verbose:
            print("=" * 70, file=sys.stderr)

        # Statistics
        attr_stats = {
            'files_scanned': 0,
            'attributes_changed': 0,
            'change_failed': 0,
            'errors': [],
        }

        # Resolve owner filters if needed
        owner_auth_ids = None
        async with client.create_session() as session:
            if args.owners:
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)

        # Create file filter (attribute find filters are already embedded)
        file_filter = create_file_filter(args, owner_auth_ids)

        # Build filter info for smart directory skipping
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

        size_filter_info = None
        if args.larger_than:
            size_filter_info = {"min_size": parse_size_to_bytes(args.larger_than)}

        owner_filter_info = None
        if owner_auth_ids:
            owner_filter_info = {"auth_ids": owner_auth_ids}

        # Create progress tracker
        progress = (
            ProgressTracker(verbose=args.progress)
            if args.progress
            else None
        )

        if args.verbose:
            if args.propagate_changes:
                log_stderr("INFO", f"Processing {args.path} and all children...", newline_before=True)
            else:
                log_stderr("INFO", f"Processing {args.path} only (use --propagate-changes for children)...", newline_before=True)
        start_time = time.time()

        async def process_file_for_attribute_change(session, entry):
            attr_stats['files_scanned'] += 1
            file_path = entry.get('path')

            if args.dry_run:
                log_stderr("DRY RUN", f"Would set attributes on: {file_path}")
                for attr, val in attrs_to_set.items():
                    current = entry.get('extended_attributes', {}).get(attr)
                    if current is not None and current != val:
                        print(f"          {attr}: {current} -> {val}", file=sys.stderr)
                    elif current == val:
                        print(f"          {attr}: {current} (no change)", file=sys.stderr)
                attr_stats['attributes_changed'] += 1
                return

            success, error_msg = await client.set_file_extended_attributes(
                session, file_path, attrs_to_set,
                current_ext_attrs=entry.get('extended_attributes'),
            )

            if success:
                attr_stats['attributes_changed'] += 1
                if args.verbose:
                    log_stderr("INFO", f"Set attributes: {file_path}")
            else:
                attr_stats['change_failed'] += 1
                attr_stats['errors'].append({
                    'path': file_path,
                    'error': error_msg,
                })
                if args.verbose:
                    log_stderr("ERROR", f"Failed to set attributes: {file_path}: {error_msg}")

                if not args.continue_on_error:
                    print(f"\nError setting attributes on: {file_path}", file=sys.stderr)
                    print(f"  {error_msg}", file=sys.stderr)
                    print("  Use --continue-on-error to skip failures", file=sys.stderr)

        async with client.create_session() as session:
            if args.propagate_changes:
                await display_scope_aggregates(
                    client, session, args.path,
                    label="Setting attributes in",
                    verbose=args.verbose,
                    max_depth=args.max_depth,
                    omit_subdirs=args.omit_subdirs,
                )

                async def tree_walk_callback(entry):
                    await process_file_for_attribute_change(session, entry)

                await client.walk_tree_async(
                    session,
                    args.path,
                    args.max_depth,
                    progress=progress,
                    file_filter=file_filter,
                    omit_subdirs=args.omit_subdirs,
                    omit_paths=args.omit_path,
                    collect_results=False,
                    verbose=args.verbose,
                    max_entries_per_dir=args.max_entries_per_dir,
                    time_filter_info=time_filter_info,
                    size_filter_info=size_filter_info,
                    owner_filter_info=owner_filter_info,
                    output_callback=tree_walk_callback,
                )
            else:
                # Only process the target path itself
                file_attr = await client.get_file_attr(session, args.path)
                if file_attr:
                    file_attr['path'] = args.path
                    if file_filter(file_attr):
                        await process_file_for_attribute_change(session, file_attr)
                    else:
                        log_stderr("INFO", f"Target path does not match filters: {args.path}")
                else:
                    log_stderr("ERROR", f"Could not get file attributes for: {args.path}")
                    attr_stats['errors'].append({
                        'path': args.path,
                        'error': 'Could not get file attributes',
                    })

        elapsed = time.time() - start_time

        if progress:
            progress.final_report()

        # Display summary
        print("\n" + "=" * 70, file=sys.stderr)
        if args.dry_run:
            print("EXTENDED ATTRIBUTE CHANGE PREVIEW (DRY RUN)", file=sys.stderr)
        else:
            print("EXTENDED ATTRIBUTE CHANGE SUMMARY", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(f"Path:               {args.path}", file=sys.stderr)
        print(f"Attributes set:     {', '.join(f'{k}={v}' for k, v in attrs_to_set.items())}", file=sys.stderr)
        print(f"Files scanned:      {attr_stats['files_scanned']:,}", file=sys.stderr)
        print(f"Files changed:      {attr_stats['attributes_changed']:,}", file=sys.stderr)
        if attr_stats['change_failed'] > 0:
            print(f"Changes failed:     {attr_stats['change_failed']:,}", file=sys.stderr)
        print(f"Elapsed time:       {elapsed:.2f}s", file=sys.stderr)
        if attr_stats['files_scanned'] > 0:
            rate = attr_stats['files_scanned'] / elapsed if elapsed > 0 else 0
            print(f"Processing rate:    {rate:.0f} files/sec", file=sys.stderr)

        if attr_stats['errors']:
            print("\nErrors encountered:", file=sys.stderr)
            for error in attr_stats['errors'][:10]:
                print(f"  {error['path']}: {error['error']}", file=sys.stderr)
            if len(attr_stats['errors']) > 10:
                print(f"  ... and {len(attr_stats['errors']) - 10} more", file=sys.stderr)

        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)

        if attr_stats['change_failed'] > 0:
            sys.exit(1)

        return  # Exit after attribute modification mode

    # Directory aggregate statistics mode (--stats)
    if args.stats:
        stats_results = []
        async with client.create_session() as session:
            await collect_stats(
                client, session, args.path,
                results=stats_results,
                max_depth=args.max_depth,
                omit_subdirs=args.omit_subdirs,
                omit_paths=args.omit_path,
            )

        # Display formatted table to stderr
        valid = [e for e in stats_results if "error" not in e]
        errors = [e for e in stats_results if "error" in e]

        # Sort table output if requested
        if args.sort and valid:
            sort_keys = {
                "size": lambda e: e["total_size"],
                "count": lambda e: e["files"],
                "name": lambda e: e["path"],
            }
            reverse = args.sort != "name"
            valid.sort(key=sort_keys[args.sort], reverse=reverse)

        if valid:
            # Build formatted columns
            rows = []
            for e in valid:
                rows.append((
                    e["path"],
                    f"{e['files']:,}",
                    f"{e['subdirectories']:,}",
                    format_bytes(e["total_size"]),
                ))

            headers = ("Path", "Files", "Subdirectories", "Total Size")
            # Calculate column widths from data and headers
            col_widths = [len(h) for h in headers]
            for row in rows:
                for i, val in enumerate(row):
                    col_widths[i] = max(col_widths[i], len(val))

            # Path left-aligned, numeric columns right-aligned
            fmt = f"{{:<{col_widths[0]}}}  {{:>{col_widths[1]}}}  {{:>{col_widths[2]}}}  {{:>{col_widths[3]}}}"
            separator = f"{{:<{col_widths[0]}}}  {{:>{col_widths[1]}}}  {{:>{col_widths[2]}}}  {{:>{col_widths[3]}}}"

            print(fmt.format(*headers), file=sys.stderr)
            print(separator.format(
                "-" * col_widths[0], "-" * col_widths[1],
                "-" * col_widths[2], "-" * col_widths[3],
            ), file=sys.stderr)
            for row in rows:
                print(fmt.format(*row), file=sys.stderr)

        for entry in errors:
            print(f"[ERROR] {entry['path']}: {entry['error']}", file=sys.stderr)

        # Write JSON to stdout if requested
        if args.json:
            json_parser.dump(valid, sys.stdout, indent=2)
            print()  # trailing newline

        # Write JSON file if requested
        if args.json_out:
            with open(args.json_out, "w") as f:
                json_parser.dump(valid, f, indent=2)
            log_stderr("INFO", f"Wrote {len(valid)} entries to {args.json_out}")

        # Write CSV file if requested
        if args.csv_out:
            import csv
            with open(args.csv_out, "w", newline="") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["path", "files", "subdirectories", "total_size"]
                )
                writer.writeheader()
                writer.writerows(valid)
            log_stderr("INFO", f"Wrote {len(valid)} entries to {args.csv_out}")

        return

    # PHASE 3: Directory statistics exploration mode
    if args.show_dir_stats:
        log_stderr("INFO", "Directory statistics mode (exploration)", newline_before=True)
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
            owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)

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
            log_stderr("WARN", "No valid owners resolved - no files will match!")

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
    # Progress tracker is needed if --progress or --limit is specified
    progress = (
        ProgressTracker(verbose=args.progress, limit=args.limit)
        if args.progress or args.limit
        else None
    )

    # Create owner stats tracker if owner-report enabled
    # Use capacity-based calculation (actual disk usage) by default to handle sparse files correctly
    owner_stats = (
        OwnerStats(use_capacity=args.use_capacity) if args.owner_report else None
    )

    # Walk tree and collect matches
    start_time = time.time()

    if profiler:
        tree_walk_start = time.time()

    # Determine which features require collecting all results in memory
    # - acl_report: needs to fetch ACLs after walk completes
    # - find_similar: needs cross-file comparison
    # - resolve_links combined with non-streaming output: needs post-walk resolution
    #
    # Features that CAN be streamed (memory-efficient):
    # - csv_out: write rows as entries arrive
    # - json_out: write NDJSON lines as entries arrive
    # - stdout output: already streams
    #
    # This change fixes OOM crashes when using --csv-out with millions of files
    features_requiring_collection = args.acl_report or args.find_similar

    # resolve_links with file output can be streamed (resolve per-entry)
    # resolve_links with stdout still needs collection for backward compatibility
    resolve_links_needs_collection = args.resolve_links and not (args.csv_out or args.json_out)

    collect_results = features_requiring_collection or resolve_links_needs_collection

    # Create output callback for streaming results
    output_callback = None
    batched_handler = None
    streaming_file_handler = None

    # STREAMING FILE OUTPUT: Use StreamingFileOutputHandler for --csv-out / --json-out
    # This writes entries to file as they arrive, avoiding OOM with large result sets
    if (args.csv_out or args.json_out) and not features_requiring_collection:
        output_format = "json" if args.json_out else "csv"
        output_path = args.json_out if args.json_out else args.csv_out

        streaming_file_handler = StreamingFileOutputHandler(
            client=client,
            output_path=output_path,
            output_format=output_format,
            batch_size=1000,  # Batch for identity resolution
            show_owner=args.show_owner,
            show_group=args.show_group,
            all_attributes=args.all_attributes,
            progress=progress,
            args=args,
            dont_resolve_ids=args.dont_resolve_ids,
            field_specs=args.parsed_fields,
            unix_time=args.unix_time,
        )

        async def output_callback(entry):
            # Handle resolve_links inline for streaming mode
            if args.resolve_links and entry.get("type") == "FS_FILE_TYPE_SYMLINK":
                async with client.create_session() as link_session:
                    target = await client.read_symlink(link_session, entry["path"])
                    if target:
                        if not target.startswith('/'):
                            symlink_dir = os.path.dirname(entry["path"])
                            entry["symlink_target"] = os.path.normpath(os.path.join(symlink_dir, target))
                        else:
                            entry["symlink_target"] = target
                    else:
                        entry["symlink_target"] = "(unreadable)"
            await streaming_file_handler.add_entry(entry)

        # Open the file and write header
        await streaming_file_handler.open()

    # STDOUT STREAMING: existing logic for stdout output
    elif not args.owner_report and not args.acl_report and not args.find_similar and not resolve_links_needs_collection:
        if args.show_owner or args.show_group:
            # Use batched output handler for streaming with identity resolution
            output_format = "json" if args.json else "text"
            # Use smaller batch size when limit is specified for faster streaming
            batch_size = min(20, args.limit) if args.limit else 100
            batched_handler = BatchedOutputHandler(
                client,
                batch_size=batch_size,
                show_owner=args.show_owner,
                show_group=args.show_group,
                output_format=output_format,
                progress=progress,
                all_attributes=args.all_attributes,
                dont_resolve_ids=args.dont_resolve_ids,
                field_specs=args.parsed_fields,
            )

            async def output_callback(entry):
                await batched_handler.add_entry(entry)

        else:
            # Direct streaming output (no owner resolution needed)
            if args.parsed_fields:
                # --fields mode: extract only requested fields
                if args.json:
                    async def output_callback(entry):
                        if args.unix_time:
                            convert_timestamps_to_epoch(entry)
                        row = extract_fields(entry, args.parsed_fields)
                        try:
                            print(json_parser.dumps(row, escape_forward_slashes=False))
                        except TypeError:
                            print(json_parser.dumps(row))
                        sys.stdout.flush()
                        if progress:
                            await progress.increment_output()
                else:
                    async def output_callback(entry):
                        if args.unix_time:
                            convert_timestamps_to_epoch(entry)
                        row = extract_fields(entry, args.parsed_fields)
                        values = [str(v) if v is not None else "" for v in row.values()]
                        print("\t".join(values))
                        sys.stdout.flush()
                        if progress:
                            await progress.increment_output()

            elif args.json:
                # JSON to stdout
                if args.all_attributes:
                    # Output full entry with all attributes
                    async def output_callback(entry):
                        if args.unix_time:
                            convert_timestamps_to_epoch(entry)
                        # Use escape_forward_slashes=False for ujson to avoid \/
                        try:
                            print(json_parser.dumps(entry, escape_forward_slashes=False))
                        except TypeError:
                            # Standard json doesn't have escape_forward_slashes parameter
                            print(json_parser.dumps(entry))
                        sys.stdout.flush()
                        if progress:
                            await progress.increment_output()
                else:
                    # Output minimal entry (just path + filter fields)
                    async def output_callback(entry):
                        minimal_entry = {"path": entry["path"]}
                        # Add filter-relevant fields
                        if args.older_than or args.newer_than:
                            minimal_entry[args.time_field] = entry.get(args.time_field)
                        if args.larger_than or args.smaller_than:
                            minimal_entry["size"] = entry.get("size")
                        if args.unix_time:
                            convert_timestamps_to_epoch(minimal_entry)
                        # Use escape_forward_slashes=False for ujson to avoid \/
                        try:
                            print(json_parser.dumps(minimal_entry, escape_forward_slashes=False))
                        except TypeError:
                            # Standard json doesn't have escape_forward_slashes parameter
                            print(json_parser.dumps(minimal_entry))
                        sys.stdout.flush()
                        if progress:
                            await progress.increment_output()

            else:
                # Plain text to stdout
                async def output_callback(entry):
                    print(entry["path"])
                    sys.stdout.flush()
                    if progress:
                        await progress.increment_output()

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
        if streaming_file_handler:
            # Streaming mode - count comes from handler
            pass  # Will be reported after handler close
        else:
            log_stderr("INFO", f"Tree walk completed, collected {len(matching_files)} matching files")

    # Flush any remaining batched output
    if batched_handler:
        await batched_handler.flush()

    # Close streaming file handler and report results
    if streaming_file_handler:
        await streaming_file_handler.close()
        rows_written = streaming_file_handler.get_rows_written()
        output_path = args.json_out if args.json_out else args.csv_out
        if args.verbose or args.progress:
            log_stderr("INFO", f"Streaming complete: wrote {rows_written:,} rows to {output_path}", newline_before=True)
        # Save identity cache and exit - no further processing needed
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
        return

    # Resolve owner and group identities if --show-owner or --show-group is enabled (for non-streaming modes only)
    # Skip if batched_handler was used (streaming mode) or --dont-resolve-ids is set
    identity_cache_for_output = {}
    if (args.show_owner or args.show_group) and matching_files and not batched_handler and not args.dont_resolve_ids:
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
                show_group=args.show_group,
                dont_resolve_ids=args.dont_resolve_ids
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
                    if args.dont_resolve_ids:
                        owner_name = format_raw_id(owner_details, acl_info.get('owner', ''))
                    else:
                        # Use the numeric owner field as the auth_id
                        owner_auth_id = acl_info.get('owner')
                        if owner_auth_id and owner_auth_id in identity_cache:
                            owner_name = format_owner_name(identity_cache[owner_auth_id])
                        elif owner_auth_id:
                            owner_name = f"auth_id:{owner_auth_id}"
                        else:
                            owner_name = "Unknown"

                if args.show_group:
                    if args.dont_resolve_ids:
                        group_name = format_raw_id(group_details, acl_info.get('group', ''))
                    else:
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

            log_stderr("INFO", f"ACL CSV exported to: {args.acl_csv}", newline_before=True)

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
                    if args.dont_resolve_ids:
                        json_entry['owner'] = format_raw_id(owner_details, acl_info.get('owner', ''))
                    else:
                        # Use the numeric owner field as the auth_id
                        owner_auth_id = acl_info.get('owner')
                        if owner_auth_id and owner_auth_id in identity_cache:
                            json_entry['owner'] = format_owner_name(identity_cache[owner_auth_id])
                        elif owner_auth_id:
                            json_entry['owner'] = f"auth_id:{owner_auth_id}"
                        else:
                            json_entry['owner'] = "Unknown"

                if args.show_group:
                    if args.dont_resolve_ids:
                        json_entry['group'] = format_raw_id(group_details, acl_info.get('group', ''))
                    else:
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
                log_stderr("INFO", f"ACL JSON exported to: {args.json_out}", newline_before=True)

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
                    log_stderr("INFO", f"Created empty CSV file: {args.csv_out}", newline_before=True)
            elif args.json_out:
                # Create empty JSON file
                with open(args.json_out, "w") as json_file:
                    pass  # Empty file
                if args.verbose:
                    log_stderr("INFO", f"Created empty JSON file: {args.json_out}", newline_before=True)
        else:
            total_groups = len(similar_files)
            total_similar = sum(len(group) for group in similar_files.values())

            # Helper function to calculate coverage for a specific file size
            def calculate_coverage(file_size):
                if args.by_size:
                    return "Low (size+metadata only)"
                if file_size == 0:
                    return "N/A"

                chunk_size = args.sample_size if args.sample_size else 65536
                requested_points = args.sample_points if args.sample_points else 11

                # If requested sampling capacity exceeds file size, report 100% coverage
                # This handles cases where large chunks + many points are requested for small files
                requested_capacity = requested_points * chunk_size
                if requested_capacity >= file_size:
                    return "100%"

                sample_offsets = calculate_sample_points(file_size, args.sample_points, chunk_size)

                # Calculate actual bytes that would be read by summing bytes at each offset
                total_bytes_sampled = 0
                for offset in sample_offsets:
                    bytes_at_offset = min(chunk_size, file_size - offset)
                    total_bytes_sampled += bytes_at_offset

                coverage_pct = min(100.0, (total_bytes_sampled / file_size) * 100)
                return f"{coverage_pct:.1f}%" if coverage_pct < 100 else "100%"

            print(f"\nFound {total_similar:,} similar files in {total_groups:,} groups", file=sys.stderr)
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
                                "coverage": calculate_coverage(file_size)
                            })

                if args.verbose:
                    log_stderr("INFO", f"Wrote {total_similar:,} similar files ({total_groups:,} groups) to {args.csv_out}", newline_before=True)
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
                                "coverage": calculate_coverage(file_size)
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
                            log_stderr("INFO", f"Wrote {total_similar:,} similar files ({total_groups:,} groups) to {args.json_out}", newline_before=True)
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
            log_stderr("INFO", f"Limiting results to {args.limit} files (found {len(matching_files)})", newline_before=True)
        matching_files = matching_files[: args.limit]

    # Output results
    if profiler:
        output_start = time.time()

    if args.csv_out:
        # CSV output
        import csv

        # --fields mode for collected results CSV
        if args.parsed_fields and matching_files:
            fieldnames = [name for name, _ in args.parsed_fields]
            with open(args.csv_out, "w", newline="") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for entry in matching_files:
                    if args.unix_time:
                        convert_timestamps_to_epoch(entry)
                    row = extract_fields(entry, args.parsed_fields)
                    for k, v in row.items():
                        if isinstance(v, (dict, list)):
                            row[k] = json_parser.dumps(v)
                    writer.writerow(row)
            if args.verbose:
                log_stderr("INFO", f"Wrote {len(matching_files)} results to {args.csv_out}", newline_before=True)
        else:
          with open(args.csv_out, "w", newline="") as csv_file:
            if not matching_files:
                if args.verbose:
                    log_stderr("INFO", "No matching files found, CSV file will be empty")
                return

            if args.all_attributes:
                # Add owner name to entries if --show-owner is enabled
                if args.show_owner:
                    for entry in matching_files:
                        if args.dont_resolve_ids:
                            owner_details = entry.get("owner_details", {})
                            entry["owner_name"] = format_raw_id(owner_details, entry.get("owner", ""))
                        else:
                            owner_details = entry.get("owner_details", {})
                            owner_auth_id = owner_details.get("auth_id") or entry.get(
                                "owner"
                            )
                            if owner_auth_id and owner_auth_id in identity_cache_for_output:
                                identity = identity_cache_for_output[owner_auth_id]
                                entry["owner_name"] = format_owner_name(identity)
                            else:
                                entry["owner_name"] = "Unknown"

                # Add group name to entries if --show-group is enabled
                if args.show_group:
                    for entry in matching_files:
                        if args.dont_resolve_ids:
                            group_details = entry.get("group_details", {})
                            entry["group_name"] = format_raw_id(group_details, entry.get("group", ""))
                        else:
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
                        if args.dont_resolve_ids:
                            owner_details = entry.get("owner_details", {})
                            row["owner"] = format_raw_id(owner_details, entry.get("owner", ""))
                        else:
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
                        if args.dont_resolve_ids:
                            group_details = entry.get("group_details", {})
                            row["group"] = format_raw_id(group_details, entry.get("group", ""))
                        else:
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
            log_stderr("INFO", f"Wrote {len(matching_files)} results to {args.csv_out}", newline_before=True)
    elif args.json or args.json_out:
        # JSON output
        # Skip if batched_handler was used (already output via streaming)
        if batched_handler:
            pass  # Already handled by batched streaming
        elif args.parsed_fields and matching_files:
            output_handle = sys.stdout
            if args.json_out:
                output_handle = open(args.json_out, "w")
            for entry in matching_files:
                if args.unix_time:
                    convert_timestamps_to_epoch(entry)
                row = extract_fields(entry, args.parsed_fields)
                try:
                    output_handle.write(json_parser.dumps(row, escape_forward_slashes=False) + "\n")
                except TypeError:
                    output_handle.write(json_parser.dumps(row) + "\n")
            if args.json_out:
                output_handle.close()
                log_stderr("INFO", f"Results written to {args.json_out}", newline_before=True)
        else:
            output_handle = sys.stdout
            if args.json_out:
                output_handle = open(args.json_out, "w")

            for entry in matching_files:
                if args.unix_time:
                    convert_timestamps_to_epoch(entry)
                if args.all_attributes:
                    # Add owner name to entry if --show-owner is enabled
                    if args.show_owner:
                        if args.dont_resolve_ids:
                            owner_details = entry.get("owner_details", {})
                            entry["owner_name"] = format_raw_id(owner_details, entry.get("owner", ""))
                        else:
                            owner_details = entry.get("owner_details", {})
                            owner_auth_id = owner_details.get("auth_id") or entry.get(
                                "owner"
                            )
                            if owner_auth_id and owner_auth_id in identity_cache_for_output:
                                identity = identity_cache_for_output[owner_auth_id]
                                entry["owner_name"] = format_owner_name(identity)
                            else:
                                entry["owner_name"] = "Unknown"

                    # Add group name to entry if --show-group is enabled
                    if args.show_group:
                        if args.dont_resolve_ids:
                            group_details = entry.get("group_details", {})
                            entry["group_name"] = format_raw_id(group_details, entry.get("group", ""))
                        else:
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
                        if args.dont_resolve_ids:
                            owner_details = entry.get("owner_details", {})
                            minimal_entry["owner"] = format_raw_id(owner_details, entry.get("owner", ""))
                        else:
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
                        if args.dont_resolve_ids:
                            group_details = entry.get("group_details", {})
                            minimal_entry["group"] = format_raw_id(group_details, entry.get("group", ""))
                        else:
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
                log_stderr("INFO", f"Results written to {args.json_out}", newline_before=True)
    else:
        # Plain text output
        # Only output if we didn't use streaming callback (which already printed results)
        if output_callback is None and args.parsed_fields:
            for entry in matching_files:
                if args.unix_time:
                    convert_timestamps_to_epoch(entry)
                row = extract_fields(entry, args.parsed_fields)
                values = [str(v) if v is not None else "" for v in row.values()]
                print("\t".join(values))
        elif output_callback is None:
            for entry in matching_files:
                output_line = entry["path"]

                # Add symlink target if --resolve-links is enabled and this is a symlink
                if args.resolve_links and "symlink_target" in entry:
                    output_line = f"{output_line} → {entry['symlink_target']}"

                # Add owner information if --show-owner is enabled
                if args.show_owner:
                    if args.dont_resolve_ids:
                        owner_details = entry.get("owner_details", {})
                        owner_name = format_raw_id(owner_details, entry.get("owner", ""))
                    else:
                        owner_details = entry.get("owner_details", {})
                        owner_auth_id = owner_details.get("auth_id") or entry.get("owner")
                        if owner_auth_id and owner_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[owner_auth_id]
                            owner_name = format_owner_name(identity)
                        else:
                            owner_name = "Unknown"
                    output_line = f"{output_line}\t{owner_name}"

                # Add group information if --show-group is enabled
                if args.show_group:
                    if args.dont_resolve_ids:
                        group_details = entry.get("group_details", {})
                        group_name = format_raw_id(group_details, entry.get("group", ""))
                    else:
                        group_details = entry.get("group_details", {})
                        group_auth_id = group_details.get("auth_id") or entry.get("group")
                        if group_auth_id and group_auth_id in identity_cache_for_output:
                            identity = identity_cache_for_output[group_auth_id]
                            group_name = format_owner_name(identity)
                        else:
                            group_name = "Unknown"
                    output_line = f"{output_line}\t{group_name}"

                print(output_line)

    # Record output timing
    if profiler:
        output_time = time.time() - output_start
        profiler.record_sync("output_generation", output_time)

    # Summary
    if args.verbose:
        log_stderr("INFO", f"Processed {progress.total_objects if progress else 'N/A'} objects in {elapsed:.2f}s", newline_before=True)
        log_stderr("INFO", f"Found {len(matching_files)} matching files")
        rate = (
            (progress.total_objects if progress else len(matching_files)) / elapsed
            if elapsed > 0
            else 0
        )
        log_stderr("INFO", f"Processing rate: {rate:.1f} obj/sec")

    # Print profiling report
    if profiler:
        profiler.print_report(elapsed)

    # Save identity cache before exiting
    save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)


def main():
    # Load or generate tuning profile for defaults
    tuning_profile = load_tuning_profile()
    is_first_run = tuning_profile is None

    # Check for --retune or --show-tuning early (before full arg parsing)
    if '--retune' in sys.argv:
        profile_name = 'balanced'
        for i, arg in enumerate(sys.argv):
            if arg == '--tuning-profile' and i + 1 < len(sys.argv):
                profile_name = sys.argv[i + 1]
        tuning_profile = generate_tuning_profile(profile_name)
        save_tuning_profile(tuning_profile)
        print("=" * 70, file=sys.stderr)
        print("GrumpWalk - Tuning Profile Regenerated", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(format_profile_summary(tuning_profile), file=sys.stderr)
        print("", file=sys.stderr)
        print(f"Profile saved to: {get_profile_path()}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        sys.exit(0)

    if '--show-tuning' in sys.argv:
        if tuning_profile is None:
            tuning_profile = generate_tuning_profile('balanced')
        print("=" * 70, file=sys.stderr)
        print("GrumpWalk - Current Tuning Profile", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(format_profile_summary(tuning_profile), file=sys.stderr)
        print("", file=sys.stderr)
        profile_path = get_profile_path()
        if profile_path.exists():
            print(f"Profile file: {profile_path}", file=sys.stderr)
        else:
            print("Profile file: (not yet saved)", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        sys.exit(0)

    # Get defaults from profile (or use hardcoded defaults if no profile)
    if tuning_profile:
        default_max_concurrent = tuning_profile['recommended']['max_concurrent']
        default_connector_limit = tuning_profile['recommended']['connector_limit']
        default_acl_concurrency = tuning_profile['recommended']['acl_concurrency']
    else:
        default_max_concurrent = 100
        default_connector_limit = 100
        default_acl_concurrency = 100

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

  # Remove an ACE from a directory and all children
  ./grumpwalk.py --host cluster.example.com --path /data --remove-ace 'Allow:Group111' --propagate-changes

  # Add an ACE with Modify permission (inheritable to files and directories)
  ./grumpwalk.py --host cluster.example.com --path /data --add-ace 'Allow:fd:Group111:Modify' --propagate-changes

  # Replace an existing ACE with different permissions (in-place, same type)
  ./grumpwalk.py --host cluster.example.com --path /data --replace-ace 'Allow:fd:Group111:Read' --propagate-changes

  # Change ACE type from Allow to Deny (using --new-ace for full replacement)
  ./grumpwalk.py --host cluster.example.com --path /data --replace-ace 'Allow:Group111' --new-ace 'Deny:fd:Group111:rw' --propagate-changes
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"grumpwalk {__version__}"
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
        "--fields",
        metavar="FIELD[,FIELD,...]",
        help="Comma-separated list of fields to include in output. "
             "Supports dot notation (owner_details.id_value) and aliases: "
             "owner_id, owner_type, group_id, group_type, attr.<name>. "
             "Cannot be combined with --all-attributes. "
             "Use --fields-list to see all available fields.",
    )
    class _FieldsListAction(argparse.Action):
        def __init__(self, option_strings, dest, **kwargs):
            super().__init__(option_strings, dest, nargs=0, default=False, **kwargs)
        def __call__(self, parser, namespace, values, option_string=None):
            from modules.output import print_field_list
            print_field_list()
            sys.exit(0)

    output.add_argument(
        "--fields-list",
        action=_FieldsListAction,
        help="List all available field names for --fields and exit",
    )
    output.add_argument(
        "--unix-time",
        action="store_true",
        help="Output timestamps as unix epoch seconds instead of ISO 8601. "
             "Applies to creation_time, modification_time, access_time, change_time. "
             "Only affects stdout and file output, not stderr/logging.",
    )
    output.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed diagnostic output to the terminal (stderr). "
             "Independent of --log-file.",
    )
    output.add_argument(
        "--log-file",
        metavar="FILE",
        help="Write log output to file (timestamps include timezone). "
             "Independent of --verbose and --progress.",
    )
    output.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "ERROR"],
        default="INFO",
        help="Minimum log level for --log-file (default: INFO). "
             "ERROR includes errors and warnings. "
             "INFO adds operational messages. "
             "DEBUG adds all diagnostic output.",
    )
    output.add_argument(
        "--progress",
        action="store_true",
        help="Show real-time progress statistics to the terminal (stderr). "
             "Independent of --log-file.",
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
    output.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what changes would be made without applying them",
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
        "--dont-resolve-ids",
        action="store_true",
        help="Skip identity resolution for --show-owner/--show-group; output raw UID/GID/SID values",
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
        help="Source object path on cluster",
        metavar="PATH"
    )

    acl_management.add_argument(
        "--source-acl-file",
        help="Source ACL from local JSON file",
        metavar="FILE"
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
        help="Continue ACL propagation on errors without prompting (errors logged to stderr)"
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

    acl_management.add_argument(
        "--acl-concurrency",
        type=int,
        default=default_acl_concurrency,
        metavar="N",
        help=f"Concurrent ACL operations during propagation (default: {default_acl_concurrency})"
    )

    acl_management.add_argument(
        "--propagate-changes",
        action="store_true",
        help="Apply changes to all children recursively. "
             "Without this flag, only the target path itself is changed. "
             "Works with ACE manipulation, owner/group changes, and ACL cloning."
    )

    acl_management.add_argument(
        "--change-owner",
        action="append",
        metavar="SOURCE:TARGET",
        help="Change file owner from SOURCE to TARGET. "
             "Finds files owned by SOURCE and changes owner to TARGET. "
             "Format: 'olduser:newuser', 'uid:1001:uid:2001', 'DOMAIN\\\\user:DOMAIN\\\\other'. "
             "Repeatable for multiple mappings. Use with --dry-run to preview changes."
    )

    acl_management.add_argument(
        "--change-group",
        action="append",
        metavar="SOURCE:TARGET",
        help="Change file group from SOURCE to TARGET. "
             "Finds files with group SOURCE and changes group to TARGET. "
             "Format: 'oldgroup:newgroup', 'gid:100:gid:200'. "
             "Repeatable for multiple mappings. Use with --dry-run to preview changes."
    )

    acl_management.add_argument(
        "--change-owners-file",
        metavar="FILE",
        help="CSV file with owner mappings (source,target format). "
             "Each row maps a source owner to target owner. "
             "Same format as --migrate-trustees CSV."
    )

    acl_management.add_argument(
        "--change-groups-file",
        metavar="FILE",
        help="CSV file with group mappings (source,target format). "
             "Each row maps a source group to target group. "
             "Same format as --migrate-trustees CSV."
    )

    # Hidden alias for backward compatibility (use --propagate-changes instead)
    acl_management.add_argument(
        "--propagate-owner-changes",
        action="store_true",
        help=argparse.SUPPRESS
    )

    # ============================================================================
    # FEATURE: EXTENDED ATTRIBUTE MANAGEMENT
    # ============================================================================
    attr_management = parser.add_argument_group('Feature: Extended Attribute Management',
        'Find files by DOS extended attributes and optionally modify them. '
        'Findable: read_only, hidden, system, archive, temporary, compressed, '
        'not_content_indexed, sparse_file, offline. '
        'Settable (DOS): read_only, hidden, system, archive.')

    attr_management.add_argument(
        "--find-attribute-true",
        action="append",
        metavar="ATTR[,ATTR,...]",
        help="Find files where listed attributes are true. "
             "Comma-separated list. Repeatable; values are merged. "
             "Aliases: sparse=sparse_file, readonly=read_only, nci=not_content_indexed."
    )

    attr_management.add_argument(
        "--find-attribute-false",
        action="append",
        metavar="ATTR[,ATTR,...]",
        help="Find files where listed attributes are false. "
             "Same attribute names as --find-attribute-true. Repeatable."
    )

    attr_management.add_argument(
        "--set-attribute-true",
        action="append",
        metavar="ATTR[,ATTR,...]",
        help="Set listed DOS attributes to true (read_only, hidden, system, archive only). "
             "Must be positionally adjacent to --find-attribute-false (opposite boolean) "
             "or used standalone. Use --propagate-changes for recursive application."
    )

    attr_management.add_argument(
        "--set-attribute-false",
        action="append",
        metavar="ATTR[,ATTR,...]",
        help="Set listed DOS attributes to false (read_only, hidden, system, archive only). "
             "Must be positionally adjacent to --find-attribute-true (opposite boolean) "
             "or used standalone. Use --propagate-changes for recursive application."
    )

    # ============================================================================
    # FEATURE: ACE MANIPULATION
    # ============================================================================
    ace_manipulation = parser.add_argument_group('Feature: ACE Manipulation',
        'Surgically add, remove, replace, or modify individual ACEs within ACLs. '
        'Use --propagate-changes to apply to all children.')

    ace_manipulation.add_argument(
        "--remove-ace",
        action="append",
        dest="remove_aces",
        metavar="PATTERN",
        help="Remove ACE(s) matching 'Type:Trustee'. "
             "Example: --remove-ace 'Allow:Group111'"
    )

    ace_manipulation.add_argument(
        "--add-ace",
        action="append",
        dest="add_aces",
        metavar="PATTERN",
        help="Add ACE with 'Type:Flags:Trustee:Rights'. Merges rights if ACE exists. "
             "Flags: f=file-inherit, d=dir-inherit. Rights: Read, Write, Modify, FullControl or NFSv4 (rwx). "
             "Example: --add-ace 'Allow:fd:Group111:Modify'"
    )

    ace_manipulation.add_argument(
        "--replace-ace",
        action="append",
        dest="replace_aces",
        metavar="PATTERN",
        help="Find ACE matching 'Type:Trustee' or 'Type:Flags:Trustee:Rights'. "
             "Use with --new-ace to specify replacement (allows type change). "
             "Without --new-ace, replaces flags/rights in-place. "
             "Example: --replace-ace 'Allow:Group111' --new-ace 'Deny:fd:Group111:Read'"
    )

    ace_manipulation.add_argument(
        "--new-ace",
        action="append",
        dest="new_aces",
        metavar="PATTERN",
        help="Replacement ACE for preceding --replace-ace. Format: 'Type:Flags:Trustee:Rights'. "
             "Allows changing ACE type (Allow<->Deny). Must pair 1:1 with --replace-ace. "
             "Example: --replace-ace 'Allow:Group111' --new-ace 'Deny:fd:Group111:rw'"
    )

    ace_manipulation.add_argument(
        "--add-rights",
        action="append",
        dest="add_rights",
        metavar="PATTERN",
        help="Add rights to existing ACE with 'Type:Trustee:Rights'. "
             "Example: --add-rights 'Allow:Group111:Write'"
    )

    ace_manipulation.add_argument(
        "--remove-rights",
        action="append",
        dest="remove_rights",
        metavar="PATTERN",
        help="Remove rights from existing ACE with 'Type:Trustee:Rights'. "
             "Example: --remove-rights 'Allow:Group111:Write'"
    )

    ace_manipulation.add_argument(
        "--clone-ace-source",
        action="append",
        dest="clone_ace_sources",
        metavar="TRUSTEE",
        help="Source trustee for ACE cloning. Must be paired with --clone-ace-target. "
             "Clones all ACEs (Allow and Deny) from source to target trustee. "
             "Supports names, uid:N, gid:N, DOMAIN\\\\user formats. "
             "Example: --clone-ace-source 'Bob' --clone-ace-target 'Joe'"
    )

    ace_manipulation.add_argument(
        "--clone-ace-target",
        action="append",
        dest="clone_ace_targets",
        metavar="TRUSTEE",
        help="Target trustee for ACE cloning. Must be paired with --clone-ace-source. "
             "Example: --clone-ace-source 'uid:1001' --clone-ace-target 'uid:1002'"
    )

    ace_manipulation.add_argument(
        "--sync-cloned-aces",
        action="store_true",
        help="When used with --clone-ace-source/--clone-ace-target, update existing "
             "target ACEs to match source ACE rights. Without this flag, existing "
             "target ACEs are left unchanged."
    )

    ace_manipulation.add_argument(
        "--migrate-trustees",
        metavar="FILE",
        help="CSV file with source,target trustee mappings for in-place replacement. "
             "All ACEs matching source trustees are updated to target trustees. "
             "CSV format: source,target (header row optional). "
             "Supports: DOMAIN\\\\user, uid:N, gid:N, SID, plain names."
    )

    ace_manipulation.add_argument(
        "--clone-ace-map",
        metavar="FILE",
        help="CSV file with source,target trustee mappings for bulk cloning. "
             "Clones all ACEs from source to target trustees. "
             "Works with --sync-cloned-aces to update existing target ACEs. "
             "CSV format: source,target (header row optional)."
    )

    # Hidden alias for backward compatibility (use --propagate-changes instead)
    ace_manipulation.add_argument(
        "--propagate-ace-changes",
        action="store_true",
        help=argparse.SUPPRESS
    )

    ace_manipulation.add_argument(
        "--ace-backup",
        metavar="FILE",
        help="Save original ACLs to JSON file before making changes"
    )

    ace_manipulation.add_argument(
        "--ace-restore",
        metavar="FILE",
        help="Restore ACLs from a backup file created by --ace-backup. "
             "Verifies file_id matches to prevent accidental overwrites if path was renamed."
    )

    ace_manipulation.add_argument(
        "--force-restore",
        action="store_true",
        help="Force ACL restore even if file_id does not match (use with caution)"
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
        "--stats",
        action="store_true",
        help="Show directory aggregate statistics and exit (no tree walk). "
             "Respects --max-depth, --omit-subdirs, and --omit-path.",
    )
    exploration.add_argument(
        "--sort",
        nargs="?",
        const="_missing_",
        default=None,
        help="Sort --stats table output by: size (largest first), "
             "count (most files first), or name (alphabetical)",
    )
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
        'Tune concurrency and connection pool settings (auto-tuned on first run)')

    performance.add_argument(
        "--max-concurrent",
        type=int,
        default=default_max_concurrent,
        help=f"Maximum concurrent operations (default: {default_max_concurrent})",
    )
    performance.add_argument(
        "--connector-limit",
        type=int,
        default=default_connector_limit,
        help=f"Maximum HTTP connections in pool (default: {default_connector_limit})",
    )
    performance.add_argument(
        "--retune",
        action="store_true",
        help="Regenerate tuning profile based on current system",
    )
    performance.add_argument(
        "--show-tuning",
        action="store_true",
        help="Display current tuning profile and exit",
    )
    performance.add_argument(
        "--tuning-profile",
        choices=['conservative', 'balanced', 'aggressive'],
        default='balanced',
        help="Tuning profile (default: balanced)",
    )
    performance.add_argument(
        "--benchmark",
        action="store_true",
        help="Run benchmark to find optimal concurrency settings for this cluster",
    )

    # Enable argcomplete bash completion if available
    if ARGCOMPLETE_AVAILABLE:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    # Validate arguments
    # Check that either --path OR (--source-acl/--source-acl-file + --acl-target) are provided
    acl_cloning_mode = (args.source_acl or args.source_acl_file) and args.acl_target
    if not args.path and not acl_cloning_mode:
        print(
            "Error: Either --path is required OR a source (--source-acl or --source-acl-file) and --acl-target for ACL cloning",
            file=sys.stderr,
        )
        sys.exit(1)

    # Validate owner/group flags (only work with --source-acl, not --source-acl-file)
    if (args.copy_owner or args.copy_group) and not args.source_acl:
        print(
            "Error: --copy-owner and --copy-group require --source-acl (not --source-acl-file)",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.owner_group_only and not (args.copy_owner or args.copy_group):
        print(
            "Error: --owner-group-only requires at least one of --copy-owner or --copy-group",
            file=sys.stderr,
        )
        sys.exit(1)

    # Validate --change-owner/--change-group flags
    change_owner_mode = (args.change_owner or args.change_group or
                         args.change_owners_file or args.change_groups_file)

    if change_owner_mode:
        # Cannot combine with --copy-owner or --copy-group (different paradigms)
        if args.copy_owner or args.copy_group:
            print(
                "Error: --change-owner/--change-group cannot be combined with --copy-owner/--copy-group",
                file=sys.stderr,
            )
            print("  --copy-owner/--copy-group copy from a source path", file=sys.stderr)
            print("  --change-owner/--change-group find files by current owner and change to a new owner", file=sys.stderr)
            sys.exit(1)

        # Requires --path (operates on tree walk)
        if not args.path:
            print(
                "Error: --change-owner/--change-group requires --path",
                file=sys.stderr,
            )
            sys.exit(1)

    # Validate and parse --fields
    if args.fields:
        args.parsed_fields = parse_field_specs(args.fields)

        if args.all_attributes:
            print("Error: --fields cannot be combined with --all-attributes", file=sys.stderr)
            sys.exit(1)

        if args.owner_report or args.acl_report:
            print("Error: --fields does not apply to --owner-report or --acl-report", file=sys.stderr)
            sys.exit(1)

        # Implicit identity resolution when field list includes resolved names
        display_names = {name for name, _ in args.parsed_fields}
        if "owner_name" in display_names:
            args.show_owner = True
        if "group_name" in display_names:
            args.show_group = True
    else:
        args.parsed_fields = None

    # Validate extended attribute arguments
    validate_attribute_args(args)

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

    # Validate --sort
    valid_sort_values = ("size", "count", "name")
    if args.sort is not None:
        if args.sort == "_missing_":
            print(
                f"Error: --sort requires a value: {', '.join(valid_sort_values)}",
                file=sys.stderr,
            )
            sys.exit(1)
        if args.sort not in valid_sort_values:
            print(
                f"Error: --sort invalid choice '{args.sort}' (choose from: {', '.join(valid_sort_values)})",
                file=sys.stderr,
            )
            sys.exit(1)
        if not args.stats:
            print(
                "Error: --sort requires --stats",
                file=sys.stderr,
            )
            sys.exit(1)

    # Check --stats conflicts with other operational modes
    if args.stats:
        conflicting = []
        if args.source_acl or args.source_acl_file or args.acl_target:
            conflicting.append("--source-acl/--acl-target")
        if getattr(args, 'ace_restore', None):
            conflicting.append("--ace-restore")
        if args.change_owner or args.change_group or args.change_owners_file or args.change_groups_file:
            conflicting.append("--change-owner/--change-group")
        if getattr(args, 'set_attribute_true', None) or getattr(args, 'set_attribute_false', None):
            conflicting.append("--set-attribute-true/--set-attribute-false")
        if args.show_dir_stats:
            conflicting.append("--show-dir-stats")
        if args.owner_report:
            conflicting.append("--owner-report")
        if args.acl_report:
            conflicting.append("--acl-report")
        if getattr(args, 'find_similar', None):
            conflicting.append("--find-similar")
        if getattr(args, 'benchmark', None):
            conflicting.append("--benchmark")
        if getattr(args, 'remove_aces', None) or getattr(args, 'add_aces', None) or getattr(args, 'replace_aces', None):
            conflicting.append("--add-ace/--remove-ace/--replace-ace")
        if conflicting:
            print(
                f"Error: --stats cannot be combined with {', '.join(conflicting)}",
                file=sys.stderr,
            )
            sys.exit(1)

    # Handle --benchmark mode
    if args.benchmark:
        if not args.host or not args.path:
            log_stderr("ERROR", "--benchmark requires --host and --path")
            sys.exit(1)

        print("=" * 70, file=sys.stderr)
        print("GrumpWalk - Performance Benchmark", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(f"Cluster: {args.host}", file=sys.stderr)
        print(f"Path:    {args.path}", file=sys.stderr)
        print(f"Testing: {BENCHMARK_CONCURRENCY_LEVELS}", file=sys.stderr)
        print(f"Limit:   {BENCHMARK_FILE_LIMIT:,} files per test", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

        # Run benchmark asynchronously
        async def run_benchmark():
            from modules.credentials import credential_store_filename, get_credentials
            creds_path = args.credentials_store or credential_store_filename()
            token = get_credentials(creds_path)
            if not token:
                log_stderr("ERROR", "No credentials found. Run: qq login")
                sys.exit(1)

            results = []
            import time

            for concurrent in BENCHMARK_CONCURRENCY_LEVELS:
                log_stderr("BENCH", f"Testing concurrent={concurrent}...", newline_before=True)

                client = AsyncQumuloClient(
                    host=args.host,
                    bearer_token=token,
                    port=args.port,
                    max_concurrent=concurrent,
                    connector_limit=concurrent,
                    verbose=False,
                )

                # Use ProgressTracker with limit to stop early
                progress = ProgressTracker(
                    verbose=False,
                    limit=BENCHMARK_FILE_LIMIT
                )

                start = time.time()

                async with client.create_session() as session:
                    await client.walk_tree_async(
                        session=session,
                        path=args.path,
                        file_filter=None,
                        collect_results=False,
                        progress=progress,
                    )

                elapsed = time.time() - start
                count = progress.matches
                rate = count / elapsed if elapsed > 0 else 0
                results.append({'concurrent': concurrent, 'rate': rate, 'time': elapsed})
                log_stderr("BENCH", f"{count:,} files in {elapsed:.1f}s = {rate:,.0f} obj/sec")

            return results

        benchmark_results = asyncio.run(run_benchmark())

        print("\n" + "=" * 70, file=sys.stderr)
        print("Benchmark Results:", file=sys.stderr)
        print(format_benchmark_results(benchmark_results), file=sys.stderr)

        suggested = suggest_from_benchmark(benchmark_results)
        print(f"\nSuggested settings:", file=sys.stderr)
        print(f"  max-concurrent:  {suggested['max_concurrent']}", file=sys.stderr)
        print(f"  connector-limit: {suggested['connector_limit']}", file=sys.stderr)
        print(f"  acl-concurrency: {suggested['acl_concurrency']}", file=sys.stderr)

        # Ask to save
        print("\nSave these settings to tuning profile? [y/N] ", file=sys.stderr, end="", flush=True)
        try:
            response = input().strip().lower()
            if response in ('y', 'yes'):
                profile = load_tuning_profile() or generate_tuning_profile('balanced')
                profile['recommended'] = suggested
                profile['profile'] = 'benchmarked'
                profile['benchmark_results'] = benchmark_results
                save_tuning_profile(profile)
                print(f"Profile saved to: {get_profile_path()}", file=sys.stderr)
        except (EOFError, KeyboardInterrupt):
            pass

        print("=" * 70, file=sys.stderr)
        sys.exit(0)

    # Handle first-run tuning profile generation
    if is_first_run:
        profile_name = args.tuning_profile if hasattr(args, 'tuning_profile') else 'balanced'
        tuning_profile = generate_tuning_profile(profile_name)
        save_tuning_profile(tuning_profile)
        print("=" * 70, file=sys.stderr)
        print("GrumpWalk - First Run Setup", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print("Detected system configuration:", file=sys.stderr)
        print(format_profile_summary(tuning_profile), file=sys.stderr)
        print("", file=sys.stderr)
        print(f"Profile saved to: {get_profile_path()}", file=sys.stderr)
        print("(Use --retune to regenerate, --show-tuning to view)", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print("", file=sys.stderr)

    # Initialize log file if requested (before any output)
    if args.log_file:
        try:
            init_log_file(args.log_file, args.log_level)
        except IOError as e:
            print(f"[ERROR] Cannot open log file: {args.log_file}: {e}", file=sys.stderr)
            sys.exit(1)

    # Run async main
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        log_stderr("INFO", "Interrupted by user", newline_before=True)
        sys.exit(130)
    except aiohttp.ClientResponseError as e:
        # HTTP error with detailed message
        path_for_error = args.path if args.path else (args.acl_target if hasattr(args, 'acl_target') else 'N/A')
        error_msg = format_http_error(e.status, str(e.request_info.url), path_for_error)
        # Route through log_stderr so it reaches the log file
        for line in error_msg.strip().split('\n'):
            line = line.strip()
            if line.startswith('[ERROR]'):
                log_stderr("ERROR", line[len('[ERROR]'):].strip())
            elif line.startswith('[HINT]'):
                log_stderr("HINT", line[len('[HINT]'):].strip())
            elif line:
                log_stderr("ERROR", line)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    except aiohttp.ClientConnectorError as e:
        log_stderr("ERROR", f"Cannot connect to cluster: {args.host}:{args.port}", newline_before=True)
        log_stderr("HINT", "Check that the cluster is reachable and the hostname/port are correct")
        if args.verbose:
            log_stderr("DEBUG", f"{e}")
        sys.exit(1)
    except aiohttp.ClientError as e:
        log_stderr("ERROR", f"Network error: {e}", newline_before=True)
        log_stderr("HINT", "Check your network connection to the cluster")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        log_stderr("ERROR", f"{e}", newline_before=True)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        close_log_file()


if __name__ == "__main__":
    main()
