#!/usr/bin/env python3

"""
Qumulo File Filter and API Tree Walk Tool

Usage:
    ./grumpwalk.py --host <cluster> --path <path> [OPTIONS]

"""

__version__ = "2.0.0"

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
    format_http_error,
    extract_pagination_token,
    parse_size_to_bytes,
    format_bytes,
    format_time,
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
            print(f"[WARN] Unknown right character '{char}' in pattern", file=sys.stderr)

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
            print(f"[WARN] Unknown flag character '{char}' in pattern", file=sys.stderr)
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
        print(f"[ERROR] Invalid ACE pattern '{pattern}': expected at least Type:Trustee", file=sys.stderr)
        return None

    ace_type = parts[0].upper()
    if ace_type in ('ALLOW', 'ALLOWED', 'A'):
        result['type'] = 'ALLOWED'
    elif ace_type in ('DENY', 'DENIED', 'D'):
        result['type'] = 'DENIED'
    else:
        print(f"[ERROR] Invalid ACE type '{parts[0]}': expected Allow or Deny", file=sys.stderr)
        return None

    if pattern_type == 'remove':
        # Format: Type:Trustee
        if len(parts) != 2:
            print(f"[ERROR] Invalid remove pattern '{pattern}': expected Type:Trustee", file=sys.stderr)
            return None
        result['raw_trustee'] = parts[1]

    elif pattern_type in ('add_rights', 'remove_rights'):
        # Format: Type:Trustee:Rights
        if len(parts) != 3:
            print(f"[ERROR] Invalid rights pattern '{pattern}': expected Type:Trustee:Rights", file=sys.stderr)
            return None
        result['raw_trustee'] = parts[1]
        result['rights'] = nfsv4_rights_to_qacl(parts[2])

    elif pattern_type == 'add':
        # Format: Type:Flags:Trustee:Rights
        if len(parts) != 4:
            print(f"[ERROR] Invalid add pattern '{pattern}': expected Type:Flags:Trustee:Rights", file=sys.stderr)
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
                print(f"[INFO] '{raw_trustee}' -> auth_id 8589934592 (Everyone)", file=sys.stderr)
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
                print(f"[INFO] '{raw_trustee}' is already auth_id {identifier}", file=sys.stderr)
            continue
        else:  # name
            identifier = payload.get('name')

        # Resolve to auth_id using identity API
        if verbose:
            print(f"[INFO] Resolving trustee '{raw_trustee}' ({id_type})...", file=sys.stderr)

        resolved = await client.resolve_identity(session, identifier, id_type)

        if resolved and resolved.get('auth_id'):
            auth_id = str(resolved['auth_id'])
            pattern['resolved_auth_id'] = auth_id
            # Always show resolution result
            print(f"[INFO] Resolved '{raw_trustee}' -> auth_id {auth_id}", file=sys.stderr)

            # Cache the resolved identity for future use
            if auth_id not in client.persistent_identity_cache:
                client.persistent_identity_cache[auth_id] = resolved
        else:
            print(f"[WARN] Could not resolve trustee '{raw_trustee}' - matching may fail", file=sys.stderr)


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
    2. Adds 'DACL_PROTECTED' to control flags (blocks parent inheritance)
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
    control.add('DACL_PROTECTED')
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
                print(f"[DEBUG] ACE type='{ace_type}' auth_id='{ace_auth_id}' "
                      f"vs pattern type='{pat_type}' auth_id='{pat_auth_id}'", file=sys.stderr)
            if match_ace(ace, pattern):
                should_remove = True
                stats['removed'] += 1
                if verbose:
                    print(f"[DEBUG]   -> MATCH - will remove", file=sys.stderr)
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
            print(f"[WARN] No matching ACE found for --add-rights pattern", file=sys.stderr)

    # 4. Replace ACEs (full replacement or type-changing replacement)
    for find_pattern, new_ace_pattern in replace_aces:
        matching_indices = []

        if verbose:
            print(f"[DEBUG] Looking for ACE: type={find_pattern.get('type')} "
                  f"trustee={find_pattern.get('raw_trustee')} "
                  f"resolved_auth_id={find_pattern.get('resolved_auth_id')}", file=sys.stderr)

        # First pass: find ALL matching ACEs
        for i, ace in enumerate(aces):
            if verbose:
                ace_trustee = ace.get('trustee')
                if isinstance(ace_trustee, dict):
                    ace_auth_id = ace_trustee.get('auth_id', '')
                else:
                    ace_auth_id = ace_trustee
                print(f"[DEBUG]   Checking ACE[{i}]: type={ace.get('type')} "
                      f"auth_id={ace_auth_id}", file=sys.stderr)
            if match_ace(ace, find_pattern):
                matching_indices.append(i)
                if verbose:
                    print(f"[DEBUG]   -> MATCH at index {i}", file=sys.stderr)

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
                    print(f"[DEBUG] Replaced ACE[{first_idx}] {find_pattern.get('type')}:{find_pattern.get('raw_trustee')} "
                          f"with {new_ace_pattern.get('type')}:{new_ace_pattern.get('raw_trustee')}", file=sys.stderr)
            else:
                # In-place mode: update flags and rights only (same type+trustee)
                aces[first_idx]['flags'] = find_pattern.get('flags', [])
                aces[first_idx]['rights'] = find_pattern.get('rights', [])
                if verbose:
                    print(f"[DEBUG] Replaced ACE[{first_idx}] in-place for {find_pattern.get('raw_trustee')}", file=sys.stderr)
            stats['replaced'] += 1

            # Remove duplicate matching ACEs (in reverse order to preserve indices)
            if len(matching_indices) > 1:
                for dup_idx in reversed(matching_indices[1:]):
                    if verbose:
                        print(f"[DEBUG] Removing duplicate ACE at index {dup_idx}", file=sys.stderr)
                    del aces[dup_idx]
                    stats['removed'] += 1

        if not matching_indices:
            # No matching ACE found
            if new_ace_pattern is not None:
                # Paired mode (--replace-ace X --new-ace Y): Don't create if X not found
                # This is a transformation operation, not "ensure exists"
                print(f"[WARN] No matching {find_pattern.get('type')} ACE found for trustee "
                      f"'{find_pattern.get('raw_trustee')}' - skipping (nothing to replace)", file=sys.stderr)
            else:
                # Non-paired mode (--replace-ace only): Create new ACE if not found
                print(f"[WARN] No matching {find_pattern.get('type')} ACE found for trustee "
                      f"'{find_pattern.get('raw_trustee')}' - creating new ACE", file=sys.stderr)
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
                    print(f"[DEBUG] Adding new ACE for {find_pattern.get('raw_trustee')}", file=sys.stderr)

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
                print(f"[DEBUG] Skipping migrate pattern - missing auth_id or target: "
                      f"source={source_auth_id}, target={target_trustee}", file=sys.stderr)
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
                        print(f"[DEBUG] Merged {ace_type} ACE rights from {source_auth_id} "
                              f"into existing {target_trustee} ACE", file=sys.stderr)
                else:
                    # No existing target - replace trustee in-place
                    ace['trustee'] = target_trustee
                    ace['_needs_resolution'] = True
                    stats['migrated'] += 1
                    if verbose:
                        print(f"[DEBUG] Migrated {ace_type} ACE from {source_auth_id} "
                              f"to {target_trustee}", file=sys.stderr)

        # Remove ACEs that were merged into existing targets
        for ace in aces_to_remove:
            aces.remove(ace)

    # 8. Clone ACEs from source trustee to target trustee (or sync if exists)
    for cp in clone_patterns:
        source_auth_id = cp.get('source_auth_id')
        target_auth_id = cp.get('target_auth_id')

        if not source_auth_id or not target_auth_id:
            if verbose:
                print(f"[DEBUG] Skipping clone pattern - missing auth_id: "
                      f"source={source_auth_id}, target={target_auth_id}", file=sys.stderr)
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
                            print(f"[DEBUG] Synced {ace.get('type')} ACE for {target_auth_id} "
                                  f"with rights from {source_auth_id}", file=sys.stderr)
                    else:
                        # Default: skip if target already exists
                        if verbose:
                            print(f"[DEBUG] Clone skipped - {ace.get('type')} ACE already exists "
                                  f"for target trustee {target_auth_id}", file=sys.stderr)
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
                        print(f"[DEBUG] Cloned {ace.get('type')} ACE from {source_auth_id} "
                              f"to {cp.get('target_trustee')}", file=sys.stderr)

        stats['cloned'] += cloned_count
        stats['synced'] += synced_count
        if verbose:
            if cloned_count > 0:
                print(f"[DEBUG] Cloned {cloned_count} ACE(s) from {cp.get('source_trustee')} "
                      f"to {cp.get('target_trustee')}", file=sys.stderr)
            if synced_count > 0:
                print(f"[DEBUG] Synced {synced_count} ACE(s) for {cp.get('target_trustee')} "
                      f"from {cp.get('source_trustee')}", file=sys.stderr)

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
    owner_group_only: bool = False,
    acl_concurrency: int = 100
) -> dict:
    """
    Apply ACL and/or owner/group to target path, optionally propagating to filtered children.

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
                print(f"\n[ERROR] Tree walk failed: {e}", file=sys.stderr)
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
                                print(f"\n[WARN] Error on {path}: {error_msg}, continuing...", file=sys.stderr)
                        else:
                            print(f"\n[ERROR] Failed to apply ACL to: {path}", file=sys.stderr)
                            print(f"[ERROR] {error_msg}", file=sys.stderr)

                            while True:
                                response = input("Continue? [C]ontinue / [A]bort: ").strip().lower()
                                if response in ['c', 'continue']:
                                    break
                                elif response in ['a', 'abort']:
                                    print("[INFO] Operation aborted by user.", file=sys.stderr)
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
                                    print(f"\n[WARN] Error on {path}: {error_msg}, continuing...", file=sys.stderr)
                            else:
                                print(f"\n[ERROR] Failed to apply ACL to: {path}", file=sys.stderr)
                                print(f"[ERROR] {error_msg}", file=sys.stderr)

                                while True:
                                    response = input("Continue? [C]ontinue / [A]bort: ").strip().lower()
                                    if response in ['c', 'continue']:
                                        break
                                    elif response in ['a', 'abort']:
                                        print("[INFO] Operation aborted by user.", file=sys.stderr)
                                        abort_requested.set()
                                        return
                                    print("Invalid response. Please enter 'c' or 'a'.")

                # Progress reporting after each batch
                if progress:
                    elapsed = time.time() - start_time
                    rate = processed / elapsed if elapsed > 0 else 0
                    queue_size = entry_queue.qsize()

                    # Show queue size to indicate backpressure
                    print(
                        f"\r[ACL CLONE] Changed: {stats['objects_changed']:,} | "
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
        print(f"[ACL CLONE] Completed in {elapsed:.1f}s", file=sys.stderr)

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
                        print(f"[DEBUG] Skipping header row: {row}", file=sys.stderr)
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
            print(f"[DEBUG] Loaded {len(mappings)} trustee mappings from {filepath}",
                  file=sys.stderr)

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
        print(f"[SIMILARITY DETECTION] Using {hash_lib} for file hashing", file=sys.stderr)
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
    # Backward compatibility: consolidate old propagation flags into unified flag
    if getattr(args, 'propagate_ace_changes', False) or getattr(args, 'propagate_owner_changes', False):
        args.propagate_changes = True

    # Determine if we're in ACL cloning mode
    acl_cloning_mode = (args.source_acl or args.source_acl_file) and args.acl_target

    print("=" * 70, file=sys.stderr)
    if acl_cloning_mode:
        print("GrumpWalk - ACL Cloning Mode", file=sys.stderr)
    else:
        print("GrumpWalk - Qumulo Directory Tree Walk", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"Cluster:          {args.host}", file=sys.stderr)

    if acl_cloning_mode:
        if args.source_acl_file:
            print(f"Source ACL:       {args.source_acl_file} (file)", file=sys.stderr)
        else:
            print(f"Source ACL:       {args.source_acl}", file=sys.stderr)
        print(f"Target path:      {args.acl_target}", file=sys.stderr)
        if args.propagate_acls:
            print(f"Propagate:        Enabled", file=sys.stderr)
        print(f"ACL concurrency:  {args.acl_concurrency}", file=sys.stderr)
    else:
        print(f"Path:             {args.path}", file=sys.stderr)

    print(f"JSON parser:      {JSON_PARSER_NAME}", file=sys.stderr)
    print(f"Walk concurrency: {args.max_concurrent}", file=sys.stderr)
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

    # Test basic TCP connectivity to cluster before proceeding
    print("Verifying cluster connection...", file=sys.stderr, end=" ", flush=True)
    try:
        await client.test_connection(timeout=10)
        print("OK", file=sys.stderr)
    except asyncio.TimeoutError:
        print("FAILED", file=sys.stderr)
        print(f"\n[ERROR] Connection timed out to {args.host}:{args.port}", file=sys.stderr)
        print(f"[HINT] Check that the cluster is powered on and reachable", file=sys.stderr)
        print(f"[HINT] Verify the hostname/IP and port are correct", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print("FAILED", file=sys.stderr)
        print(f"\n[ERROR] Cannot connect to {args.host}:{args.port}", file=sys.stderr)
        err_str = str(e).lower()
        if "refused" in err_str or "errno 61" in err_str or "errno 111" in err_str:
            print(f"[HINT] Connection refused - verify host and port are correct", file=sys.stderr)
        elif "no route" in err_str or "unreachable" in err_str:
            print(f"[HINT] Host unreachable - check network connectivity", file=sys.stderr)
        elif "nodename" in err_str or "name or service not known" in err_str or "errno 8" in err_str:
            print(f"[HINT] DNS resolution failed - check hostname spelling", file=sys.stderr)
        else:
            print(f"[HINT] {e}", file=sys.stderr)
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
                print(f"\n[ERROR] Authentication failed (401 Unauthorized)", file=sys.stderr)
                print(f"[HINT] Your bearer token may be expired or invalid", file=sys.stderr)
                print(f"[HINT] Generate a new token: qq --host {args.host} login", file=sys.stderr)
            else:
                print(f"\n[ERROR] HTTP {e.status}: {e.message}", file=sys.stderr)
            sys.exit(1)

    # ACL Cloning Mode
    if args.source_acl or args.source_acl_file or args.acl_target:
        # Validate: need a source and a target
        if not ((args.source_acl or args.source_acl_file) and args.acl_target):
            print("[ERROR] Both a source (--source-acl or --source-acl-file) and --acl-target must be specified", file=sys.stderr)
            sys.exit(1)

        # Validate: can't specify both source types
        if args.source_acl and args.source_acl_file:
            print("[ERROR] Cannot specify both --source-acl and --source-acl-file", file=sys.stderr)
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
                        print(f"[INFO] Loaded ACL from file with {ace_count} ACEs", file=sys.stderr)
                except FileNotFoundError:
                    print(f"[ERROR] ACL file not found: {args.source_acl_file}", file=sys.stderr)
                    sys.exit(1)
                except json.JSONDecodeError as e:
                    print(f"[ERROR] Invalid JSON in ACL file: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                # Retrieve ACL from cluster
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
                if args.source_acl_file:
                    print("[ERROR] Cannot use --copy-owner or --copy-group with --source-acl-file", file=sys.stderr)
                    sys.exit(1)

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
                acl_concurrency=args.acl_concurrency
            )

            # Step 5: Print summary
            if args.owner_group_only:
                print("\nOWNER/GROUP COPY SUMMARY", file=sys.stderr)
            elif args.copy_owner or args.copy_group:
                print("\nACL + OWNER/GROUP COPY SUMMARY", file=sys.stderr)
            else:
                print("\nACL CLONING SUMMARY", file=sys.stderr)
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

    # ACE RESTORE MODE
    # Restore ACLs from a backup file created by --ace-backup
    if args.ace_restore:
        import json

        print("\n[INFO] ACE Restore Mode", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(f"Backup file:       {args.ace_restore}", file=sys.stderr)

        # Load the backup file
        try:
            with open(args.ace_restore, 'r') as f:
                backup_data = json.load(f)
        except FileNotFoundError:
            print(f"[ERROR] Backup file not found: {args.ace_restore}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON in backup file: {e}", file=sys.stderr)
            sys.exit(1)

        # Extract backup data
        backup_path = backup_data.get('path')
        backup_file_id = backup_data.get('file_id')
        backup_acl = backup_data.get('original_acl')
        backup_timestamp = backup_data.get('timestamp')

        if not backup_path or not backup_acl:
            print("[ERROR] Backup file is missing required fields (path, original_acl)", file=sys.stderr)
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
                print(f"[ERROR] Could not retrieve attributes from {target_path}", file=sys.stderr)
                print("        The path may not exist or you may not have permission to access it.", file=sys.stderr)
                sys.exit(1)

            current_file_id = current_attr.get('id')

            # Verify file_id matches (safety check)
            if backup_file_id and current_file_id:
                if str(backup_file_id) != str(current_file_id):
                    print(f"\n[WARNING] File ID mismatch detected!", file=sys.stderr)
                    print(f"          Backup file ID:  {backup_file_id}", file=sys.stderr)
                    print(f"          Current file ID: {current_file_id}", file=sys.stderr)
                    print(f"          This may indicate the path now refers to a different file.", file=sys.stderr)

                    if not args.force_restore:
                        print(f"\n[ERROR] Refusing to restore due to file ID mismatch.", file=sys.stderr)
                        print(f"        Use --force-restore to override this safety check.", file=sys.stderr)
                        sys.exit(1)
                    else:
                        print(f"\n[WARNING] Proceeding with restore due to --force-restore flag.", file=sys.stderr)
                else:
                    print(f"[INFO] File ID verified: {current_file_id}", file=sys.stderr)
            elif backup_file_id and not current_file_id:
                print(f"[WARNING] Could not verify file ID (current file has no ID)", file=sys.stderr)
            elif not backup_file_id:
                print(f"[WARNING] Backup does not contain file_id (older backup format)", file=sys.stderr)

            # Dry run: show what would be restored
            if args.dry_run:
                print("\n[DRY RUN] Would restore the following ACL:", file=sys.stderr)
                print("-" * 60, file=sys.stderr)
                for i, ace in enumerate(backup_aces):
                    ace_str = qacl_ace_to_readable(ace, is_dir=True)
                    print(f"  {i+1}. {ace_str}", file=sys.stderr)
                print("-" * 60, file=sys.stderr)
                print("[DRY RUN] No changes were made.", file=sys.stderr)
                return

            # Apply the backed-up ACL
            print(f"\n[INFO] Restoring ACL to: {target_path}", file=sys.stderr)
            success, error = await client.set_file_acl(session, target_path, backup_acl, mark_inherited=False)

            if not success:
                print(f"[ERROR] Failed to restore ACL: {error}", file=sys.stderr)
                sys.exit(1)

            print(f"[INFO] ACL restored successfully ({len(backup_aces)} ACEs)", file=sys.stderr)

            # Propagate if requested
            if args.propagate_changes:
                print(f"\n[INFO] Propagating restored ACL to children of: {target_path}", file=sys.stderr)

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

                print(f"\n[INFO] Propagation complete:", file=sys.stderr)
                print(f"  Objects changed:  {propagate_stats['objects_changed']:,}", file=sys.stderr)
                print(f"  Objects failed:   {propagate_stats['objects_failed']:,}", file=sys.stderr)

        print("\n[INFO] ACE restore complete", file=sys.stderr)
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
        print("[ERROR] ACL cloning (--source-acl, --source-acl-file, --acl-target) cannot be combined with", file=sys.stderr)
        print("        ACE manipulation (--add-ace, --remove-ace, --replace-ace, --add-rights, --remove-rights, --clone-ace-*)", file=sys.stderr)
        print("", file=sys.stderr)
        print("        Use ACL cloning to copy an entire ACL from one path to another.", file=sys.stderr)
        print("        Use ACE manipulation to surgically modify individual ACEs.", file=sys.stderr)
        sys.exit(1)

    if ace_manipulation_mode:
        if not args.path:
            print("[ERROR] --path is required for ACE manipulation", file=sys.stderr)
            sys.exit(1)

        # Validate --replace-ace / --new-ace pairing
        replace_count = len(args.replace_aces) if args.replace_aces else 0
        new_ace_count = len(args.new_aces) if args.new_aces else 0

        if new_ace_count > 0 and replace_count == 0:
            print("[ERROR] --new-ace requires --replace-ace to specify which ACE to replace", file=sys.stderr)
            sys.exit(1)

        if new_ace_count > 0 and new_ace_count != replace_count:
            print(f"[ERROR] --replace-ace and --new-ace must be paired 1:1", file=sys.stderr)
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
                    print(f"[ERROR] --new-ace at position {new_pos} has no matching --replace-ace", file=sys.stderr)
                    sys.exit(1)
                replace_pos = replace_positions[j]
                # --new-ace should be 2 positions after --replace-ace (--replace-ace VALUE --new-ace)
                if new_pos != replace_pos + 2:
                    print(f"[ERROR] --new-ace must immediately follow --replace-ace 'PATTERN'", file=sys.stderr)
                    print(f"        Expected: --replace-ace 'FIND' --new-ace 'REPLACE'", file=sys.stderr)
                    sys.exit(1)

        # Validate --clone-ace-source / --clone-ace-target pairing
        clone_source_count = len(args.clone_ace_sources) if args.clone_ace_sources else 0
        clone_target_count = len(args.clone_ace_targets) if args.clone_ace_targets else 0

        if clone_source_count > 0 and clone_target_count == 0:
            print("[ERROR] --clone-ace-source requires --clone-ace-target", file=sys.stderr)
            sys.exit(1)

        if clone_target_count > 0 and clone_source_count == 0:
            print("[ERROR] --clone-ace-target requires --clone-ace-source", file=sys.stderr)
            sys.exit(1)

        if clone_source_count != clone_target_count:
            print(f"[ERROR] --clone-ace-source and --clone-ace-target must be paired 1:1", file=sys.stderr)
            print(f"        Found {clone_source_count} --clone-ace-source and {clone_target_count} --clone-ace-target", file=sys.stderr)
            sys.exit(1)

        print("\n[INFO] ACE Manipulation Mode", file=sys.stderr)
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
                print(f"[INFO] Loaded {len(csv_mappings)} clone mappings from {args.clone_ace_map}",
                      file=sys.stderr)
            except FileNotFoundError as e:
                print(f"[ERROR] {e}", file=sys.stderr)
                sys.exit(1)
            except ValueError as e:
                print(f"[ERROR] {e}", file=sys.stderr)
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
                print(f"[INFO] Loaded {len(csv_mappings)} migration mappings from {args.migrate_trustees}",
                      file=sys.stderr)
            except FileNotFoundError as e:
                print(f"[ERROR] {e}", file=sys.stderr)
                sys.exit(1)
            except ValueError as e:
                print(f"[ERROR] {e}", file=sys.stderr)
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
                print(f"\n[INFO] Resolving clone trustee identities...", file=sys.stderr)
                for cp in clone_patterns:
                    # Resolve source trustee
                    source = cp['source_trustee']
                    print(f"[INFO] Resolving source trustee '{source}'...", file=sys.stderr)

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
                        print(f"[INFO] Resolved source '{source}' -> auth_id {cp['source_auth_id']}", file=sys.stderr)
                    else:
                        print(f"[ERROR] Could not resolve source trustee: {source}", file=sys.stderr)
                        sys.exit(1)

                    # Resolve target trustee
                    target = cp['target_trustee']
                    print(f"[INFO] Resolving target trustee '{target}'...", file=sys.stderr)

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
                        print(f"[INFO] Resolved target '{target}' -> auth_id {cp['target_auth_id']}", file=sys.stderr)
                    else:
                        print(f"[ERROR] Could not resolve target trustee: {target}", file=sys.stderr)
                        sys.exit(1)

            # Resolve migrate pattern trustees (both source and target need auth_id)
            if migrate_patterns:
                if args.verbose:
                    print(f"\n[INFO] Resolving migrate trustee identities...", file=sys.stderr)
                for mp in migrate_patterns:
                    # Resolve source trustee to get auth_id for matching
                    source = mp['source_trustee']
                    if args.verbose:
                        print(f"[INFO] Resolving source trustee '{source}'...", file=sys.stderr)

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
                            print(f"[INFO] Resolved source '{source}' -> auth_id {mp['source_auth_id']}", file=sys.stderr)
                    else:
                        print(f"[ERROR] Could not resolve source trustee: {source}", file=sys.stderr)
                        sys.exit(1)

                    # Resolve target trustee to get auth_id for duplicate detection
                    target = mp['target_trustee']
                    if args.verbose:
                        print(f"[INFO] Resolving target trustee '{target}'...", file=sys.stderr)

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
                            print(f"[INFO] Resolved target '{target}' -> auth_id {mp['target_auth_id']}", file=sys.stderr)
                    else:
                        print(f"[ERROR] Could not resolve target trustee: {target}", file=sys.stderr)
                        sys.exit(1)

            if all_patterns:
                print(f"\n[INFO] Resolving trustee identities...", file=sys.stderr)
                await resolve_pattern_trustees(client, session, all_patterns, verbose=args.verbose)

            # Step 2: Get current ACL and file attributes from path
            print(f"[INFO] Retrieving ACL from: {args.path}", file=sys.stderr)
            current_acl = await client.get_file_acl(session, args.path)
            file_attr = await client.get_file_attr(session, args.path)

            if not current_acl:
                print(f"[ERROR] Could not retrieve ACL from {args.path}", file=sys.stderr)
                sys.exit(1)

            # Extract file_id for backup safety (allows restore even if path is renamed)
            file_id = file_attr.get('id') if file_attr else None

            # Show current ACL summary
            acl_inner = current_acl.get('acl', current_acl)
            current_aces = acl_inner.get('aces', [])
            inherited_count = sum(1 for ace in current_aces if 'INHERITED' in ace.get('flags', []))
            print(f"[INFO] Current ACL has {len(current_aces)} ACEs ({inherited_count} inherited)", file=sys.stderr)

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
            print(f"\n[INFO] Modifications:", file=sys.stderr)
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
                print("\n[DRY RUN] Would apply the following ACL:", file=sys.stderr)
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
                print("[DRY RUN] No changes were made.", file=sys.stderr)
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
                    print(f"[INFO] Backup saved to: {args.ace_backup}", file=sys.stderr)
                    if file_id:
                        print(f"[INFO] File ID {file_id} recorded for safety verification", file=sys.stderr)
                except Exception as e:
                    print(f"[ERROR] Failed to save backup: {e}", file=sys.stderr)
                    sys.exit(1)

            # Step 4: Resolve any new trustees that need auth_id
            for ace in new_aces:
                if ace.get('_needs_resolution'):
                    raw_trustee = ace.get('trustee')
                    if args.verbose:
                        print(f"[INFO] Resolving trustee: {raw_trustee}", file=sys.stderr)

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
                            print(f"[INFO] Resolved '{raw_trustee}' to auth_id {resolved['auth_id']}", file=sys.stderr)
                    else:
                        print(f"[ERROR] Could not resolve trustee: {raw_trustee}", file=sys.stderr)
                        sys.exit(1)

            # Step 5: Apply modified ACL to target path
            print(f"\n[INFO] Applying modified ACL to: {args.path}", file=sys.stderr)
            # Normalize ACL for PUT request (convert trustee objects to auth_id strings)
            normalized_acl = normalize_acl_for_put(modified_acl)
            success, error = await client.set_file_acl(session, args.path, normalized_acl, mark_inherited=False)

            if not success:
                print(f"[ERROR] Failed to apply ACL: {error}", file=sys.stderr)
                sys.exit(1)

            print("[INFO] ACL applied successfully", file=sys.stderr)

            # Step 6: Propagate to children if requested
            if args.propagate_changes:
                print(f"\n[INFO] Propagating ACL to children of: {args.path}", file=sys.stderr)

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

                print(f"\n[INFO] Propagation complete:", file=sys.stderr)
                print(f"  Objects changed:  {propagate_stats['objects_changed']:,}", file=sys.stderr)
                print(f"  Objects failed:   {propagate_stats['objects_failed']:,}", file=sys.stderr)
                if file_filter:
                    print(f"  Objects skipped:  {propagate_stats['objects_skipped']:,}", file=sys.stderr)

                if propagate_stats['objects_failed'] > 0:
                    sys.exit(1)

        print("\n[INFO] ACE manipulation complete", file=sys.stderr)
        # Save identity cache before exiting
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
        return  # Exit after ACE manipulation

    # OWNER/GROUP CHANGE MODE
    # Selective ownership change - find files by current owner/group and change to new owner/group
    change_owner_mode = (args.change_owner or args.change_group or
                         args.change_owners_file or args.change_groups_file)

    if change_owner_mode:
        if args.verbose:
            print("\n[INFO] Owner/Group Change Mode", file=sys.stderr)
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
                    print(f"[ERROR] {e}", file=sys.stderr)
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
                    print(f"[ERROR] {e}", file=sys.stderr)
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
                print(f"[ERROR] Failed to load owner mappings file: {e}", file=sys.stderr)
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
                print(f"[ERROR] Failed to load group mappings file: {e}", file=sys.stderr)
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
            print(f"[DRY RUN] Preview mode - no changes will be made", file=sys.stderr)

        if args.verbose:
            print("=" * 70, file=sys.stderr)
            print("\n[INFO] Resolving identities...", file=sys.stderr)

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
                    print(f"[INFO] Resolving source owner '{source_name}'...", file=sys.stderr)
                source_identifier, source_id_type = get_identifier_and_type(p['source_trustee'])
                result = await client.resolve_identity(session, source_identifier, source_id_type)
                if result and result.get('auth_id'):
                    p['source_auth_id'] = str(result['auth_id'])
                    if args.verbose:
                        print(f"[INFO] Resolved source '{source_name}' -> auth_id {p['source_auth_id']}", file=sys.stderr)
                else:
                    print(f"[WARN] Could not resolve source owner '{source_name}' - may not exist", file=sys.stderr)
                    p['source_auth_id'] = None

                # Resolve target - MUST succeed
                target_name = p['target']
                if args.verbose:
                    print(f"[INFO] Resolving target owner '{target_name}'...", file=sys.stderr)
                target_identifier, target_id_type = get_identifier_and_type(p['target_trustee'])
                result = await client.resolve_identity(session, target_identifier, target_id_type)
                if result and result.get('auth_id'):
                    p['target_auth_id'] = str(result['auth_id'])
                    if args.verbose:
                        print(f"[INFO] Resolved target '{target_name}' -> auth_id {p['target_auth_id']}", file=sys.stderr)
                else:
                    print(f"[ERROR] Could not resolve target owner '{target_name}'", file=sys.stderr)
                    print(f"[ERROR] Target must exist before changing ownership", file=sys.stderr)
                    sys.exit(1)

            # Resolve group change patterns
            for p in group_change_patterns:
                # Resolve source
                source_name = p['source']
                if args.verbose:
                    print(f"[INFO] Resolving source group '{source_name}'...", file=sys.stderr)
                source_identifier, source_id_type = get_identifier_and_type(p['source_trustee'])
                result = await client.resolve_identity(session, source_identifier, source_id_type)
                if result and result.get('auth_id'):
                    p['source_auth_id'] = str(result['auth_id'])
                    if args.verbose:
                        print(f"[INFO] Resolved source '{source_name}' -> auth_id {p['source_auth_id']}", file=sys.stderr)
                else:
                    print(f"[WARN] Could not resolve source group '{source_name}' - may not exist", file=sys.stderr)
                    p['source_auth_id'] = None

                # Resolve target - MUST succeed
                target_name = p['target']
                if args.verbose:
                    print(f"[INFO] Resolving target group '{target_name}'...", file=sys.stderr)
                target_identifier, target_id_type = get_identifier_and_type(p['target_trustee'])
                result = await client.resolve_identity(session, target_identifier, target_id_type)
                if result and result.get('auth_id'):
                    p['target_auth_id'] = str(result['auth_id'])
                    if args.verbose:
                        print(f"[INFO] Resolved target '{target_name}' -> auth_id {p['target_auth_id']}", file=sys.stderr)
                else:
                    print(f"[ERROR] Could not resolve target group '{target_name}'", file=sys.stderr)
                    print(f"[ERROR] Target must exist before changing group", file=sys.stderr)
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
            print("\n[WARN] No valid source identities could be resolved. No files will be changed.", file=sys.stderr)
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
                print(f"\n[INFO] Processing {args.path} and all children...", file=sys.stderr)
            else:
                print(f"\n[INFO] Processing {args.path} only (use --propagate-changes for children)...", file=sys.stderr)
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
                    print(f"[DRY RUN] Would change owner: {file_path}", file=sys.stderr)
                    print(f"          {owner_change_info['source_name']} (auth_id: {file_owner}) -> "
                          f"{owner_change_info['target_name']} (auth_id: {new_owner})", file=sys.stderr)
                    change_stats['owners_changed'] += 1
                if new_group:
                    print(f"[DRY RUN] Would change group: {file_path}", file=sys.stderr)
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
                        print(f"[INFO] Changed owner: {file_path}", file=sys.stderr)
                if new_group:
                    change_stats['groups_changed'] += 1
                    if args.verbose:
                        print(f"[INFO] Changed group: {file_path}", file=sys.stderr)
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
                    print(f"[ERROR] Failed to change ownership: {file_path}: {error_msg}", file=sys.stderr)

        async with client.create_session() as session:
            if args.propagate_changes:
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
                    print(f"[ERROR] Could not get attributes for: {args.path}", file=sys.stderr)
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
    # Progress tracker is needed if --progress or --limit is specified
    progress = (
        ProgressTracker(verbose=args.progress, limit=args.limit)
        if args.progress or args.limit
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
            )

            async def output_callback(entry):
                await batched_handler.add_entry(entry)

        else:
            # Direct streaming output (no owner resolution needed)
            if args.json:
                # JSON to stdout
                if args.all_attributes:
                    # Output full entry with all attributes
                    async def output_callback(entry):
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
            print(
                f"[INFO] Tree walk completed, collected {len(matching_files)} matching files",
                file=sys.stderr,
            )

    # Flush any remaining batched output
    if batched_handler:
        await batched_handler.flush()

    # Close streaming file handler and report results
    if streaming_file_handler:
        await streaming_file_handler.close()
        rows_written = streaming_file_handler.get_rows_written()
        output_path = args.json_out if args.json_out else args.csv_out
        if args.verbose or args.progress:
            print(
                f"\n[INFO] Streaming complete: wrote {rows_written:,} rows to {output_path}",
                file=sys.stderr,
            )
        # Save identity cache and exit - no further processing needed
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
        return

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
        default=100,
        metavar="N",
        help="Concurrent ACL operations during propagation (default: 100, try 500 for faster throughput)"
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
