#!/usr/bin/env python3

"""
Qumulo File Filter and API Tree Walk Tool

Usage:
    ./grumpwalk.py --host <cluster> --path <path> [OPTIONS]

"""

__version__ = "3.4.0"

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
    resolve_detail_field_specs,
    emit_detail_output,
    CopyProgress,
    build_renamer,
    RenamePatternError,
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
# POSIX MODE TO ACL CONVERSION
# ============================================================================

# Rights granted by each POSIX permission bit, derived from Qumulo's
# native POSIX-mode-to-ACL mapping (verified against cluster reference files).
POSIX_READ_RIGHTS = ['READ', 'READ_EA', 'READ_ATTR', 'READ_ACL', 'SYNCHRONIZE']
POSIX_WRITE_RIGHTS = ['WRITE_EA', 'WRITE_ATTR', 'MODIFY', 'EXTEND', 'DELETE_CHILD']
POSIX_EXECUTE_RIGHTS = ['EXECUTE']


def mode_to_acl(mode_str: str, owner_auth_id: str = None, group_auth_id: str = None) -> tuple:
    """
    Convert a chmod-style octal mode string to a Qumulo ACL dict.

    Accepts 1-4 octal digits. A leading 0 is optional (0755 == 755).
    The leading digit encodes special bits (setuid=4, setgid=2, sticky=1).

    Args:
        mode_str: Octal mode string, e.g. '755', '2770', '0644'
        owner_auth_id: If provided, use this auth_id for the owner ACE
                       instead of the OWNER@ (File Owner) placeholder.
        group_auth_id: If provided, use this auth_id for the group ACE
                       instead of the GROUP@ (File Group Owner) placeholder.

    Returns:
        Tuple of (acl_dict, has_setgid: bool).
        has_setgid is True when the mode includes setgid (2xxx), so the
        caller can apply it only to directories during propagation.

    Raises:
        ValueError: If the mode string is not valid octal (digits 0-7).
    """
    # Strip leading 0s for parsing, but keep at least one digit
    stripped = mode_str.lstrip('0') or '0'

    # Validate: all digits must be 0-7
    if not all(c in '01234567' for c in stripped):
        raise ValueError(f"Invalid octal mode: {mode_str}")

    # Pad to 4 digits: e.g. '755' -> '0755', '2770' -> '2770'
    padded = stripped.zfill(4)
    if len(padded) > 4:
        raise ValueError(f"Mode too long: {mode_str}")

    special = int(padded[0])
    owner = int(padded[1])
    group = int(padded[2])
    others = int(padded[3])

    def bits_to_rights(bits):
        rights = []
        if bits & 4:
            rights.extend(POSIX_READ_RIGHTS)
        if bits & 2:
            rights.extend(POSIX_WRITE_RIGHTS)
        if bits & 1:
            rights.extend(POSIX_EXECUTE_RIGHTS)
        return rights

    # Trustees: use explicit auth_ids if provided, otherwise POSIX placeholders
    trustee_owner = {'auth_id': owner_auth_id} if owner_auth_id else {'auth_id': '18446744065119617025'}
    trustee_group = {'auth_id': group_auth_id} if group_auth_id else {'auth_id': '18446744065119617026'}
    trustee_everyone = {'auth_id': '8589934592'}

    # Build ACEs -- only emit an ACE if the triplet is non-zero
    aces = []
    trustees = [(trustee_owner, owner), (trustee_group, group), (trustee_everyone, others)]
    for trustee, bits in trustees:
        if bits:
            aces.append({
                'type': 'ALLOWED',
                'flags': [],
                'trustee': trustee,
                'rights': bits_to_rights(bits),
            })

    # Special permission bits
    posix_special = []
    has_setgid = False
    if special & 4:
        posix_special.append('SET_UID')
    if special & 2:
        posix_special.append('SET_GID')
        has_setgid = True
    if special & 1:
        posix_special.append('STICKY_BIT')

    acl_data = {
        'control': ['PRESENT'],
        'posix_special_permissions': posix_special,
        'aces': aces,
    }

    return acl_data, has_setgid


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

    # Clean each ACE - remove internal marker fields and normalize trustees
    for ace in inner.get('aces', []):
        # Remove internal marker fields
        ace.pop('_needs_resolution', None)
        ace.pop('trustee_details', None)

        # v2 API requires trustee as object, not string
        trustee = ace.get('trustee')
        if isinstance(trustee, str):
            ace['trustee'] = {'auth_id': trustee}

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


def strip_inherited_aces(acl: dict) -> Tuple[dict, int]:
    """
    Remove all inherited ACEs and block future inheritance.

    Equivalent to Windows "Disable Inheritance" > "Remove inherited entries"
    or icacls /inheritance:r.

    This:
    1. Removes all ACEs with 'INHERITED' flag
    2. Adds 'PROTECTED' to control flags (blocks parent inheritance)
    3. Removes 'AUTO_INHERIT' from control flags
    4. Keeps 'PRESENT' in control flags

    Args:
        acl: ACL dict (may have nested 'acl' structure)

    Returns:
        Tuple of (modified ACL dict, count of removed ACEs)
    """
    import copy
    result = copy.deepcopy(acl)

    # Handle nested structure
    if 'acl' in result and 'aces' not in result:
        inner = result['acl']
    else:
        inner = result

    original_aces = inner.get('aces', [])
    explicit_aces = [
        ace for ace in original_aces
        if 'INHERITED' not in ace.get('flags', [])
    ]
    removed_count = len(original_aces) - len(explicit_aces)
    inner['aces'] = explicit_aces

    # Update control flags
    control = set(inner.get('control', []))
    control.add('PRESENT')
    control.add('PROTECTED')
    control.discard('AUTO_INHERIT')
    inner['control'] = list(control)

    return result, removed_count


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
        # Smart skip: total_directories from aggregates is recursive.
        # If 0, there are no subdirectories anywhere in this subtree, so we
        # can skip enumeration entirely (no point paging through millions of
        # file entries just to find no directories).
        if total_dirs == 0:
            return

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


class _RootAttrError(Exception):
    """Raised when a tag operation cannot read the root object's attributes."""

    def __init__(self, path: str):
        self.path = path
        super().__init__(path)


async def _process_tag_targets(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    root_path: str,
    file_filter,
    args,
    process_object,
    record_result,
    abort_event: asyncio.Event,
    concurrency: int,
    progress: bool = False,
    make_progress_line=None,
    examined_limit: Optional[int] = None,
    start_time: Optional[float] = None,
) -> int:
    """
    Shared scaffolding for object-tag operations (add / remove / find).

    Processes the root object when it matches the filter, then streams matching
    descendants from a bounded tree walk through process_object/record_result in
    concurrent batches of `concurrency`.

      process_object(entry) -> result   (async; the per-object work)
      record_result(path, result)        (async; update stats/log/output; may set
                                           abort_event to stop early). `result` is
                                           whatever process_object returned, or an
                                           Exception if it raised.

    When set, `examined_limit` stops queueing after that many descendants have
    been examined (used by add/remove). Find passes None and stops itself via
    abort_event once enough matches are recorded.

    Returns the count of objects skipped due to filter mismatch (including the
    root). Raises _RootAttrError if the root attributes cannot be read.
    """
    if start_time is None:
        start_time = time.time()

    # Step 1: the root object itself.
    root_attr = await client.get_file_attr(session, root_path)
    if root_attr is None:
        raise _RootAttrError(root_path)
    root_attr['path'] = root_path

    root_skipped = 0
    if file_filter is None or file_filter(root_attr):
        try:
            result = await process_object(root_attr)
        except Exception as e:  # surface as a normal failed result
            result = e
        await record_result(root_path, result)
    else:
        root_skipped = 1
        if args and args.verbose:
            log_stderr("INFO", f"Root does not match filter: {root_path}")

    if abort_event.is_set():
        return root_skipped

    # Step 2: stream descendants through a bounded producer/consumer.
    walk_progress = ProgressTracker(verbose=False, limit=args.limit if args else None)
    entry_queue = asyncio.Queue(maxsize=10000)
    producer_done = asyncio.Event()
    limit_reached = asyncio.Event()
    entries_queued = [0]

    async def queue_entry(entry):
        if abort_event.is_set() or limit_reached.is_set():
            return
        # The root is handled above; never double-process it.
        if entry.get('path') == root_path:
            return
        if examined_limit and entries_queued[0] >= examined_limit:
            limit_reached.set()
            return
        await entry_queue.put(entry)
        entries_queued[0] += 1

    async def producer():
        try:
            await client.walk_tree_async(
                session=session,
                path=root_path,
                max_depth=args.max_depth if args else None,
                progress=walk_progress,
                file_filter=file_filter,
                omit_subdirs=args.omit_subdirs if args else None,
                omit_paths=args.omit_path if args else None,
                collect_results=False,
                verbose=args.verbose if args else False,
                max_entries_per_dir=args.max_entries_per_dir if args else None,
                output_callback=queue_entry,
            )
        except Exception as e:
            if progress:
                log_stderr("ERROR", f"Tree walk failed: {e}", newline_before=True)
        finally:
            producer_done.set()

    def print_progress(processed):
        if not (progress and make_progress_line is not None):
            return
        line = make_progress_line()
        if line is None:
            return
        elapsed = time.time() - start_time
        rate = processed / elapsed if elapsed > 0 else 0
        print(
            f"\r{line} | Queue: {entry_queue.qsize():,} | Rate: {rate:.0f}/s",
            end='',
            file=sys.stderr,
        )
        sys.stderr.flush()

    async def consumer():
        batch = []
        processed = 0
        last_redraw = 0.0

        while True:
            if abort_event.is_set():
                break

            try:
                entry = await asyncio.wait_for(entry_queue.get(), timeout=0.1)
                batch.append(entry)
                while len(batch) < concurrency:
                    try:
                        batch.append(entry_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
            except asyncio.TimeoutError:
                if producer_done.is_set() and entry_queue.empty():
                    break
                if not batch:
                    continue

            if not batch:
                continue

            async def run_one(entry):
                path = entry['path']
                try:
                    return path, await process_object(entry)
                except Exception as exc:  # surfaced to record_result as a failure
                    return path, exc

            # Launch the batch concurrently and handle each result as it lands so
            # the progress counter climbs in real time rather than once per batch.
            tasks = [asyncio.ensure_future(run_one(entry)) for entry in batch]
            try:
                for finished in asyncio.as_completed(tasks):
                    path, result = await finished
                    await record_result(path, result)
                    processed += 1
                    # Throttle redraws to ~10/sec to avoid flooding stderr.
                    now = time.time()
                    if now - last_redraw >= 0.1:
                        last_redraw = now
                        print_progress(processed)
                    if abort_event.is_set():
                        for task in tasks:
                            if not task.done():
                                task.cancel()
                        break
            finally:
                await asyncio.gather(*tasks, return_exceptions=True)

            batch = []

        print_progress(processed)

    await asyncio.gather(producer(), consumer())

    return root_skipped + (walk_progress.total_objects - walk_progress.matches)


async def apply_tags_to_tree(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    key: str,
    value: str,
    root_path: str,
    file_filter=None,
    overwrite: bool = False,
    progress: bool = False,
    continue_on_error: bool = False,
    args=None,
    tag_concurrency: int = 100,
    dry_run: bool = False,
) -> dict:
    """
    Add a GENERIC user-metadata tag (key/value) to every object at or under
    root_path that matches the active filter.

    The root object is tagged when it matches the filter; descendants are
    streamed from a filtered tree walk and tagged in concurrent batches. Use
    --max-depth 0 to tag only the root object.

    Conflict handling (key already exists with a DIFFERENT value):
      - Without overwrite: the object is skipped and a warning is logged.
      - With overwrite: the existing value is replaced.
    A key already set to the same value is a no-op. A key absent on a
    previously-tagged object is written. Objects whose user_metadata_revision
    is exactly "0" have never been tagged, so their existing tags are not read;
    any other (or missing) revision triggers a read so a conflict is never
    missed.

    Genuine API errors (failed reads or writes) follow continue_on_error:
    continue (log and proceed) or, when False, an interactive Continue/Abort
    prompt - mirroring ACL propagation. Conflicts are not errors and never
    prompt.

    Returns a statistics dict:
        {
            'objects_tagged': int,        # value written (new, added, or overwritten)
            'objects_unchanged': int,     # key already had this value
            'objects_conflict': int,      # different value, skipped (no overwrite)
            'objects_failed': int,        # read/write error
            'objects_skipped': int,       # did not match filter
            'total_objects_processed': int,
            'errors': list[dict],         # [{path, error_code, message}]
        }
    """
    stats = {
        'objects_tagged': 0,
        'objects_unchanged': 0,
        'objects_conflict': 0,
        'objects_failed': 0,
        'objects_skipped': 0,
        'total_objects_processed': 0,
        'errors': [],
    }

    start_time = time.time()
    abort_event = asyncio.Event()

    async def process(entry: dict):
        """
        Decide and perform the tag action for one object.

        Returns (status, detail):
          status in {'tagged', 'unchanged', 'conflict', 'failed'}
          detail: existing value for 'conflict', error message for 'failed', else None
        """
        path = entry['path']
        # Treat ONLY an explicit "0"/0 as never-tagged. A missing revision falls
        # through to a read so we never silently overwrite a differing value.
        never_tagged = str(entry.get('user_metadata_revision')) == '0'

        if not never_tagged:
            existing = await client.get_file_user_metadata(session, path)
            if existing is None:
                return ('failed', 'Could not read existing tags')
            if key in existing:
                if existing[key] == value:
                    return ('unchanged', None)
                if not overwrite:
                    return ('conflict', existing[key])

        # never tagged, key absent, or overwriting a differing value
        if dry_run:
            return ('tagged', None)
        ok, err = await client.set_file_user_metadata(session, path, key, value)
        return ('tagged', None) if ok else ('failed', err)

    async def record(path: str, result):
        """Update stats and emit logging for one object's result."""
        stats['total_objects_processed'] += 1
        status, detail = ('failed', str(result)) if isinstance(result, Exception) else result

        if status == 'tagged':
            stats['objects_tagged'] += 1
            # Per-item lines: always in dry-run (preview), and on --verbose for a
            # real run. Plain --progress shows only the live counter. This matches
            # the convention used by --change-owner and --set-attribute.
            if dry_run or (args and args.verbose):
                label = "DRY RUN" if dry_run else "TAG"
                verb = "Would set" if dry_run else "Set"
                log_stderr(label, f"{verb} {key}={value} on {path}", newline_before=progress)
        elif status == 'unchanged':
            stats['objects_unchanged'] += 1
            if args and args.verbose:
                log_stderr("SKIP", f"{path}: {key} already set to '{value}'", newline_before=progress)
        elif status == 'conflict':
            stats['objects_conflict'] += 1
            log_stderr(
                "WARN",
                f"{path}: key '{key}' exists = '{detail}' (would set '{value}') -- skipped (use --overwrite)",
                newline_before=progress,
            )
        elif status == 'failed':
            stats['objects_failed'] += 1
            stats['errors'].append({'path': path, 'error_code': 'TAG_FAILURE', 'message': detail})
            if continue_on_error:
                if progress:
                    log_stderr("WARN", f"Error on {path}: {detail}, continuing...", newline_before=True)
            else:
                log_stderr("ERROR", f"Failed to tag: {path}", newline_before=True)
                log_stderr("ERROR", f"{detail}")
                while True:
                    response = input("Continue? [C]ontinue / [A]bort: ").strip().lower()
                    if response in ['c', 'continue']:
                        break
                    elif response in ['a', 'abort']:
                        log_stderr("INFO", "Operation aborted by user.")
                        abort_event.set()
                        return
                    print("Invalid response. Please enter 'c' or 'a'.")

    def progress_line():
        tagged_label = "Would tag" if dry_run else "Tagged"
        return (
            f"[{'DRY RUN' if dry_run else 'TAG'}] {tagged_label}: {stats['objects_tagged']:,} | "
            f"Unchanged: {stats['objects_unchanged']:,} | "
            f"Conflicts: {stats['objects_conflict']:,} | "
            f"Failed: {stats['objects_failed']:,}"
        )

    try:
        stats['objects_skipped'] = await _process_tag_targets(
            client, session, root_path, file_filter, args,
            process_object=process,
            record_result=record,
            abort_event=abort_event,
            concurrency=tag_concurrency,
            progress=progress,
            make_progress_line=progress_line,
            examined_limit=(args.limit if args else None),
            start_time=start_time,
        )
    except _RootAttrError as e:
        log_stderr("ERROR", f"Could not read attributes for: {e.path}")
        stats['objects_failed'] = 1
        stats['errors'].append({
            'path': e.path,
            'error_code': 'ATTR_FAILURE',
            'message': 'Could not get file attributes',
        })
        return stats

    if progress:
        print()
        elapsed = time.time() - start_time
        log_stderr("DRY RUN" if dry_run else "TAG", f"Completed in {elapsed:.1f}s")

    return stats


async def remove_tags_from_tree(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    key: str,
    root_path: str,
    file_filter=None,
    value: Optional[str] = None,
    progress: bool = False,
    continue_on_error: bool = False,
    args=None,
    tag_concurrency: int = 100,
    dry_run: bool = False,
) -> dict:
    """
    Remove the GENERIC tag `key` from every object at or under root_path that
    matches the active filter.

    When `value` is given, the key is removed only if its current value equals
    `value` (a guard against deleting an unexpected value); otherwise the object
    is left unchanged and counted as a value mismatch. Objects whose
    user_metadata_revision is exactly "0" have never been tagged and are skipped
    without a read.

    Returns a statistics dict:
        {
            'objects_removed': int,         # tag deleted (or would be, in dry-run)
            'objects_absent': int,          # object had no such key
            'objects_value_mismatch': int,  # key present but value != requested value
            'objects_failed': int,          # read/delete error
            'objects_skipped': int,         # did not match filter
            'total_objects_processed': int,
            'errors': list[dict],
        }
    """
    stats = {
        'objects_removed': 0,
        'objects_absent': 0,
        'objects_value_mismatch': 0,
        'objects_failed': 0,
        'objects_skipped': 0,
        'total_objects_processed': 0,
        'errors': [],
    }

    start_time = time.time()
    abort_event = asyncio.Event()

    async def process(entry: dict):
        path = entry['path']
        if str(entry.get('user_metadata_revision')) == '0':
            return ('absent', None)
        existing = await client.get_file_user_metadata(session, path)
        if existing is None:
            return ('failed', 'Could not read existing tags')
        if key not in existing:
            return ('absent', None)
        if value is not None and existing[key] != value:
            return ('mismatch', existing[key])
        if dry_run:
            return ('removed', None)
        ok, err = await client.delete_file_user_metadata(session, path, key)
        return ('removed', None) if ok else ('failed', err)

    async def record(path: str, result):
        stats['total_objects_processed'] += 1
        status, detail = ('failed', str(result)) if isinstance(result, Exception) else result

        if status == 'removed':
            stats['objects_removed'] += 1
            # Per-item: always in dry-run, on --verbose for a real run (see add).
            if dry_run or (args and args.verbose):
                verb = "Would remove" if dry_run else "Removed"
                log_stderr("DRY RUN" if dry_run else "UNTAG",
                           f"{verb} {key} from {path}", newline_before=progress)
        elif status == 'absent':
            stats['objects_absent'] += 1
        elif status == 'mismatch':
            stats['objects_value_mismatch'] += 1
            if args and args.verbose:
                log_stderr("SKIP", f"{path}: {key}='{detail}' != '{value}' -- not removed",
                           newline_before=progress)
        elif status == 'failed':
            stats['objects_failed'] += 1
            stats['errors'].append({'path': path, 'error_code': 'UNTAG_FAILURE', 'message': detail})
            if continue_on_error:
                if progress:
                    log_stderr("WARN", f"Error on {path}: {detail}, continuing...", newline_before=True)
            else:
                log_stderr("ERROR", f"Failed to remove tag from: {path}", newline_before=True)
                log_stderr("ERROR", f"{detail}")
                while True:
                    response = input("Continue? [C]ontinue / [A]bort: ").strip().lower()
                    if response in ['c', 'continue']:
                        break
                    elif response in ['a', 'abort']:
                        log_stderr("INFO", "Operation aborted by user.")
                        abort_event.set()
                        return
                    print("Invalid response. Please enter 'c' or 'a'.")

    def progress_line():
        return (
            f"[{'DRY RUN' if dry_run else 'UNTAG'}] Removed: {stats['objects_removed']:,} | "
            f"Absent: {stats['objects_absent']:,} | "
            f"Mismatch: {stats['objects_value_mismatch']:,} | "
            f"Failed: {stats['objects_failed']:,}"
        )

    try:
        stats['objects_skipped'] = await _process_tag_targets(
            client, session, root_path, file_filter, args,
            process_object=process,
            record_result=record,
            abort_event=abort_event,
            concurrency=tag_concurrency,
            progress=progress,
            make_progress_line=progress_line,
            examined_limit=(args.limit if args else None),
            start_time=start_time,
        )
    except _RootAttrError as e:
        log_stderr("ERROR", f"Could not read attributes for: {e.path}")
        stats['objects_failed'] = 1
        stats['errors'].append({
            'path': e.path,
            'error_code': 'ATTR_FAILURE',
            'message': 'Could not get file attributes',
        })
        return stats

    if progress:
        print()
        elapsed = time.time() - start_time
        log_stderr("DRY RUN" if dry_run else "UNTAG", f"Completed in {elapsed:.1f}s")

    return stats


async def find_tagged_objects(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    root_path: str,
    file_filter=None,
    key: Optional[str] = None,
    value: Optional[str] = None,
    progress: bool = False,
    args=None,
    tag_concurrency: int = 100,
) -> dict:
    """
    Find objects whose GENERIC tags match the search criteria and stream them to
    stdout as NDJSON (one {"path", "type", "tags"} object per line).

    Matching:
      - key set, value None  -> object has a tag with that key
      - value set, key None  -> object has any tag with that value
      - both set             -> object has key == value
      - neither set          -> object has at least one tag

    Objects whose user_metadata_revision is exactly "0" are never tagged and are
    skipped without a read. --limit stops after N matches.

    Returns a statistics dict:
        {'matches', 'objects_failed', 'objects_skipped', 'total_objects_processed', 'errors'}
    """
    stats = {
        'matches': 0,
        'objects_failed': 0,
        'objects_skipped': 0,
        'total_objects_processed': 0,
        'errors': [],
    }

    start_time = time.time()
    abort_event = asyncio.Event()
    limit = args.limit if args else None

    def matched_tags(tags):
        """Return the subset of tags satisfying the search, or None if no match."""
        if not tags:
            return None
        if key is not None and value is not None:
            return {key: tags[key]} if tags.get(key) == value else None
        if key is not None:
            return {key: tags[key]} if key in tags else None
        if value is not None:
            subset = {k: v for k, v in tags.items() if v == value}
            return subset or None
        return dict(tags)  # neither set -> any tagged object

    async def process(entry: dict):
        path = entry['path']
        if str(entry.get('user_metadata_revision')) == '0':
            return ('nomatch', None)
        tags = await client.get_file_user_metadata(session, path)
        if tags is None:
            return ('failed', 'Could not read tags')
        if matched_tags(tags) is None:
            return ('nomatch', None)
        return ('match', {'path': path, 'type': entry.get('type'), 'tags': tags})

    async def record(path: str, result):
        stats['total_objects_processed'] += 1
        if isinstance(result, Exception):
            stats['objects_failed'] += 1
            stats['errors'].append({'path': path, 'error_code': 'READ_FAILURE', 'message': str(result)})
            return
        status, detail = result
        if status == 'failed':
            stats['objects_failed'] += 1
            stats['errors'].append({'path': path, 'error_code': 'READ_FAILURE', 'message': detail})
        elif status == 'match':
            stats['matches'] += 1
            print(json.dumps(detail, ensure_ascii=False))
            if limit and stats['matches'] >= limit:
                abort_event.set()

    def progress_line():
        return (
            f"[FIND] Matches: {stats['matches']:,} | "
            f"Examined: {stats['total_objects_processed']:,} | "
            f"Failed: {stats['objects_failed']:,}"
        )

    try:
        stats['objects_skipped'] = await _process_tag_targets(
            client, session, root_path, file_filter, args,
            process_object=process,
            record_result=record,
            abort_event=abort_event,
            concurrency=tag_concurrency,
            progress=progress,
            make_progress_line=progress_line,
            examined_limit=None,  # find limits by matches, handled in record
            start_time=start_time,
        )
    except _RootAttrError as e:
        log_stderr("ERROR", f"Could not read attributes for: {e.path}")
        stats['objects_failed'] = 1
        stats['errors'].append({
            'path': e.path,
            'error_code': 'ATTR_FAILURE',
            'message': 'Could not get file attributes',
        })
        return stats

    if progress:
        print()
        elapsed = time.time() - start_time
        log_stderr("FIND", f"Completed in {elapsed:.1f}s")

    return stats


def _mv_parent_of(path: str) -> str:
    """Parent directory of an absolute path (no trailing slash, root-safe)."""
    p = path.rstrip("/")
    if "/" not in p:
        return "/"
    parent = p.rsplit("/", 1)[0]
    return parent or "/"


def _mv_basename(path: str) -> str:
    """Final path component (no trailing slash)."""
    p = path.rstrip("/")
    return p.rsplit("/", 1)[-1] if "/" in p else p


def _mv_join(parent: str, name: str) -> str:
    """Join a destination directory and a name into an absolute path."""
    if parent == "/":
        return "/" + name
    return parent.rstrip("/") + "/" + name


def _mv_record_error(stats: dict, path: str, message: str) -> None:
    stats["errors"].append({"path": path, "message": message})


async def move_rename_objects(
    client: AsyncQumuloClient,
    session,
    args,
    file_filter,
) -> dict:
    """Move and/or rename objects matching the filters, POSIX-mv style.

    Four phases: collect matches, plan every target (resolving renames,
    collisions, directory pruning and self-containment), confirm (or print a
    dry-run plan), then execute the renames concurrently. A Qumulo move is a
    RENAME, so this is one metadata operation per object.

    Returns a stats dict; the caller prints the summary and sets the exit code.
    """
    stats = {
        "total_matched": 0, "planned": 0, "moved": 0, "failed": 0,
        "skipped_directory": 0, "skipped_inside_moved_dir": 0,
        "skipped_rename_no_match": 0, "skipped_rename_invalid": 0,
        "skipped_noop": 0, "skipped_into_self": 0,
        "skipped_target_collision": 0, "skipped_exists": 0,
        "errors": [],
    }

    # Build the renamer first so a bad pattern fails before any cluster work.
    renamer = None
    if args.rename_to:
        try:
            renamer = build_renamer(args.rename_to, args.name_patterns or [])
        except RenamePatternError as e:
            log_stderr("ERROR", f"Invalid --rename-to pattern: {e}")
            sys.exit(1)

    # Validate the destination directory up front (if moving).
    move_to = None
    if args.move_to:
        if not args.move_to.startswith("/"):
            log_stderr("ERROR", "--move-to must be an absolute path")
            sys.exit(1)
        move_to = args.move_to.rstrip("/") or "/"
        attrs = await client.get_file_attr(session, move_to)
        if attrs is None:
            if not args.create_destination_directory:
                log_stderr("ERROR", f"--move-to destination does not exist: {move_to}")
                log_stderr("HINT", "pass --create-destination-directory to create it")
                sys.exit(1)
            if not await _create_destination_directory(client, session, move_to, args):
                sys.exit(1)
            # In a real run the directory now exists; in --dry-run it does not, but
            # planning only computes target path strings, so that is fine.
        elif attrs.get("type") != "FS_FILE_TYPE_DIRECTORY":
            log_stderr("ERROR", f"--move-to destination is not a directory: {move_to}")
            sys.exit(1)
        else:
            # Destination already exists: owner/mode flags do not apply.
            _warn_ignored_dest_dir_flags(args, move_to)

    # Phase 1: collect matches.
    progress = ProgressTracker(verbose=True, limit=args.limit) if args.progress else None
    log_stderr("INFO", f"Scanning {args.path} for matches...")
    entries = await client.walk_tree_async(
        session,
        args.path,
        args.max_depth,
        progress=progress,
        file_filter=file_filter,
        omit_subdirs=args.omit_subdirs,
        omit_paths=args.omit_path,
        collect_results=True,
        verbose=args.verbose,
        max_entries_per_dir=args.max_entries_per_dir,
    )
    if progress:
        print(file=sys.stderr)
    if args.limit and len(entries) > args.limit:
        entries = entries[:args.limit]
    stats["total_matched"] = len(entries)

    # Phase 2: plan.
    # 2a. Type gate: directories require --include-directories.
    candidates = []  # (source, is_dir, old_name)
    for e in entries:
        src = e.get("path", "").rstrip("/")
        if not src:
            continue
        is_dir = e.get("type") == "FS_FILE_TYPE_DIRECTORY"
        if is_dir and not args.include_directories:
            stats["skipped_directory"] += 1
            continue
        candidates.append((src, is_dir, _mv_basename(src)))

    # 2b. Prune objects that live under a directory we are already moving; the
    # subtree travels with its ancestor, so moving it again would fail.
    if args.include_directories:
        moved_dirs = {src for src, is_dir, _ in candidates if is_dir}

        def _under_moved_dir(path: str) -> bool:
            parent = _mv_parent_of(path)
            while parent != "/":
                if parent in moved_dirs:
                    return True
                parent = _mv_parent_of(parent)
            return False

        kept = []
        for src, is_dir, name in candidates:
            if _under_moved_dir(src):
                stats["skipped_inside_moved_dir"] += 1
                continue
            kept.append((src, is_dir, name))
        candidates = kept

    # 2c. Resolve each target path.
    planned = []  # {source, dest_parent, new_name, target, is_dir}
    for src, is_dir, old_name in candidates:
        new_name = old_name
        if renamer:
            r = renamer(old_name)
            if r is None:
                stats["skipped_rename_no_match"] += 1
                continue
            if r == "" or "/" in r:
                stats["skipped_rename_invalid"] += 1
                if args.verbose:
                    log_stderr("SKIP", f"{src}: rename produced an invalid name: {r!r}")
                continue
            new_name = r
        dest_parent = move_to if move_to else _mv_parent_of(src)
        target = _mv_join(dest_parent, new_name)
        if target == src:
            stats["skipped_noop"] += 1
            continue
        if is_dir and (dest_parent == src or dest_parent.startswith(src + "/")):
            stats["skipped_into_self"] += 1
            continue
        planned.append({
            "source": src, "dest_parent": dest_parent,
            "new_name": new_name, "target": target, "is_dir": is_dir,
        })

    # 2d. Global guard: the destination must not sit inside a directory we move.
    if move_to:
        for p in planned:
            if p["is_dir"] and (move_to == p["source"] or move_to.startswith(p["source"] + "/")):
                log_stderr("ERROR",
                           f"--move-to {move_to} is inside a directory being moved "
                           f"({p['source']}); aborting")
                sys.exit(1)

    # 2e. Intra-run collisions: two sources mapping to one target are both skipped
    # (overwriting one moved object with another is never intended).
    target_sources = {}
    for p in planned:
        target_sources.setdefault(p["target"], []).append(p)
    deduped = []
    for p in planned:
        if len(target_sources[p["target"]]) > 1:
            stats["skipped_target_collision"] += 1
        else:
            deduped.append(p)
    planned = deduped
    stats["planned"] = len(planned)

    # Phase 3: dry-run prints the plan and stops; otherwise confirm.
    if args.dry_run:
        for p in planned:
            log_stderr("DRY RUN", f"{p['source']} -> {p['target']}")
        return stats

    if not planned:
        log_stderr("INFO", "Nothing to move after planning.")
        return stats

    if not args.yes:
        if not sys.stdin.isatty():
            log_stderr("ERROR",
                       "Refusing to move/rename without confirmation in non-interactive "
                       "mode; pass --yes to proceed")
            sys.exit(1)
        verb = "move and rename" if (move_to and renamer) else ("move" if move_to else "rename")
        print(f"\nAbout to {verb} {len(planned):,} object(s):", file=sys.stderr)
        for p in planned[:5]:
            print(f"  {p['source']} -> {p['target']}", file=sys.stderr)
        if len(planned) > 5:
            print(f"  ... and {len(planned) - 5:,} more", file=sys.stderr)
        resp = input("Proceed? [y]es / [N]o: ").strip().lower()
        if resp not in ("y", "yes"):
            log_stderr("INFO", "Aborted by user.")
            return stats

    # Phase 4: execute with bounded concurrency.
    sem = asyncio.Semaphore(max(1, args.move_concurrency))

    async def _do_move(p):
        async with sem:
            ok, error_class, msg = await client.rename_entry(
                session, p["source"], p["dest_parent"], p["new_name"], clobber=args.clobber)
            return p, ok, error_class, msg

    tasks = [asyncio.create_task(_do_move(p)) for p in planned]
    done = 0
    for fut in asyncio.as_completed(tasks):
        p, ok, error_class, msg = await fut
        done += 1
        if ok:
            stats["moved"] += 1
            if args.verbose:
                log_stderr("MOVED", f"{p['source']} -> {p['target']}", newline_before=args.progress)
        elif error_class == "fs_entry_exists_error" and not args.clobber:
            stats["skipped_exists"] += 1
            log_stderr("SKIP", f"{p['target']} exists (use --clobber to overwrite)",
                       newline_before=args.progress)
        else:
            stats["failed"] += 1
            _mv_record_error(stats, p["source"], msg)
            log_stderr("WARN" if args.continue_on_error else "ERROR",
                       f"Failed: {p['source']} -> {p['target']}: {msg}",
                       newline_before=args.progress)
        if args.progress and done % 50 == 0:
            print(f"\r[MOVE] {done:,}/{len(planned):,}", end="", file=sys.stderr, flush=True)
    if args.progress:
        print(file=sys.stderr)

    return stats


# Filesystem object type constants used by the copy driver.
_FS_TYPE_DIR = "FS_FILE_TYPE_DIRECTORY"
_FS_TYPE_SYMLINK = "FS_FILE_TYPE_SYMLINK"


def _preserve_flags(args):
    """Return (do_preserve, preserve_all) for the active copy preservation mode."""
    return (bool(args.preserve_permissions or args.preserve_all), bool(args.preserve_all))


async def _preserve_early(client, session, source_path, target_path, preserve_all,
                          is_symlink=False, snapshot_id=None):
    """Preserve attributes that are safe to apply before a directory's children.

    Always copies owner/group; for non-symlinks also the ACL/mode, and with
    preserve_all the GENERIC user-metadata tags. DOS extended attributes and
    timestamps are deferred to _preserve_late so they are applied last. The
    SOURCE is read with snapshot_id (snapshot context); the target is always live.
    Best-effort: returns a short problem string, or None.
    """
    problems = []
    og = await client.get_file_owner_group(session, source_path, snapshot_id=snapshot_id)
    if og:
        ok, err = await client.set_file_owner_group(
            session, target_path, owner=og.get("owner"), group=og.get("group"))
        if not ok:
            problems.append(f"owner/group: {err}")
    if not is_symlink:
        acl = await client.get_file_acl(session, source_path, snapshot_id=snapshot_id)
        if acl:
            ok, err = await client.set_file_acl(session, target_path, acl)
            if not ok:
                problems.append(f"acl: {err}")
        if preserve_all:
            tags = await client.get_file_user_metadata(session, source_path, snapshot_id=snapshot_id)
            if tags:
                for key, value in tags.items():
                    ok, err = await client.set_file_user_metadata(session, target_path, key, value)
                    if not ok:
                        problems.append(f"tag {key}: {err}")
    return "; ".join(problems) if problems else None


async def _preserve_late(client, session, source_path, target_path, is_symlink=False, snapshot_id=None):
    """Preserve attributes that must be applied LAST (only for --preserve-all).

    DOS extended attributes (non-symlinks) and timestamps (modification/access/
    creation). For a directory this must run AFTER its children are copied, or
    creating the children would re-bump the directory's mtime. change_time
    (ctime) is not preserved -- it always reflects the last metadata change.
    Best-effort: returns a short problem string, or None.
    """
    problems = []
    src = await client.get_file_attr(session, source_path, snapshot_id=snapshot_id)
    if not src:
        return "could not read source attributes"
    if not is_symlink:
        ea = src.get("extended_attributes")
        if ea:
            ok, err = await client.set_file_extended_attributes(session, target_path, ea)
            if not ok:
                problems.append(f"dos-attrs: {err}")
    times = {k: src.get(k) for k in ("modification_time", "access_time", "creation_time") if src.get(k)}
    if times:
        ok, err = await client.set_file_timestamps(session, target_path, times)
        if not ok:
            problems.append(f"timestamps: {err}")
    return "; ".join(problems) if problems else None


async def _preserve_object(client, session, source_path, target_path, args, is_symlink=False):
    """Apply both preserve phases to a non-directory object (file or symlink).

    Directories must interleave the phases around their children, so they call
    _preserve_early / _preserve_late directly instead.
    """
    do_preserve, preserve_all = _preserve_flags(args)
    if not do_preserve:
        return None
    snap = getattr(args, "snapshot", None)
    warns = []
    early = await _preserve_early(client, session, source_path, target_path, preserve_all,
                                  is_symlink, snapshot_id=snap)
    if early:
        warns.append(early)
    if preserve_all:
        late = await _preserve_late(client, session, source_path, target_path, is_symlink, snapshot_id=snap)
        if late:
            warns.append(late)
    return "; ".join(warns) if warns else None


def _conflict_stamp(args):
    """The conflict-rename suffix for this run, computed ONCE in local time.

    Default '_restored_<YYYY-MM-DD>_<HH-MM-SS>'. Customizable via --conflict-suffix
    with {date}/{time}/{datetime}/{snapshot} placeholders. Stamped once so every
    item renamed in one run shares the suffix (identifies the batch).
    """
    cached = getattr(args, "_conflict_stamp_cache", None)
    if cached is None:
        now = datetime.now()  # local time of the grumpwalk host
        d, t = now.strftime("%Y-%m-%d"), now.strftime("%H-%M-%S")
        snap = getattr(args, "snapshot", None)
        template = args.conflict_suffix or "_restored_{datetime}"
        try:
            cached = template.format(date=d, time=t, datetime=f"{d}_{t}",
                                     snapshot=("" if snap is None else snap))
        except (KeyError, IndexError):
            cached = f"_restored_{d}_{t}"
        args._conflict_stamp_cache = cached
    return cached


def _suffix_name(name, suffix, counter=0):
    """Insert suffix before the final extension; add _N when counter > 0.

    'report.docx' + '_restored_..' -> 'report_restored_...docx'; a name without an
    extension (or a leading-dot dotfile) gets the suffix appended.
    """
    extra = f"_{counter + 1}" if counter else ""
    dot = name.rfind(".")
    if dot > 0:
        return f"{name[:dot]}{suffix}{extra}{name[dot:]}"
    return f"{name}{suffix}{extra}"


async def _rename_into_place(client, session, temp_path, dest_parent, new_name, args, clobber=None):
    """Rename a freshly-written temp object to new_name in dest_parent, applying the
    skip / --clobber / --rename-on-conflict strategy.

    clobber overrides args.clobber when given (used by --skip-unchanged to overwrite
    a destination whose contents changed). Returns (status, final_name, message):
    status in copied/skipped_exists/failed. On any non-success the temp is left for
    the caller to delete.
    """
    if clobber is None:
        clobber = args.clobber
    ok, ec, err = await client.rename_entry(session, temp_path, dest_parent, new_name,
                                            clobber=clobber)

    # A transport-level failure (error_class is None, e.g. a socket read timeout) is
    # ambiguous: the rename may have taken effect server-side even though we never got
    # the response. Retry. A retry that reports the temp source is gone proves the
    # original (timed-out) rename actually landed it - so report success, not a false
    # failure. This keeps the copied/failed counts honest under heavy load.
    attempt = 0
    while not ok and ec is None and attempt < 3:
        attempt += 1
        await asyncio.sleep(0.5 * attempt)
        ok, ec, err = await client.rename_entry(session, temp_path, dest_parent, new_name,
                                                clobber=clobber)
        if not ok and ec == "fs_no_such_entry_error":
            if args.verbose:
                log_stderr("INFO", f"rename verified after timed-out response: {new_name}")
            return ("copied", new_name, None)

    if ok:
        return ("copied", new_name, None)
    if ec != "fs_entry_exists_error":
        return ("failed", None, f"rename into place failed: {err}")
    # Destination exists and we did not clobber.
    if not args.rename_on_conflict:
        return ("skipped_exists", None, None)
    suffix = _conflict_stamp(args)
    for counter in range(1000):
        candidate = _suffix_name(new_name, suffix, counter)
        ok, ec, err = await client.rename_entry(session, temp_path, dest_parent, candidate,
                                                clobber=False)
        if ok:
            return ("renamed", candidate, None)
        if ec != "fs_entry_exists_error":
            return ("failed", None, f"rename-on-conflict failed: {err}")
    return ("failed", None, "rename-on-conflict exhausted")


def _copy_unchanged(p, dest_attr):
    """True when the destination already matches the source's size and mtime.

    Qumulo returns size as a string and times as ISO strings; compare as-is. Returns
    False if the source size/mtime are unknown (treat as changed -> copy)."""
    src_size, src_mtime = p.get("src_size"), p.get("src_mtime")
    if src_size is None or src_mtime is None:
        return False
    return (str(src_size) == str(dest_attr.get("size"))
            and src_mtime == dest_attr.get("modification_time"))


async def _copy_one_file(client, session, p, args, idx, progress=None):
    """Copy a single file via a temp file + atomic rename into place.

    Copy-chunk does not truncate, and a mid-copy failure could corrupt an
    existing destination, so the data is copied into a uniquely-named temp file
    and renamed over the final name once the copy succeeds. Attributes are then
    preserved on the final path (after the rename) so read_only/timestamps land
    last. Returns (status, message): status is copied/skipped_unchanged/
    skipped_exists/failed.

    A destination check runs BEFORE any data is copied (server-side copy-chunk is
    not free), so a skip costs one get_file_attr instead of a full copy-then-discard.

    progress (a CopyProgress, optional) is fed per-chunk byte counts; a skip settles
    the file's full size so the aggregate bar still completes.
    """
    src, dest_parent, new_name = p["source"], p["dest_parent"], p["new_name"]
    snap = getattr(args, "snapshot", None)
    target = p.get("target") or _mv_join(dest_parent, new_name)
    file_size = int(p.get("src_size") or 0)

    # Pre-copy destination check. Only needed when a skip is possible: the default
    # (no --clobber) skips existing targets, and --skip-unchanged compares them.
    # Pure --clobber / --rename-on-conflict always write, so they skip the check.
    skip_unchanged = getattr(args, "skip_unchanged", False)
    overwrite = args.clobber
    if skip_unchanged or (not args.clobber and not args.rename_on_conflict):
        dest_attr = await client.get_file_attr(session, target)  # live destination
        if dest_attr is not None:
            if skip_unchanged and _copy_unchanged(p, dest_attr):
                if progress is not None:
                    progress.advance_bytes(file_size, moved=False)
                return ("skipped_unchanged", None)
            if skip_unchanged:
                overwrite = True              # exists but changed -> overwrite
            elif not args.clobber:
                if progress is not None:
                    progress.advance_bytes(file_size, moved=False)
                return ("skipped_exists", None)  # default skip, no data copied

    temp_name = f".grumpwalk-copytmp.{os.getpid()}.{idx}.{new_name}"
    ok, ec, err = await client.create_entry(session, dest_parent, temp_name, "CREATE_FILE")
    if not ok:
        return ("failed", f"create temp failed: {err}")
    temp_path = _mv_join(dest_parent, temp_name)

    on_chunk = None
    chunk_state = {"sent": 0}
    if progress is not None:
        def on_chunk(delta):
            chunk_state["sent"] += delta
            progress.advance_bytes(delta)

    ok, err = await client.copy_file_data(session, src, temp_path, source_snapshot=snap,
                                          on_progress=on_chunk)
    if not ok:
        await client.delete_entry(session, temp_path)
        return ("failed", f"copy failed: {err}")
    status, final_name, msg = await _rename_into_place(client, session, temp_path,
                                                       dest_parent, new_name, args,
                                                       clobber=overwrite)
    if status in ("copied", "renamed"):
        if progress is not None:
            # Settle the tail copy-chunk could not report (and small single-chunk
            # files, which report nothing) so the byte total lands on file_size.
            progress.advance_bytes(file_size - chunk_state["sent"])
        preserve_warn = await _preserve_object(
            client, session, src, _mv_join(dest_parent, final_name), args)
        note = preserve_warn
        if status == "renamed":
            note = f"renamed to {final_name} (conflict)" + (f"; {note}" if note else "")
        return ("copied", note)
    await client.delete_entry(session, temp_path)
    return (status, msg)


async def _copy_one_symlink(client, session, p, args):
    """Recreate a symlink at the destination (read target + CREATE_SYMLINK)."""
    src, dest_parent, new_name = p["source"], p["dest_parent"], p["new_name"]
    snap = getattr(args, "snapshot", None)
    target_of = await client.read_symlink(session, src, snapshot_id=snap)
    if target_of is None:
        return ("failed", "could not read symlink target")
    if args.clobber:
        await client.delete_entry(session, p["target"])
    ok, ec, err = await client.create_entry(
        session, dest_parent, new_name, "CREATE_SYMLINK", old_path=target_of)
    if not ok:
        if ec == "fs_entry_exists_error":
            return ("skipped_exists", None)
        return ("failed", f"create symlink failed: {err}")
    preserve_warn = await _preserve_object(client, session, src, p["target"], args, is_symlink=True)
    return ("copied", preserve_warn)


async def _copy_tree(client, session, source_dir, target_dir, args, stats):
    """Recursively copy the contents of source_dir into an existing target_dir.

    target_dir is created fresh by the caller, so there are no collisions inside
    it. Directories, files, and symlinks are recreated; --preserve is applied to
    each object. Per-object failures are recorded and do not abort the tree.
    """
    do_preserve, preserve_all = _preserve_flags(args)
    snap = getattr(args, "snapshot", None)
    children = await client.enumerate_directory(session, source_dir, snapshot_id=snap)
    for child in children:
        cpath = child.get("path", "").rstrip("/")
        if not cpath:
            continue
        cname = _mv_basename(cpath)
        ctype = child.get("type")
        if ctype == _FS_TYPE_DIR:
            ok, ec, err = await client.create_entry(session, target_dir, cname, "CREATE_DIRECTORY")
            if not ok:
                stats["tree_failed"] += 1
                _mv_record_error(stats, cpath, f"mkdir failed: {err}")
                continue
            ctarget = _mv_join(target_dir, cname)
            if do_preserve:
                await _preserve_early(client, session, cpath, ctarget, preserve_all, snapshot_id=snap)
            await _copy_tree(client, session, cpath, ctarget, args, stats)
            if preserve_all:
                await _preserve_late(client, session, cpath, ctarget, snapshot_id=snap)  # after children
        elif ctype == _FS_TYPE_SYMLINK:
            target_of = await client.read_symlink(session, cpath, snapshot_id=snap)
            if target_of is None:
                stats["tree_failed"] += 1
                _mv_record_error(stats, cpath, "could not read symlink target")
                continue
            ok, ec, err = await client.create_entry(
                session, target_dir, cname, "CREATE_SYMLINK", old_path=target_of)
            if ok:
                await _preserve_object(client, session, cpath, _mv_join(target_dir, cname),
                                       args, is_symlink=True)
                stats["copied_in_tree"] += 1
            else:
                stats["tree_failed"] += 1
                _mv_record_error(stats, cpath, f"symlink failed: {err}")
        else:
            ok, ec, err = await client.create_entry(session, target_dir, cname, "CREATE_FILE")
            if not ok:
                stats["tree_failed"] += 1
                _mv_record_error(stats, cpath, f"create failed: {err}")
                continue
            ctarget = _mv_join(target_dir, cname)
            ok, err = await client.copy_file_data(session, cpath, ctarget, source_snapshot=snap)
            if not ok:
                stats["tree_failed"] += 1
                _mv_record_error(stats, cpath, f"copy failed: {err}")
                continue
            await _preserve_object(client, session, cpath, ctarget, args)
            stats["copied_in_tree"] += 1


async def _copy_one_dir(client, session, p, args, stats):
    """Copy a matched directory: create the top dir fresh, then recurse."""
    src, dest_parent, new_name = p["source"], p["dest_parent"], p["new_name"]
    ok, ec, err = await client.create_entry(session, dest_parent, new_name, "CREATE_DIRECTORY")
    if not ok:
        if ec == "fs_entry_exists_error":
            return ("skipped_exists", None)   # no directory merge in v1
        return ("failed", f"mkdir failed: {err}")
    target_dir = _mv_join(dest_parent, new_name)
    do_preserve, preserve_all = _preserve_flags(args)
    snap = getattr(args, "snapshot", None)
    if do_preserve:
        await _preserve_early(client, session, src, target_dir, preserve_all, snapshot_id=snap)
    await _copy_tree(client, session, src, target_dir, args, stats)
    if preserve_all:
        await _preserve_late(client, session, src, target_dir, snapshot_id=snap)  # after children
    return ("copied", None)


def _normalize_mode(mode_str):
    """Validate and normalize an octal POSIX mode (e.g. '755' -> '0755').

    Returns the 4-character octal string, or None if the input is not a valid
    3- or 4-digit octal mode.
    """
    if not mode_str:
        return None
    m = mode_str.strip()
    if re.fullmatch(r"[0-7]{3,4}", m):
        return m if len(m) == 4 else "0" + m
    return None


def _choose_new_dir_mode(args):
    """Decide the new destination directory's permissions.

    Returns an octal mode string to apply, or None to inherit from the parent
    (the cluster's default). Uses --destination-directory-mode when given;
    otherwise prompts interactively, defaulting to inherit in non-interactive
    runs (--yes or no TTY).
    """
    if args.destination_directory_mode:
        return _normalize_mode(args.destination_directory_mode)
    if args.yes or not sys.stdin.isatty():
        return None
    while True:
        resp = input("New destination directory permissions - "
                     "[I]nherit from parent or specify a [P]OSIX mode? [I/p]: ").strip().lower()
        if resp in ("", "i", "inherit"):
            return None
        if resp in ("p", "posix", "mode"):
            while True:
                entered = input("Enter POSIX mode (e.g. 0755): ").strip()
                normalized = _normalize_mode(entered)
                if normalized:
                    return normalized
                print("Invalid mode; use an octal value like 0755 or 750.")
        print("Please answer I (inherit) or P (POSIX mode).")


async def _resolve_owner_to_auth_id(client, session, spec):
    """Resolve an owner spec (name, uid:N, SID, DOMAIN\\user, ...) to an auth_id."""
    trustee = parse_trustee(spec)
    payload, id_type = trustee["payload"], trustee["type"]
    identifier = payload.get(id_type) if id_type in ("uid", "gid", "sid", "auth_id") else payload.get("name")
    result = await client.resolve_identity(session, identifier, id_type)
    if result and result.get("auth_id"):
        return str(result["auth_id"])
    return None


async def _create_destination_directory(client, session, dest, args):
    """Create dest and any missing parent directories (like mkdir -p).

    Applies the chosen permissions (inherit-from-parent or an explicit POSIX
    mode) and optional owner to each newly created directory. In --dry-run the
    intended creations are printed and nothing is created. Returns True on
    success (or would-succeed), False on failure.
    """
    # Walk up to the first existing ancestor, collecting the missing chain.
    missing = []
    p = dest
    while p != "/":
        existing = await client.get_file_attr(session, p)
        if existing is not None:
            if existing.get("type") != _FS_TYPE_DIR:
                log_stderr("ERROR", f"Cannot create {dest}: {p} exists and is not a directory")
                return False
            break
        missing.append(p)
        p = _mv_parent_of(p)
    missing.reverse()  # shallowest first
    if not missing:
        return True

    owner_auth_id = None
    if args.destination_directory_owner:
        owner_auth_id = await _resolve_owner_to_auth_id(
            client, session, args.destination_directory_owner)
        if owner_auth_id is None:
            log_stderr("ERROR",
                       f"Could not resolve --destination-directory-owner "
                       f"'{args.destination_directory_owner}'")
            return False

    mode = _choose_new_dir_mode(args)
    perm_desc = f"POSIX mode {mode}" if mode else "inherited from parent"
    owner_desc = f", owner {args.destination_directory_owner}" if owner_auth_id else ""

    if args.dry_run:
        for m in missing:
            log_stderr("DRY RUN", f"Would create directory {m} ({perm_desc}{owner_desc})")
        return True

    for m in missing:
        parent, name = _mv_parent_of(m), _mv_basename(m)
        ok, ec, err = await client.create_entry(session, parent, name, "CREATE_DIRECTORY")
        if not ok:
            log_stderr("ERROR", f"Failed to create directory {m}: {err}")
            return False
        # Chown before chmod so the mode's owner bits apply to the new owner.
        if owner_auth_id:
            ok2, err2 = await client.set_file_owner_group(session, m, owner=owner_auth_id)
            if not ok2:
                log_stderr("WARN", f"Created {m} but could not set owner: {err2}")
        if mode:
            ok3, err3 = await client.set_file_mode(session, m, mode)
            if not ok3:
                log_stderr("WARN", f"Created {m} but could not set mode {mode}: {err3}")
        log_stderr("INFO", f"Created directory {m} ({perm_desc}{owner_desc})")
    return True


def _warn_ignored_dest_dir_flags(args, dest):
    """Warn that --destination-directory-owner/-mode were ignored.

    These only apply to directories grumpwalk creates; when the destination
    already exists they have no effect, so make that visible rather than silently
    doing nothing.
    """
    ignored = []
    if args.destination_directory_owner:
        ignored.append(f"--destination-directory-owner {args.destination_directory_owner}")
    if args.destination_directory_mode:
        ignored.append(f"--destination-directory-mode {args.destination_directory_mode}")
    if ignored:
        log_stderr("WARN", f"Destination {dest} already exists; ignoring "
                           f"{', '.join(ignored)} (applies only to newly created directories). "
                           f"The existing directory's owner and permissions are unchanged.")


async def copy_objects(client, session, args, file_filter) -> dict:
    """Server-side copy of objects matching the filters, POSIX cp style.

    Files are copied with copy-chunk; with --include-directories matched
    directories are recreated and their subtree copied. --rename-to renames the
    copied object; --preserve also copies owner/group/ACL. Collect -> plan ->
    confirm -> execute, mirroring move_rename_objects.
    """
    stats = {
        "total_matched": 0, "planned": 0, "copied": 0, "failed": 0,
        "copied_in_tree": 0, "tree_failed": 0,
        "skipped_directory": 0, "skipped_inside_copied_dir": 0,
        "skipped_rename_no_match": 0, "skipped_rename_invalid": 0,
        "skipped_noop": 0, "skipped_into_self": 0,
        "skipped_target_collision": 0, "skipped_exists": 0, "skipped_unchanged": 0,
        "errors": [],
    }

    renamer = None
    if args.rename_to:
        try:
            renamer = build_renamer(args.rename_to, args.name_patterns or [])
        except RenamePatternError as e:
            log_stderr("ERROR", f"Invalid --rename-to pattern: {e}")
            sys.exit(1)

    # Copy from a snapshot: validate it, default --path to its source, check coverage.
    src_snapshot = getattr(args, "snapshot", None)
    if src_snapshot is not None:
        snap = await client.get_snapshot(session, src_snapshot)
        if snap is None:
            log_stderr("ERROR", f"Snapshot {src_snapshot} not found")
            sys.exit(1)
        snap_src = await client.resolve_id_to_path(session, snap.get("source_file_id"))
        if not args.path:
            if snap_src is None:
                log_stderr("ERROR", f"Snapshot {src_snapshot} source no longer exists; "
                                    "specify --path within the snapshot")
                sys.exit(1)
            args.path = snap_src.rstrip("/") or "/"
        elif snap_src is not None and not _path_within(args.path, snap_src):
            log_stderr("ERROR", f"Snapshot {src_snapshot} (source {snap_src}) does not cover "
                                f"{args.path} -- a read there would return LIVE data.")
            sys.exit(1)

    if not args.copy_to.startswith("/"):
        log_stderr("ERROR", "--copy-to must be an absolute path")
        sys.exit(1)
    copy_to = args.copy_to.rstrip("/") or "/"
    dest_attrs = await client.get_file_attr(session, copy_to)
    if dest_attrs is None:
        if not args.create_destination_directory:
            log_stderr("ERROR", f"--copy-to destination does not exist: {copy_to}")
            log_stderr("HINT", "pass --create-destination-directory to create it")
            sys.exit(1)
        if not await _create_destination_directory(client, session, copy_to, args):
            sys.exit(1)
        # In a real run the directory now exists; in --dry-run it does not, but
        # planning only computes target path strings, so that is fine.
    elif dest_attrs.get("type") != _FS_TYPE_DIR:
        log_stderr("ERROR", f"--copy-to destination is not a directory: {copy_to}")
        sys.exit(1)
    else:
        # Destination already exists: owner/mode flags do not apply.
        _warn_ignored_dest_dir_flags(args, copy_to)

    # Phase 1: collect matches.
    progress = ProgressTracker(verbose=True, limit=args.limit) if args.progress else None
    log_stderr("INFO", f"Scanning {args.path} for matches...")
    entries = await client.walk_tree_async(
        session, args.path, args.max_depth, progress=progress, file_filter=file_filter,
        omit_subdirs=args.omit_subdirs, omit_paths=args.omit_path,
        collect_results=True, verbose=args.verbose,
        max_entries_per_dir=args.max_entries_per_dir,
        snapshot_id=getattr(args, "snapshot", None),
    )
    if progress:
        print(file=sys.stderr)
    if args.limit and len(entries) > args.limit:
        entries = entries[:args.limit]
    stats["total_matched"] = len(entries)

    # Phase 2: plan.
    candidates = []  # (source, kind, old_name); kind in {file, dir, symlink}
    src_meta = {}    # source path -> entry (size/mtime for --skip-unchanged)
    for e in entries:
        src = e.get("path", "").rstrip("/")
        if not src:
            continue
        etype = e.get("type")
        is_dir = etype == _FS_TYPE_DIR
        if is_dir and not args.include_directories:
            stats["skipped_directory"] += 1
            continue
        kind = "dir" if is_dir else ("symlink" if etype == _FS_TYPE_SYMLINK else "file")
        candidates.append((src, kind, _mv_basename(src)))
        src_meta[src] = e

    if args.include_directories:
        copied_dirs = {src for src, kind, _ in candidates if kind == "dir"}

        def _under_copied_dir(path):
            parent = _mv_parent_of(path)
            while parent != "/":
                if parent in copied_dirs:
                    return True
                parent = _mv_parent_of(parent)
            return False

        kept = []
        for src, kind, name in candidates:
            if _under_copied_dir(src):
                stats["skipped_inside_copied_dir"] += 1
                continue
            kept.append((src, kind, name))
        candidates = kept

    planned = []  # {source, dest_parent, new_name, target, kind}
    for src, kind, old_name in candidates:
        new_name = old_name
        if renamer:
            r = renamer(old_name)
            if r is None:
                stats["skipped_rename_no_match"] += 1
                continue
            if r == "" or "/" in r:
                stats["skipped_rename_invalid"] += 1
                continue
            new_name = r
        target = _mv_join(copy_to, new_name)
        if target == src:
            stats["skipped_noop"] += 1
            continue
        if kind == "dir" and (copy_to == src or copy_to.startswith(src + "/")):
            stats["skipped_into_self"] += 1
            continue
        meta = src_meta.get(src, {})
        planned.append({"source": src, "dest_parent": copy_to,
                        "new_name": new_name, "target": target, "kind": kind,
                        "src_size": meta.get("size"),
                        "src_mtime": meta.get("modification_time")})

    # The destination must not sit inside a directory we copy (would recurse into
    # the growing copy).
    for p in planned:
        if p["kind"] == "dir" and (copy_to == p["source"] or copy_to.startswith(p["source"] + "/")):
            log_stderr("ERROR",
                       f"--copy-to {copy_to} is inside a directory being copied "
                       f"({p['source']}); aborting")
            sys.exit(1)

    target_sources = {}
    for p in planned:
        target_sources.setdefault(p["target"], []).append(p)
    deduped = []
    for p in planned:
        if len(target_sources[p["target"]]) > 1:
            stats["skipped_target_collision"] += 1
        else:
            deduped.append(p)
    planned = deduped
    stats["planned"] = len(planned)

    if args.dry_run:
        for p in planned:
            suffix = "/" if p["kind"] == "dir" else ""
            log_stderr("DRY RUN", f"{p['source']}{suffix} -> {p['target']}{suffix}")
        return stats

    if not planned:
        log_stderr("INFO", "Nothing to copy after planning.")
        return stats

    if not args.yes:
        if not sys.stdin.isatty():
            log_stderr("ERROR",
                       "Refusing to copy without confirmation in non-interactive mode; "
                       "pass --yes to proceed")
            sys.exit(1)
        verb = "copy and rename" if renamer else "copy"
        if args.preserve_all:
            preserve_note = " (preserving all attributes)"
        elif args.preserve_permissions:
            preserve_note = " (preserving owner/group/ACL)"
        else:
            preserve_note = ""
        print(f"\nAbout to {verb} {len(planned):,} object(s) to {copy_to}"
              f"{preserve_note}:", file=sys.stderr)
        for p in planned[:5]:
            print(f"  {p['source']} -> {p['target']}", file=sys.stderr)
        if len(planned) > 5:
            print(f"  ... and {len(planned) - 5:,} more", file=sys.stderr)
        resp = input("Proceed? [y]es / [N]o: ").strip().lower()
        if resp not in ("y", "yes"):
            log_stderr("INFO", "Aborted by user.")
            return stats

    # Phase 4: execute with bounded concurrency.
    sem = asyncio.Semaphore(max(1, args.copy_concurrency))

    copy_progress = None
    if args.progress and planned:
        total_bytes = sum(int(p.get("src_size") or 0) for p in planned if p["kind"] == "file")
        copy_progress = CopyProgress(len(planned), total_bytes, label="COPY")

    async def _run(p, idx):
        async with sem:
            if p["kind"] == "dir":
                return p, await _copy_one_dir(client, session, p, args, stats)
            if p["kind"] == "symlink":
                return p, await _copy_one_symlink(client, session, p, args)
            return p, await _copy_one_file(client, session, p, args, idx, progress=copy_progress)

    tasks = [asyncio.create_task(_run(p, i)) for i, p in enumerate(planned)]
    done = 0
    for fut in asyncio.as_completed(tasks):
        p, (status, message) = await fut
        done += 1
        if status == "copied":
            stats["copied"] += 1
            if args.verbose:
                log_stderr("COPIED", f"{p['source']} -> {p['target']}", newline_before=args.progress)
            if message:  # preserve warning
                log_stderr("WARN", f"{p['target']}: preserve incomplete: {message}",
                           newline_before=args.progress)
        elif status == "skipped_unchanged":
            stats["skipped_unchanged"] += 1
            if args.verbose:
                log_stderr("SKIP", f"{p['target']} unchanged (size + mtime match)",
                           newline_before=args.progress)
        elif status == "skipped_exists":
            stats["skipped_exists"] += 1
            log_stderr("SKIP", f"{p['target']} exists (use --clobber to overwrite)",
                       newline_before=args.progress)
        else:
            stats["failed"] += 1
            _mv_record_error(stats, p["source"], message or "copy failed")
            log_stderr("WARN" if args.continue_on_error else "ERROR",
                       f"Failed: {p['source']} -> {p['target']}: {message}",
                       newline_before=args.progress)
        if copy_progress is not None:
            copy_progress.file_done()
    if copy_progress is not None:
        copy_progress.finish()

    return stats


# ============================================================================
# SNAPSHOTS: search and restore data from Qumulo snapshots
# ============================================================================

def _parse_snapshot_time(ts_str):
    """Parse a snapshot RFC 3339 timestamp into an aware UTC datetime, or None.

    Qumulo timestamps carry nanosecond precision, which datetime.fromisoformat
    cannot parse; the fractional part is truncated to microseconds first.
    """
    if not ts_str:
        return None
    s = ts_str.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac, tz = rest, ""
        for marker in ("+", "-"):
            if marker in rest:
                frac, tzrest = rest.split(marker, 1)
                tz = marker + tzrest
                break
        s = f"{head}.{frac[:6]}{tz}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _path_within(path, root):
    """True if path equals root or is a descendant of root."""
    p = path.rstrip("/") or "/"
    r = root.rstrip("/") or "/"
    return r == "/" or p == r or p.startswith(r + "/")


async def _resolve_snapshot_source(client, session, snap, cache):
    """Resolve a snapshot's source_file_id to a live path (cached). None if unresolvable.

    Uses a LIVE read (no snapshot context). Returns None when the source directory
    no longer exists live (deleted/moved), so coverage cannot be confirmed.
    """
    sid = snap.get("source_file_id")
    if sid in cache:
        return cache[sid]
    raw = await client.resolve_id_to_path(session, sid)
    path = raw.rstrip("/") if raw else None
    if raw is not None and path == "":
        path = "/"
    cache[sid] = path
    return path


def _parse_age_to_hours(value):
    """Parse a snapshot-age threshold to hours.

    Accepts a bare number (days, for back-compat) or a number with a unit:
    '5'/'5d'/'5 days' -> 120h; '12h'/'12 hours' -> 12h. Returns float hours, or
    None if the input is not a valid non-negative number with an optional d/h unit.
    """
    if value is None:
        return None
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$", str(value))
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2).lower()
    if unit in ("", "d", "day", "days"):
        return num * 24.0
    if unit in ("h", "hr", "hrs", "hour", "hours"):
        return num
    return None


def _filter_snapshots_by_age(snapshots, newer_hours, older_hours):
    """Filter snapshots by their own age (UTC), not file age.

    Snapshot timestamps are UTC and 'now' is taken in UTC, so the age is timezone-
    correct regardless of the grumpwalk host's local time. newer_hours/older_hours
    are float hours (or None). Snapshots with an unparseable timestamp are dropped.
    """
    now = datetime.now(timezone.utc)
    out = []
    for snap in snapshots:
        ts = _parse_snapshot_time(snap.get("timestamp"))
        if ts is None:
            continue
        age_hours = (now - ts).total_seconds() / 3600.0
        if newer_hours is not None and age_hours > newer_hours:
            continue
        if older_hours is not None and age_hours < older_hours:
            continue
        out.append(snap)
    return out


# Qumulo's replication system auto-creates snapshots named replication_from_<cluster>
# (target side) and replication_to_<cluster> (source side). They are not useful for
# admin restore, so listing and multi-snapshot search drop them by default.
_REPLICATION_SNAPSHOT_PREFIXES = ("replication_from_", "replication_to_")


def _is_replication_snapshot(snap):
    """True if snap is a Qumulo replication-system snapshot (by name convention)."""
    return (snap.get("name") or "").startswith(_REPLICATION_SNAPSHOT_PREFIXES)


def _admin_snapshots(snaps, args):
    """The snapshots an admin cares about: age-filtered, with snapshots being deleted
    (in_delete) always dropped, and replication snapshots dropped unless
    --include-replication-snapshots is set."""
    snaps = _filter_snapshots_by_age(
        snaps, args.snapshots_newer_hours, args.snapshots_older_hours)
    snaps = [s for s in snaps if not s.get("in_delete")]
    if not getattr(args, "include_replication_snapshots", False):
        snaps = [s for s in snaps if not _is_replication_snapshot(s)]
    return snaps


async def list_snapshots_mode(client, session, args):
    """--list-snapshots: print available snapshots (age-filtered) to stdout. With
    --path, list only snapshots whose source covers that path (source is the path
    itself or an ancestor) - i.e. the snapshots you can search or restore it from."""
    snaps = _admin_snapshots(await client.list_snapshots(session), args)
    if not snaps:
        log_stderr("INFO", "No snapshots match.")
        return
    cache = {}
    rows = []
    for snap in sorted(snaps, key=lambda s: s.get("id", 0)):
        src = await _resolve_snapshot_source(client, session, snap, cache)
        if args.path and (src is None or not _path_within(args.path, src)):
            continue  # source does not cover --path (or could not be resolved)
        rows.append((snap, src))
    if args.path:
        if not rows:
            log_stderr("INFO", f"No snapshots cover {args.path}.")
            return
        log_stderr("INFO", f"Snapshots whose source covers {args.path}:")
    print(f"{'ID':>6}  {'TIMESTAMP (UTC)':<21}  {'NAME':<22}  SOURCE")
    for snap, src in rows:
        ts = (snap.get("timestamp") or "")[:19].replace("T", " ")
        name = (snap.get("name") or "")[:22]
        print(f"{snap.get('id'):>6}  {ts:<21}  {name:<22}  {src or '<source deleted/moved>'}")


def _emit_snapshot_match(entry, snap, args, annotate):
    """Emit one snapshot search match: NDJSON with --json, else a path line."""
    if getattr(args, "json", False):
        out = dict(entry)
        out["snapshot"] = {"id": snap.get("id"), "name": snap.get("name"),
                           "timestamp": snap.get("timestamp")}
        print(json.dumps(out))
    else:
        path = entry.get("path", "")
        print(f"[snap {snap.get('id')}] {path}" if annotate else path)


def _snapshot_sort_key(snap):
    """UTC datetime for ordering snapshots by recency (oldest sentinel if unparseable)."""
    return _parse_snapshot_time(snap.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc)


async def _select_search_snapshots(client, session, args):
    """Resolve which snapshots to crawl: list of (snapshot, root_path).

    Multi-snapshot search (--all-snapshots or --in-the-last-snapshots): every
    age-passing snapshot whose source covers --path (or rooted at its source when
    --path is omitted). With --in-the-last-snapshots N the covering snapshots are
    ordered newest-first (by UTC timestamp) and trimmed to the N most recent.
    --snapshot ID: just that one, rooted at --path (or its source); aborts if
    --path is outside the snapshot (would read live).
    """
    cache = {}
    pairs = []
    if args.all_snapshots or args.in_the_last_snapshots:
        snaps = _admin_snapshots(await client.list_snapshots(session), args)
        for snap in snaps:
            src = await _resolve_snapshot_source(client, session, snap, cache)
            if args.path:
                if src is None or not _path_within(args.path, src):
                    continue
                pairs.append((snap, args.path.rstrip("/") or "/"))
            elif src is not None:
                pairs.append((snap, src))
        if args.in_the_last_snapshots:
            # Newest-first, keep the N most recent (so dedup keeps the newest version).
            pairs.sort(key=lambda pr: _snapshot_sort_key(pr[0]), reverse=True)
            pairs = pairs[:args.in_the_last_snapshots]
        else:
            pairs.sort(key=lambda pr: pr[0].get("id", 0))
    else:
        snap = await client.get_snapshot(session, args.snapshot)
        if snap is None:
            log_stderr("ERROR", f"Snapshot {args.snapshot} not found")
            sys.exit(1)
        src = await _resolve_snapshot_source(client, session, snap, cache)
        if args.path and src is not None and not _path_within(args.path, src):
            log_stderr("ERROR", f"Snapshot {args.snapshot} (source {src}) does not cover "
                                f"{args.path} -- a read there would return LIVE data, not the "
                                f"snapshot. Use a --path within {src}.")
            sys.exit(1)
        root = (args.path.rstrip("/") if args.path else src) or "/"
        pairs.append((snap, root))
    return pairs


async def _attach_dir_capacity(client, session, records, concurrency=50):
    """Fetch each directory record's recursive aggregate capacity and store it on
    the entry as 'total_capacity' (bytes, data + metadata). Files are left
    untouched. Each record is read in its own snapshot context when present. Adds
    one aggregates call per matched directory.
    """
    dirs = [e for e in records if e.get("type") == _FS_TYPE_DIR]
    if not dirs:
        return
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(e):
        path = e.get("path", "").rstrip("/") or "/"
        sid = (e.get("snapshot") or {}).get("id")
        async with sem:
            agg = await client.get_directory_aggregates(session, path, snapshot_id=sid)
        if isinstance(agg, dict) and "error" not in agg:
            e["total_capacity"] = agg.get("total_capacity")

    await asyncio.gather(*[_one(e) for e in dirs])


def _detail_needs_capacity(specs):
    """True when the resolved detail columns include the directory capacity."""
    return any(resolve_path == "total_capacity" for _, resolve_path in specs)


async def _inc_walk(client, session, path, snap_id, args, file_filter):
    """Walk one path (a single file, or a directory subtree) in a snapshot with the
    search filter, reusing the exact same walk + filter as a full crawl so the
    entries are byte-for-byte what a full crawl would produce. A file path yields
    [entry] or []; a directory path yields its matching descendants."""
    return await client.walk_tree_async(
        session, path, args.max_depth, file_filter=file_filter,
        omit_subdirs=args.omit_subdirs, omit_paths=args.omit_path,
        collect_results=True, verbose=False,
        max_entries_per_dir=args.max_entries_per_dir, snapshot_id=snap_id)


async def _inc_eval_dir_self(client, session, M, dpath, snap_id, file_filter):
    """Evaluate a directory node itself against the filter and update the match set.
    A subtree walk returns a directory's descendants but not the directory itself,
    so a directory that matches by its own attributes (e.g. name, --type directory)
    is checked here."""
    a = await client.get_file_attr(session, dpath, snapshot_id=snap_id)
    if a is None:
        M.pop(dpath, None)
        return
    if not a.get("path"):
        a = dict(a)
        a["path"] = dpath
    if file_filter is None or file_filter(a):
        M[dpath] = a
    else:
        M.pop(dpath, None)


async def _inc_apply_diff(client, session, M, newer_id, older_id, root, args, file_filter):
    """Replay the consecutive tree diff (older -> newer) onto match set M.

    Each changed path is re-evaluated with the same walk + filter as a full crawl:
    a changed file is re-walked (added/updated/removed), a created directory has its
    whole subtree walked (the diff reports only the directory node, not descendants)
    and the directory itself evaluated, a deleted directory drops itself and every
    match beneath it, and a modified directory re-evaluates only itself.
    """
    entries, err = await client.get_tree_diff(session, newer_id, older_id)
    if err:
        log_stderr("WARN", f"Tree diff {older_id}->{newer_id} may be incomplete: {err}")
    base = root.rstrip("/") + "/"
    for e in entries:
        p, op = e.get("path"), e.get("op")
        if not p or not (p.startswith(base) or p.rstrip("/") == root):
            continue
        if p.endswith("/"):                       # directory node
            d = p.rstrip("/")
            if op == "DELETE":
                M.pop(d, None)
                for k in [k for k in M if k.startswith(d + "/")]:
                    del M[k]
            elif op == "CREATE":
                await _inc_eval_dir_self(client, session, M, d, newer_id, file_filter)
                for se in await _inc_walk(client, session, d, newer_id, args, file_filter):
                    M[se["path"]] = se
            else:                                 # MODIFY: only the directory itself
                await _inc_eval_dir_self(client, session, M, d, newer_id, file_filter)
        else:                                     # file node
            if op == "DELETE":
                M.pop(p, None)
            else:                                 # CREATE / MODIFY
                res = await _inc_walk(client, session, p, newer_id, args, file_filter)
                if res:
                    M[p] = res[0]
                else:
                    M.pop(p, None)


async def _incremental_match_sets(client, session, args, file_filter, pairs):
    """Compute each snapshot's match set with one baseline crawl + consecutive tree
    diffs, instead of crawling every snapshot.

    Returns {snapshot_id: [entry, ...]} for every snapshot in `pairs`. The oldest
    covered snapshot is crawled in full; each later snapshot's match set is derived
    from the previous one by replaying the tree diff and re-checking only the changed
    paths with the same walk + filter -- so the result is identical to crawling each
    snapshot, but the unchanged majority of the tree is never re-walked. All pairs
    share the same root (--path is required with --incremental).
    """
    ordered = sorted(pairs, key=lambda pr: _snapshot_sort_key(pr[0]))  # oldest first
    base_snap, root = ordered[0]
    log_stderr("INFO", f"Incremental search: baseline crawl of snapshot {base_snap.get('id')} "
                       f"at {root}, then {len(ordered) - 1} consecutive diff(s)")
    base_entries = await _inc_walk(client, session, root, base_snap.get("id"), args, file_filter)
    M = {e["path"]: e for e in base_entries}
    # Each snapshot keeps its OWN copy of every entry: an unchanged file shares one
    # dict across all snapshots in M, and the emit/detail path annotates entries with
    # their snapshot in place -- copying here keeps per-snapshot annotations independent.
    out = {base_snap.get("id"): [dict(e) for e in M.values()]}
    prev = base_snap
    for snap, _root in ordered[1:]:
        await _inc_apply_diff(client, session, M, snap.get("id"), prev.get("id"),
                              root, args, file_filter)
        out[snap.get("id")] = [dict(e) for e in M.values()]
        prev = snap
    return out


async def search_snapshots(client, session, args, file_filter):
    """Search one or all snapshots. Streams path/JSON lines, or - when
    --show-details/--fields is set - collects matches and renders an aligned
    detail table (or --csv-out/--json-out/--json). Returns count.

    With --incremental, a multi-snapshot search crawls only the oldest covered
    snapshot in full and derives the rest from consecutive tree diffs (identical
    results, far fewer calls when snapshots are mostly alike)."""
    pairs = await _select_search_snapshots(client, session, args)
    if not pairs:
        log_stderr("INFO", "No snapshots to search (after age/coverage filters).")
        return 0
    multi = args.all_snapshots or bool(args.in_the_last_snapshots)
    # --in-the-last-snapshots: pairs are newest-first, so the first time a path is
    # seen it is its newest version; later (older) occurrences are suppressed.
    dedupe = bool(args.in_the_last_snapshots)
    detail = args.show_details or bool(args.fields)
    incremental = getattr(args, "incremental", False) and multi
    precomputed = None
    if incremental:
        precomputed = await _incremental_match_sets(client, session, args, file_filter, pairs)
    seen = set()
    total = 0
    records = [] if detail else None
    for snap, root in pairs:
        if args.limit and total >= args.limit:
            break
        if (multi or args.verbose) and not incremental:
            log_stderr("INFO", f"Searching snapshot {snap.get('id')} "
                               f"({(snap.get('timestamp') or '')[:19]} UTC) at {root}")
        if precomputed is not None:
            entries = precomputed.get(snap.get("id"), [])
        else:
            entries = await client.walk_tree_async(
                session, root, args.max_depth, file_filter=file_filter,
                omit_subdirs=args.omit_subdirs, omit_paths=args.omit_path,
                collect_results=True, verbose=args.verbose,
                max_entries_per_dir=args.max_entries_per_dir, snapshot_id=snap.get("id"))
        for e in entries:
            if args.limit and total >= args.limit:
                break
            if dedupe:
                key = e.get("path")
                if key in seen:
                    continue
                seen.add(key)
            if detail:
                e["snapshot"] = {"id": snap.get("id"), "name": snap.get("name"),
                                 "timestamp": snap.get("timestamp")}
                records.append(e)
            else:
                _emit_snapshot_match(e, snap, args, multi)
            total += 1
    if detail:
        specs, is_all = resolve_detail_field_specs(args.fields, dir_default=_type_is_directory(args))
        if _detail_needs_capacity(specs):
            await _attach_dir_capacity(client, session, records,
                                       concurrency=max(1, args.max_concurrent))
        emit_detail_output(records, specs, is_all, snapshot_col=multi,
                           unix_time=args.unix_time, want_json=args.json,
                           json_out=args.json_out, csv_out=args.csv_out)
        if args.csv_out:
            log_stderr("INFO", f"Wrote {total:,} result(s) to {args.csv_out}")
        elif args.json_out:
            log_stderr("INFO", f"Wrote {total:,} result(s) to {args.json_out}")
    return total


async def _ensure_restore_parent(client, session, parent, args, created):
    """Ensure parent exists live (mkdir -p), recreating dirs deleted since the
    snapshot and restoring their snapshot metadata when --preserve. Cached via
    `created`. Returns True on success.
    """
    if parent in created or parent == "/":
        return True
    missing = []
    p = parent
    while p != "/":
        if (await client.get_file_attr(session, p)) is not None:  # live
            break
        missing.append(p)
        p = _mv_parent_of(p)
    missing.reverse()
    snap = getattr(args, "snapshot", None)
    do_preserve, preserve_all = _preserve_flags(args)
    for m in missing:
        ok, ec, err = await client.create_entry(
            session, _mv_parent_of(m), _mv_basename(m), "CREATE_DIRECTORY")
        if not ok and ec != "fs_entry_exists_error":
            return False
        if do_preserve:
            await _preserve_early(client, session, m, m, preserve_all, snapshot_id=snap)
            if preserve_all:
                await _preserve_late(client, session, m, m, snapshot_id=snap)
        created.add(m)
    created.add(parent)
    return True


def _type_is_directory(args) -> bool:
    """True when --type selects directories (directory/dir/d)."""
    return getattr(args, "type", None) in ("directory", "dir", "d")


async def _collect_snapshot_subtree(client, session, dir_path, snapshot_id):
    """Recursively enumerate dir_path within the snapshot.

    Returns (files, dirs): files is a list of (path, is_symlink, size) for every file
    and symlink in the subtree; dirs is a list of every descendant directory path (not
    dir_path itself). Used to restore an entire directory to its original location,
    including files that did not match the filter and empty subdirectories.

    Enumeration is sequential (one listing per directory); a large subtree means many
    API calls. Per-directory listing errors are surfaced by walk_tree's caller; here a
    failed listing simply yields no children for that node.
    """
    files = []
    dirs = []
    stack = [dir_path]
    while stack:
        d = stack.pop()
        children = await client.enumerate_directory(session, d, snapshot_id=snapshot_id)
        for child in children:
            cpath = child.get("path", "").rstrip("/")
            if not cpath:
                continue
            ctype = child.get("type")
            if ctype == _FS_TYPE_DIR:
                dirs.append(cpath)
                stack.append(cpath)
            else:
                files.append((cpath, ctype == _FS_TYPE_SYMLINK, child.get("size")))
    return files, dirs


async def _delta_restore_file(client, session, path, good_snap, now_snap, progress=None,
                              threshold=0):
    """Patch a live file in place to its good_snap version, copying ONLY the byte
    ranges that differ (the diff of now_snap vs good_snap).

    Returns (status, message). status is:
      copied   - file patched to the snapshot version
      recreate - file no longer exists live; the caller must whole-file restore it
                 (there is nothing to diff against)
      failed   - an API call failed (message has the reason)

    Size changes are handled: the file is first resized to the good size (truncate
    or extend), every changed region within the overlap is copied from good_snap,
    and -- because the diff only covers the overlapping range -- a file that shrank
    live (good is larger) has its truncated tail [live_size, good_size) copied
    explicitly, since the diff never reports it.

    `threshold` (bytes) gates the byte-range diff: a file smaller than `threshold`
    is restored by copying its whole content in place (still mode-preserving, but
    skipping the per-file diff call, which buys nothing when the file is tiny). At
    or above the threshold the byte-range diff is used so only changed regions move.
    threshold=0 always uses the byte-range diff.
    """
    good_attr = await client.get_file_attr(session, path, snapshot_id=good_snap)
    if good_attr is None:
        return ("failed", "file not present in snapshot")
    live_attr = await client.get_file_attr(session, path)  # live version
    if live_attr is None:
        return ("recreate", None)  # deleted live -> whole-file restore by caller

    good_size = int(good_attr.get("size") or 0)
    live_size = int(live_attr.get("size") or 0)
    file_id = good_attr.get("id")

    # Small file: copy the whole content in place (no byte-range diff). The diff
    # round-trip is not worth it when there is little data to save, and copying in
    # place still preserves the file's mode (unlike a temp-file + rename restore).
    if 0 < threshold and good_size < threshold:
        if good_size != live_size:
            ok, err = await client.set_file_size(session, path, good_size)
            if not ok:
                return ("failed", f"set-size failed: {err}")
        if good_size > 0:
            ok, err = await client.copy_file_range(session, path, path, good_snap, 0, good_size)
            if not ok:
                return ("failed", f"whole copy failed: {err}")
        if progress is not None:
            progress.advance_bytes(good_size, moved=True)
        return ("copied", f"whole-in-place {good_size:,} bytes")

    regions, err = await client.get_file_byte_diff(session, now_snap, good_snap, file_id)
    if regions is None:
        return ("failed", f"byte-range diff failed: {err}")

    if good_size != live_size:
        ok, err = await client.set_file_size(session, path, good_size)
        if not ok:
            return ("failed", f"set-size failed: {err}")

    copied = 0
    for off, sz in regions:
        if off >= good_size:
            continue  # region lies entirely beyond the restored size
        length = min(sz, good_size - off)
        if length <= 0:
            continue
        ok, err = await client.copy_file_range(session, path, path, good_snap, off, length)
        if not ok:
            return ("failed", f"range copy failed at offset {off}: {err}")
        copied += length

    if good_size > live_size:
        length = good_size - live_size
        ok, err = await client.copy_file_range(session, path, path, good_snap, live_size, length)
        if not ok:
            return ("failed", f"tail copy failed: {err}")
        copied += length

    if progress is not None:
        # The bar's total is the sum of restored (good) sizes. Count the bytes we
        # actually copied as real movement (feeds the rate), then settle the
        # untouched remainder so the file's full size lands on the bar.
        moved = min(copied, good_size)
        progress.advance_bytes(moved, moved=True)
        if good_size > moved:
            progress.advance_bytes(good_size - moved, moved=False)
    return ("copied", f"delta {copied:,}/{good_size:,} bytes")


async def restore_in_place(client, session, args, file_filter) -> dict:
    """Restore matched snapshot files/symlinks to their ORIGINAL live paths.

    Recreates parent directories deleted since the snapshot, then writes each file
    via temp + atomic rename (the skip/--clobber/--rename-on-conflict strategy).

    By default directories are skipped (their files are restored individually,
    recreating only the dirs that contain files). With --include-directories or
    --type directory, each matched directory is restored as a full subtree: the
    directory and every descendant - including non-matching files and EMPTY
    subdirectories - are recreated at their original paths, and the per-file
    conflict strategy still applies to files that already exist live. Destructive
    when overwriting live data: needs confirmation/--yes.
    """
    stats = {"total_matched": 0, "planned": 0, "planned_dirs": 0, "restored": 0,
             "delta_patched": 0, "dirs_created": 0, "skipped_exists": 0,
             "skipped_directory": 0, "failed": 0, "errors": []}
    snap_id = args.snapshot

    snap = await client.get_snapshot(session, snap_id)
    if snap is None:
        log_stderr("ERROR", f"Snapshot {snap_id} not found")
        sys.exit(1)
    snap_src = await client.resolve_id_to_path(session, snap.get("source_file_id"))
    if not args.path:
        if snap_src is None:
            log_stderr("ERROR", f"Snapshot {snap_id} source no longer exists; specify --path")
            sys.exit(1)
        args.path = snap_src.rstrip("/") or "/"
    elif snap_src is not None and not _path_within(args.path, snap_src):
        log_stderr("ERROR", f"Snapshot {snap_id} (source {snap_src}) does not cover {args.path}")
        sys.exit(1)

    log_stderr("INFO", f"Scanning snapshot {snap_id} at {args.path} for matches...")
    entries = await client.walk_tree_async(
        session, args.path, args.max_depth, file_filter=file_filter,
        omit_subdirs=args.omit_subdirs, omit_paths=args.omit_path, collect_results=True,
        verbose=args.verbose, max_entries_per_dir=args.max_entries_per_dir, snapshot_id=snap_id)
    stats["total_matched"] = len(entries)

    restore_dirs = bool(args.include_directories) or _type_is_directory(args)
    matched_dirs = set()
    if restore_dirs:
        for e in entries:
            if e.get("type") == _FS_TYPE_DIR:
                p = e.get("path", "").rstrip("/")
                if p:
                    matched_dirs.add(p)

    def _under_matched(path):
        parent = _mv_parent_of(path)
        while parent != "/":
            if parent in matched_dirs:
                return True
            parent = _mv_parent_of(parent)
        return False

    file_targets = {}   # path -> is_symlink (dedup by destination path)
    dir_targets = set()  # directory paths to recreate (subtree, incl. empty dirs)
    for e in entries:
        path = e.get("path", "").rstrip("/")
        if not path:
            continue
        etype = e.get("type")
        if etype == _FS_TYPE_DIR:
            if not restore_dirs:
                stats["skipped_directory"] += 1
                continue
            if _under_matched(path):
                continue  # covered by an ancestor matched directory
            sub_files, sub_dirs = await _collect_snapshot_subtree(
                client, session, path, snap_id)
            dir_targets.add(path)
            dir_targets.update(sub_dirs)
            for fp, is_sl, sz in sub_files:
                file_targets[fp] = (is_sl, sz)
        else:
            if restore_dirs and _under_matched(path):
                continue  # restored as part of its matched ancestor directory
            file_targets[path] = (etype == _FS_TYPE_SYMLINK, e.get("size"))

    targets = sorted(file_targets.items())  # [(path, (is_symlink, size)), ...]
    stats["planned"] = len(targets)
    stats["planned_dirs"] = len(dir_targets)

    sorted_dirs = sorted(dir_targets, key=lambda d: (d.count("/"), d))

    if args.dry_run:
        verb = "delta-restore" if args.delta else "restore"
        for d in sorted_dirs:
            log_stderr("DRY RUN", f"restore dir snapshot {snap_id}:{d} -> {d}")
        for path, _ in targets:
            log_stderr("DRY RUN", f"{verb} snapshot {snap_id}:{path} -> {path}")
        if stats["skipped_directory"]:
            log_stderr("INFO", f"{stats['skipped_directory']} matched director(ies) skipped "
                               "(pass --include-directories or --type directory to restore "
                               "directory subtrees)")
        return stats
    if not targets and not dir_targets:
        log_stderr("INFO", "Nothing to restore after planning.")
        return stats

    if not args.yes:
        if not sys.stdin.isatty():
            log_stderr("ERROR", "Refusing to restore in place without confirmation in "
                                "non-interactive mode; pass --yes")
            sys.exit(1)
        mode = ("delta-patching modified files in place, recreating deleted ones" if args.delta else
                "overwriting live versions" if args.clobber else
                "renaming on conflict" if args.rename_on_conflict else
                "skipping files that still exist live")
        dir_note = f" and recreate {len(dir_targets):,} director(ies)" if dir_targets else ""
        print(f"\nAbout to restore {len(targets):,} file(s){dir_note} from snapshot {snap_id} to "
              f"their original paths ({mode}):", file=sys.stderr)
        for path, _ in targets[:5]:
            print(f"  {path}", file=sys.stderr)
        if len(targets) > 5:
            print(f"  ... and {len(targets) - 5:,} more", file=sys.stderr)
        if input("Proceed? [y]es / [N]o: ").strip().lower() not in ("y", "yes"):
            log_stderr("INFO", "Aborted by user.")
            return stats

    sem = asyncio.Semaphore(max(1, args.copy_concurrency))
    created = set()

    # Delta restore diffs each live file against the snapshot, which needs a second
    # snapshot capturing the CURRENT live state. Create a temporary one of the same
    # source subtree; if it cannot be made (no privilege, or the source is gone),
    # degrade gracefully to whole-file restore for this run.
    now_snap = None
    if args.delta:
        src_id = snap.get("source_file_id")
        now_snap, derr = await client.create_snapshot(
            session, src_id, name=f"grumpwalk-delta-{snap_id}")
        if now_snap is None:
            log_stderr("WARN", f"Could not create temporary snapshot for delta restore "
                               f"({derr}); falling back to whole-file restore")
        else:
            log_stderr("INFO", f"Created temporary snapshot {now_snap} of the live tree "
                               "to compute byte-range diffs")

    try:
        # Recreate directories first, shallow-first, so parents exist before children and
        # empty subdirectories are restored even when they contain no files.
        for d in sorted_dirs:
            existed = (await client.get_file_attr(session, d)) is not None
            if await _ensure_restore_parent(client, session, d, args, created):
                if not existed:
                    stats["dirs_created"] += 1
            else:
                stats["failed"] += 1
                _mv_record_error(stats, d, "could not recreate directory")
                log_stderr("WARN" if args.continue_on_error else "ERROR",
                           f"Failed to recreate directory {d}")

        restore_progress = None
        if args.progress and targets:
            total_bytes = sum(int(sz or 0) for _, (is_sl, sz) in targets if not is_sl)
            restore_progress = CopyProgress(len(targets), total_bytes, label="RESTORE")

        async def _run(path, is_symlink, size, idx):
            async with sem:
                parent = _mv_parent_of(path)
                if not await _ensure_restore_parent(client, session, parent, args, created):
                    return path, ("failed", f"could not recreate parent {parent}"), False
                p = {"source": path, "dest_parent": parent, "new_name": _mv_basename(path),
                     "target": path, "src_size": size}
                if is_symlink:
                    return path, await _copy_one_symlink(client, session, p, args), False
                if now_snap is not None and not is_symlink:
                    status, msg = await _delta_restore_file(
                        client, session, path, snap_id, now_snap, progress=restore_progress,
                        threshold=args.delta_threshold)
                    if status != "recreate":
                        return path, (status, msg), True
                    # File no longer exists live -> nothing to diff; whole-file restore.
                return path, await _copy_one_file(
                    client, session, p, args, idx, progress=restore_progress), False

        tasks = [asyncio.create_task(_run(path, sl, sz, i))
                 for i, (path, (sl, sz)) in enumerate(targets)]
        for fut in asyncio.as_completed(tasks):
            path, (status, msg), was_delta = await fut
            if restore_progress is not None:
                restore_progress.file_done()
            if status == "copied":
                stats["restored"] += 1
                if was_delta:
                    stats["delta_patched"] += 1
                if args.verbose:
                    log_stderr("RESTORED", f"{path}" + (f" ({msg})" if msg else ""),
                               newline_before=args.progress)
            elif status == "skipped_exists":
                stats["skipped_exists"] += 1
                log_stderr("SKIP", f"{path} exists live (use --clobber or --rename-on-conflict)",
                           newline_before=args.progress)
            else:
                stats["failed"] += 1
                _mv_record_error(stats, path, msg or "restore failed")
                log_stderr("WARN" if args.continue_on_error else "ERROR",
                           f"Failed to restore {path}: {msg}", newline_before=args.progress)
        if restore_progress is not None:
            restore_progress.finish()
    finally:
        if now_snap is not None:
            ok, derr = await client.delete_snapshot(session, now_snap)
            if not ok:
                log_stderr("WARN", f"Could not delete temporary snapshot {now_snap}: {derr} "
                                   "(remove it manually with: qq snapshot_delete --id "
                                   f"{now_snap})")
    return stats


def _revert_under_any(path, dirs):
    """True if `path` lies under any directory in `dirs` (trailing slashes ignored).
    Used to collapse subtree create/delete to their topmost root, since the tree
    diff reports a created/deleted directory but not its descendants."""
    base = path.rstrip("/")
    return any(base != d.rstrip("/") and base.startswith(d.rstrip("/") + "/") for d in dirs)


async def _delete_live_tree(client, session, dir_path, stats):
    """Recursively delete a live directory and everything under it (revert of a
    CREATEd directory). Enumerates the whole subtree, deletes files/symlinks first,
    then directories deepest-first so each is empty when removed. Returns
    (deleted_object_count, ok)."""
    files, subdirs, stack = [], [], [dir_path]
    while stack:
        d = stack.pop()
        for child in await client.enumerate_directory(session, d):
            cpath = child.get("path", "").rstrip("/")
            if not cpath:
                continue
            if child.get("type") == _FS_TYPE_DIR:
                subdirs.append(cpath)
                stack.append(cpath)
            else:
                files.append(cpath)
    ok = True
    deleted = 0
    for f in files:
        good, err = await client.delete_entry(session, f)
        if good:
            deleted += 1
        else:
            ok = False
            _mv_record_error(stats, f, f"delete failed: {err}")
    # directories deepest-first (root deleted last)
    for d in sorted(subdirs + [dir_path], key=lambda x: (-x.count("/"), -len(x))):
        good, err = await client.delete_entry(session, d)
        if good:
            deleted += 1
        else:
            ok = False
            _mv_record_error(stats, d, f"rmdir failed: {err}")
    return deleted, ok


async def _revert_recreate_file(client, session, path, is_symlink, size, args, created, stats):
    """Recreate a single deleted file/symlink at its original path from the snapshot."""
    parent = _mv_parent_of(path)
    if not await _ensure_restore_parent(client, session, parent, args, created):
        stats["failed"] += 1
        _mv_record_error(stats, path, f"could not recreate parent {parent}")
        return
    p = {"source": path, "dest_parent": parent, "new_name": _mv_basename(path),
         "target": path, "src_size": size}
    if is_symlink:
        status, msg = await _copy_one_symlink(client, session, p, args)
    else:
        status, msg = await _copy_one_file(client, session, p, args, 0)
    if status in ("copied", "renamed"):
        stats["recreated_files"] += 1
    else:
        stats["failed"] += 1
        _mv_record_error(stats, path, msg or "recreate failed")


async def _revert_recreate_standalone_file(client, session, path, snap_id, args, created, stats):
    """Recreate a deleted file whose containing directory still exists (the tree
    diff lists it directly). Reads its snapshot attrs to handle symlinks."""
    a = await client.get_file_attr(session, path, snapshot_id=snap_id)
    if a is None:
        stats["failed"] += 1
        _mv_record_error(stats, path, "not present in snapshot")
        return
    await _revert_recreate_file(
        client, session, path, a.get("type") == _FS_TYPE_SYMLINK, a.get("size"),
        args, created, stats)


async def _revert_restore_modified(client, session, path, snap_id, now_snap, args, stats):
    """Restore a modified file to its snapshot version: delta-patch (--delta) or
    whole-file overwrite."""
    if args.delta:
        status, msg = await _delta_restore_file(client, session, path, snap_id, now_snap,
                                                threshold=args.delta_threshold)
        if status == "recreate":
            # The file disappeared between the diff and now; recreate it whole-file.
            await _revert_recreate_standalone_file(client, session, path, snap_id, args, set(), stats)
            return
    else:
        parent = _mv_parent_of(path)
        p = {"source": path, "dest_parent": parent, "new_name": _mv_basename(path),
             "target": path, "src_size": None}
        status, msg = await _copy_one_file(client, session, p, args, 0)
    if status in ("copied", "renamed"):
        stats["patched"] += 1
    else:
        stats["failed"] += 1
        _mv_record_error(stats, path, msg or "restore failed")


async def revert_to_snapshot(client, session, args) -> dict:
    """Restore the directory at --path to its state in --snapshot.

    Uses the snapshot tree diff (changes-since, against a temporary snapshot of the
    live tree) to find only what changed under --path, then applies the inverse of
    each change: recreate files/dirs deleted since (repopulating deleted directories
    from the snapshot subtree) and restore modified files (delta-patched with --delta,
    else whole-file). Files/dirs CREATED since the snapshot are kept by default
    (non-destructive to new data); with --delete-new they are also removed, making the
    directory byte-identical to the snapshot (an exact rollback). Overwrites modified
    files, so it requires --yes; --dry-run previews the full plan.

    This is a whole-directory operation; content filters (--name/--type/--owner) do
    not apply. Discovery is proportional to the number of changes, not the tree size.
    """
    stats = {"diff_changes": 0, "recreated_files": 0, "recreated_dirs": 0, "patched": 0,
             "deleted_files": 0, "deleted_dirs": 0, "kept_new": 0, "failed": 0, "errors": []}
    snap_id = args.snapshot
    snap = await client.get_snapshot(session, snap_id)
    if snap is None:
        log_stderr("ERROR", f"Snapshot {snap_id} not found")
        sys.exit(1)
    path = (args.path or "").rstrip("/") or "/"
    snap_src = await client.resolve_id_to_path(session, snap.get("source_file_id"))
    if snap_src is not None and not _path_within(path, snap_src):
        log_stderr("ERROR", f"Snapshot {snap_id} (source {snap_src}) does not cover {path}")
        sys.exit(1)

    snap_attr = await client.get_file_attr(session, path, snapshot_id=snap_id)
    if snap_attr is None:
        log_stderr("ERROR", f"{path} did not exist in snapshot {snap_id}; nothing to revert to")
        sys.exit(1)
    if snap_attr.get("type") != _FS_TYPE_DIR:
        log_stderr("ERROR", f"--revert operates on a directory; {path} is a file in snapshot "
                            f"{snap_id} (use --restore-in-place --snapshot {snap_id} --path {path})")
        sys.exit(1)

    now_snap, derr = await client.create_snapshot(
        session, snap.get("source_file_id"), name=f"grumpwalk-revert-{snap_id}")
    if now_snap is None:
        log_stderr("ERROR", f"Could not create temporary snapshot for revert ({derr}); "
                            "--revert needs the snapshot-write privilege")
        sys.exit(1)

    try:
        log_stderr("INFO", f"Diffing {path} against snapshot {snap_id}...")
        entries, err = await client.get_tree_diff(session, now_snap, snap_id)
        if err:
            log_stderr("WARN", f"Tree diff may be incomplete: {err}")
        base = path.rstrip("/") + "/"
        changes = [e for e in entries
                   if e["path"].startswith(base) or e["path"].rstrip("/") == path]
        stats["diff_changes"] = len(changes)

        deleted = [e["path"] for e in changes if e["op"] == "DELETE"]
        modified = [e["path"] for e in changes if e["op"] == "MODIFY"]
        created = [e["path"] for e in changes if e["op"] == "CREATE"]
        deleted_dirs = [p for p in deleted if p.endswith("/")]
        deleted_files = [p for p in deleted if not p.endswith("/")]
        created_dirs = [p for p in created if p.endswith("/")]
        created_files = [p for p in created if not p.endswith("/")]
        modified_files = [p for p in modified if not p.endswith("/")]

        del_dir_roots = sorted([d for d in deleted_dirs if not _revert_under_any(d, deleted_dirs)],
                               key=lambda x: x.count("/"))
        cre_dir_roots = [d for d in created_dirs if not _revert_under_any(d, created_dirs)]
        standalone_del_files = [p for p in deleted_files if not _revert_under_any(p, deleted_dirs)]
        standalone_cre_files = [p for p in created_files if not _revert_under_any(p, created_dirs)]

        if not changes:
            log_stderr("INFO", f"No differences between {path} and snapshot {snap_id}; "
                               "nothing to revert.")
            return stats

        delete_new = args.delete_new
        new_count = len(standalone_cre_files) + len(cre_dir_roots)

        log_stderr("INFO", f"Revert plan for {path} -> snapshot {snap_id}:")
        log_stderr("INFO", f"  recreate: {len(del_dir_roots)} deleted dir subtree(s), "
                           f"{len(standalone_del_files)} deleted file(s)")
        log_stderr("INFO", f"  restore : {len(modified_files)} modified file(s)"
                           + (" (delta)" if args.delta else " (whole-file)"))
        if delete_new:
            log_stderr("INFO", f"  DELETE  : {len(standalone_cre_files)} created file(s), "
                               f"{len(cre_dir_roots)} created dir subtree(s) "
                               "(data added since the snapshot)")
        else:
            log_stderr("INFO", f"  keep    : {new_count} object(s) created since the snapshot "
                               "left in place (use --delete-new for an exact rollback)")

        if args.dry_run:
            for d in del_dir_roots:
                log_stderr("DRY RUN", f"recreate dir subtree {d} (from snapshot {snap_id})")
            for f in standalone_del_files:
                log_stderr("DRY RUN", f"recreate file {f}")
            for f in modified_files:
                log_stderr("DRY RUN", f"{'delta-restore' if args.delta else 'restore'} {f}")
            if delete_new:
                for f in standalone_cre_files:
                    log_stderr("DRY RUN", f"DELETE created file {f}")
                for d in cre_dir_roots:
                    log_stderr("DRY RUN", f"DELETE created dir subtree {d}")
            else:
                for f in standalone_cre_files:
                    log_stderr("DRY RUN", f"keep created file {f}")
                for d in cre_dir_roots:
                    log_stderr("DRY RUN", f"keep created dir subtree {d}")
            return stats

        if not args.yes:
            if not sys.stdin.isatty():
                log_stderr("ERROR", "Refusing to revert without confirmation in non-interactive "
                                    "mode; pass --yes")
                sys.exit(1)
            print(f"\nAbout to revert {path} to snapshot {snap_id}.", file=sys.stderr)
            if delete_new:
                print(f"  This will DELETE {len(standalone_cre_files)} file(s) and "
                      f"{len(cre_dir_roots)} director(ies) created since the snapshot,",
                      file=sys.stderr)
            print(f"  restore {len(modified_files)} modified file(s) to the snapshot version "
                  f"and recreate {len(standalone_del_files) + len(del_dir_roots)} deleted item(s).",
                  file=sys.stderr)
            if not delete_new and new_count:
                print(f"  {new_count} object(s) created since the snapshot will be KEPT "
                      "(pass --delete-new to remove them).", file=sys.stderr)
            if input("Proceed? [y]es / [N]o: ").strip().lower() not in ("y", "yes"):
                log_stderr("INFO", "Aborted by user.")
                return stats

        # Revert overwrites modified files and never renames; force those semantics.
        args.clobber = True
        args.rename_on_conflict = False
        created_set = set()
        sem = asyncio.Semaphore(max(1, args.copy_concurrency))

        # Phase 1 (sequential): recreate the directory structure of each deleted dir
        # subtree, shallow-first so parents exist before children, and collect the
        # files to restore. Directory creation is cheap relative to the file copies.
        subtree_files = []
        for root in del_dir_roots:
            sub_files, sub_dirs = await _collect_snapshot_subtree(
                client, session, root.rstrip("/"), snap_id)
            for d in sorted([root.rstrip("/")] + sub_dirs, key=lambda x: (x.count("/"), x)):
                if await _ensure_restore_parent(client, session, d, args, created_set):
                    stats["recreated_dirs"] += 1
                else:
                    stats["failed"] += 1
                    _mv_record_error(stats, d, "could not recreate directory")
            subtree_files.extend(sub_files)

        # Phase 2 (concurrent): restore every file - recreated (deleted) and modified -
        # through a bounded-concurrency pool. Stat counters/error list are mutated
        # without an intervening await, so increments are atomic under asyncio.
        async def _recreate_file(path, is_sl, size):
            async with sem:
                await _revert_recreate_file(client, session, path, is_sl, size,
                                            args, created_set, stats)

        async def _recreate_standalone(path):
            async with sem:
                await _revert_recreate_standalone_file(client, session, path, snap_id,
                                                       args, created_set, stats)

        async def _restore_modified(path):
            async with sem:
                await _revert_restore_modified(client, session, path, snap_id, now_snap,
                                               args, stats)

        await asyncio.gather(
            *[_recreate_file(p, sl, sz) for (p, sl, sz) in subtree_files],
            *[_recreate_standalone(p) for p in standalone_del_files],
            *[_restore_modified(p) for p in modified_files],
        )

        # Phase 3 (concurrent): delete objects created since the snapshot (--delete-new).
        if delete_new:
            async def _del_file(f):
                async with sem:
                    ok, err2 = await client.delete_entry(session, f.rstrip("/"))
                    if ok:
                        stats["deleted_files"] += 1
                    else:
                        stats["failed"] += 1
                        _mv_record_error(stats, f, f"delete failed: {err2}")

            async def _del_tree(root):
                async with sem:
                    _, ok = await _delete_live_tree(client, session, root.rstrip("/"), stats)
                    if ok:
                        stats["deleted_dirs"] += 1
                    else:
                        stats["failed"] += 1

            await asyncio.gather(*[_del_file(f) for f in standalone_cre_files],
                                 *[_del_tree(r) for r in cre_dir_roots])
        else:
            stats["kept_new"] = new_count
    finally:
        ok, derr = await client.delete_snapshot(session, now_snap)
        if not ok:
            log_stderr("WARN", f"Could not delete temporary snapshot {now_snap}: {derr} "
                               f"(remove it manually with: qq snapshot_delete --id {now_snap})")
    return stats


async def recurse_ace_modifications_to_tree(
    client: AsyncQumuloClient,
    session: aiohttp.ClientSession,
    target_path: str,
    remove_patterns: List[dict],
    add_patterns: List[dict],
    add_rights_patterns: List[dict],
    remove_rights_patterns: List[dict],
    replace_patterns: List[Tuple[dict, dict]] = None,
    clone_patterns: List[dict] = None,
    migrate_patterns: List[dict] = None,
    sync_cloned_aces: bool = False,
    file_filter = None,
    progress: bool = False,
    continue_on_error: bool = False,
    args = None,
    acl_concurrency: int = 100,
    dry_run: bool = False,
    verbose: bool = False
) -> dict:
    """
    Walk a directory tree and apply ACE modifications to each child's individual ACL.

    Unlike apply_acl_to_tree (which stamps one ACL onto all children), this function
    preserves each child's existing ACL and only applies the specified modifications.
    This prevents non-inherited permissions from being incorrectly propagated.

    For each child:
    1. GET the child's current ACL
    2. Apply the same modification patterns (remove, add, replace, etc.)
    3. If changes were made, PUT the modified ACL back (preserving original flags)

    The target_path itself is NOT modified (caller handles that separately).

    Args:
        client: AsyncQumuloClient instance
        session: aiohttp session
        target_path: Root path (children are processed, not this path itself)
        remove_patterns: Patterns for ACEs to remove
        add_patterns: Patterns for ACEs to add
        add_rights_patterns: Patterns for rights to add to existing ACEs
        remove_rights_patterns: Patterns for rights to remove from existing ACEs
        replace_patterns: List of (find_pattern, new_ace_pattern) tuples
        clone_patterns: Patterns for cloning ACEs between trustees
        migrate_patterns: Patterns for migrating trustees in-place
        sync_cloned_aces: If True, sync existing cloned ACEs to match source
        file_filter: Filter function for matching objects
        progress: Show progress output
        continue_on_error: Continue on errors without prompting
        args: Command line arguments
        acl_concurrency: Number of concurrent operations (default 100)
        dry_run: Report changes without applying them
        verbose: Show detailed logging

    Returns:
        Statistics dict with objects_changed, objects_unchanged, objects_failed,
        objects_skipped, total_objects_processed, errors
    """
    stats = {
        'objects_changed': 0,
        'objects_unchanged': 0,
        'objects_failed': 0,
        'objects_skipped': 0,
        'total_objects_processed': 0,
        'errors': []
    }

    start_time = time.time()

    walk_progress = ProgressTracker(verbose=False, limit=args.limit if args else None)

    entry_queue = asyncio.Queue(maxsize=10000)

    producer_done = asyncio.Event()
    abort_requested = asyncio.Event()
    limit_reached = asyncio.Event()
    entries_queued = [0]

    async def modify_single_file(path: str):
        """GET ACL, apply modifications, PUT if changed."""
        # GET current ACL
        current_acl = await client.get_file_acl(session, path)
        if current_acl is None:
            return (False, "Failed to get ACL", False)

        # Apply the same modifications to this child's ACL
        modified_acl, mod_stats = apply_ace_modifications(
            current_acl,
            remove_patterns, add_patterns,
            add_rights_patterns, remove_rights_patterns,
            replace_aces=replace_patterns,
            clone_patterns=clone_patterns,
            migrate_patterns=migrate_patterns,
            sync_cloned_aces=sync_cloned_aces,
            verbose=verbose
        )

        # Check if anything changed (including inheritance break which modifies
        # control flags even if no individual ACEs were added/removed)
        total_changes = (
            mod_stats['removed'] + mod_stats['added'] +
            mod_stats['modified'] + mod_stats['replaced'] +
            mod_stats['cloned'] + mod_stats['synced'] +
            mod_stats['migrated']
        )
        if total_changes == 0 and not mod_stats.get('inheritance_broken'):
            return (True, None, False)

        if dry_run:
            return (True, None, True)

        # Normalize and PUT back, preserving original inheritance flags
        normalized = normalize_acl_for_put(modified_acl)
        success, error = await client.set_file_acl(
            session, path, normalized, mark_inherited=False
        )
        return (success, error, True)

    async def queue_entry(entry):
        """Callback to add matching entries to the processing queue."""
        if abort_requested.is_set() or limit_reached.is_set():
            return
        # Skip target path (already handled by caller)
        if entry.get('path') == target_path:
            return
        if args and args.limit and entries_queued[0] >= args.limit:
            limit_reached.set()
            return
        await entry_queue.put(entry)
        entries_queued[0] += 1

    async def producer():
        """Walk tree and stream matching entries to queue."""
        try:
            await client.walk_tree_async(
                session=session,
                path=target_path,
                max_depth=args.max_depth if args else None,
                progress=walk_progress,
                file_filter=file_filter,
                collect_results=False,
                output_callback=queue_entry,
            )
        except Exception as e:
            if progress:
                log_stderr("ERROR", f"Tree walk failed: {e}", newline_before=True)
        finally:
            producer_done.set()

    async def consumer():
        """Process entries from queue, applying ACE modifications in batches."""
        batch_size = acl_concurrency
        batch = []
        processed = 0

        while True:
            if abort_requested.is_set():
                break

            try:
                entry = await asyncio.wait_for(entry_queue.get(), timeout=0.1)
                batch.append(entry)
                while len(batch) < batch_size:
                    try:
                        entry = entry_queue.get_nowait()
                        batch.append(entry)
                    except asyncio.QueueEmpty:
                        break
            except asyncio.TimeoutError:
                if producer_done.is_set() and entry_queue.empty():
                    break
                if not batch:
                    continue

            if batch:
                tasks = []
                paths = []
                for entry in batch:
                    path = entry['path']
                    paths.append(path)
                    tasks.append(modify_single_file(path))

                results = await asyncio.gather(*tasks, return_exceptions=True)

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
                            log_stderr("ERROR", f"Failed to modify ACL on: {path}", newline_before=True)
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
                        success, error_msg, had_changes = result
                        if success:
                            if had_changes:
                                stats['objects_changed'] += 1
                            else:
                                stats['objects_unchanged'] += 1
                        else:
                            stats['objects_failed'] += 1
                            stats['errors'].append({
                                'path': path,
                                'error_code': 'MODIFY_FAILURE',
                                'message': error_msg
                            })
                            if continue_on_error:
                                if progress:
                                    log_stderr("WARN", f"Error on {path}: {error_msg}, continuing...", newline_before=True)
                            else:
                                log_stderr("ERROR", f"Failed to modify ACL on: {path}", newline_before=True)
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

                if progress:
                    elapsed = time.time() - start_time
                    rate = processed / elapsed if elapsed > 0 else 0
                    queue_size = entry_queue.qsize()
                    progress_label = "DRY RUN" if dry_run else "ACE MODIFY"
                    changed_label = "Would change" if dry_run else "Changed"
                    print(
                        f"\r[{progress_label}] {changed_label}: {stats['objects_changed']:,} | "
                        f"Unchanged: {stats['objects_unchanged']:,} | "
                        f"Failed: {stats['objects_failed']:,} | "
                        f"Queue: {queue_size:,} | "
                        f"Rate: {rate:.0f}/s",
                        end='',
                        file=sys.stderr
                    )
                    sys.stderr.flush()

                batch = []

    await asyncio.gather(producer(), consumer())

    stats['objects_skipped'] = walk_progress.total_objects - walk_progress.matches

    if progress:
        print()  # New line after progress
        elapsed = time.time() - start_time
        complete_label = "DRY RUN" if dry_run else "ACE MODIFY"
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
        if args.add_tag:
            banner_line(f"Mode:             Object Tagging ({args.key}={args.value})")
            banner_line(f"Tag concurrency:  {args.tag_concurrency}")
        elif args.find_tag:
            crit = []
            if args.key is not None:
                crit.append(f"key={args.key}")
            if args.value is not None:
                crit.append(f"value={args.value}")
            banner_line(f"Mode:             Tag Search ({', '.join(crit) if crit else 'any tagged'})")
            banner_line(f"Tag concurrency:  {args.tag_concurrency}")
        elif args.remove_tag:
            removal_desc = f"key={args.key}"
            if args.value is not None:
                removal_desc += f", value={args.value}"
            banner_line(f"Mode:             Tag Removal ({removal_desc})")
            banner_line(f"Tag concurrency:  {args.tag_concurrency}")

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
        update_atime=args.update_atime,
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

        # Probe cluster version to decide whether to suppress atime updates
        await client.detect_capabilities(session)

    # Single, actionable notice: the user asked to update atime but the cluster
    # is too old to honor the request. Otherwise stay silent (default behavior).
    if args.update_atime and not client.supports_skip_atime:
        log_stderr("WARN", "--update-atime has no effect: this cluster does not support "
                           "skip-atime-update (requires Qumulo Core 7.9.0+); reads use "
                           "the cluster's default atime behavior")

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

    # --new-owner / --new-group require --set-mode
    if (args.new_owner or args.new_group) and not args.set_mode:
        log_stderr("ERROR", "--new-owner and --new-group require --set-mode")
        sys.exit(1)

    # --set-mode validation
    if args.set_mode:
        if not args.path:
            log_stderr("ERROR", "--set-mode requires --path")
            sys.exit(1)
        if args.source_acl or args.source_acl_file:
            log_stderr("ERROR", "--set-mode cannot be combined with --source-acl or --source-acl-file")
            sys.exit(1)
        if args.owner_group_only:
            log_stderr("ERROR", "--set-mode cannot be combined with --owner-group-only")
            sys.exit(1)
        # Validate octal format
        try:
            mode_to_acl(args.set_mode)
        except ValueError as e:
            log_stderr("ERROR", str(e))
            sys.exit(1)

    # --disable-inheritance validation
    if args.disable_inheritance:
        if not args.path:
            log_stderr("ERROR", "--disable-inheritance requires --path")
            sys.exit(1)
        if args.set_mode:
            log_stderr("ERROR", "--disable-inheritance cannot be combined with --set-mode")
            sys.exit(1)
        if args.source_acl or args.source_acl_file:
            log_stderr("ERROR", "--disable-inheritance cannot be combined with --source-acl or --source-acl-file")
            sys.exit(1)
    if args.remove_inherited and not args.disable_inheritance:
        log_stderr("ERROR", "--remove-inherited requires --disable-inheritance")
        sys.exit(1)

    # POSIX Mode Setting
    if args.set_mode:
        import copy as _copy

        # Resolve --new-owner / --new-group if provided
        resolved_owner_auth_id = None
        resolved_group_auth_id = None

        if args.new_owner or args.new_group:
            async with client.create_session() as resolve_session:
                if args.new_owner:
                    trustee_spec = parse_trustee(args.new_owner)
                    payload = trustee_spec['payload']
                    id_type = trustee_spec['type']
                    identifier = payload.get(id_type) if id_type in ('uid', 'gid', 'sid', 'auth_id') else payload.get('name')
                    result = await client.resolve_identity(resolve_session, identifier, id_type)
                    if result and result.get('auth_id'):
                        resolved_owner_auth_id = str(result['auth_id'])
                        if args.verbose:
                            log_stderr("INFO", f"Resolved owner '{args.new_owner}' -> auth_id {resolved_owner_auth_id}")
                    else:
                        log_stderr("ERROR", f"Could not resolve owner '{args.new_owner}'")
                        sys.exit(1)

                if args.new_group:
                    trustee_spec = parse_trustee(args.new_group)
                    payload = trustee_spec['payload']
                    id_type = trustee_spec['type']
                    identifier = payload.get(id_type) if id_type in ('uid', 'gid', 'sid', 'auth_id') else payload.get('name')
                    result = await client.resolve_identity(resolve_session, identifier, id_type)
                    if result and result.get('auth_id'):
                        resolved_group_auth_id = str(result['auth_id'])
                        if args.verbose:
                            log_stderr("INFO", f"Resolved group '{args.new_group}' -> auth_id {resolved_group_auth_id}")
                    else:
                        log_stderr("ERROR", f"Could not resolve group '{args.new_group}'")
                        sys.exit(1)

        acl_data, has_setgid = mode_to_acl(args.set_mode, resolved_owner_auth_id, resolved_group_auth_id)

        # Build a version without SET_GID for files when propagating with setgid
        acl_data_no_setgid = None
        if has_setgid:
            acl_data_no_setgid = _copy.deepcopy(acl_data)
            acl_data_no_setgid['posix_special_permissions'] = [
                p for p in acl_data_no_setgid['posix_special_permissions'] if p != 'SET_GID'
            ]

        file_filter = create_file_filter(args, None)

        if args.progress or args.verbose:
            log_stderr("INFO", f"Setting POSIX mode {args.set_mode} on {args.path}")

        async with client.create_session() as session:
            if args.dry_run:
                log_stderr("DRY RUN", f"Would set mode {args.set_mode} on: {args.path}")
                if args.propagate_acls:
                    log_stderr("DRY RUN", "Would propagate to all matching children")
                if has_setgid:
                    log_stderr("DRY RUN", "SET_GID would be applied to directories only")
                return

            # Apply to target path (skip if it doesn't match the filter)
            attr = await client.get_file_attr(session, args.path)
            target_entry = attr if attr else {}
            skip_target = file_filter and not file_filter(target_entry)

            if not skip_target:
                # Use no-setgid variant for non-directories
                target_acl = acl_data
                if has_setgid and target_entry.get('type') != 'FS_FILE_TYPE_DIRECTORY':
                    target_acl = acl_data_no_setgid

                success, error_msg = await client.set_file_acl(
                    session, args.path, target_acl, mark_inherited=False
                )
                if not success:
                    log_stderr("ERROR", f"Failed to set mode on {args.path}: {error_msg}")
                    sys.exit(1)

                # Change owner/group if requested
                if resolved_owner_auth_id or resolved_group_auth_id:
                    ok, err = await client.set_file_owner_group(
                        session, args.path,
                        owner=resolved_owner_auth_id,
                        group=resolved_group_auth_id,
                    )
                    if not ok:
                        log_stderr("ERROR", f"Failed to set owner/group on {args.path}: {err}")
                        sys.exit(1)

                if args.progress or args.verbose:
                    log_stderr("SET-MODE", f"Applied mode {args.set_mode} to {args.path}")
            else:
                if args.verbose:
                    log_stderr("INFO", f"Skipped target path (does not match filter): {args.path}")

            # Propagate to children if requested
            if args.propagate_acls:
                acl_concurrency = args.acl_concurrency if hasattr(args, 'acl_concurrency') else 100

                progress_tracker = ProgressTracker(verbose=True) if args.progress else None

                # Producer-consumer queue for concurrent ACL operations
                acl_queue = asyncio.Queue(maxsize=10_000)
                stats = {'changed': 0, 'failed': 0, 'skipped': 0}
                stats_lock = asyncio.Lock()

                async def acl_worker():
                    while True:
                        item = await acl_queue.get()
                        try:
                            child_path, child_type = item
                            # Choose ACL variant: directories get setgid, files don't
                            if has_setgid and child_type != 'FS_FILE_TYPE_DIRECTORY':
                                child_acl = acl_data_no_setgid
                            else:
                                child_acl = acl_data

                            ok, err = await client.set_file_acl(
                                session, child_path, child_acl, mark_inherited=True
                            )
                            if ok and (resolved_owner_auth_id or resolved_group_auth_id):
                                ok, err = await client.set_file_owner_group(
                                    session, child_path,
                                    owner=resolved_owner_auth_id,
                                    group=resolved_group_auth_id,
                                )
                            async with stats_lock:
                                if ok:
                                    stats['changed'] += 1
                                else:
                                    stats['failed'] += 1
                                    if args.verbose:
                                        log_stderr("ERROR", f"Failed: {child_path}: {err}")
                        except Exception as e:
                            async with stats_lock:
                                stats['failed'] += 1
                            if args.verbose:
                                log_stderr("ERROR", f"Error: {child_path}: {e}")
                        finally:
                            acl_queue.task_done()

                workers = [asyncio.create_task(acl_worker()) for _ in range(acl_concurrency)]

                async def output_callback(entry):
                    child_path = entry.get('path')
                    child_type = entry.get('type')
                    await acl_queue.put((child_path, child_type))

                # Walk tree from target path
                await client.walk_tree_async(
                    session,
                    args.path,
                    max_depth=args.max_depth,
                    progress=progress_tracker,
                    file_filter=file_filter,
                    collect_results=False,
                    verbose=args.verbose,
                    output_callback=output_callback,
                )

                await acl_queue.join()

                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

                if progress_tracker:
                    progress_tracker.final_report()

                log_stderr("INFO",
                    f"Set-mode propagation complete: {stats['changed']:,} changed, "
                    f"{stats['failed']:,} failed",
                    newline_before=True)

        return

    # Disable Inheritance Mode
    if args.disable_inheritance:
        mode_label = "remove" if args.remove_inherited else "convert"
        icacls_equiv = "/inheritance:r" if args.remove_inherited else "/inheritance:d"

        file_filter = create_file_filter(args, None)

        if args.progress or args.verbose:
            log_stderr("INFO",
                f"Disabling inheritance on {args.path} "
                f"(mode: {mode_label}, equivalent to icacls {icacls_equiv})")

        async with client.create_session() as session:
            # Get current ACL for the target path
            current_acl = await client.get_file_acl(session, args.path)
            if not current_acl:
                log_stderr("ERROR", f"Could not read ACL for {args.path}")
                sys.exit(1)

            # Handle nested structure for counting
            if 'acl' in current_acl and 'aces' not in current_acl:
                current_aces = current_acl['acl'].get('aces', [])
            else:
                current_aces = current_acl.get('aces', [])

            inherited_count = sum(
                1 for ace in current_aces
                if 'INHERITED' in ace.get('flags', [])
            )
            explicit_count = len(current_aces) - inherited_count

            if args.verbose:
                log_stderr("INFO",
                    f"Current ACL has {len(current_aces)} ACEs "
                    f"({inherited_count} inherited, {explicit_count} explicit)")

            if inherited_count == 0:
                log_stderr("INFO", f"No inherited ACEs found on {args.path} - nothing to do")
                if not args.propagate_acls:
                    return

            if args.remove_inherited and inherited_count > 0 and explicit_count == 0:
                log_stderr("WARNING",
                    f"All {inherited_count} ACEs on {args.path} are inherited. "
                    "Removing them will leave the object with NO access control entries.")

            if args.dry_run:
                if inherited_count > 0:
                    if args.remove_inherited:
                        log_stderr("DRY RUN",
                            f"Would remove {inherited_count} inherited ACEs from {args.path} "
                            f"({explicit_count} explicit ACEs would remain)")
                    else:
                        log_stderr("DRY RUN",
                            f"Would convert {inherited_count} inherited ACEs to explicit on {args.path}")
                if args.propagate_acls:
                    log_stderr("DRY RUN", "Would apply to all matching children recursively")
                return

            # Apply to target path
            if inherited_count > 0:
                if args.remove_inherited:
                    modified_acl, removed = strip_inherited_aces(current_acl)
                    action_msg = f"Removed {removed} inherited ACEs from"
                else:
                    modified_acl = break_acl_inheritance(current_acl)
                    action_msg = f"Converted {inherited_count} inherited ACEs to explicit on"

                normalized = normalize_acl_for_put(modified_acl)
                success, error_msg = await client.set_file_acl(
                    session, args.path, normalized, mark_inherited=False
                )
                if not success:
                    log_stderr("ERROR", f"Failed to set ACL on {args.path}: {error_msg}")
                    sys.exit(1)

                if args.progress or args.verbose:
                    log_stderr("INHERITANCE", f"{action_msg} {args.path}")
            else:
                if args.verbose:
                    log_stderr("INFO", f"Skipped {args.path} (no inherited ACEs)")

            # Propagate to children if requested
            if args.propagate_acls:
                acl_concurrency = args.acl_concurrency if hasattr(args, 'acl_concurrency') else 100

                progress_tracker = ProgressTracker(verbose=True) if args.progress else None

                acl_queue = asyncio.Queue(maxsize=10_000)
                stats = {'changed': 0, 'skipped': 0, 'failed': 0, 'warnings': 0}
                stats_lock = asyncio.Lock()

                async def inheritance_worker():
                    while True:
                        item = await acl_queue.get()
                        try:
                            child_path = item
                            child_acl = await client.get_file_acl(session, child_path)
                            if not child_acl:
                                async with stats_lock:
                                    stats['failed'] += 1
                                if args.verbose:
                                    log_stderr("ERROR", f"Could not read ACL: {child_path}")
                                continue

                            # Count inherited ACEs on this child
                            if 'acl' in child_acl and 'aces' not in child_acl:
                                child_aces = child_acl['acl'].get('aces', [])
                            else:
                                child_aces = child_acl.get('aces', [])

                            child_inherited = sum(
                                1 for ace in child_aces
                                if 'INHERITED' in ace.get('flags', [])
                            )

                            if child_inherited == 0:
                                async with stats_lock:
                                    stats['skipped'] += 1
                                continue

                            child_explicit = len(child_aces) - child_inherited
                            if args.remove_inherited and child_explicit == 0:
                                async with stats_lock:
                                    stats['warnings'] += 1
                                if args.verbose:
                                    log_stderr("WARNING",
                                        f"All ACEs inherited, removing leaves no ACEs: {child_path}")

                            if args.remove_inherited:
                                child_modified, _ = strip_inherited_aces(child_acl)
                            else:
                                child_modified = break_acl_inheritance(child_acl)

                            normalized = normalize_acl_for_put(child_modified)
                            ok, err = await client.set_file_acl(
                                session, child_path, normalized, mark_inherited=False
                            )
                            async with stats_lock:
                                if ok:
                                    stats['changed'] += 1
                                else:
                                    stats['failed'] += 1
                                    if args.verbose:
                                        log_stderr("ERROR", f"Failed: {child_path}: {err}")
                                    if not args.continue_on_error:
                                        log_stderr("ERROR",
                                            f"Stopping on error. Use --continue-on-error to skip failures.")
                                        raise SystemExit(1)
                        except SystemExit:
                            raise
                        except Exception as e:
                            async with stats_lock:
                                stats['failed'] += 1
                            if args.verbose:
                                log_stderr("ERROR", f"Error: {child_path}: {e}")
                        finally:
                            acl_queue.task_done()

                workers = [asyncio.create_task(inheritance_worker()) for _ in range(acl_concurrency)]

                async def output_callback(entry):
                    child_path = entry.get('path')
                    await acl_queue.put(child_path)

                await client.walk_tree_async(
                    session,
                    args.path,
                    max_depth=args.max_depth,
                    progress=progress_tracker,
                    file_filter=file_filter,
                    collect_results=False,
                    verbose=args.verbose,
                    output_callback=output_callback,
                )

                await acl_queue.join()

                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

                if progress_tracker:
                    progress_tracker.final_report()

                summary_parts = [f"{stats['changed']:,} changed"]
                if stats['skipped']:
                    summary_parts.append(f"{stats['skipped']:,} skipped (no inherited ACEs)")
                if stats['failed']:
                    summary_parts.append(f"{stats['failed']:,} failed")
                if stats['warnings']:
                    summary_parts.append(f"{stats['warnings']:,} warnings (all ACEs were inherited)")

                log_stderr("INFO",
                    f"Inheritance propagation complete: {', '.join(summary_parts)}",
                    newline_before=True)

        return

    # SNAPSHOT: list snapshots
    if args.list_snapshots:
        async with client.create_session() as session:
            await list_snapshots_mode(client, session, args)
        return

    # SNAPSHOT SEARCH: --snapshot ID (alone) or --all-snapshots, search-only
    if args.all_snapshots or args.in_the_last_snapshots or \
            (args.snapshot is not None and
             not (args.copy_to or args.restore_in_place or args.revert)):
        async with client.create_session() as session:
            owner_auth_ids = None
            if args.owners:
                print("\nResolving owner identities...", file=sys.stderr)
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)
            file_filter = create_file_filter(args, owner_auth_ids)
            count = await search_snapshots(client, session, args, file_filter)
            log_stderr("INFO", f"{count:,} match(es) found")
        return

    # SNAPSHOT REVERT: revert a directory to its exact state in a snapshot
    if args.revert:
        async with client.create_session() as session:
            stats = await revert_to_snapshot(client, session, args)
            dry = " (DRY RUN)" if args.dry_run else ""
            print(f"\nSNAPSHOT REVERT SUMMARY{dry}", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Snapshot:              {args.snapshot}", file=sys.stderr)
            print(f"Path:                  {args.path}", file=sys.stderr)
            print(f"Changes in diff:       {stats['diff_changes']:,}", file=sys.stderr)
            if not args.dry_run:
                print(f"Files recreated:       {stats['recreated_files']:,}", file=sys.stderr)
                print(f"Directories recreated: {stats['recreated_dirs']:,}", file=sys.stderr)
                print(f"Files restored:        {stats['patched']:,}", file=sys.stderr)
                if args.delete_new:
                    print(f"Files deleted:         {stats['deleted_files']:,}", file=sys.stderr)
                    print(f"Dir subtrees deleted:  {stats['deleted_dirs']:,}", file=sys.stderr)
                else:
                    print(f"New objects kept:      {stats['kept_new']:,} "
                          "(use --delete-new for an exact rollback)", file=sys.stderr)
                print(f"Failed:                {stats['failed']:,}", file=sys.stderr)
            if stats["errors"]:
                print("\nErrors encountered:", file=sys.stderr)
                for error in stats["errors"][:10]:
                    print(f"  {error['path']}: {error['message']}", file=sys.stderr)
            save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
            if stats["failed"] > 0:
                sys.exit(1)
        return

    # SNAPSHOT RESTORE IN PLACE: restore matched snapshot files to original paths
    if args.restore_in_place:
        async with client.create_session() as session:
            owner_auth_ids = None
            if args.owners:
                print("\nResolving owner identities...", file=sys.stderr)
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)
            file_filter = create_file_filter(args, owner_auth_ids)
            stats = await restore_in_place(client, session, args, file_filter)
            dry = " (DRY RUN)" if args.dry_run else ""
            print(f"\nSNAPSHOT RESTORE SUMMARY{dry}", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Snapshot:          {args.snapshot}", file=sys.stderr)
            print(f"Path:              {args.path}", file=sys.stderr)
            print(f"Matched:           {stats['total_matched']:,}", file=sys.stderr)
            label = "Would restore:" if args.dry_run else "Restored:"
            print(f"{label:<19}{(stats['planned'] if args.dry_run else stats['restored']):,}", file=sys.stderr)
            if not args.dry_run and stats.get("delta_patched"):
                print(f"  Delta-patched in place: {stats['delta_patched']:,} "
                      "(only changed byte ranges copied)", file=sys.stderr)
            if stats["planned_dirs"]:
                dlabel = "  Directories (would recreate):" if args.dry_run else "  Directories recreated:"
                dcount = stats["planned_dirs"] if args.dry_run else stats["dirs_created"]
                print(f"{dlabel} {dcount:,}", file=sys.stderr)
            if stats["skipped_directory"]:
                print(f"  Directories skipped (files restored individually): {stats['skipped_directory']:,}", file=sys.stderr)
            if stats["skipped_exists"]:
                print(f"  Skipped (exists live): {stats['skipped_exists']:,}", file=sys.stderr)
            if not args.dry_run:
                print(f"Failed:            {stats['failed']:,}", file=sys.stderr)
            if stats["errors"]:
                print("\nErrors encountered:", file=sys.stderr)
                for error in stats["errors"][:10]:
                    print(f"  {error['path']}: {error['message']}", file=sys.stderr)
            save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
            if stats["failed"] > 0:
                sys.exit(1)
        return

    # COPY MODE: server-side copy matching objects (POSIX cp style)
    if args.copy_to:
        async with client.create_session() as session:
            owner_auth_ids = None
            if args.owners:
                print("\nResolving owner identities...", file=sys.stderr)
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)
                if owner_auth_ids:
                    print(f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr)

            file_filter = create_file_filter(args, owner_auth_ids)
            stats = await copy_objects(client, session, args, file_filter)

            dry_label = " (DRY RUN)" if args.dry_run else ""
            print(f"\nCOPY SUMMARY{dry_label}", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Path:              {args.path}", file=sys.stderr)
            print(f"Destination:       {args.copy_to}", file=sys.stderr)
            if args.rename_to:
                print(f"Rename pattern:    {args.rename_to}", file=sys.stderr)
            if args.preserve_all:
                print(f"Preserve:          all attributes (owner, group, ACL/mode, "
                      f"DOS attrs, tags, timestamps)", file=sys.stderr)
            elif args.preserve_permissions:
                print(f"Preserve:          owner, group, ACL/mode", file=sys.stderr)
            print(f"Matched:           {stats['total_matched']:,}", file=sys.stderr)
            copied_label = "Would copy:" if args.dry_run else "Copied:"
            copied_count = stats["planned"] if args.dry_run else stats["copied"]
            print(f"{copied_label:<19}{copied_count:,}", file=sys.stderr)
            if stats["copied_in_tree"]:
                print(f"  (+{stats['copied_in_tree']:,} objects inside copied directories)", file=sys.stderr)

            copy_skip_lines = [
                ("skipped_directory", "Directories skipped (use --include-directories)"),
                ("skipped_inside_copied_dir", "Travel with a copied directory"),
                ("skipped_rename_no_match", "Rename pattern did not match"),
                ("skipped_rename_invalid", "Rename produced an invalid name"),
                ("skipped_noop", "Source and target identical"),
                ("skipped_into_self", "Cannot copy a directory into itself"),
                ("skipped_target_collision", "Multiple sources to one target"),
                ("skipped_unchanged", "Unchanged (size + mtime match)"),
                ("skipped_exists", "Target exists (use --clobber)"),
            ]
            for key, label in copy_skip_lines:
                if stats[key]:
                    print(f"  {label}: {stats[key]:,}", file=sys.stderr)
            if not args.dry_run:
                print(f"Failed:            {stats['failed'] + stats['tree_failed']:,}", file=sys.stderr)

            if stats["errors"]:
                print("\nErrors encountered:", file=sys.stderr)
                for error in stats["errors"][:10]:
                    print(f"  {error['path']}: {error['message']}", file=sys.stderr)
                if len(stats["errors"]) > 10:
                    print(f"  ... and {len(stats['errors']) - 10} more", file=sys.stderr)

            save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
            if stats["failed"] + stats["tree_failed"] > 0:
                sys.exit(1)
        return

    # MOVE / RENAME MODE: move and/or rename matching objects (POSIX mv style)
    if args.move_to or args.rename_to:
        async with client.create_session() as session:
            owner_auth_ids = None
            if args.owners:
                print("\nResolving owner identities...", file=sys.stderr)
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)
                if owner_auth_ids:
                    print(f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr)

            file_filter = create_file_filter(args, owner_auth_ids)
            stats = await move_rename_objects(client, session, args, file_filter)

            dry_label = " (DRY RUN)" if args.dry_run else ""
            print(f"\nMOVE / RENAME SUMMARY{dry_label}", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Path:              {args.path}", file=sys.stderr)
            if args.move_to:
                print(f"Destination:       {args.move_to}", file=sys.stderr)
            if args.rename_to:
                print(f"Rename pattern:    {args.rename_to}", file=sys.stderr)
            print(f"Matched:           {stats['total_matched']:,}", file=sys.stderr)
            moved_label = "Would move:" if args.dry_run else "Moved:"
            moved_count = stats["planned"] if args.dry_run else stats["moved"]
            print(f"{moved_label:<19}{moved_count:,}", file=sys.stderr)

            skip_lines = [
                ("skipped_directory", "Directories skipped (use --include-directories)"),
                ("skipped_inside_moved_dir", "Travel with a moved directory"),
                ("skipped_rename_no_match", "Rename pattern did not match"),
                ("skipped_rename_invalid", "Rename produced an invalid name"),
                ("skipped_noop", "Already at target (no change)"),
                ("skipped_into_self", "Cannot move a directory into itself"),
                ("skipped_target_collision", "Multiple sources to one target"),
                ("skipped_exists", "Target exists (use --clobber)"),
            ]
            for key, label in skip_lines:
                if stats[key]:
                    print(f"  {label}: {stats[key]:,}", file=sys.stderr)
            if not args.dry_run:
                print(f"Failed:            {stats['failed']:,}", file=sys.stderr)

            if stats["errors"]:
                print("\nErrors encountered:", file=sys.stderr)
                for error in stats["errors"][:10]:
                    print(f"  {error['path']}: {error['message']}", file=sys.stderr)
                if len(stats["errors"]) > 10:
                    print(f"  ... and {len(stats['errors']) - 10} more", file=sys.stderr)

            save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
            if stats["failed"] > 0:
                sys.exit(1)
        return

    # ACL Cloning Mode
    # OBJECT TAGGING MODE: add a GENERIC user-metadata tag to matching objects
    if args.add_tag:
        async with client.create_session() as session:
            owner_auth_ids = None
            if args.owners:
                print("\nResolving owner identities...", file=sys.stderr)
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)
                if owner_auth_ids:
                    print(f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr)

            file_filter = create_file_filter(args, owner_auth_ids)

            stats = await apply_tags_to_tree(
                client=client,
                session=session,
                key=args.key,
                value=args.value,
                root_path=args.path,
                file_filter=file_filter,
                overwrite=args.overwrite,
                progress=args.progress,
                continue_on_error=args.continue_on_error,
                args=args,
                tag_concurrency=args.tag_concurrency,
                dry_run=args.dry_run,
            )

            dry_label = " (DRY RUN)" if args.dry_run else ""
            print(f"\nOBJECT TAGGING SUMMARY{dry_label}", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Path:              {args.path}", file=sys.stderr)
            print(f"Tag:               {args.key}={args.value}", file=sys.stderr)
            if args.overwrite:
                print(f"Overwrite:         Enabled", file=sys.stderr)
            tagged_label = "Would tag:" if args.dry_run else "Objects tagged:"
            print(f"{tagged_label:<19}{stats['objects_tagged']:,}", file=sys.stderr)
            print(f"Already set:       {stats['objects_unchanged']:,}", file=sys.stderr)
            if stats['objects_conflict']:
                print(
                    f"Conflicts skipped: {stats['objects_conflict']:,} "
                    f"(key exists with different value; use --overwrite)",
                    file=sys.stderr,
                )
            print(f"Objects failed:    {stats['objects_failed']:,}", file=sys.stderr)
            if file_filter:
                print(f"Objects skipped:   {stats['objects_skipped']:,} (filter mismatch)", file=sys.stderr)

            if stats['errors']:
                print("\nErrors encountered:", file=sys.stderr)
                for error in stats['errors'][:10]:
                    print(f"  {error['path']}: {error['message']}", file=sys.stderr)
                if len(stats['errors']) > 10:
                    print(f"  ... and {len(stats['errors']) - 10} more", file=sys.stderr)

            save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)

            if stats['objects_failed'] > 0:
                sys.exit(1)

        return  # Exit after tagging operation

    # OBJECT TAG SEARCH MODE: find objects whose tags match --key/--value
    if args.find_tag:
        async with client.create_session() as session:
            owner_auth_ids = None
            if args.owners:
                print("\nResolving owner identities...", file=sys.stderr)
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)
                if owner_auth_ids:
                    print(f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr)

            file_filter = create_file_filter(args, owner_auth_ids)

            stats = await find_tagged_objects(
                client=client,
                session=session,
                root_path=args.path,
                file_filter=file_filter,
                key=args.key,
                value=args.value,
                progress=args.progress,
                args=args,
                tag_concurrency=args.tag_concurrency,
            )

            criteria = []
            if args.key is not None:
                criteria.append(f"key={args.key}")
            if args.value is not None:
                criteria.append(f"value={args.value}")
            print("\nTAG SEARCH SUMMARY", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Path:              {args.path}", file=sys.stderr)
            print(f"Criteria:          {', '.join(criteria) if criteria else 'any tagged object'}", file=sys.stderr)
            print(f"Matches:           {stats['matches']:,}", file=sys.stderr)
            print(f"Objects failed:    {stats['objects_failed']:,}", file=sys.stderr)
            if file_filter:
                print(f"Objects skipped:   {stats['objects_skipped']:,} (filter mismatch)", file=sys.stderr)

            if stats['errors']:
                print("\nErrors encountered:", file=sys.stderr)
                for error in stats['errors'][:10]:
                    print(f"  {error['path']}: {error['message']}", file=sys.stderr)
                if len(stats['errors']) > 10:
                    print(f"  ... and {len(stats['errors']) - 10} more", file=sys.stderr)

            save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)

            if stats['objects_failed'] > 0:
                sys.exit(1)

        return  # Exit after tag search

    # OBJECT TAG REMOVAL MODE: remove tag --key from matching objects
    if args.remove_tag:
        async with client.create_session() as session:
            owner_auth_ids = None
            if args.owners:
                print("\nResolving owner identities...", file=sys.stderr)
                owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)
                if owner_auth_ids:
                    print(f"Filtering by {len(owner_auth_ids)} owner auth_id(s)", file=sys.stderr)

            file_filter = create_file_filter(args, owner_auth_ids)

            stats = await remove_tags_from_tree(
                client=client,
                session=session,
                key=args.key,
                root_path=args.path,
                file_filter=file_filter,
                value=args.value,
                progress=args.progress,
                continue_on_error=args.continue_on_error,
                args=args,
                tag_concurrency=args.tag_concurrency,
                dry_run=args.dry_run,
            )

            dry_label = " (DRY RUN)" if args.dry_run else ""
            print(f"\nTAG REMOVAL SUMMARY{dry_label}", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(f"Path:              {args.path}", file=sys.stderr)
            print(f"Key:               {args.key}", file=sys.stderr)
            if args.value is not None:
                print(f"Only when value:   {args.value}", file=sys.stderr)
            removed_label = "Would remove:" if args.dry_run else "Tags removed:"
            print(f"{removed_label:<19}{stats['objects_removed']:,}", file=sys.stderr)
            print(f"No such key:       {stats['objects_absent']:,}", file=sys.stderr)
            if stats['objects_value_mismatch']:
                print(
                    f"Value mismatch:    {stats['objects_value_mismatch']:,} "
                    f"(key present, value differs)",
                    file=sys.stderr,
                )
            print(f"Objects failed:    {stats['objects_failed']:,}", file=sys.stderr)
            if file_filter:
                print(f"Objects skipped:   {stats['objects_skipped']:,} (filter mismatch)", file=sys.stderr)

            if stats['errors']:
                print("\nErrors encountered:", file=sys.stderr)
                for error in stats['errors'][:10]:
                    print(f"  {error['path']}: {error['message']}", file=sys.stderr)
                if len(stats['errors']) > 10:
                    print(f"  ... and {len(stats['errors']) - 10} more", file=sys.stderr)

            save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)

            if stats['objects_failed'] > 0:
                sys.exit(1)

        return  # Exit after tag removal

    if args.source_acl or args.source_acl_file or (args.acl_target and not args.set_mode):
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

            # Step 6: Recurse modifications to children if requested
            # Uses per-file modification: GET each child's ACL, apply the same
            # modifications, PUT back. This preserves each child's existing ACL
            # and prevents non-inherited permissions from being incorrectly propagated.
            if args.propagate_changes:
                log_stderr("INFO", f"Applying modifications to children of: {args.path}", newline_before=True)
                await display_scope_aggregates(
                    client, session, args.path,
                    label="Modifying children of",
                    verbose=args.verbose,
                    max_depth=args.max_depth,
                    omit_subdirs=args.omit_subdirs,
                )

                # Pre-resolve trustees in add/replace patterns for child ACE creation.
                # The parent's resolution already ran; use resolved_auth_id so children
                # don't need per-file API calls to resolve new ACE trustees.
                for p in add_patterns:
                    if p.get('raw_trustee') and p.get('resolved_auth_id'):
                        p['raw_trustee'] = str(p['resolved_auth_id'])
                for find_pat, new_pat in replace_patterns:
                    if new_pat and new_pat.get('raw_trustee') and new_pat.get('resolved_auth_id'):
                        new_pat['raw_trustee'] = str(new_pat['resolved_auth_id'])

                # Resolve owner filters if any
                owner_auth_ids = None
                if args.owners:
                    owner_auth_ids = await resolve_owner_filters(client, session, args, parse_trustee)

                file_filter = create_file_filter(args, owner_auth_ids)

                propagate_stats = await recurse_ace_modifications_to_tree(
                    client=client,
                    session=session,
                    target_path=args.path,
                    remove_patterns=remove_patterns,
                    add_patterns=add_patterns,
                    add_rights_patterns=add_rights_patterns,
                    remove_rights_patterns=remove_rights_patterns,
                    replace_patterns=replace_patterns,
                    clone_patterns=clone_patterns,
                    migrate_patterns=migrate_patterns,
                    sync_cloned_aces=args.sync_cloned_aces,
                    file_filter=file_filter,
                    progress=args.progress,
                    continue_on_error=args.continue_on_error,
                    args=args,
                    acl_concurrency=args.acl_concurrency,
                    dry_run=args.dry_run,
                    verbose=args.verbose
                )

                log_stderr("INFO", "Recursion complete:", newline_before=True)
                print(f"  Objects changed:    {propagate_stats['objects_changed']:,}", file=sys.stderr)
                print(f"  Objects unchanged:  {propagate_stats['objects_unchanged']:,}", file=sys.stderr)
                print(f"  Objects failed:     {propagate_stats['objects_failed']:,}", file=sys.stderr)
                if file_filter:
                    print(f"  Objects skipped:    {propagate_stats['objects_skipped']:,}", file=sys.stderr)

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

    # --show-details collects matches and renders a table/CSV/JSON after the walk.
    collect_results = features_requiring_collection or resolve_links_needs_collection \
        or args.show_details

    # Create output callback for streaming results
    output_callback = None
    batched_handler = None
    streaming_file_handler = None

    # STREAMING FILE OUTPUT: Use StreamingFileOutputHandler for --csv-out / --json-out
    # This writes entries to file as they arrive, avoiding OOM with large result sets
    if (args.csv_out or args.json_out) and not features_requiring_collection \
            and not args.show_details:
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
    elif not args.owner_report and not args.acl_report and not args.find_similar \
            and not resolve_links_needs_collection and not args.show_details:
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

    # --show-details: render collected matches as a table/CSV/JSON and return.
    if args.show_details:
        if args.limit:
            matching_files = matching_files[:args.limit]
        specs, is_all = resolve_detail_field_specs(args.fields, dir_default=_type_is_directory(args))
        if _detail_needs_capacity(specs):
            async with client.create_session() as session:
                await _attach_dir_capacity(client, session, matching_files,
                                           concurrency=max(1, args.max_concurrent))
        wanted = {dn for dn, _ in specs}
        if (("owner_name" in wanted or "group_name" in wanted)
                and matching_files and not args.dont_resolve_ids):
            auth_ids = set()
            for e in matching_files:
                if "owner_name" in wanted:
                    aid = (e.get("owner_details") or {}).get("auth_id") or e.get("owner")
                    if aid:
                        auth_ids.add(aid)
                if "group_name" in wanted:
                    aid = (e.get("group_details") or {}).get("auth_id") or e.get("group")
                    if aid:
                        auth_ids.add(aid)
            icache = {}
            if auth_ids:
                async with client.create_session() as session:
                    icache = await client.resolve_multiple_identities(
                        session, list(auth_ids),
                        show_progress=args.verbose or args.progress)
            for e in matching_files:
                if "owner_name" in wanted:
                    aid = (e.get("owner_details") or {}).get("auth_id") or e.get("owner")
                    e["owner_name"] = (format_owner_name(icache[aid]) if aid in icache
                                       else format_raw_id(e.get("owner_details") or {}, e.get("owner", "")))
                if "group_name" in wanted:
                    aid = (e.get("group_details") or {}).get("auth_id") or e.get("group")
                    e["group_name"] = (format_owner_name(icache[aid]) if aid in icache
                                       else format_raw_id(e.get("group_details") or {}, e.get("group", "")))
        emit_detail_output(matching_files, specs, is_all, snapshot_col=False,
                           unix_time=args.unix_time, want_json=args.json,
                           json_out=args.json_out, csv_out=args.csv_out)
        if args.csv_out:
            log_stderr("INFO", f"Wrote {len(matching_files):,} result(s) to {args.csv_out}")
        elif args.json_out:
            log_stderr("INFO", f"Wrote {len(matching_files):,} result(s) to {args.json_out}")
        save_identity_cache(client.persistent_identity_cache, verbose=args.verbose)
        return

    # Flush any remaining batched output
    if batched_handler:
        await batched_handler.flush()
        if batched_handler.duplicates_skipped > 0:
            log_stderr("WARN", f"Skipped {batched_handler.duplicates_skipped:,} duplicate entries during output", newline_before=True)

    # Close streaming file handler and report results
    if streaming_file_handler:
        await streaming_file_handler.close()
        rows_written = streaming_file_handler.get_rows_written()
        dupes_skipped = streaming_file_handler.get_duplicates_skipped()
        output_path = args.json_out if args.json_out else args.csv_out
        if args.verbose or args.progress:
            log_stderr("INFO", f"Streaming complete: wrote {rows_written:,} rows to {output_path}", newline_before=True)
        if dupes_skipped > 0:
            log_stderr("WARN", f"Skipped {dupes_skipped:,} duplicate entries during output", newline_before=True)
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
    required.add_argument("--path", help="Path to search: a directory (walked recursively) or a "
                                         "single file/symlink (acted on directly). Not required for "
                                         "ACL cloning with --source-acl/--acl-target.")

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
        "--show-details",
        action="store_true",
        help="Show attributes of matched results instead of just paths "
             "(works for the live walk and for snapshot search). Defaults to "
             "path, human-readable size, and change_time (ctime). Choose columns "
             "with --fields; use --fields all for every attribute. Renders an "
             "aligned table to stdout, or honors --csv-out / --json-out / --json.",
    )
    output.add_argument(
        "--fields",
        metavar="FIELD[,FIELD,...]",
        help="Comma-separated list of fields to include in output. "
             "Supports dot notation (owner_details.id_value) and aliases: "
             "owner_id, owner_type, group_id, group_type, attr.<name>. "
             "The special value 'all' selects every attribute (implies "
             "--show-details). Cannot be combined with --all-attributes. "
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
        "--set-mode",
        help="Set POSIX permissions using chmod-style octal mode (e.g., 755, 2770, 0644). "
             "Replaces the ACL with OWNER@/GROUP@/EVERYONE@ entries. "
             "Use with --path. Supports --propagate-acls for recursive application. "
             "Setgid (2xxx) is applied to directories only.",
        metavar="MODE"
    )

    acl_management.add_argument(
        "--new-owner",
        help="Set file owner (use with --set-mode). Accepts uid:N, username, DOMAIN\\\\user, or SID. "
             "Replaces the OWNER@ placeholder in the ACL with this identity and changes file ownership.",
        metavar="IDENTITY"
    )

    acl_management.add_argument(
        "--new-group",
        help="Set file group (use with --set-mode). Accepts gid:N, groupname, DOMAIN\\\\group, or SID. "
             "Replaces the GROUP@ placeholder in the ACL with this identity and changes file group.",
        metavar="IDENTITY"
    )

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
        "--propagate",
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
        "--disable-inheritance",
        action="store_true",
        help="Disable ACL inheritance at --path. By default, converts inherited ACEs "
             "to explicit (like icacls /inheritance:d). Use with --remove-inherited to "
             "remove all inherited ACEs instead (like icacls /inheritance:r). "
             "Supports --propagate for recursive application and --dry-run for preview."
    )

    acl_management.add_argument(
        "--remove-inherited",
        action="store_true",
        help="When used with --disable-inheritance, removes all inherited ACEs entirely "
             "instead of converting them to explicit. Equivalent to icacls /inheritance:r. "
             "WARNING: If the only ACEs are inherited, this leaves the object with no ACEs."
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
    # FEATURE: OBJECT TAGGING (USER METADATA)
    # ============================================================================
    tagging = parser.add_argument_group('Feature: Object Tagging',
        'Add custom key/value user-metadata tags to objects matching the filters')

    tagging.add_argument(
        "--add-tag",
        action="store_true",
        help="Add a custom tag to every object at or under --path that matches the "
             "active filters. Requires --key and --value. Composes with all universal "
             "filters (time, size, name, type, owner, depth). Use --max-depth 0 to tag "
             "only the object at --path. Supports --progress, --dry-run, --limit, and "
             "--continue-on-error."
    )

    tagging.add_argument(
        "--find-tag",
        action="store_true",
        help="Find objects whose tags match --key and/or --value (or any tagged object "
             "if neither is given) and stream them as NDJSON to stdout. Composes with all "
             "universal filters. --limit stops after N matches."
    )

    tagging.add_argument(
        "--remove-tag",
        action="store_true",
        help="Remove the tag --key from every object at or under --path that matches the "
             "active filters. With --value, the key is removed only when its current value "
             "matches. Requires --key. Supports --dry-run, --progress, --limit, and "
             "--continue-on-error."
    )

    tagging.add_argument(
        "--key",
        metavar="KEY",
        help="Tag key. Required with --add-tag and --remove-tag; optional filter for --find-tag."
    )

    tagging.add_argument(
        "--value",
        metavar="VALUE",
        help="Tag value. Required with --add-tag; optional filter/guard for --find-tag and --remove-tag."
    )

    tagging.add_argument(
        "--overwrite",
        action="store_true",
        help="(--add-tag) Replace an existing value when the key is already present with a "
             "DIFFERENT value. Without this flag, such objects are skipped with a "
             "warning (a key already set to the same value is always a no-op)."
    )

    tagging.add_argument(
        "--tag-concurrency",
        type=int,
        default=default_acl_concurrency,
        metavar="N",
        help=f"Concurrent tag operations during a walk (default: {default_acl_concurrency})"
    )

    # ============================================================================
    # FEATURE: MOVE AND RENAME
    # ============================================================================
    move_rename = parser.add_argument_group('Feature: Move, Copy, and Rename',
        'Move, server-side copy, and/or rename objects matching the filters, like POSIX mv/cp')
    move_rename.add_argument(
        "--move-to",
        metavar="DEST",
        help="Move matching objects into the existing directory DEST (flattened, "
             "like mv). On a name collision the object is skipped with a warning "
             "unless --clobber is given.",
    )
    move_rename.add_argument(
        "--copy-to",
        metavar="DEST",
        help="Server-side copy matching objects into the existing directory DEST "
             "(flattened, like cp). Files are copied with copy-chunk; add "
             "--include-directories to copy matched directory subtrees. Mutually "
             "exclusive with --move-to.",
    )
    move_rename.add_argument(
        "--rename-to",
        metavar="PATTERN",
        help="Rename matching objects. '{old|new}' substitutes within the name "
             "(regex and * wildcards supported); a pattern without braces is a "
             "whole-name template whose * / ? come from the matching --name glob. "
             "Use alone to rename in place, or with --move-to/--copy-to.",
    )
    move_rename.add_argument(
        "--preserve-permissions",
        action="store_true",
        help="With --copy-to, also copy each source's owner, group, and ACL/mode "
             "to the copy (default: copies data only, like plain cp).",
    )
    move_rename.add_argument(
        "--preserve-all",
        action="store_true",
        help="With --copy-to, preserve every settable attribute: owner, group, "
             "ACL/mode, DOS extended attributes, GENERIC user-metadata tags, and "
             "timestamps (modification/access/creation). change_time always "
             "reflects the copy and cannot be preserved.",
    )
    move_rename.add_argument(
        "--create-destination-directory",
        action="store_true",
        help="With --copy-to or --move-to, create the destination directory (and "
             "any missing parents) if it does not exist. You are prompted to "
             "either inherit permissions from the parent or set a POSIX mode (see "
             "--destination-directory-mode to choose non-interactively).",
    )
    move_rename.add_argument(
        "--destination-directory-mode",
        metavar="MODE",
        help="With --create-destination-directory, set this octal POSIX mode "
             "(e.g. 0755) on newly created directories instead of prompting. "
             "Omit to inherit permissions from the parent directory.",
    )
    move_rename.add_argument(
        "--destination-directory-owner",
        metavar="OWNER",
        help="With --create-destination-directory, set the owner of newly created "
             "directories (name, uid:N, SID, or DOMAIN\\user).",
    )
    move_rename.add_argument(
        "--clobber",
        action="store_true",
        help="Overwrite an existing destination entry (default: skip with a warning). "
             "For --copy-to this applies to files; an existing target directory is skipped.",
    )
    move_rename.add_argument(
        "--skip-unchanged",
        action="store_true",
        help="With --copy-to, incremental sync: skip a destination file whose size and "
             "modification_time already match the source, and copy only missing or changed "
             "files (overwriting changed ones). The match check happens BEFORE any data is "
             "copied, so re-runs are near-instant. Implies --preserve-all (so timestamps are "
             "preserved and the comparison is meaningful on re-runs). Applies to files; not "
             "yet supported with --include-directories.",
    )
    move_rename.add_argument(
        "--include-directories",
        action="store_true",
        help="Also move/copy matched directories (the whole subtree). "
             "Default: only files and symlinks are moved/copied.",
    )
    move_rename.add_argument(
        "--move-concurrency",
        type=int,
        default=default_acl_concurrency,
        metavar="N",
        help=f"Concurrent move/rename operations (default: {default_acl_concurrency})",
    )
    move_rename.add_argument(
        "--copy-concurrency",
        type=int,
        default=default_acl_concurrency,
        metavar="N",
        help=f"Concurrent copy operations (default: {default_acl_concurrency})",
    )
    move_rename.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt before moving/copying/renaming.",
    )

    # ============================================================================
    # FEATURE: SNAPSHOTS
    # ============================================================================
    snapshots = parser.add_argument_group('Feature: Snapshots',
        'Search, and copy/restore data from, Qumulo snapshots')
    snapshots.add_argument(
        "--list-snapshots",
        action="store_true",
        help="List available snapshots (id, name, timestamp, source path) and exit. "
             "Honors --snapshots-newer-than/--snapshots-older-than to bound the list. "
             "With --path, lists only snapshots whose source covers that path.",
    )
    snapshots.add_argument(
        "--include-replication-snapshots",
        action="store_true",
        help="Include Qumulo replication-system snapshots (replication_from_*/"
             "replication_to_*) in listing and search. By default they are excluded, "
             "since they are not useful for restoring data.",
    )
    snapshots.add_argument(
        "--snapshot",
        type=int,
        metavar="ID",
        help="Run the crawl/search in the context of snapshot ID (all reads use it). "
             "Composes with every filter. With --copy-to or --restore-in-place, copies "
             "the snapshot version of matched files (incl. files deleted since).",
    )
    snapshots.add_argument(
        "--all-snapshots",
        action="store_true",
        help="Search across ALL snapshots instead of a single --snapshot. Each match is "
             "annotated with its snapshot. Use in place of --path (or with --path to "
             "restrict to snapshots whose source covers that path). Search-only.",
    )
    snapshots.add_argument(
        "--snapshots-newer-than",
        metavar="DURATION",
        help="Only consider snapshots taken within the last DURATION. Accepts days or "
             "hours: '5' or '5d' = 5 days, '12h' = 12 hours (filters snapshots by their "
             "UTC timestamp, not files). On its own this searches across the snapshots in "
             "that window (implies --all-snapshots); also works with --list-snapshots or "
             "--in-the-last-snapshots.",
    )
    snapshots.add_argument(
        "--snapshots-older-than",
        metavar="DURATION",
        help="Only consider snapshots older than DURATION ('5'/'5d' = days, '12h' = hours).",
    )
    snapshots.add_argument(
        "--in-the-last-snapshots",
        type=int,
        metavar="N",
        help="Search the N most recent snapshots (by UTC timestamp) and show only the "
             "NEWEST matching result for each path (dedupes across the N snapshots). "
             "Composes with the filters and snapshot-age limits. Search-only.",
    )
    snapshots.add_argument(
        "--incremental",
        action="store_true",
        help="Speed up a multi-snapshot search (--all-snapshots / --snapshots-newer-than / "
             "--in-the-last-snapshots) by crawling only the OLDEST covered snapshot in full, "
             "then using the snapshot tree diff (changes-since) between consecutive snapshots "
             "to update the match set for each later one - re-checking only the files that "
             "changed instead of re-crawling every snapshot. Identical results to a full "
             "crawl of each snapshot, far fewer API calls when snapshots are mostly alike. "
             "Requires --path; not supported with --max-depth or access-time filters (the "
             "snapshot diff does not report atime-only changes, so a reported access_time "
             "may be from an earlier snapshot for otherwise-unchanged entries).",
    )
    snapshots.add_argument(
        "--restore-in-place",
        action="store_true",
        help="With --snapshot, restore each matched file to its ORIGINAL live path "
             "(undelete/roll back): recreate files/dirs deleted since the snapshot, and "
             "(with --clobber) overwrite live versions. Destructive: needs --yes / confirmation.",
    )
    snapshots.add_argument(
        "--delta",
        action="store_true",
        help="With --restore-in-place, patch modified files in place by copying ONLY "
             "the byte ranges that differ from the snapshot, instead of rewriting the "
             "whole file. Much faster for large files with localized changes (e.g. a "
             "database or VM image). Creates a temporary snapshot of the live tree to "
             "compute the diff and deletes it when done (needs snapshot-write privilege); "
             "files deleted since the snapshot still restore whole-file. Patches existing "
             "files in place (no temp-file + rename), so it overwrites live data: needs --yes.",
    )
    snapshots.add_argument(
        "--delta-threshold",
        type=parse_size_to_bytes,
        default=1 << 20,
        metavar="SIZE",
        help="With --delta, only files at least SIZE are restored by byte-range diff; "
             "smaller files are copied whole in place (the per-file diff buys nothing when "
             "there is little data to save). Default 1MiB. Set 0 to byte-range-diff every "
             "modified file regardless of size. Accepts 100KB, 4MiB, etc.",
    )
    snapshots.add_argument(
        "--revert",
        action="store_true",
        help="With --snapshot, restore the directory at --path to its state in that "
             "snapshot. Uses the snapshot tree diff (changes-since) to find only what "
             "changed, then recreates files/dirs deleted since and restores modified "
             "files to the snapshot version (add --delta to patch them by byte range). "
             "By default files/dirs CREATED since the snapshot are KEPT (non-destructive "
             "to new data); add --delete-new for an exact byte-identical rollback. "
             "Whole-directory operation (ignores name/type/owner filters). Overwrites "
             "modified files, so it needs --yes; use --dry-run to preview.",
    )
    snapshots.add_argument(
        "--delete-new",
        action="store_true",
        help="With --revert, ALSO delete files and directories created since the "
             "snapshot, making --path byte-identical to the snapshot (an exact "
             "rollback/mirror). Without it, new objects are left in place. Destructive: "
             "--dry-run lists exactly what would be deleted.",
    )
    snapshots.add_argument(
        "--rename-on-conflict",
        action="store_true",
        help="On a name conflict during copy/restore, write the item under a new name with "
             "a '_restored_<date>_<time>' suffix instead of skipping (default) or "
             "overwriting (--clobber). Mutually exclusive with --clobber.",
    )
    snapshots.add_argument(
        "--conflict-suffix",
        metavar="TEMPLATE",
        help="Customize the --rename-on-conflict suffix. Placeholders: {date}, {time}, "
             "{datetime}, {snapshot}. Default: '_restored_{datetime}'.",
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
    connection.add_argument(
        "--update-atime",
        action="store_true",
        help="Allow access times (atime) to be updated by grumpwalk's reads. "
             "By default, on clusters that support it (Qumulo Core 7.9.0+), "
             "grumpwalk suppresses atime updates so a crawl does not disturb "
             "access-time metadata. This flag restores normal atime behavior.",
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
    # Check that either --path OR (--source-acl/--source-acl-file + --acl-target) are provided.
    # Snapshot modes supply their own root: --list-snapshots needs no path,
    # --all-snapshots replaces --path, and --snapshot defaults to the snapshot source.
    acl_cloning_mode = (args.source_acl or args.source_acl_file) and args.acl_target

    # A snapshot-age filter (--snapshots-newer-than / --snapshots-older-than) bounds a
    # SET of snapshots. On its own it already means "search the snapshots in that window",
    # so imply --all-snapshots rather than make the user also type it.
    _age_filter = args.snapshots_newer_than is not None or args.snapshots_older_than is not None
    if _age_filter and args.snapshot is not None:
        print("Error: --snapshots-newer-than / --snapshots-older-than bound a set of snapshots "
              "and cannot be combined with a single --snapshot ID", file=sys.stderr)
        sys.exit(1)
    if _age_filter and (args.copy_to or args.restore_in_place):
        print("Error: copying/restoring needs a specific --snapshot ID; "
              "--snapshots-newer-than / --snapshots-older-than only apply to listing or searching",
              file=sys.stderr)
        sys.exit(1)
    if (_age_filter and not args.all_snapshots and not args.in_the_last_snapshots
            and not args.list_snapshots):
        args.all_snapshots = True
        log_stderr("INFO", "Searching across snapshots in the given age window (--all-snapshots implied)")

    if args.incremental:
        if not (args.all_snapshots or args.in_the_last_snapshots):
            print("Error: --incremental speeds up a multi-snapshot search; use it with "
                  "--all-snapshots, --snapshots-newer-than/--snapshots-older-than, or "
                  "--in-the-last-snapshots", file=sys.stderr)
            sys.exit(1)
        if not args.path:
            print("Error: --incremental requires --path (the directory to search across "
                  "snapshots)", file=sys.stderr)
            sys.exit(1)
        if args.max_depth is not None:
            print("Error: --incremental is not supported with --max-depth", file=sys.stderr)
            sys.exit(1)
        # changes-since does not report an entry whose only change is its access time,
        # so the incremental match set can carry a stale atime. Reject atime-based
        # filters (which would otherwise silently diverge from a full crawl); a stale
        # atime in OUTPUT is documented but harmless to non-atime filtering.
        atime_filter = ((args.time_field == "access_time" and (args.older_than or args.newer_than))
                        or args.accessed_older_than is not None
                        or args.accessed_newer_than is not None)
        if atime_filter:
            print("Error: --incremental cannot be used with access-time filters "
                  "(--accessed/--time-field access_time with --older-than/--newer-than, or "
                  "--accessed-older-than/--accessed-newer-than): the snapshot diff does not "
                  "report access-time-only changes, so atime is not reliable incrementally. "
                  "Run the search without --incremental for access-time filtering.",
                  file=sys.stderr)
            sys.exit(1)

    snapshot_root_mode = (args.list_snapshots or args.all_snapshots or args.in_the_last_snapshots
                          or args.snapshot is not None)
    if not args.path and not acl_cloning_mode and not snapshot_root_mode:
        print(
            "Error: Either --path is required OR a source (--source-acl or --source-acl-file) and --acl-target for ACL cloning",
            file=sys.stderr,
        )
        sys.exit(1)

    # Snapshot-mode validation
    multi_snapshot = bool(args.all_snapshots or args.in_the_last_snapshots)
    if args.all_snapshots and args.snapshot is not None:
        print("Error: --all-snapshots and --snapshot cannot be combined; choose one", file=sys.stderr)
        sys.exit(1)
    if args.in_the_last_snapshots is not None:
        if args.in_the_last_snapshots <= 0:
            print("Error: --in-the-last-snapshots must be a positive integer", file=sys.stderr)
            sys.exit(1)
        if args.snapshot is not None:
            print("Error: --in-the-last-snapshots searches multiple snapshots; do not combine with --snapshot",
                  file=sys.stderr)
            sys.exit(1)
        if args.copy_to or args.restore_in_place:
            print("Error: --in-the-last-snapshots is search-only; pick a specific --snapshot to copy/restore",
                  file=sys.stderr)
            sys.exit(1)
    # Parse snapshot-age durations (days by default; Nd / Nh units) to hours.
    args.snapshots_newer_hours = None
    args.snapshots_older_hours = None
    for flag, raw, dest in (("--snapshots-newer-than", args.snapshots_newer_than, "snapshots_newer_hours"),
                            ("--snapshots-older-than", args.snapshots_older_than, "snapshots_older_hours")):
        if raw is None:
            continue
        hours = _parse_age_to_hours(raw)
        if hours is None:
            print(f"Error: invalid {flag} '{raw}'; use N or Nd for days, Nh for hours (e.g. 5, 5d, 12h)",
                  file=sys.stderr)
            sys.exit(1)
        setattr(args, dest, hours)
    if args.all_snapshots and (args.copy_to or args.restore_in_place):
        print("Error: --all-snapshots is search-only; pick a specific --snapshot to copy/restore",
              file=sys.stderr)
        sys.exit(1)
    if args.restore_in_place and args.snapshot is None:
        print("Error: --restore-in-place requires --snapshot", file=sys.stderr)
        sys.exit(1)
    if args.revert:
        if args.snapshot is None:
            print("Error: --revert requires --snapshot", file=sys.stderr)
            sys.exit(1)
        if not args.path:
            print("Error: --revert requires --path (the directory to revert)", file=sys.stderr)
            sys.exit(1)
        if args.restore_in_place or args.copy_to or args.move_to:
            print("Error: --revert cannot be combined with --restore-in-place / --copy-to / "
                  "--move-to (it is its own operation)", file=sys.stderr)
            sys.exit(1)
        if args.all_snapshots:
            print("Error: --revert needs a specific --snapshot, not --all-snapshots", file=sys.stderr)
            sys.exit(1)
    if args.delete_new and not args.revert:
        print("Error: --delete-new only applies to --revert", file=sys.stderr)
        sys.exit(1)
    if args.delta:
        if not (args.restore_in_place or args.revert):
            print("Error: --delta requires --restore-in-place or --revert", file=sys.stderr)
            sys.exit(1)
        if args.rename_on_conflict:
            print("Error: --delta patches files in place and cannot be combined with "
                  "--rename-on-conflict", file=sys.stderr)
            sys.exit(1)
    if args.clobber and args.rename_on_conflict:
        print("Error: --clobber and --rename-on-conflict cannot be combined", file=sys.stderr)
        sys.exit(1)
    if args.skip_unchanged:
        if not args.copy_to:
            print("Error: --skip-unchanged requires --copy-to", file=sys.stderr)
            sys.exit(1)
        if args.rename_on_conflict:
            print("Error: --skip-unchanged and --rename-on-conflict cannot be combined",
                  file=sys.stderr)
            sys.exit(1)
        if args.include_directories:
            print("Error: --skip-unchanged is not yet supported with --include-directories "
                  "(it applies to file matches)", file=sys.stderr)
            sys.exit(1)
        # The size+mtime comparison is only meaningful if the destination keeps the
        # source's mtime, so a sync implies full attribute preservation.
        if not args.preserve_all:
            args.preserve_all = True
            log_stderr("INFO", "--skip-unchanged implies --preserve-all (preserving timestamps "
                               "so unchanged files can be detected on re-runs)")

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

    # Validate object tagging modes (--add-tag / --find-tag / --remove-tag)
    active_tag_modes = [name for name, on in (
        ('--add-tag', args.add_tag),
        ('--find-tag', args.find_tag),
        ('--remove-tag', args.remove_tag),
    ) if on]
    if len(active_tag_modes) > 1:
        print(
            f"Error: {' and '.join(active_tag_modes)} cannot be combined; choose one",
            file=sys.stderr,
        )
        sys.exit(1)

    tag_mode = active_tag_modes[0] if active_tag_modes else None
    if tag_mode:
        if not args.path:
            print(f"Error: {tag_mode} requires --path", file=sys.stderr)
            sys.exit(1)
        if args.add_tag and (not args.key or not args.value):
            print("Error: --add-tag requires both --key and --value", file=sys.stderr)
            sys.exit(1)
        if args.remove_tag and not args.key:
            print("Error: --remove-tag requires --key", file=sys.stderr)
            sys.exit(1)
        if not args.add_tag and args.overwrite:
            print("Error: --overwrite only applies to --add-tag", file=sys.stderr)
            sys.exit(1)

        conflicting = []
        if args.source_acl or args.source_acl_file or args.acl_target:
            conflicting.append("--source-acl/--acl-target")
        if args.set_mode:
            conflicting.append("--set-mode")
        if args.disable_inheritance:
            conflicting.append("--disable-inheritance")
        if getattr(args, 'ace_restore', None):
            conflicting.append("--ace-restore")
        if (args.change_owner or args.change_group or
                args.change_owners_file or args.change_groups_file):
            conflicting.append("--change-owner/--change-group")
        if getattr(args, 'set_attribute_true', None) or getattr(args, 'set_attribute_false', None):
            conflicting.append("--set-attribute-true/--set-attribute-false")
        if args.owner_report or args.acl_report:
            conflicting.append("--owner-report/--acl-report")
        if args.move_to or args.rename_to or args.copy_to:
            conflicting.append("--move-to/--copy-to/--rename-to")
        if conflicting:
            print(
                f"Error: {tag_mode} cannot be combined with: {', '.join(conflicting)}",
                file=sys.stderr,
            )
            sys.exit(1)
    elif args.key or args.value or args.overwrite:
        print("Error: --key/--value/--overwrite require --add-tag, --find-tag, or --remove-tag", file=sys.stderr)
        sys.exit(1)

    # Move / Rename mode validation
    # --copy-to and --move-to are mutually exclusive transfer modes.
    if args.copy_to and args.move_to:
        print("Error: --copy-to and --move-to cannot be combined; choose one", file=sys.stderr)
        sys.exit(1)
    if (args.preserve_permissions or args.preserve_all) and not args.copy_to:
        print("Error: --preserve-permissions/--preserve-all require --copy-to", file=sys.stderr)
        sys.exit(1)
    if args.create_destination_directory and not (args.copy_to or args.move_to):
        print("Error: --create-destination-directory requires --copy-to or --move-to", file=sys.stderr)
        sys.exit(1)
    if (args.destination_directory_owner or args.destination_directory_mode) \
            and not args.create_destination_directory:
        print("Error: --destination-directory-owner/--destination-directory-mode "
              "require --create-destination-directory", file=sys.stderr)
        sys.exit(1)
    if args.destination_directory_mode and _normalize_mode(args.destination_directory_mode) is None:
        print(f"Error: invalid --destination-directory-mode "
              f"'{args.destination_directory_mode}'; use an octal mode like 0755", file=sys.stderr)
        sys.exit(1)

    copy_mode = bool(args.copy_to)
    # --rename-to alone (no --copy-to) is handled by the move/rename driver.
    move_rename_mode = bool(args.move_to or args.rename_to) and not copy_mode

    def _transfer_conflicts(label):
        conflicts = []
        if args.source_acl or args.source_acl_file or args.acl_target:
            conflicts.append("--source-acl/--acl-target")
        if args.set_mode:
            conflicts.append("--set-mode")
        if args.disable_inheritance:
            conflicts.append("--disable-inheritance")
        if getattr(args, 'ace_restore', None):
            conflicts.append("--ace-restore")
        if (args.change_owner or args.change_group or
                args.change_owners_file or args.change_groups_file):
            conflicts.append("--change-owner/--change-group")
        if getattr(args, 'set_attribute_true', None) or getattr(args, 'set_attribute_false', None):
            conflicts.append("--set-attribute-true/--set-attribute-false")
        if args.owner_report or args.acl_report:
            conflicts.append("--owner-report/--acl-report")
        if conflicts:
            print(f"Error: {label} cannot be combined with: {', '.join(conflicts)}", file=sys.stderr)
            sys.exit(1)

    if copy_mode:
        if not args.path:
            print("Error: --copy-to requires --path", file=sys.stderr)
            sys.exit(1)
        if args.rename_to:
            try:
                build_renamer(args.rename_to, args.name_patterns or [])
            except RenamePatternError as e:
                print(f"Error: invalid --rename-to pattern: {e}", file=sys.stderr)
                sys.exit(1)
        _transfer_conflicts("--copy-to")
    elif move_rename_mode:
        if not args.path:
            print("Error: --move-to/--rename-to requires --path", file=sys.stderr)
            sys.exit(1)
        if args.rename_to:
            try:
                build_renamer(args.rename_to, args.name_patterns or [])
            except RenamePatternError as e:
                print(f"Error: invalid --rename-to pattern: {e}", file=sys.stderr)
                sys.exit(1)
        _transfer_conflicts("--move-to/--rename-to")
    elif (args.clobber or args.include_directories or args.yes) \
            and not (args.restore_in_place or args.snapshot is not None):
        print("Error: --clobber/--include-directories/--yes require --move-to, --copy-to, or --rename-to",
              file=sys.stderr)
        sys.exit(1)

    # Validate and parse --fields
    # '--fields all' is a detail-mode selector (every attribute), not a literal
    # field name, and implies --show-details.
    args.fields_all = bool(args.fields) and args.fields.strip().lower() == "all"
    if args.fields_all:
        args.show_details = True
        args.parsed_fields = None
        if args.all_attributes:
            print("Error: --fields cannot be combined with --all-attributes", file=sys.stderr)
            sys.exit(1)
        if args.owner_report or args.acl_report:
            print("Error: --fields does not apply to --owner-report or --acl-report", file=sys.stderr)
            sys.exit(1)
    elif args.fields:
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

    # --show-details applies only to result-producing searches (the live filtered
    # walk and snapshot search), not to mutating actions or specialized reports.
    if args.show_details:
        _detail_incompat = [
            name for flag, name in (
                (args.copy_to, "--copy-to"), (args.move_to, "--move-to"),
                (args.rename_to, "--rename-to"), (args.restore_in_place, "--restore-in-place"),
                (args.revert, "--revert"),
                (args.owner_report, "--owner-report"), (args.acl_report, "--acl-report"),
                (args.find_similar, "--find-similar"), (args.list_snapshots, "--list-snapshots"),
                (args.show_dir_stats, "--show-dir-stats"),
                (args.source_acl, "--source-acl"), (args.acl_target, "--acl-target"),
            ) if flag
        ]
        if _detail_incompat:
            print(f"Error: --show-details cannot be combined with {', '.join(_detail_incompat)}",
                  file=sys.stderr)
            sys.exit(1)
        if args.all_attributes:
            print("Error: --show-details ignores --all-attributes; use '--fields all' "
                  "for every attribute", file=sys.stderr)
            sys.exit(1)

    # Validate extended attribute arguments
    validate_attribute_args(args)

    # A two-sided time window keeps files between the bounds: timestamp older than the
    # --older-than age AND newer than the --newer-than age. That is only non-empty when
    # the --newer-than value is GREATER than the --older-than value (e.g. older-than 7 +
    # newer-than 30 = files 7-30 days old). Validate each same-field pair; cross-field
    # combinations (e.g. --accessed-older-than 90 --modified-newer-than 7) are unrelated
    # and untouched.
    _time_ranges = [
        (args.older_than, args.newer_than, "--older-than", "--newer-than",
         " (e.g. --older-than 7 --newer-than 30 selects files 7-30 days old)"),
        (args.accessed_older_than, args.accessed_newer_than,
         "--accessed-older-than", "--accessed-newer-than", ""),
        (args.modified_older_than, args.modified_newer_than,
         "--modified-older-than", "--modified-newer-than", ""),
        (args.created_older_than, args.created_newer_than,
         "--created-older-than", "--created-newer-than", ""),
        (args.changed_older_than, args.changed_newer_than,
         "--changed-older-than", "--changed-newer-than", ""),
    ]
    for _older, _newer, _older_flag, _newer_flag, _hint in _time_ranges:
        if _older and _newer and _newer <= _older:
            print(f"Error: {_newer_flag} must be greater than {_older_flag} for a valid "
                  f"time range{_hint}", file=sys.stderr)
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
        if args.add_tag or args.find_tag or args.remove_tag:
            conflicting.append("--add-tag/--find-tag/--remove-tag")
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
