#!/bin/bash

# Filter files by age from qq fs_walk_tree output using streaming to avoid OOM
# Usage: ./filter_old_files.sh --path <path> (--older-than <days> | --newer-than <days>) [--created | --accessed | --modified | --changed] [--max-depth <depth>] [--file-only | --all] [--omit-subdirs "pattern1 pattern2"] [--json | --json-out <file>] [--verbose]
# Example: ./filter_old_files.sh --path /home --older-than 30 --accessed --max-depth 1 --file-only --omit-subdirs "temp cache 100k*" --json-out results.json --verbose

set -euo pipefail

# Default values
PATH_TO_SEARCH=""
OLDER_THAN=""
NEWER_THAN=""
MAX_DEPTH=""
FILE_ONLY=true
OUTPUT_JSON=false
OMIT_SUBDIRS=""
VERBOSE=false
JSON_OUT_FILE=""
CSV_OUT_FILE=""
TIME_FIELD="creation_time"
OWNERS=()
OWNER_TYPE=""
EXPAND_IDENTITY=false
ALL_ATTRIBUTES=false
GREATER_THAN=""
SMALLER_THAN=""
QQ_HOST=""
QQ_CREDENTIALS_STORE=""

# Field-specific time filters
ACCESSED_OLDER_THAN=""
ACCESSED_NEWER_THAN=""
MODIFIED_OLDER_THAN=""
MODIFIED_NEWER_THAN=""
CREATED_OLDER_THAN=""
CREATED_NEWER_THAN=""
CHANGED_OLDER_THAN=""
CHANGED_NEWER_THAN=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --path)
            PATH_TO_SEARCH="$2"
            shift 2
            ;;
        --older-than)
            OLDER_THAN="$2"
            shift 2
            ;;
        --newer-than)
            NEWER_THAN="$2"
            shift 2
            ;;
        --max-depth)
            MAX_DEPTH="$2"
            shift 2
            ;;
        --file-only)
            FILE_ONLY=true
            shift
            ;;
        --all)
            FILE_ONLY=false
            shift
            ;;
        --omit-subdirs)
            OMIT_SUBDIRS="$2"
            shift 2
            ;;
        --json)
            OUTPUT_JSON=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --json-out)
            JSON_OUT_FILE="$2"
            OUTPUT_JSON=true
            shift 2
            ;;
        --csv-out)
            CSV_OUT_FILE="$2"
            shift 2
            ;;
        --created)
            TIME_FIELD="creation_time"
            shift
            ;;
        --accessed)
            TIME_FIELD="access_time"
            shift
            ;;
        --modified)
            TIME_FIELD="modification_time"
            shift
            ;;
        --changed)
            TIME_FIELD="change_time"
            shift
            ;;
        --accessed-older-than)
            ACCESSED_OLDER_THAN="$2"
            shift 2
            ;;
        --accessed-newer-than)
            ACCESSED_NEWER_THAN="$2"
            shift 2
            ;;
        --modified-older-than)
            MODIFIED_OLDER_THAN="$2"
            shift 2
            ;;
        --modified-newer-than)
            MODIFIED_NEWER_THAN="$2"
            shift 2
            ;;
        --created-older-than)
            CREATED_OLDER_THAN="$2"
            shift 2
            ;;
        --created-newer-than)
            CREATED_NEWER_THAN="$2"
            shift 2
            ;;
        --changed-older-than)
            CHANGED_OLDER_THAN="$2"
            shift 2
            ;;
        --changed-newer-than)
            CHANGED_NEWER_THAN="$2"
            shift 2
            ;;
        --owner)
            OWNERS+=("$2")
            shift 2
            ;;
        --ad)
            OWNER_TYPE="ad"
            shift
            ;;
        --local)
            OWNER_TYPE="local"
            shift
            ;;
        --uid)
            OWNER_TYPE="uid"
            shift
            ;;
        --expand-identity)
            EXPAND_IDENTITY=true
            shift
            ;;
        --all-attributes)
            ALL_ATTRIBUTES=true
            shift
            ;;
        --greater-than)
            GREATER_THAN="$2"
            shift 2
            ;;
        --smaller-than)
            SMALLER_THAN="$2"
            shift 2
            ;;
        --host)
            QQ_HOST="$2"
            shift 2
            ;;
        --credentials-store)
            QQ_CREDENTIALS_STORE="$2"
            shift 2
            ;;
        --help|-h)
            cat << 'EOF'
Filter files by age from qq fs_walk_tree output using streaming to avoid OOM

Usage:
  filter_old_files.sh --path <path> [--older-than <days> | --newer-than <days>] [OPTIONS]

Required Arguments:
  --path <path>              Path to search

Time Filter Options (optional):
  --older-than <days>        Find files older than N days (uses field selected by --accessed/--modified/etc.)
  --newer-than <days>        Find files newer than N days (uses field selected by --accessed/--modified/etc.)
                             Both can be used together for time range filtering

Time Field Options (for use with --older-than/--newer-than):
  --created                  Filter by creation time (default)
  --accessed                 Filter by last access time
  --modified                 Filter by last modification time
  --changed                  Filter by last metadata change time

Field-Specific Time Filters (for complex multi-field queries):
  --accessed-older-than <days>    Files accessed older than N days
  --accessed-newer-than <days>    Files accessed newer than N days
  --modified-older-than <days>    Files modified older than N days
  --modified-newer-than <days>    Files modified newer than N days
  --created-older-than <days>     Files created older than N days
  --created-newer-than <days>     Files created newer than N days
  --changed-older-than <days>     Files with metadata changed older than N days
  --changed-newer-than <days>     Files with metadata changed newer than N days
                                  All field-specific filters use AND logic

Size Filter Options (optional):
  --greater-than <size>      Find files greater than specified size
  --smaller-than <size>      Find files smaller than specified size
                             Both can be used together for range filtering
                             Supported units: B, KB, MB, GB, TB, PB, KiB, MiB, GiB, TiB, PiB
                             Examples: 100MB, 1.5GiB, 500, 10KB

Owner Filter Options:
  --owner <name>             Filter by file owner (can be specified multiple times for OR logic)
  --ad                       Owner(s) are Active Directory users
  --local                    Owner(s) are local users
  --uid                      Owner(s) are specified as UID numbers
  --expand-identity          Match all equivalent identities (e.g., AD user + NFS UID)
                             Note: Cannot mix --uid with --ad or --local

Search Options:
  --max-depth <N>            Maximum directory depth to search
  --file-only                Search files only (default)
  --all                      Search both files and directories
  --omit-subdirs "patterns"  Space-separated patterns to omit (supports wildcards)

Output Options:
  --json                     Output results as JSON to stdout
  --json-out <file>          Write JSON results to file (allows --verbose)
  --csv-out <file>           Write results to CSV file (mutually exclusive with --json/--json-out)
  --verbose                  Show detailed logging to stderr
  --all-attributes           Include all file attributes in JSON output (default: path + time field only)

Qumulo Connection Options:
  --host <host>              Qumulo cluster hostname or IP
  --credentials-store <path> Path to credentials file (default: ~/.qfsd_cred)

Examples:
  # Find files created more than 30 days ago
  filter_old_files.sh --path /home --older-than 30

  # Find files owned by a user with identity expansion
  filter_old_files.sh --path /home --owner jdoe --expand-identity

  # Find files in size and time ranges, save to CSV
  filter_old_files.sh --path /home --older-than 90 --greater-than 1GB --smaller-than 10GB --csv-out results.csv

  # Exclude directories and limit depth
  filter_old_files.sh --path /home --older-than 30 --omit-subdirs "temp cache" --max-depth 3

  # Complex multi-field query with multiple conditions
  filter_old_files.sh --path /home --accessed-newer-than 10 --accessed-older-than 30 \
    --modified-older-than 20 --created-older-than 100 --owner joe
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 --path <path> (--older-than <days> | --newer-than <days>) [--created | --accessed | --modified | --changed] [--max-depth <depth>] [--file-only | --all] [--omit-subdirs \"pattern1 pattern2\"] [--json | --json-out <file>] [--verbose]" >&2
            echo "Example: $0 --path /home --older-than 30 --accessed --max-depth 1 --file-only --omit-subdirs \"temp cache 100k*\" --json-out results.json --verbose" >&2
            echo "Try '$0 --help' for more information." >&2
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$PATH_TO_SEARCH" ]; then
    echo "Error: --path is required" >&2
    echo "Usage: $0 --path <path> (--older-than <days> | --newer-than <days>) [--created | --accessed | --modified | --changed] [--max-depth <depth>] [--file-only | --all] [--omit-subdirs \"pattern1 pattern2\"] [--json | --json-out <file>] [--verbose]" >&2
    echo "Example: $0 --path /home --older-than 30 --accessed --max-depth 1 --file-only --omit-subdirs \"temp cache 100k*\" --json-out results.json --verbose" >&2
    exit 1
fi

# Validate time range if both --older-than and --newer-than are specified
if [ -n "$OLDER_THAN" ] && [ -n "$NEWER_THAN" ]; then
    if [ "$NEWER_THAN" -ge "$OLDER_THAN" ]; then
        echo "Error: --newer-than ($NEWER_THAN) must be less than --older-than ($OLDER_THAN) for a valid time range" >&2
        echo "Example: --newer-than 7 --older-than 30 (files between 7 and 30 days old)" >&2
        exit 1
    fi
fi

# Allow both --greater-than and --smaller-than for range filtering

# Check for conflicting options
if [ "$VERBOSE" = true ] && [ "$OUTPUT_JSON" = true ] && [ -z "$JSON_OUT_FILE" ]; then
    echo "Error: --json and --verbose produce conflicting output to stdout" >&2
    echo "Suggestion: Use --json-out <file> instead of --json to separate JSON output from verbose logs" >&2
    echo "Example: $0 --path /home --older-than 30 --json-out results.json --verbose" >&2
    exit 1
fi

# Check for mutually exclusive CSV and JSON output
if [ -n "$CSV_OUT_FILE" ] && { [ "$OUTPUT_JSON" = true ] || [ -n "$JSON_OUT_FILE" ]; }; then
    echo "Error: --csv-out cannot be used with --json or --json-out" >&2
    echo "Please choose either CSV or JSON output format" >&2
    exit 1
fi

# Validate owner filter options
if [ ${#OWNERS[@]} -eq 0 ] && [ -n "$OWNER_TYPE" ]; then
    echo "Error: Owner type flag (--ad, --local, --uid) requires --owner" >&2
    echo "Example: $0 --path /home --older-than 30 --owner jdoe --ad" >&2
    exit 1
fi

# Validate that --uid is not mixed with --ad or --local
if [ "$OWNER_TYPE" = "uid" ] && [ ${#OWNERS[@]} -gt 0 ]; then
    # Check if any owner looks like it might be a name (for clarity in error message)
    # We'll prevent mixing types for simplicity
    if [ "$VERBOSE" = true ]; then
        echo "[INFO] Using --uid for all owners" >&2
    fi
elif [ "$OWNER_TYPE" = "ad" ] || [ "$OWNER_TYPE" = "local" ]; then
    if [ "$VERBOSE" = true ]; then
        echo "[INFO] Using --$OWNER_TYPE for all owners" >&2
    fi
fi

# If owner specified without type, use auto-detection
if [ ${#OWNERS[@]} -gt 0 ] && [ -z "$OWNER_TYPE" ]; then
    if [ "$VERBOSE" = true ]; then
        echo "[INFO] No owner type specified, will auto-detect" >&2
    fi
    OWNER_TYPE="auto"
fi

# Function to build qq command with connection options
build_qq_cmd() {
    local cmd="qq"
    if [ -n "$QQ_HOST" ]; then
        cmd="$cmd --host $QQ_HOST"
    fi
    if [ -n "$QQ_CREDENTIALS_STORE" ]; then
        cmd="$cmd --credentials-store $QQ_CREDENTIALS_STORE"
    fi
    echo "$cmd"
}

# Function to parse size with units to bytes (must be defined before use)
parse_size_to_bytes() {
    local size_str="$1"
    local size_num=""
    local size_unit=""

    # Extract number and unit using regex
    if [[ "$size_str" =~ ^([0-9]+\.?[0-9]*)([A-Za-z]*)$ ]]; then
        size_num="${BASH_REMATCH[1]}"
        size_unit="${BASH_REMATCH[2]}"
    else
        echo "Error: Invalid size format '$size_str'" >&2
        echo "Expected format: <number>[unit] (e.g., 100MB, 1.5GiB, 500)" >&2
        exit 1
    fi

    # Convert to bytes based on unit (case insensitive)
    # Use Python for calculations to avoid bc dependency and handle large numbers
    local bytes=""
    bytes=$(python3 -c "
size_num = float('$size_num')
unit = '${size_unit,,}'

multipliers = {
    '': 1, 'b': 1,
    'kb': 1000, 'mb': 1000000, 'gb': 1000000000, 'tb': 1000000000000, 'pb': 1000000000000000,
    'kib': 1024, 'mib': 1048576, 'gib': 1073741824, 'tib': 1099511627776, 'pib': 1125899906842624
}

if unit in multipliers:
    print(int(size_num * multipliers[unit]))
else:
    import sys
    sys.exit(1)
" 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "$bytes" ]; then
        echo "Error: Unknown size unit '$size_unit'" >&2
        echo "Supported units: B, KB, MB, GB, TB, PB, KiB, MiB, GiB, TiB, PiB" >&2
        exit 1
    fi

    echo "$bytes"
}

# Parse size filters (if specified) - moved here to be right after function definition
SIZE_GREATER_BYTES=""
SIZE_SMALLER_BYTES=""
if [ -n "$GREATER_THAN" ]; then
    SIZE_GREATER_BYTES=$(parse_size_to_bytes "$GREATER_THAN")
    if [ "$VERBOSE" = true ]; then
        echo "[INFO] Size filter: greater than $SIZE_GREATER_BYTES bytes ($GREATER_THAN)" >&2
    fi
fi
if [ -n "$SMALLER_THAN" ]; then
    SIZE_SMALLER_BYTES=$(parse_size_to_bytes "$SMALLER_THAN")
    if [ "$VERBOSE" = true ]; then
        echo "[INFO] Size filter: smaller than $SIZE_SMALLER_BYTES bytes ($SMALLER_THAN)" >&2
    fi
fi

# Calculate the timestamp threshold(s) for legacy flags (backward compatibility)
threshold_older=""
threshold_newer=""
comparison=""

if [ -n "$OLDER_THAN" ] && [ -n "$NEWER_THAN" ]; then
    # Range: both thresholds needed
    threshold_older=$(date -u +%s -d "$OLDER_THAN days ago")
    threshold_newer=$(date -u +%s -d "$NEWER_THAN days ago")
    comparison="range"
elif [ -n "$OLDER_THAN" ]; then
    threshold_older=$(date -u +%s -d "$OLDER_THAN days ago")
    comparison="older"
elif [ -n "$NEWER_THAN" ]; then
    threshold_newer=$(date -u +%s -d "$NEWER_THAN days ago")
    comparison="newer"
fi

# Calculate thresholds for field-specific time filters
ACCESSED_THRESHOLD_OLDER=""
ACCESSED_THRESHOLD_NEWER=""
MODIFIED_THRESHOLD_OLDER=""
MODIFIED_THRESHOLD_NEWER=""
CREATED_THRESHOLD_OLDER=""
CREATED_THRESHOLD_NEWER=""
CHANGED_THRESHOLD_OLDER=""
CHANGED_THRESHOLD_NEWER=""

if [ -n "$ACCESSED_OLDER_THAN" ]; then
    ACCESSED_THRESHOLD_OLDER=$(date -u +%s -d "$ACCESSED_OLDER_THAN days ago")
fi
if [ -n "$ACCESSED_NEWER_THAN" ]; then
    ACCESSED_THRESHOLD_NEWER=$(date -u +%s -d "$ACCESSED_NEWER_THAN days ago")
fi
if [ -n "$MODIFIED_OLDER_THAN" ]; then
    MODIFIED_THRESHOLD_OLDER=$(date -u +%s -d "$MODIFIED_OLDER_THAN days ago")
fi
if [ -n "$MODIFIED_NEWER_THAN" ]; then
    MODIFIED_THRESHOLD_NEWER=$(date -u +%s -d "$MODIFIED_NEWER_THAN days ago")
fi
if [ -n "$CREATED_OLDER_THAN" ]; then
    CREATED_THRESHOLD_OLDER=$(date -u +%s -d "$CREATED_OLDER_THAN days ago")
fi
if [ -n "$CREATED_NEWER_THAN" ]; then
    CREATED_THRESHOLD_NEWER=$(date -u +%s -d "$CREATED_NEWER_THAN days ago")
fi
if [ -n "$CHANGED_OLDER_THAN" ]; then
    CHANGED_THRESHOLD_OLDER=$(date -u +%s -d "$CHANGED_OLDER_THAN days ago")
fi
if [ -n "$CHANGED_NEWER_THAN" ]; then
    CHANGED_THRESHOLD_NEWER=$(date -u +%s -d "$CHANGED_NEWER_THAN days ago")
fi

# Function to resolve a single owner to auth_id(s)
resolve_owner_identity() {
    local owner="$1"
    local owner_type="$2"
    local expand_identity="$3"
    local verbose="$4"

    if [ "$verbose" = true ]; then
        echo "[INFO] Resolving owner identity: $owner (type: $owner_type)" >&2
    fi

    local AUTH_RESULT=""
    local OWNER_AUTH_ID=""

    # Build qq command with connection options
    local QQ_CMD=$(build_qq_cmd)

    # Capture both stdout and error information
    case "$owner_type" in
        ad)
            AUTH_RESULT=$($QQ_CMD auth_find_identity --name "$owner" --domain ACTIVE_DIRECTORY --json 2>&1)
            ;;
        local)
            AUTH_RESULT=$($QQ_CMD auth_find_identity --name "$owner" --domain LOCAL --json 2>&1)
            ;;
        uid)
            AUTH_RESULT=$($QQ_CMD auth_find_identity --uid "$owner" --json 2>&1)
            ;;
        auto)
            # Check if owner is numeric (UID)
            if [[ "$owner" =~ ^[0-9]+$ ]]; then
                if [ "$verbose" = true ]; then
                    echo "[INFO] Owner appears to be numeric, trying UID lookup for '$owner'..." >&2
                fi
                AUTH_RESULT=$($QQ_CMD auth_find_identity --uid "$owner" --json 2>&1)
                TEMP_AUTH_ID=$(echo "$AUTH_RESULT" | jq -r '.auth_id // .id // empty' 2>/dev/null)
                if [ -n "$TEMP_AUTH_ID" ]; then
                    if [ "$verbose" = true ]; then
                        echo "[INFO] Auto-detected owner type: UID" >&2
                    fi
                fi
            else
                # Try generic lookup first for non-numeric names
                if [ "$verbose" = true ]; then
                    echo "[INFO] Trying generic lookup for '$owner'..." >&2
                fi
                AUTH_RESULT=$($QQ_CMD auth_find_identity "$owner" --json 2>&1)

                # If generic lookup failed, try with --name flag which supports various AD formats
                TEMP_AUTH_ID=$(echo "$AUTH_RESULT" | jq -r '.auth_id // .id // empty' 2>/dev/null)
                if [ -z "$TEMP_AUTH_ID" ]; then
                    if [ "$verbose" = true ]; then
                        echo "[INFO] Generic lookup failed, trying --name lookup..." >&2
                    fi
                    AUTH_RESULT=$($QQ_CMD auth_find_identity --name "$owner" --json 2>&1)
                fi

                if [ "$verbose" = true ]; then
                    DETECTED_TYPE=$(echo "$AUTH_RESULT" | jq -r '.id_type // empty' 2>/dev/null)
                    if [ -n "$DETECTED_TYPE" ]; then
                        echo "[INFO] Auto-detected owner type: $DETECTED_TYPE" >&2
                    fi
                fi
            fi
            ;;
    esac

    # Try to extract the auth_id (support both 'id' and 'auth_id' fields)
    OWNER_AUTH_ID=$(echo "$AUTH_RESULT" | jq -r '.auth_id // .id // empty' 2>/dev/null)

    if [ -z "$OWNER_AUTH_ID" ]; then
        echo "Error: Could not resolve owner identity for '$owner' (type: $owner_type)" >&2

        # Try to find the user with different methods to provide helpful suggestions
        echo "[INFO] Attempting alternative lookups..." >&2

        # Try positional argument
        GENERIC_RESULT=$($QQ_CMD auth_find_identity "$owner" 2>&1)
        GENERIC_AUTH_ID=$(echo "$GENERIC_RESULT" | jq -r '.auth_id // .id // empty' 2>/dev/null)

        if [ -n "$GENERIC_AUTH_ID" ]; then
            FOUND_TYPE=$(echo "$GENERIC_RESULT" | jq -r '.domain // empty' 2>/dev/null)
            FOUND_NAME=$(echo "$GENERIC_RESULT" | jq -r '.name // empty' 2>/dev/null)
            echo "" >&2
            echo "Found user successfully with positional lookup:" >&2
            echo "  Domain: $FOUND_TYPE" >&2
            echo "  Name: $FOUND_NAME" >&2
            echo "  Auth ID: $GENERIC_AUTH_ID" >&2
            echo "" >&2
            echo "This is likely a script bug - the identity was found but not extracted correctly." >&2
            echo "Using the found auth_id: $GENERIC_AUTH_ID" >&2
            OWNER_AUTH_ID="$GENERIC_AUTH_ID"
        else
            # Try one more time with --name and various formats
            for try_name in "$owner" "ad:$owner" "local:$owner"; do
                if [ "$verbose" = true ]; then
                    echo "[INFO] Trying lookup with: $try_name" >&2
                fi
                TRY_RESULT=$($QQ_CMD auth_find_identity --name "$try_name" --json 2>&1)
                TRY_AUTH_ID=$(echo "$TRY_RESULT" | jq -r '.auth_id // .id // empty' 2>/dev/null)
                if [ -n "$TRY_AUTH_ID" ]; then
                    echo "Found using name format: $try_name" >&2
                    OWNER_AUTH_ID="$TRY_AUTH_ID"
                    break
                fi
            done

            if [ -z "$OWNER_AUTH_ID" ]; then
                echo "User '$owner' not found in any domain" >&2
                echo "Try running: $QQ_CMD auth_find_identity $owner" >&2
                echo "Or: $QQ_CMD auth_find_identity --help" >&2
                exit 1
            fi
        fi
    fi

    if [ "$verbose" = true ]; then
        echo "[INFO] Resolved owner auth_id: $OWNER_AUTH_ID" >&2
    fi

    # If expand-identity is enabled, get all equivalent auth_ids
    if [ "$expand_identity" = true ]; then
        if [ "$verbose" = true ]; then
            echo "[INFO] Expanding identity to find equivalent auth_ids..." >&2
        fi

        # Use auth_expand_identity to get all equivalent IDs
        EXPAND_RESULT=$($QQ_CMD auth_expand_identity --auth-id "$OWNER_AUTH_ID" --json 2>/dev/null)

        if [ -n "$EXPAND_RESULT" ]; then
            # Extract all auth_ids from equivalent_ids, nfs_id, smb_id, and id
            EQUIVALENT_AUTH_IDS=$(echo "$EXPAND_RESULT" | jq -r '[
                .id.auth_id,
                .nfs_id.auth_id,
                .smb_id.auth_id,
                (.equivalent_ids[]?.auth_id // empty)
            ] | unique | .[]' 2>/dev/null | tr '\n' ' ')

            if [ -n "$EQUIVALENT_AUTH_IDS" ]; then
                if [ "$verbose" = true ]; then
                    echo "[INFO] Found equivalent auth_ids: $EQUIVALENT_AUTH_IDS" >&2
                fi
                # Return space-separated auth_ids
                echo "$EQUIVALENT_AUTH_IDS"
                return
            else
                if [ "$verbose" = true ]; then
                    echo "[WARN] Identity expansion returned no results, using original auth_id" >&2
                fi
            fi
        else
            if [ "$verbose" = true ]; then
                echo "[WARN] Could not expand identity, using original auth_id only" >&2
            fi
        fi
    fi

    # Return single auth_id
    echo "$OWNER_AUTH_ID"
}

# Resolve all owners to auth_ids if owner filter is specified
ALL_OWNER_AUTH_IDS=""
if [ ${#OWNERS[@]} -gt 0 ]; then
    if [ "$VERBOSE" = true ]; then
        echo "[INFO] Resolving ${#OWNERS[@]} owner(s)..." >&2
    fi

    for OWNER in "${OWNERS[@]}"; do
        RESOLVED_IDS=$(resolve_owner_identity "$OWNER" "$OWNER_TYPE" "$EXPAND_IDENTITY" "$VERBOSE")
        # Append to the list of all auth_ids (space-separated)
        if [ -n "$ALL_OWNER_AUTH_IDS" ]; then
            ALL_OWNER_AUTH_IDS="$ALL_OWNER_AUTH_IDS $RESOLVED_IDS"
        else
            ALL_OWNER_AUTH_IDS="$RESOLVED_IDS"
        fi
    done

    # Remove duplicates
    ALL_OWNER_AUTH_IDS=$(echo "$ALL_OWNER_AUTH_IDS" | tr ' ' '\n' | sort -u | tr '\n' ' ')

    if [ "$VERBOSE" = true ]; then
        echo "[INFO] Final auth_id list (OR filter): $ALL_OWNER_AUTH_IDS" >&2
    fi
fi

# Function to process a single directory path
process_directory() {
    local dir_path="$1"
    local qq_base=$(build_qq_cmd)
    local qq_cmd="$qq_base fs_walk_tree --path \"$dir_path\" --display-all-attributes"

    if [ "$FILE_ONLY" = true ]; then
        qq_cmd="$qq_cmd --file-only"
    fi
    if [ -n "$MAX_DEPTH" ]; then
        qq_cmd="$qq_cmd --max-depth $MAX_DEPTH"
    fi

    eval "$qq_cmd"
}

# If omit-subdirs is specified, we need to discover subdirectories first
if [ -n "$OMIT_SUBDIRS" ]; then
    # Use Python to handle directory filtering with proper space handling and wildcards
    {
        # First, process the root directory itself (max-depth 1, file-only)
        if [ "$VERBOSE" = true ]; then
            echo "[INFO] Processing root directory: $PATH_TO_SEARCH" >&2
        fi

        QQ_BASE=$(build_qq_cmd)
        ROOT_CMD="$QQ_BASE fs_walk_tree --path \"$PATH_TO_SEARCH\" --display-all-attributes --max-depth 1"
        if [ "$FILE_ONLY" = true ]; then
            ROOT_CMD="$ROOT_CMD --file-only"
        fi
        eval "$ROOT_CMD"

        # Then, process subdirectories (excluding omitted ones)
        $QQ_BASE fs_walk_tree --path "$PATH_TO_SEARCH" --max-depth 1 --display-all-attributes | \
        python3 -c "
import sys
import json
import subprocess
import shlex
import fnmatch

omit_patterns = shlex.split('$OMIT_SUBDIRS')
verbose = '$VERBOSE' == 'true'
qq_base = '$QQ_BASE'
data = json.load(sys.stdin)

def should_omit(dirname, patterns):
    \"\"\"Check if dirname matches any pattern (supports wildcards)\"\"\"
    for pattern in patterns:
        if fnmatch.fnmatch(dirname, pattern):
            return True, pattern
    return False, None

if verbose:
    print(f'[INFO] Omit patterns: {omit_patterns}', file=sys.stderr)
    print(f'[INFO] Scanning subdirectories in: $PATH_TO_SEARCH', file=sys.stderr)

processed_count = 0
omitted_count = 0

for node in data.get('tree_nodes', []):
    if node.get('type') == 'FS_FILE_TYPE_DIRECTORY':
        path = node.get('path', '')
        # Skip the root path itself (already processed above)
        if path in ['$PATH_TO_SEARCH', '$PATH_TO_SEARCH/']:
            continue

        # Get just the directory name
        dirname = node.get('name', '')

        # Skip if matches any omit pattern
        omit, matched_pattern = should_omit(dirname, omit_patterns)
        if omit:
            omitted_count += 1
            if verbose:
                print(f'[OMIT] Skipping directory \"{dirname}\" (matched pattern: {matched_pattern})', file=sys.stderr)
            continue

        # Process this directory
        if verbose:
            print(f'[PROCESS] Processing subdirectory: {dirname}', file=sys.stderr)

        processed_count += 1
        cmd = qq_base + ' fs_walk_tree --path ' + shlex.quote(path) + ' --display-all-attributes'
        if '$FILE_ONLY' == 'true':
            cmd += ' --file-only'
        if '$MAX_DEPTH':
            cmd += ' --max-depth $MAX_DEPTH'

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            sys.stdout.write(result.stdout)

if verbose:
    print(f'[INFO] Summary: {processed_count} subdirectories processed, {omitted_count} subdirectories omitted', file=sys.stderr)
"
    } | jq -c --stream
else
    # No subdirectory filtering, process normally
    process_directory "$PATH_TO_SEARCH" | jq -c --stream
fi | python3 -u -c "
import sys
import json
import csv
from datetime import datetime

# Ensure unbuffered output
sys.stdout.reconfigure(line_buffering=True)

threshold_older = '$threshold_older'
threshold_newer = '$threshold_newer'
comparison = '${comparison}'
output_json = '${OUTPUT_JSON}' == 'true'
output_csv = '$CSV_OUT_FILE' != ''
time_field = '$TIME_FIELD'
owner_auth_id = '$ALL_OWNER_AUTH_IDS'
all_attributes = '${ALL_ATTRIBUTES}' == 'true'
size_greater = '$SIZE_GREATER_BYTES'
size_smaller = '$SIZE_SMALLER_BYTES'
verbose = '${VERBOSE}' == 'true'

# Field-specific thresholds
accessed_threshold_older = '$ACCESSED_THRESHOLD_OLDER'
accessed_threshold_newer = '$ACCESSED_THRESHOLD_NEWER'
modified_threshold_older = '$MODIFIED_THRESHOLD_OLDER'
modified_threshold_newer = '$MODIFIED_THRESHOLD_NEWER'
created_threshold_older = '$CREATED_THRESHOLD_OLDER'
created_threshold_newer = '$CREATED_THRESHOLD_NEWER'
changed_threshold_older = '$CHANGED_THRESHOLD_OLDER'
changed_threshold_newer = '$CHANGED_THRESHOLD_NEWER'

# Calculate threshold_str values only if thresholds are provided (legacy)
threshold_older_str = ''
threshold_newer_str = ''
if threshold_older:
    threshold_older_str = datetime.utcfromtimestamp(int(threshold_older)).strftime('%Y-%m-%dT%H:%M:%S') + '.000000000Z'
if threshold_newer:
    threshold_newer_str = datetime.utcfromtimestamp(int(threshold_newer)).strftime('%Y-%m-%dT%H:%M:%S') + '.000000000Z'

# Convert field-specific thresholds to timestamp strings
def to_timestamp_str(ts):
    if ts:
        return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%dT%H:%M:%S') + '.000000000Z'
    return ''

accessed_older_str = to_timestamp_str(accessed_threshold_older)
accessed_newer_str = to_timestamp_str(accessed_threshold_newer)
modified_older_str = to_timestamp_str(modified_threshold_older)
modified_newer_str = to_timestamp_str(modified_threshold_newer)
created_older_str = to_timestamp_str(created_threshold_older)
created_newer_str = to_timestamp_str(created_threshold_newer)
changed_older_str = to_timestamp_str(changed_threshold_older)
changed_newer_str = to_timestamp_str(changed_threshold_newer)

current_obj = {}
current_idx = None

def matches_filter(time_value):
    # Legacy time filter (for backward compatibility with --older-than/--newer-than + --accessed/--modified etc.)
    if not comparison:
        return True

    if comparison == 'range':
        return time_value > threshold_older_str and time_value < threshold_newer_str
    elif comparison == 'older':
        return time_value < threshold_older_str
    elif comparison == 'newer':
        return time_value > threshold_newer_str

    return True

def matches_field_specific_time_filters(obj):
    # Check field-specific time filters (all must match - AND logic)

    # Access time filter
    if accessed_older_str or accessed_newer_str:
        access_time = obj.get('access_time')
        if not access_time:
            return False
        if accessed_older_str and accessed_newer_str:
            # Range
            if not (access_time > accessed_older_str and access_time < accessed_newer_str):
                return False
        elif accessed_older_str:
            if not access_time < accessed_older_str:
                return False
        elif accessed_newer_str:
            if not access_time > accessed_newer_str:
                return False

    # Modification time filter
    if modified_older_str or modified_newer_str:
        modification_time = obj.get('modification_time')
        if not modification_time:
            return False
        if modified_older_str and modified_newer_str:
            # Range
            if not (modification_time > modified_older_str and modification_time < modified_newer_str):
                return False
        elif modified_older_str:
            if not modification_time < modified_older_str:
                return False
        elif modified_newer_str:
            if not modification_time > modified_newer_str:
                return False

    # Creation time filter
    if created_older_str or created_newer_str:
        creation_time = obj.get('creation_time')
        if not creation_time:
            return False
        if created_older_str and created_newer_str:
            # Range
            if not (creation_time > created_older_str and creation_time < created_newer_str):
                return False
        elif created_older_str:
            if not creation_time < created_older_str:
                return False
        elif created_newer_str:
            if not creation_time > created_newer_str:
                return False

    # Change time filter
    if changed_older_str or changed_newer_str:
        change_time = obj.get('change_time')
        if not change_time:
            return False
        if changed_older_str and changed_newer_str:
            # Range
            if not (change_time > changed_older_str and change_time < changed_newer_str):
                return False
        elif changed_older_str:
            if not change_time < changed_older_str:
                return False
        elif changed_newer_str:
            if not change_time > changed_newer_str:
                return False

    return True

def matches_owner(file_owner):
    # If no owner filter specified, match everything
    if not owner_auth_id:
        return True
    # Support multiple auth_ids (space-separated from identity expansion)
    owner_ids = owner_auth_id.split()
    return file_owner in owner_ids

def matches_size(file_size):
    # If no size filter specified, match everything
    if not size_greater and not size_smaller:
        return True

    # Handle missing file_size
    if not file_size:
        return False

    # Convert file_size to int for comparison
    try:
        size_bytes = int(file_size)
    except (ValueError, TypeError):
        return False

    # Check size filters (both can be specified for range filtering)
    if size_greater and size_smaller:
        # Range: file must be greater than min AND smaller than max
        return size_bytes > int(size_greater) and size_bytes < int(size_smaller)
    elif size_greater:
        return size_bytes > int(size_greater)
    elif size_smaller:
        return size_bytes < int(size_smaller)
    return True

json_out_file = '$JSON_OUT_FILE'
csv_out_file = '$CSV_OUT_FILE'
json_file_handle = None
csv_file_handle = None
csv_writer = None
csv_header_written = False

if json_out_file:
    json_file_handle = open(json_out_file, 'w')

if csv_out_file:
    csv_file_handle = open(csv_out_file, 'w', newline='')
    csv_writer = csv.writer(csv_file_handle)

for line in sys.stdin:
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue

    if len(item) == 2 and len(item[0]) >= 3 and item[0][0] == 'tree_nodes':
        idx = item[0][1]
        key = item[0][2]
        val = item[1]

        # New object detected
        if idx != current_idx:
            # Process previous object
            # Check if we have minimum required data (path, and time_field if time filter is used)
            has_required_data = current_obj.get('path') and (not comparison or current_obj.get(time_field))
            if has_required_data:
                # AND logic: all specified filters must match
                time_match = matches_filter(current_obj.get(time_field))
                field_time_match = matches_field_specific_time_filters(current_obj)
                owner_match = matches_owner(current_obj.get('owner'))
                size_match = matches_size(current_obj.get('size'))

                if time_match and field_time_match and owner_match and size_match:
                    if output_csv:
                        # CSV output
                        if all_attributes:
                            # Write header on first row
                            if not csv_header_written:
                                csv_writer.writerow(sorted(current_obj.keys()))
                                csv_header_written = True
                            # Write values in same order as header
                            csv_writer.writerow([current_obj.get(k, '') for k in sorted(current_obj.keys())])
                        else:
                            # Write selective fields
                            row_data = {'path': current_obj['path']}
                            if comparison and time_field in current_obj:
                                row_data[time_field] = current_obj[time_field]
                            if owner_auth_id and 'owner' in current_obj:
                                row_data['owner'] = current_obj['owner']
                            if (size_greater or size_smaller) and 'size' in current_obj:
                                row_data['size'] = current_obj['size']

                            if not csv_header_written:
                                csv_writer.writerow(row_data.keys())
                                csv_header_written = True
                            csv_writer.writerow(row_data.values())
                        csv_file_handle.flush()
                    elif output_json:
                        if all_attributes:
                            # Include all attributes
                            output = json.dumps(current_obj)
                        else:
                            # Include path and any fields used in filtering
                            filtered_obj = {'path': current_obj['path']}

                            # Add time field if time filter was used
                            if comparison and time_field in current_obj:
                                filtered_obj[time_field] = current_obj[time_field]

                            # Add owner if owner filter was used
                            if owner_auth_id and 'owner' in current_obj:
                                filtered_obj['owner'] = current_obj['owner']

                            # Add size if size filter was used
                            if (size_greater or size_smaller) and 'size' in current_obj:
                                filtered_obj['size'] = current_obj['size']

                            output = json.dumps(filtered_obj)
                        if json_file_handle:
                            json_file_handle.write(output + '\n')
                            json_file_handle.flush()
                        else:
                            print(output)
                    else:
                        if comparison and time_field in current_obj:
                            print(current_obj[time_field])
                        print(current_obj['path'])

            # Reset for new object
            current_obj = {}
            current_idx = idx

        # Collect all attributes if --all-attributes, otherwise just what we need
        if all_attributes:
            current_obj[key] = val
        elif key in ('path', 'creation_time', 'access_time', 'modification_time', 'change_time', 'owner', 'size'):
            current_obj[key] = val

# Process final object
# Check if we have minimum required data (path, and time_field if time filter is used)
has_required_data = current_obj.get('path') and (not comparison or current_obj.get(time_field))
if has_required_data:
    # AND logic: all specified filters must match
    time_match = matches_filter(current_obj.get(time_field))
    field_time_match = matches_field_specific_time_filters(current_obj)
    owner_match = matches_owner(current_obj.get('owner'))
    size_match = matches_size(current_obj.get('size'))

    if time_match and field_time_match and owner_match and size_match:
        if output_csv:
            # CSV output
            if all_attributes:
                # Write header on first row
                if not csv_header_written:
                    csv_writer.writerow(sorted(current_obj.keys()))
                    csv_header_written = True
                # Write values in same order as header
                csv_writer.writerow([current_obj.get(k, '') for k in sorted(current_obj.keys())])
            else:
                # Write selective fields
                row_data = {'path': current_obj['path']}
                if comparison and time_field in current_obj:
                    row_data[time_field] = current_obj[time_field]
                if owner_auth_id and 'owner' in current_obj:
                    row_data['owner'] = current_obj['owner']
                if (size_greater or size_smaller) and 'size' in current_obj:
                    row_data['size'] = current_obj['size']

                if not csv_header_written:
                    csv_writer.writerow(row_data.keys())
                    csv_header_written = True
                csv_writer.writerow(row_data.values())
            csv_file_handle.flush()
        elif output_json:
            if all_attributes:
                # Include all attributes
                output = json.dumps(current_obj)
            else:
                # Include path and any fields used in filtering
                filtered_obj = {'path': current_obj['path']}

                # Add time field if time filter was used
                if comparison and time_field in current_obj:
                    filtered_obj[time_field] = current_obj[time_field]

                # Add owner if owner filter was used
                if owner_auth_id and 'owner' in current_obj:
                    filtered_obj['owner'] = current_obj['owner']

                # Add size if size filter was used
                if (size_greater or size_smaller) and 'size' in current_obj:
                    filtered_obj['size'] = current_obj['size']

                output = json.dumps(filtered_obj)
            if json_file_handle:
                json_file_handle.write(output + '\n')
                json_file_handle.flush()
            else:
                print(output)
        else:
            if comparison and time_field in current_obj:
                print(current_obj[time_field])
            print(current_obj['path'])

if json_file_handle:
    json_file_handle.close()
if csv_file_handle:
    csv_file_handle.close()
"
