#!/bin/bash

# Qumulo File Filter - Linux/GNU version
# Filter files by age from qq fs_walk_tree output using streaming to avoid OOM
# Usage: ./qumulo_file_filter.sh --path <path> (--older-than <days> | --newer-than <days>) [--created | --accessed | --modified | --changed] [--max-depth <depth>] [--file-only | --all] [--omit-subdirs "pattern1 pattern2"] [--json | --json-out <file>] [--verbose]
# Example: ./qumulo_file_filter.sh --path /home --older-than 30 --accessed --max-depth 1 --file-only --omit-subdirs "temp cache 100k*" --json-out results.json --verbose

set -euo pipefail

# Default values
PATH_TO_SEARCH=""
OLDER_THAN=""
NEWER_THAN=""
MAX_DEPTH=""
FILE_ONLY=false
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
LARGER_THAN=""
SMALLER_THAN=""
QQ_HOST=""
QQ_CREDENTIALS_STORE=""
OWNER_REPORT=false
MAX_WORKERS=10
LIMIT=""
PROGRESS=false
INCLUDE_METADATA=false

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
        --larger-than)
            LARGER_THAN="$2"
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
        --owner-report)
            OWNER_REPORT=true
            shift
            ;;
        --max-workers)
            MAX_WORKERS="$2"
            shift 2
            ;;
        --limit)
            LIMIT="$2"
            shift 2
            ;;
        --progress)
            PROGRESS=true
            shift
            ;;
        --include-metadata)
            INCLUDE_METADATA=true
            shift
            ;;
        --help|-h)
            cat << 'EOF'
Qumulo File Filter - Linux/GNU version

Usage:
  qumulo_file_filter.sh --path <path> [--older-than <days> | --newer-than <days>] [OPTIONS]

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
  --larger-than <size>       Find files larger than specified size
  --smaller-than <size>      Find files smaller than specified size
                             Both can be used together for range filtering
                             Supported units: B, KB, MB, GB, TB, PB, KiB, MiB, GiB, TiB, PiB
                             Examples: 100MB, 1.5GiB, 500, 10KB
  --include-metadata         Include metadata blocks in size calculations (metablocks * 4KB)

Owner Filter Options:
  --owner <name>             Filter by file owner (can be specified multiple times for OR logic)
  --ad                       Owner(s) are Active Directory users
  --local                    Owner(s) are local users
  --uid                      Owner(s) are specified as UID numbers
  --expand-identity          Match all equivalent identities (e.g., AD user + NFS UID)
                             Note: Cannot mix --uid with --ad or --local

Search Options:
  --max-depth <N>            Maximum directory depth to search
  --file-only                Search files only
  --all                      Search both files and directories (default)
  --omit-subdirs "patterns"  Space-separated patterns to omit (supports wildcards)

Output Options:
  --json                     Output results as JSON to stdout
  --json-out <file>          Write JSON results to file (allows --verbose)
  --csv-out <file>           Write results to CSV file (mutually exclusive with --json/--json-out)
  --verbose                  Show detailed logging to stderr
  --all-attributes           Include all file attributes in JSON output (default: path + time field only)
  --owner-report             Generate usage report by file owner (auto-enables --all-attributes)
  --max-workers <N>          Number of parallel workers for owner resolution (default: 10)
  --limit <N>                Stop after finding N matching results (useful for quick sampling/testing)
  --progress                 Show real-time progress stats (objects processed, matches found, rate)

Qumulo Connection Options:
  --host <host>              Qumulo cluster hostname or IP
  --credentials-store <path> Path to credentials file (default: ~/.qfsd_cred)

Examples:
  # Find files created more than 30 days ago
  qumulo_file_filter.sh --path /home --older-than 30

  # Find files owned by a user with identity expansion (Match Names to UID Numbers or vice versa)
  qumulo_file_filter.sh --path /home --owner jdoe --expand-identity

  # Find files in size and time ranges, save to CSV
  qumulo_file_filter.sh --path /home --older-than 90 --larger-than 1GB --smaller-than 10GB --csv-out results.csv

  # Exclude directories and limit depth
  qumulo_file_filter.sh --path /home --older-than 30 --omit-subdirs "temp cache" --max-depth 3

  # Complex multi-field query with multiple conditions
  qumulo_file_filter.sh --path /home --accessed-newer-than 10 --accessed-older-than 30 \
    --modified-older-than 20 --created-older-than 100 --owner joe

  # Generate owner usage report
  qumulo_file_filter.sh --path /home --owner-report --csv-out owner_report.csv
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

# Allow both --larger-than and --smaller-than for range filtering

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

# Note: --owner-report does NOT auto-enable --all-attributes
# Owner reports only need 'owner' and 'size' fields for aggregation
# Users can manually specify --all-attributes if needed for other purposes

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
SIZE_LARGER_BYTES=""
SIZE_SMALLER_BYTES=""
if [ -n "$LARGER_THAN" ]; then
    SIZE_LARGER_BYTES=$(parse_size_to_bytes "$LARGER_THAN")
    if [ "$VERBOSE" = true ]; then
        echo "[INFO] Size filter: larger than $SIZE_LARGER_BYTES bytes ($LARGER_THAN)" >&2
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
        # Scan root directory once and output results + discover subdirectories for parallel processing
        if [ "$VERBOSE" = true ]; then
            echo "[INFO] Scanning root directory for filtering and subdirectory discovery: $PATH_TO_SEARCH" >&2
        fi

        QQ_BASE=$(build_qq_cmd)
        # Then, process subdirectories (excluding omitted ones) in parallel
        $QQ_BASE fs_walk_tree --path "$PATH_TO_SEARCH" --max-depth 1 --display-all-attributes | \
        python3 -c "
import sys
import json
import subprocess
import shlex
import fnmatch
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

omit_patterns = shlex.split('$OMIT_SUBDIRS')
verbose = '$VERBOSE' == 'true'
qq_base = '$QQ_BASE'
max_workers_config = int('$MAX_WORKERS') if '$MAX_WORKERS' else 10
data = json.load(sys.stdin)

# Output root-level results immediately (apply file-only filter if requested)
if '$FILE_ONLY' == 'true':
    # Filter out directories from tree_nodes for output
    filtered_data = dict(data)
    filtered_data['tree_nodes'] = [
        node for node in data.get('tree_nodes', [])
        if node.get('type') != 'FS_FILE_TYPE_DIRECTORY'
    ]
    sys.stdout.write(json.dumps(filtered_data))
else:
    sys.stdout.write(json.dumps(data))

sys.stdout.flush()

def should_omit(dirname, patterns):
    \"\"\"Check if dirname matches any pattern (supports wildcards)\"\"\"
    for pattern in patterns:
        if fnmatch.fnmatch(dirname, pattern):
            return True, pattern
    return False, None

def process_directory(path, dirname):
    \"\"\"Process a single directory and return its output.\"\"\"
    cmd = qq_base + ' fs_walk_tree --path ' + shlex.quote(path) + ' --display-all-attributes'
    if '$FILE_ONLY' == 'true':
        cmd += ' --file-only'
    if '$MAX_DEPTH':
        # Subtract 1 from max-depth since we already descended one level from root
        remaining_depth = int('$MAX_DEPTH') - 1
        if remaining_depth > 0:
            cmd += f' --max-depth {remaining_depth}'
        # If remaining_depth <= 0, don't add max-depth flag (only process this directory)

    if verbose:
        print(f'[PROCESS] Processing subdirectory: {dirname}', file=sys.stderr)

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout, dirname, True
    else:
        return '', dirname, False

if verbose:
    print(f'[INFO] Omit patterns: {omit_patterns}', file=sys.stderr)
    print(f'[INFO] Scanning subdirectories in: $PATH_TO_SEARCH', file=sys.stderr)

# First, collect all directories to process
dirs_to_process = []
omitted_count = 0

for node in data.get('tree_nodes', []):
    if node.get('type') == 'FS_FILE_TYPE_DIRECTORY':
        path = node.get('path', '')
        # Skip the root path itself (we only want its immediate subdirectories)
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

        dirs_to_process.append((path, dirname))

# Smart worker scaling: Use min(max_workers_config, actual tasks, 2x CPU cores)
cpu_count = os.cpu_count() or 1
optimal_workers = min(max_workers_config, len(dirs_to_process), cpu_count * 2)

if verbose:
    print(f'[INFO] Processing {len(dirs_to_process)} subdirectories with {optimal_workers} parallel workers (CPUs: {cpu_count}, max configured: {max_workers_config})...', file=sys.stderr)

# Process directories in parallel
processed_count = 0
if dirs_to_process:
    try:
        with ThreadPoolExecutor(max_workers=optimal_workers) as executor:
            # Submit all directory processing tasks
            future_to_dir = {
                executor.submit(process_directory, path, dirname): (path, dirname)
                for path, dirname in dirs_to_process
            }

            # Collect results as they complete and write immediately
            for future in as_completed(future_to_dir):
                path, dirname = future_to_dir[future]
                try:
                    output, dirname, success = future.result()
                    if success:
                        sys.stdout.write(output)
                        processed_count += 1
                        if verbose and processed_count % 10 == 0:
                            print(f'[INFO] Processed {processed_count}/{len(dirs_to_process)} subdirectories...', file=sys.stderr)
                except Exception as e:
                    if verbose:
                        print(f'[ERROR] Failed to process directory {dirname}: {e}', file=sys.stderr)
    except Exception as e:
        if verbose:
            print(f'[ERROR] Parallel processing failed: {e}, falling back to sequential', file=sys.stderr)
        # Fallback to sequential processing if parallel fails
        for path, dirname in dirs_to_process:
            output, dirname, success = process_directory(path, dirname)
            if success:
                sys.stdout.write(output)
                processed_count += 1

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
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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
size_larger = '$SIZE_LARGER_BYTES'
size_smaller = '$SIZE_SMALLER_BYTES'
verbose = '${VERBOSE}' == 'true'
owner_report = '${OWNER_REPORT}' == 'true'
qq_host = '$QQ_HOST'
qq_creds = '$QQ_CREDENTIALS_STORE'
max_workers = int('$MAX_WORKERS') if '$MAX_WORKERS' else 10
limit = int('$LIMIT') if '$LIMIT' else 0
match_count = 0
progress = '${PROGRESS}' == 'true'
progress_interval = 1000  # Report progress every N objects
objects_processed = 0
start_time = None
include_metadata = '${INCLUDE_METADATA}' == 'true'

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

def calculate_total_size(file_size, metablocks):
    # Calculate total size including metadata if requested
    # Each metablock is 4KB (4096 bytes)
    size_bytes = 0
    try:
        size_bytes = int(file_size) if file_size else 0
    except (ValueError, TypeError):
        size_bytes = 0

    if include_metadata and metablocks:
        try:
            metadata_bytes = int(metablocks) * 4096
            size_bytes += metadata_bytes
        except (ValueError, TypeError):
            pass  # If metablocks is invalid, just use file size

    return size_bytes

def matches_size(file_size, metablocks=None):
    # If no size filter specified, match everything
    if not size_larger and not size_smaller:
        return True

    # Handle missing file_size
    if not file_size:
        return False

    # Calculate total size (file + metadata if requested)
    size_bytes = calculate_total_size(file_size, metablocks)

    if size_bytes == 0:
        return False

    # Check size filters (both can be specified for range filtering)
    if size_larger and size_smaller:
        # Range: file must be larger than min AND smaller than max
        return size_bytes > int(size_larger) and size_bytes < int(size_smaller)
    elif size_larger:
        return size_bytes > int(size_larger)
    elif size_smaller:
        return size_bytes < int(size_smaller)
    return True

json_out_file = '$JSON_OUT_FILE'
csv_out_file = '$CSV_OUT_FILE'
json_file_handle = None
csv_file_handle = None
csv_writer = None
csv_header_written = False

# Batch processing for large result sets (100k+)
batch_size = 1000  # Flush output every N results
json_batch = []
csv_batch = []

def flush_json_batch():
    \"\"\"Flush accumulated JSON results to output.\"\"\"
    if not json_batch:
        return
    if json_file_handle:
        for item in json_batch:
            json_file_handle.write(item + '\n')
        json_file_handle.flush()
    else:
        for item in json_batch:
            print(item)
    json_batch.clear()

def flush_csv_batch():
    \"\"\"Flush accumulated CSV rows to output.\"\"\"
    if not csv_batch:
        return
    for row in csv_batch:
        csv_writer.writerow(row)
    csv_file_handle.flush()
    csv_batch.clear()

# Owner report aggregation data
# When --include-metadata is used, we track data and metadata separately
# Structure: auth_id -> {'data': bytes, 'metadata': bytes} if include_metadata
#            auth_id -> total_bytes (int) if not include_metadata
owner_aggregates = {}
owner_name_cache = {}  # auth_id -> resolved_name

def resolve_owner_name(auth_id):
    \"\"\"Resolve owner auth_id to human-readable name using qq auth_find_identity with caching.\"\"\"
    if auth_id in owner_name_cache:
        return owner_name_cache[auth_id]

    try:
        import subprocess

        # Build qq command with connection options
        qq_cmd = ['qq']
        if qq_host:
            qq_cmd.extend(['--host', qq_host])
        if qq_creds:
            qq_cmd.extend(['--credentials-store', qq_creds])
        qq_cmd.extend(['auth_find_identity', '--auth-id', auth_id, '--json'])

        if verbose:
            print(f'[INFO] Resolving auth_id {auth_id} to name...', file=sys.stderr)

        result = subprocess.run(qq_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            try:
                identity = json.loads(result.stdout)
                # Try to get name from various fields
                name = identity.get('name') or identity.get('sid') or identity.get('uid') or auth_id

                # Check if we got a POSIX user SID (S-1-5-88-1-*) which indicates a UID
                # These SIDs encode the UID in the last component: S-1-5-88-1-{UID}
                if isinstance(name, str) and name.startswith('S-1-5-88-1-'):
                    # Extract UID from SID
                    try:
                        uid = name.split('-')[-1]
                        if verbose:
                            print(f'[INFO] Detected POSIX user SID {name}, extracting UID {uid}', file=sys.stderr)

                        # Try to resolve UID to username using auth_expand_identity
                        expand_cmd = ['qq']
                        if qq_host:
                            expand_cmd.extend(['--host', qq_host])
                        if qq_creds:
                            expand_cmd.extend(['--credentials-store', qq_creds])
                        expand_cmd.extend(['auth_expand_identity', '--auth-id', auth_id, '--json'])

                        expand_result = subprocess.run(expand_cmd, capture_output=True, text=True)
                        if expand_result.returncode == 0:
                            expand_data = json.loads(expand_result.stdout)
                            # Look for AD identity with a name
                            for equiv in expand_data.get('equivalent_ids', []):
                                if equiv.get('name') and equiv.get('domain') == 'ACTIVE_DIRECTORY':
                                    name = equiv['name']
                                    if verbose:
                                        print(f'[INFO] Resolved UID {uid} to AD user: {name}', file=sys.stderr)
                                    break
                            # If no AD name found, check main identity
                            if name.startswith('S-1-5-88-1-'):
                                main_name = expand_data.get('id', {}).get('name')
                                if main_name:
                                    name = main_name
                                    if verbose:
                                        print(f'[INFO] Resolved UID {uid} to: {name}', file=sys.stderr)
                    except (IndexError, ValueError, json.JSONDecodeError) as e:
                        if verbose:
                            print(f'[WARN] Could not resolve POSIX SID to username: {e}', file=sys.stderr)

                # Format name nicely
                if isinstance(name, str) and name:
                    owner_name_cache[auth_id] = name
                else:
                    # Fall back to auth_id if no name found
                    owner_name_cache[auth_id] = f'auth_id:{auth_id}'

                if verbose:
                    print(f'[INFO] Resolved auth_id {auth_id} to: {owner_name_cache[auth_id]}', file=sys.stderr)

                return owner_name_cache[auth_id]
            except json.JSONDecodeError:
                pass

        # If resolution fails, use auth_id as fallback
        if verbose:
            print(f'[WARN] Could not resolve auth_id {auth_id}, using auth_id as name', file=sys.stderr)
        owner_name_cache[auth_id] = f'auth_id:{auth_id}'
        return owner_name_cache[auth_id]

    except Exception as e:
        if verbose:
            print(f'[ERROR] Exception resolving auth_id {auth_id}: {e}', file=sys.stderr)
        owner_name_cache[auth_id] = f'auth_id:{auth_id}'
        return owner_name_cache[auth_id]

if json_out_file:
    json_file_handle = open(json_out_file, 'w')

if csv_out_file:
    csv_file_handle = open(csv_out_file, 'w', newline='')
    csv_writer = csv.writer(csv_file_handle)

# Initialize start time for progress reporting
if progress:
    start_time = time.time()

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
            # Increment objects processed counter
            objects_processed += 1

            # Report progress periodically
            if progress and objects_processed % progress_interval == 0:
                elapsed = time.time() - start_time
                rate = objects_processed / elapsed if elapsed > 0 else 0
                # Use carriage return to overwrite the same line
                print(f'\r[PROGRESS] Processed: {objects_processed:,} objects | Matches: {match_count:,} | Rate: {rate:.1f} obj/sec | Elapsed: {elapsed:.1f}s', end='', file=sys.stderr, flush=True)
            # Process previous object
            # Check if we have minimum required data (path, and time_field if time filter is used)
            has_required_data = current_obj.get('path') and (not comparison or current_obj.get(time_field))
            if has_required_data:
                # AND logic with short-circuit evaluation: check cheapest filters first
                # Order: size (int) -> owner (dict lookup) -> time (string) -> field-time (multiple strings)
                if not matches_size(current_obj.get('size'), current_obj.get('metablocks')):
                    # Reset for new object
                    current_obj = {}
                    current_idx = idx
                    continue

                if not matches_owner(current_obj.get('owner')):
                    # Reset for new object
                    current_obj = {}
                    current_idx = idx
                    continue

                if not matches_filter(current_obj.get(time_field)):
                    # Reset for new object
                    current_obj = {}
                    current_idx = idx
                    continue

                if not matches_field_specific_time_filters(current_obj):
                    # Reset for new object
                    current_obj = {}
                    current_idx = idx
                    continue

                # All filters passed
                # Increment match count for progress reporting
                match_count += 1

                # Check limit (only for non-owner_report output)
                if not owner_report and limit and match_count > limit:
                    if verbose:
                        print(f'[INFO] Reached limit of {limit} matches, stopping...', file=sys.stderr)
                    break

                if owner_report:
                    # Aggregate by owner instead of outputting individual files
                    file_owner = current_obj.get('owner')
                    file_size = current_obj.get('size', 0)
                    file_metablocks = current_obj.get('metablocks')
                    if file_owner:
                        try:
                            data_bytes = int(file_size) if file_size else 0
                            metadata_bytes = 0
                            if include_metadata and file_metablocks:
                                metadata_bytes = int(file_metablocks) * 4096

                            if file_owner not in owner_aggregates:
                                if include_metadata:
                                    owner_aggregates[file_owner] = {'data': 0, 'metadata': 0}
                                else:
                                    owner_aggregates[file_owner] = 0

                            if include_metadata:
                                owner_aggregates[file_owner]['data'] += data_bytes
                                owner_aggregates[file_owner]['metadata'] += metadata_bytes
                            else:
                                owner_aggregates[file_owner] += data_bytes
                        except (ValueError, TypeError):
                            pass  # Skip files with invalid size
                elif output_csv:
                    # CSV output with batching
                    if all_attributes:
                        # Write header on first row
                        if not csv_header_written:
                            csv_writer.writerow(sorted(current_obj.keys()))
                            csv_header_written = True
                        # Add to batch instead of writing immediately
                        csv_batch.append([current_obj.get(k, '') for k in sorted(current_obj.keys())])
                    else:
                        # Write selective fields
                        row_data = {'path': current_obj['path']}
                        if comparison and time_field in current_obj:
                            row_data[time_field] = current_obj[time_field]
                        if owner_auth_id and 'owner' in current_obj:
                            row_data['owner'] = current_obj['owner']
                        if (size_larger or size_smaller) and 'size' in current_obj:
                            row_data['size'] = current_obj['size']

                        if not csv_header_written:
                            csv_writer.writerow(row_data.keys())
                            csv_header_written = True
                        csv_batch.append(list(row_data.values()))

                    # Flush batch when it reaches batch_size
                    if len(csv_batch) >= batch_size:
                        flush_csv_batch()
                elif output_json:
                    # JSON output with batching
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
                        if (size_larger or size_smaller) and 'size' in current_obj:
                            filtered_obj['size'] = current_obj['size']

                        output = json.dumps(filtered_obj)

                    # Add to batch instead of writing immediately
                    json_batch.append(output)

                    # Flush batch when it reaches batch_size
                    if len(json_batch) >= batch_size:
                        flush_json_batch()
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
        elif key in ('path', 'creation_time', 'access_time', 'modification_time', 'change_time', 'owner', 'size', 'metablocks'):
            current_obj[key] = val

# Process final object
# Check if we have minimum required data (path, and time_field if time filter is used)
has_required_data = current_obj.get('path') and (not comparison or current_obj.get(time_field))
if has_required_data:
    # AND logic with short-circuit evaluation: check cheapest filters first
    # Order: size (int) -> owner (dict lookup) -> time (string) -> field-time (multiple strings)
    if matches_size(current_obj.get('size'), current_obj.get('metablocks')) and \
       matches_owner(current_obj.get('owner')) and \
       matches_filter(current_obj.get(time_field)) and \
       matches_field_specific_time_filters(current_obj):
        # Increment match count for progress reporting
        match_count += 1

        # Check limit (only for non-owner_report output)
        if not owner_report and limit and match_count > limit:
            if verbose:
                print(f'[INFO] Reached limit of {limit} matches (skipping final object)', file=sys.stderr)

        # Only output if limit not exceeded (or owner_report which doesn't use limit)
        if owner_report or not limit or match_count <= limit:
            if owner_report:
                # Aggregate by owner instead of outputting individual files
                file_owner = current_obj.get('owner')
                file_size = current_obj.get('size', 0)
                file_metablocks = current_obj.get('metablocks')
                if file_owner:
                    try:
                        data_bytes = int(file_size) if file_size else 0
                        metadata_bytes = 0
                        if include_metadata and file_metablocks:
                            metadata_bytes = int(file_metablocks) * 4096

                        if file_owner not in owner_aggregates:
                            if include_metadata:
                                owner_aggregates[file_owner] = {'data': 0, 'metadata': 0}
                            else:
                                owner_aggregates[file_owner] = 0

                        if include_metadata:
                            owner_aggregates[file_owner]['data'] += data_bytes
                            owner_aggregates[file_owner]['metadata'] += metadata_bytes
                        else:
                            owner_aggregates[file_owner] += data_bytes
                    except (ValueError, TypeError):
                        pass  # Skip files with invalid size
            elif output_csv:
                # CSV output with batching
                if all_attributes:
                    # Write header on first row
                    if not csv_header_written:
                        csv_writer.writerow(sorted(current_obj.keys()))
                        csv_header_written = True
                    # Add to batch (final flush will handle it)
                    csv_batch.append([current_obj.get(k, '') for k in sorted(current_obj.keys())])
                else:
                    # Write selective fields
                    row_data = {'path': current_obj['path']}
                    if comparison and time_field in current_obj:
                        row_data[time_field] = current_obj[time_field]
                    if owner_auth_id and 'owner' in current_obj:
                        row_data['owner'] = current_obj['owner']
                    if (size_larger or size_smaller) and 'size' in current_obj:
                        row_data['size'] = current_obj['size']

                    if not csv_header_written:
                        csv_writer.writerow(row_data.keys())
                        csv_header_written = True
                    # Add to batch (final flush will handle it)
                    csv_batch.append(list(row_data.values()))
            elif output_json:
                # JSON output with batching
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
                    if (size_larger or size_smaller) and 'size' in current_obj:
                        filtered_obj['size'] = current_obj['size']

                    output = json.dumps(filtered_obj)

                # Add to batch (final flush will handle it)
                json_batch.append(output)
            else:
                if comparison and time_field in current_obj:
                    print(current_obj[time_field])
                print(current_obj['path'])

# Output owner report if requested
if owner_report and owner_aggregates:
    if verbose:
        print(f'[INFO] Generating owner report for {len(owner_aggregates)} unique owners...', file=sys.stderr)

    # Resolve all owner names in parallel for better performance
    # Use ThreadPoolExecutor to parallelize API calls (I/O bound operation)
    owner_report_data = []

    # Prepare data structure for parallel processing
    auth_ids = list(owner_aggregates.keys())

    # Smart worker scaling: Use min(max_workers, actual tasks, 2x CPU cores)
    import os
    cpu_count = os.cpu_count() or 1
    optimal_workers = min(max_workers, len(auth_ids), cpu_count * 2)

    if verbose:
        print(f'[INFO] Resolving owner names using {optimal_workers} parallel workers (CPUs: {cpu_count}, tasks: {len(auth_ids)}, max configured: {max_workers})...', file=sys.stderr)

    # Parallel resolution with error handling
    owner_name_map = {}
    try:
        with ThreadPoolExecutor(max_workers=optimal_workers) as executor:
            # Submit all resolution tasks
            future_to_auth_id = {
                executor.submit(resolve_owner_name, auth_id): auth_id
                for auth_id in auth_ids
            }

            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_auth_id):
                auth_id = future_to_auth_id[future]
                try:
                    owner_name = future.result()
                    owner_name_map[auth_id] = owner_name
                    completed += 1
                    if verbose and completed % 10 == 0:
                        print(f'[INFO] Resolved {completed}/{len(auth_ids)} owners...', file=sys.stderr)
                except Exception as e:
                    if verbose:
                        print(f'[ERROR] Failed to resolve auth_id {auth_id}: {e}', file=sys.stderr)
                    # Fallback to auth_id as name
                    owner_name_map[auth_id] = f'auth_id:{auth_id}'
    except Exception as e:
        if verbose:
            print(f'[ERROR] Parallel resolution failed: {e}, falling back to sequential', file=sys.stderr)
        # Fallback to sequential processing if parallel fails
        for auth_id in auth_ids:
            try:
                owner_name_map[auth_id] = resolve_owner_name(auth_id)
            except Exception as fallback_error:
                if verbose:
                    print(f'[ERROR] Failed to resolve {auth_id}: {fallback_error}', file=sys.stderr)
                owner_name_map[auth_id] = f'auth_id:{auth_id}'

    # Build report data using resolved names
    for auth_id, size_data in owner_aggregates.items():
        owner_name = owner_name_map.get(auth_id, f'auth_id:{auth_id}')

        if include_metadata:
            # Separate columns for data and metadata
            data_bytes = size_data['data']
            metadata_bytes = size_data['metadata']
            total_bytes = data_bytes + metadata_bytes
            owner_report_data.append({
                'owner': owner_name,
                'auth_id': auth_id,
                'data_capacity_bytes': data_bytes,
                'metadata_capacity_bytes': metadata_bytes,
                'total_capacity_bytes': total_bytes
            })
        else:
            # Single total column
            owner_report_data.append({
                'owner': owner_name,
                'auth_id': auth_id,
                'total_capacity_bytes': size_data
            })

    # Sort by total size descending
    owner_report_data.sort(key=lambda x: x['total_capacity_bytes'], reverse=True)

    if output_csv or csv_file_handle:
        # CSV output
        if not csv_file_handle:
            csv_file_handle = open(csv_out_file, 'w', newline='')
            csv_writer = csv.writer(csv_file_handle)

        # Conditional header based on include_metadata flag
        if include_metadata:
            csv_writer.writerow(['owner', 'auth_id', 'data_capacity_bytes', 'metadata_capacity_bytes', 'total_capacity_bytes'])
            for item in owner_report_data:
                csv_writer.writerow([item['owner'], item['auth_id'], item['data_capacity_bytes'], item['metadata_capacity_bytes'], item['total_capacity_bytes']])
        else:
            csv_writer.writerow(['owner', 'auth_id', 'total_capacity_bytes'])
            for item in owner_report_data:
                csv_writer.writerow([item['owner'], item['auth_id'], item['total_capacity_bytes']])
        csv_file_handle.flush()

        if verbose:
            print(f'[INFO] Owner report written to {csv_out_file}', file=sys.stderr)
    elif output_json or json_file_handle:
        # JSON output
        for item in owner_report_data:
            output = json.dumps(item)
            if json_file_handle:
                json_file_handle.write(output + '\\n')
                json_file_handle.flush()
            else:
                print(output)

        if verbose and json_out_file:
            print(f'[INFO] Owner report written to {json_out_file}', file=sys.stderr)
    else:
        # Plain text output
        print('Owner Report')
        print('=' * 80)
        if include_metadata:
            print(f'{\"Owner\":<40} {\"Auth ID\":<20} {\"Data (bytes)\":>15} {\"Metadata (bytes)\":>17} {\"Total (bytes)\":>15}')
        else:
            print(f'{\"Owner\":<40} {\"Auth ID\":<20} {\"Total Capacity\":>15}')
        print('-' * 80)
        for item in owner_report_data:
            if include_metadata:
                data_str = f\"{item['data_capacity_bytes']:,}\"
                metadata_str = f\"{item['metadata_capacity_bytes']:,}\"
                total_str = f\"{item['total_capacity_bytes']:,}\"
                print(f\"{item['owner']:<40} {item['auth_id']:<20} {data_str:>15} {metadata_str:>17} {total_str:>15}\")
            else:
                capacity_str = f\"{item['total_capacity_bytes']:,} bytes\"
                print(f\"{item['owner']:<40} {item['auth_id']:<20} {capacity_str:>15}\")
        print('=' * 80)
        print(f'Total owners: {len(owner_report_data)}')

# Flush any remaining batched output
flush_json_batch()
flush_csv_batch()

# Final progress report
if progress and start_time:
    elapsed = time.time() - start_time
    rate = objects_processed / elapsed if elapsed > 0 else 0
    # Clear the progress line and print final stats on a new line
    print(f'\r[PROGRESS] FINAL: Processed: {objects_processed:,} objects | Matches: {match_count:,} | Rate: {rate:.1f} obj/sec | Total time: {elapsed:.1f}s', file=sys.stderr)

if json_file_handle:
    json_file_handle.close()
if csv_file_handle:
    csv_file_handle.close()
"
