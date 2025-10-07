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
TIME_FIELD="creation_time"

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
        --help|-h)
            cat << 'EOF'
Filter files by age from qq fs_walk_tree output using streaming to avoid OOM

Usage:
  filter_old_files.sh --path <path> (--older-than <days> | --newer-than <days>) [OPTIONS]

Required Arguments:
  --path <path>              Path to search
  --older-than <days>        Find files older than N days
  --newer-than <days>        Find files newer than N days

Time Field Options (default: --created):
  --created                  Filter by creation time (default)
  --accessed                 Filter by last access time
  --modified                 Filter by last modification time
  --changed                  Filter by last metadata change time

Search Options:
  --max-depth <N>            Maximum directory depth to search
  --file-only                Search files only (default)
  --all                      Search both files and directories
  --omit-subdirs "patterns"  Space-separated patterns to omit (supports wildcards)

Output Options:
  --json                     Output results as JSON to stdout
  --json-out <file>          Write JSON results to file (allows --verbose)
  --verbose                  Show detailed logging to stderr

Examples:
  # Find files created more than 30 days ago
  filter_old_files.sh --path /home --older-than 30

  # Find files accessed in the last 7 days
  filter_old_files.sh --path /home --newer-than 7 --accessed

  # Find old files, exclude temp directories, save to JSON with logging
  filter_old_files.sh --path /home --older-than 90 --omit-subdirs "temp cache 100k*" --json-out old-files.json --verbose

  # Find recently modified files with depth limit
  filter_old_files.sh --path /data --newer-than 1 --modified --max-depth 3
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

if [ -z "$OLDER_THAN" ] && [ -z "$NEWER_THAN" ]; then
    echo "Error: either --older-than or --newer-than is required" >&2
    echo "Usage: $0 --path <path> (--older-than <days> | --newer-than <days>) [--created | --accessed | --modified | --changed] [--max-depth <depth>] [--file-only | --all] [--omit-subdirs \"pattern1 pattern2\"] [--json | --json-out <file>] [--verbose]" >&2
    echo "Example: $0 --path /home --older-than 30 --accessed --max-depth 1 --file-only --omit-subdirs \"temp cache 100k*\" --json-out results.json --verbose" >&2
    exit 1
fi

if [ -n "$OLDER_THAN" ] && [ -n "$NEWER_THAN" ]; then
    echo "Error: cannot use both --older-than and --newer-than" >&2
    echo "Usage: $0 --path <path> (--older-than <days> | --newer-than <days>) [--created | --accessed | --modified | --changed] [--max-depth <depth>] [--file-only | --all] [--omit-subdirs \"pattern1 pattern2\"] [--json | --json-out <file>] [--verbose]" >&2
    exit 1
fi

# Check for conflicting options
if [ "$VERBOSE" = true ] && [ "$OUTPUT_JSON" = true ] && [ -z "$JSON_OUT_FILE" ]; then
    echo "Error: --json and --verbose produce conflicting output to stdout" >&2
    echo "Suggestion: Use --json-out <file> instead of --json to separate JSON output from verbose logs" >&2
    echo "Example: $0 --path /home --older-than 30 --json-out results.json --verbose" >&2
    exit 1
fi

# Calculate the timestamp threshold
if [ -n "$OLDER_THAN" ]; then
    threshold=$(date -u +%s -d "$OLDER_THAN days ago")
    comparison="older"
else
    threshold=$(date -u +%s -d "$NEWER_THAN days ago")
    comparison="newer"
fi

# Function to process a single directory path
process_directory() {
    local dir_path="$1"
    local qq_cmd="qq fs_walk_tree --path \"$dir_path\" --display-all-attributes"

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

        ROOT_CMD="qq fs_walk_tree --path \"$PATH_TO_SEARCH\" --display-all-attributes --max-depth 1"
        if [ "$FILE_ONLY" = true ]; then
            ROOT_CMD="$ROOT_CMD --file-only"
        fi
        eval "$ROOT_CMD"

        # Then, process subdirectories (excluding omitted ones)
        qq fs_walk_tree --path "$PATH_TO_SEARCH" --max-depth 1 --display-all-attributes | \
        python3 -c "
import sys
import json
import subprocess
import shlex
import fnmatch

omit_patterns = shlex.split('$OMIT_SUBDIRS')
verbose = '$VERBOSE' == 'true'
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
        cmd = 'qq fs_walk_tree --path ' + shlex.quote(path) + ' --display-all-attributes'
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
from datetime import datetime

# Ensure unbuffered output
sys.stdout.reconfigure(line_buffering=True)

threshold = $threshold
threshold_str = datetime.utcfromtimestamp(threshold).strftime('%Y-%m-%dT%H:%M:%S') + '.000000000Z'
comparison = '${comparison}'
output_json = '${OUTPUT_JSON}' == 'true'
time_field = '$TIME_FIELD'

current_obj = {}
current_idx = None

def matches_filter(time_value):
    if comparison == 'older':
        return time_value < threshold_str
    else:  # newer
        return time_value > threshold_str

json_out_file = '$JSON_OUT_FILE'
json_file_handle = None
if json_out_file:
    json_file_handle = open(json_out_file, 'w')

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
            if current_obj.get('path') and current_obj.get(time_field):
                if matches_filter(current_obj[time_field]):
                    if output_json:
                        # Only include path and the selected time field
                        filtered_obj = {
                            'path': current_obj['path'],
                            time_field: current_obj[time_field]
                        }
                        output = json.dumps(filtered_obj)
                        if json_file_handle:
                            json_file_handle.write(output + '\n')
                            json_file_handle.flush()
                        else:
                            print(output)
                    else:
                        print(current_obj[time_field])
                        print(current_obj['path'])

            # Reset for new object
            current_obj = {}
            current_idx = idx

        # Collect path and time fields
        if key in ('path', 'creation_time', 'access_time', 'modification_time', 'change_time'):
            current_obj[key] = val

# Process final object
if current_obj.get('path') and current_obj.get(time_field):
    if matches_filter(current_obj[time_field]):
        if output_json:
            # Only include path and the selected time field
            filtered_obj = {
                'path': current_obj['path'],
                time_field: current_obj[time_field]
            }
            output = json.dumps(filtered_obj)
            if json_file_handle:
                json_file_handle.write(output + '\n')
                json_file_handle.flush()
            else:
                print(output)
        else:
            print(current_obj[time_field])
            print(current_obj['path'])

if json_file_handle:
    json_file_handle.close()
"
