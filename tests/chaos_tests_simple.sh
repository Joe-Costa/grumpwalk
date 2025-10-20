#!/bin/bash
#
# Simple Chaos Tests for GrumpWalk
# Tests various flag combinations (no timeout dependency)
#

CLUSTER="music.eng.qumulo.com"
TEST_PATH="/home/joe/100k"
SCRIPT="./grumpwalk.py"

# Test counters
TOTAL=0
PASSED=0
FAILED=0

# Function to run a test
test_cmd() {
    local name="$1"
    local cmd="$2"

    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"

    if eval "$cmd" > /tmp/chaos_$TOTAL.out 2>&1; then
        echo "  ✓ PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "  ✗ FAILED (exit code: $?)"
        echo "  Output: $(head -3 /tmp/chaos_$TOTAL.out | tr '\n' ' ')"
        FAILED=$((FAILED + 1))
    fi
    echo ""
}

echo "========================================================================"
echo "GrumpWalk Chaos Tests"
echo "========================================================================"
echo ""

# Filter Combinations
echo "=== Filter Combinations ==="
test_cmd "Time + Size" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 30 --larger-than 1MB --limit 5"

test_cmd "Multi-time fields" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --modified-older-than 60 --accessed-older-than 30 --limit 5"

test_cmd "Time + Type + Name" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 180 --type file --name '*.log' --limit 5"

test_cmd "Size range" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --larger-than 100KB --smaller-than 10MB --limit 5"

test_cmd "Name OR" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --name '*.log' --name '*.txt' --limit 5"

test_cmd "Name AND" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --name-and '*test*' --name-and '*.py' --limit 5"

# Output Formats
echo "=== Output Formats ==="
test_cmd "Show owner+group+attrs" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --limit 3 --show-owner --show-group --all-attributes"

test_cmd "JSON output" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 30 --limit 3 --json-out /tmp/chaos_json.json"

test_cmd "Owner report" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 90 --owner-report --limit 100"

# Depth and Limits
echo "=== Depth and Limits ==="
test_cmd "Shallow depth" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --max-depth 1 --limit 5"

test_cmd "Deep with early limit" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --max-depth 5 --limit 3"

test_cmd "Strict filters" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --newer-than 1 --larger-than 100MB --limit 5"

# ACL Operations
echo "=== ACL Operations ==="
test_cmd "ACL + type filter" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --type file --limit 5"

test_cmd "ACL + time filter" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --newer-than 30 --limit 5"

test_cmd "ACL + size filter" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --smaller-than 1MB --limit 5"

test_cmd "Owner copy + filters" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --copy-owner --owner-group-only --type file --limit 5"

# Edge Cases
echo "=== Edge Cases ==="
test_cmd "Conflicting time (expect 0)" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 30 --newer-than 60 --limit 5"

test_cmd "Conflicting size (expect 0)" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --larger-than 10MB --smaller-than 1MB --limit 5"

test_cmd "Case-sensitive" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --name 'README' --name-case-sensitive --limit 5"

test_cmd "Limit 1" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --limit 1"

test_cmd "Deep depth" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --max-depth 10 --limit 5"

# Time Fields
echo "=== Time Field Variations ==="
test_cmd "Modified time" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --modified --modified-older-than 90 --limit 5"

test_cmd "Access time" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --accessed --accessed-older-than 180 --limit 5"

test_cmd "Creation time" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --created --created-older-than 365 --limit 5"

test_cmd "All time fields" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --modified-older-than 90 --accessed-older-than 180 --created-older-than 365 --limit 5"

# Summary
echo "========================================================================"
echo "Summary: $PASSED/$TOTAL passed, $FAILED failed"
echo "========================================================================"

[ $FAILED -eq 0 ] && exit 0 || exit 1
