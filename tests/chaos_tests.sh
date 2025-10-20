#!/bin/bash
#
# Chaos Tests for GrumpWalk
# Tests various flag combinations to ensure proper interaction
#

set -e

# Configuration
CLUSTER="music.eng.qumulo.com"
TEST_PATH="/home/joe/100k"
SCRIPT="./grumpwalk.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test
run_test() {
    local test_name="$1"
    local cmd="$2"
    local expected_behavior="$3"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${BLUE}[TEST $TOTAL_TESTS]${NC} $test_name"
    echo -e "${YELLOW}Command:${NC} $cmd"
    echo -e "${YELLOW}Expected:${NC} $expected_behavior"

    # Run command (skip timeout if not available)
    TIMEOUT_CMD=""
    if command -v gtimeout &> /dev/null; then
        TIMEOUT_CMD="gtimeout 30"
    elif command -v timeout &> /dev/null; then
        TIMEOUT_CMD="timeout 30"
    fi

    if eval "$TIMEOUT_CMD $cmd" > /tmp/chaos_test_$TOTAL_TESTS.out 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo ""
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo -e "${RED}✗ FAILED (timeout)${NC}"
        else
            echo -e "${RED}✗ FAILED (exit code: $EXIT_CODE)${NC}"
        fi
        echo "Output:"
        cat /tmp/chaos_test_$TOTAL_TESTS.out | head -20
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo ""
    fi
}

echo "========================================================================"
echo "GrumpWalk Chaos Tests"
echo "========================================================================"
echo ""

# ============================================================================
# CATEGORY 1: Filter Combinations
# ============================================================================
echo -e "${BLUE}=== CATEGORY 1: Filter Combinations ===${NC}"
echo ""

run_test "Time + Size filters" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 30 --larger-than 1MB --limit 5" \
    "Find files older than 30 days AND larger than 1MB"

run_test "Multiple time field filters (AND logic)" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --modified-older-than 60 --accessed-older-than 30 --limit 5" \
    "Files modified >60 days AND accessed >30 days"

run_test "Time + Type + Name filters" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 180 --type file --name '*.log' --limit 5" \
    "Old log files only"

run_test "Size range filter" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --larger-than 100KB --smaller-than 10MB --limit 5" \
    "Files between 100KB and 10MB"

run_test "Multiple name patterns (OR logic)" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --name '*.log' --name '*.txt' --limit 5" \
    "Files matching *.log OR *.txt"

run_test "Multiple name patterns (AND logic)" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --name-and '*test*' --name-and '*.py' --limit 5" \
    "Python files with 'test' in name"

run_test "Mixed name patterns (OR and AND)" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --name '*.py' --name '*.sh' --name-and '*test*' --limit 5" \
    "Python or shell scripts with 'test' in name"

# ============================================================================
# CATEGORY 2: Output Format Combinations
# ============================================================================
echo -e "${BLUE}=== CATEGORY 2: Output Format Combinations ===${NC}"
echo ""

run_test "Show owner + group + all attributes" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --limit 3 --show-owner --show-group --all-attributes" \
    "Display full file details with owner/group names"

run_test "JSON output with filters" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 30 --limit 3 --json-out /tmp/chaos_json_test.json" \
    "Write filtered results to JSON file"

run_test "Owner report with filters" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 90 --owner-report --limit 100" \
    "Generate ownership stats for old files"

run_test "Show owner + JSON output" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --limit 3 --show-owner --json-out /tmp/chaos_json_owner.json" \
    "JSON with resolved owner names"

# ============================================================================
# CATEGORY 3: Depth and Limit Combinations
# ============================================================================
echo -e "${BLUE}=== CATEGORY 3: Depth and Limit Combinations ===${NC}"
echo ""

run_test "Shallow depth with limit" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --max-depth 1 --limit 5" \
    "Search only 1 level deep, max 5 results"

run_test "Deep search with early limit" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --max-depth 5 --limit 3" \
    "Stop at 3 matches even if searching deep"

run_test "No depth limit with strict filters" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --newer-than 1 --larger-than 100MB --limit 5" \
    "Unlimited depth but very specific criteria"

# ============================================================================
# CATEGORY 4: ACL Operations with Filters
# ============================================================================
echo -e "${BLUE}=== CATEGORY 4: ACL Operations with Filters ===${NC}"
echo ""

run_test "ACL clone with type filter" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --type file --limit 5 --progress" \
    "Clone ACL only to files, not directories"

run_test "ACL clone with time filter" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --newer-than 30 --limit 5 --progress" \
    "Clone ACL only to recently created/modified files"

run_test "ACL clone with size filter" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --smaller-than 1MB --limit 5 --progress" \
    "Clone ACL only to small files"

run_test "Owner/group copy with filters" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --copy-owner --owner-group-only --type file --limit 5 --progress" \
    "Copy owner to files only, no ACL changes"

run_test "ACL clone with multiple filters" \
    "$SCRIPT --host $CLUSTER --source-acl /home/joe/source_acl --acl-target /home/joe/100k --type file --larger-than 100KB --newer-than 60 --limit 3 --progress" \
    "Clone ACL with complex filter combination"

# ============================================================================
# CATEGORY 5: Edge Cases and Conflicts
# ============================================================================
echo -e "${BLUE}=== CATEGORY 5: Edge Cases and Conflicts ===${NC}"
echo ""

run_test "Conflicting time filters (should still work)" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 30 --newer-than 60 --limit 5" \
    "Older than 30 AND newer than 60 (impossible, should return 0 matches)"

run_test "Conflicting size filters (should still work)" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --larger-than 10MB --smaller-than 1MB --limit 5" \
    "Larger than 10MB AND smaller than 1MB (impossible, should return 0 matches)"

run_test "Case-sensitive name search" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --name 'README' --name-case-sensitive --limit 5" \
    "Only match exact case 'README'"

run_test "Limit of 1 with progress" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --limit 1 --progress" \
    "Stop immediately after first match"

run_test "Very deep max-depth" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --max-depth 10 --limit 5" \
    "Search up to 10 levels deep"

run_test "Metadata size calculation" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --larger-than 1MB --include-metadata --limit 5" \
    "Include metadata blocks in size calculation"

# ============================================================================
# CATEGORY 6: Performance and Concurrency
# ============================================================================
echo -e "${BLUE}=== CATEGORY 6: Performance and Concurrency ===${NC}"
echo ""

run_test "High concurrency with filters" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 30 --max-concurrent 200 --connector-limit 200 --limit 10" \
    "Stress test with high concurrency"

run_test "Low concurrency with complex filters" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --older-than 30 --larger-than 1MB --name '*.log' --max-concurrent 10 --limit 5" \
    "Throttled concurrency with complex filters"

# ============================================================================
# CATEGORY 7: Time Field Variations
# ============================================================================
echo -e "${BLUE}=== CATEGORY 7: Time Field Variations ===${NC}"
echo ""

run_test "Modification time filter" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --modified --modified-older-than 90 --limit 5" \
    "Use modification_time as primary field"

run_test "Access time filter" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --accessed --accessed-older-than 180 --limit 5" \
    "Use access_time as primary field"

run_test "Creation time filter" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --created --created-older-than 365 --limit 5" \
    "Use creation_time as primary field"

run_test "All time fields combined" \
    "$SCRIPT --host $CLUSTER --path $TEST_PATH --modified-older-than 90 --accessed-older-than 180 --created-older-than 365 --limit 5" \
    "Files matching all time criteria (AND logic)"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "========================================================================"
echo "Test Summary"
echo "========================================================================"
echo -e "Total Tests:  ${BLUE}$TOTAL_TESTS${NC}"
echo -e "Passed:       ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed:       ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check output above for details.${NC}"
    exit 1
fi
