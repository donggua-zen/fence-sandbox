#!/bin/bash
# AI Sandbox - Linux Security Tests
# Run inside Docker: bash test_security_linux.sh <path-to-sandbox>

set -u

SANDBOX="${1:-/workspace/build/bin/sandbox}"
PASS=0
FAIL=0

# Setup test dirs
WS=$(mktemp -d /tmp/sandbox_ws_XXXXXX)
WS2=$(mktemp -d /tmp/sandbox_ws2_XXXXXX)
OUTSIDE=$(mktemp -d /tmp/sandbox_outside_XXXXXX)

echo "============================================"
echo " AI Sandbox - Linux Security Tests"
echo "============================================"
echo ""

echo "--- Test 1: Write file inside workspace (ALLOW) ---"
"$SANDBOX" -c "echo test > file.txt" --workspace "$WS" 2>/dev/null
if [ -f "$WS/file.txt" ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 2: Write file outside workspace (DENY) ---"
"$SANDBOX" -c "echo hacked > $OUTSIDE/evil.txt" --workspace "$WS" 2>/dev/null
if [ -f "$OUTSIDE/evil.txt" ]; then echo "[FAIL]"; FAIL=$((FAIL+1)); else echo "[PASS]"; PASS=$((PASS+1)); fi

echo "--- Test 3: Delete file outside workspace (DENY) ---"
echo dummy > "$OUTSIDE/dummy.txt"
"$SANDBOX" -c "rm $OUTSIDE/dummy.txt" --workspace "$WS" 2>/dev/null
if [ -f "$OUTSIDE/dummy.txt" ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 4: Delete file inside workspace (ALLOW) ---"
echo dummy > "$WS/todelete.txt"
"$SANDBOX" -c "rm todelete.txt" --workspace "$WS" 2>/dev/null
if [ -f "$WS/todelete.txt" ]; then echo "[FAIL]"; FAIL=$((FAIL+1)); else echo "[PASS]"; PASS=$((PASS+1)); fi

echo "--- Test 5: Create directory inside workspace (ALLOW) ---"
"$SANDBOX" -c "mkdir newdir" --workspace "$WS" 2>/dev/null
if [ -d "$WS/newdir" ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 6: Create directory outside workspace (DENY) ---"
"$SANDBOX" -c "mkdir $OUTSIDE/evil_dir" --workspace "$WS" 2>/dev/null
if [ -d "$OUTSIDE/evil_dir" ]; then echo "[FAIL]"; FAIL=$((FAIL+1)); else echo "[PASS]"; PASS=$((PASS+1)); fi

echo "--- Test 7: Read file outside workspace (ALLOW) ---"
echo secret > "$OUTSIDE/readable.txt"
"$SANDBOX" -c "cat $OUTSIDE/readable.txt" --workspace "$WS" 2>/dev/null
if [ $? -eq 0 ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 8: Read-only mode - write inside workspace (DENY) ---"
"$SANDBOX" -c "echo test > ro.txt" --workspace "$WS" --read-only 2>/dev/null
if [ -f "$WS/ro.txt" ]; then echo "[FAIL]"; FAIL=$((FAIL+1)); else echo "[PASS]"; PASS=$((PASS+1)); fi

echo "--- Test 9: Read-only mode - read file (ALLOW) ---"
echo secret > "$WS/readable.txt"
"$SANDBOX" -c "cat readable.txt" --workspace "$WS" --read-only 2>/dev/null
if [ $? -eq 0 ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 10: Multi-workspace - write to first workspace (ALLOW) ---"
"$SANDBOX" -c "echo test > ws1.txt" --workspace "$WS,$WS2" 2>/dev/null
if [ -f "$WS/ws1.txt" ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 11: Multi-workspace - write to second workspace (ALLOW) ---"
"$SANDBOX" -c "echo test > $WS2/ws2.txt" --workspace "$WS,$WS2" 2>/dev/null
if [ -f "$WS2/ws2.txt" ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 12: Exit code passthrough (expect 42) ---"
"$SANDBOX" -c "exit 42" --workspace "$WS" 2>/dev/null
if [ $? -eq 42 ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 13: Exit code 0 passthrough ---"
"$SANDBOX" -c "exit 0" --workspace "$WS" 2>/dev/null
if [ $? -eq 0 ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 14: Move file from workspace to outside (DENY) ---"
echo test > "$WS/move.txt"
"$SANDBOX" -c "mv $WS/move.txt $OUTSIDE/moved.txt" --workspace "$WS" 2>/dev/null
if [ -f "$OUTSIDE/moved.txt" ]; then echo "[FAIL]"; FAIL=$((FAIL+1)); else echo "[PASS]"; PASS=$((PASS+1)); fi

echo "--- Test 15: Overwrite existing file inside workspace (ALLOW) ---"
echo old > "$WS/overwrite.txt"
"$SANDBOX" -c "echo new > overwrite.txt" --workspace "$WS" 2>/dev/null
if grep -q "new" "$WS/overwrite.txt" 2>/dev/null; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo "--- Test 16: Move file within workspace (ALLOW) ---"
echo test > "$WS/intra_move.txt"
"$SANDBOX" -c "mv $WS/intra_move.txt $WS/intra_moved.txt" --workspace "$WS" 2>/dev/null
if [ -f "$WS/intra_moved.txt" ]; then echo "[PASS]"; PASS=$((PASS+1)); else echo "[FAIL]"; FAIL=$((FAIL+1)); fi

echo ""
echo "============================================"
echo " Results: $PASS passed, $FAIL failed"
echo "============================================"

# Cleanup
rm -rf "$WS" "$WS2" "$OUTSIDE"

exit $FAIL
