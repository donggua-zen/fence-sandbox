#!/bin/bash
# Integration tests for sandbox (macOS)
# Usage: test_mac.sh <path-to-sandbox>

set -u

SANDBOX="$1"
if [ -z "$SANDBOX" ]; then
    echo "Usage: test_mac.sh <path-to-sandbox>"
    exit 2
fi

EXIT_CODE=0

# Setup temp dirs
WS=$(mktemp -d /tmp/sandbox_test_ws_XXXXXX)
OUTSIDE=$(mktemp -d /tmp/sandbox_test_outside_XXXXXX)

echo "=== Test 1: Write inside workspace (should succeed) ==="
"$SANDBOX" -c "echo hello > test.txt" --workspace "$WS"
rc=$?
if [ $rc -eq 0 ] && [ -f "$WS/test.txt" ]; then
    echo "[PASS] Write inside workspace"
else
    echo "[FAIL] Write inside workspace (rc=$rc)"
    EXIT_CODE=1
fi

echo "=== Test 2: Write outside workspace (should fail) ==="
"$SANDBOX" -c "echo hello > $OUTSIDE/test.txt" --workspace "$WS"
rc=$?
if [ $rc -ne 0 ]; then
    echo "[PASS] Write outside workspace denied"
else
    echo "[FAIL] Write outside workspace - should have been denied"
    EXIT_CODE=1
fi

echo "=== Test 3: Read-only mode (should fail) ==="
"$SANDBOX" -c "echo hello > test2.txt" --workspace "$WS" --read-only
rc=$?
if [ $rc -ne 0 ]; then
    echo "[PASS] Read-only mode denies write"
else
    echo "[FAIL] Read-only mode - should have been denied"
    EXIT_CODE=1
fi

echo "=== Test 4: Exit code passthrough ==="
"$SANDBOX" -c "exit 42" --workspace "$WS"
rc=$?
if [ $rc -eq 42 ]; then
    echo "[PASS] Exit code passthrough"
else
    echo "[FAIL] Exit code passthrough (rc=$rc, expected 42)"
    EXIT_CODE=1
fi

echo "=== Test 5: --shell bash - write inside workspace (should succeed) ==="
"$SANDBOX" --shell bash -c "echo hello > bash_test.txt" --workspace "$WS"
rc=$?
if [ $rc -eq 0 ] && [ -f "$WS/bash_test.txt" ]; then
    echo "[PASS] bash shell write inside workspace"
else
    echo "[FAIL] bash shell write inside workspace (rc=$rc)"
    EXIT_CODE=1
fi

echo "=== Test 6: --shell zsh - write inside workspace (should succeed) ==="
"$SANDBOX" --shell zsh -c "echo hello > zsh_test.txt" --workspace "$WS"
rc=$?
if [ $rc -eq 0 ] && [ -f "$WS/zsh_test.txt" ]; then
    echo "[PASS] zsh shell write inside workspace"
else
    echo "[FAIL] zsh shell write inside workspace (rc=$rc)"
    EXIT_CODE=1
fi

# Cleanup
rm -rf "$WS" "$OUTSIDE"

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "=== All tests passed ==="
else
    echo "=== Some tests FAILED ==="
fi
exit $EXIT_CODE
