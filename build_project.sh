#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "=== Step 1: CMake Configure ==="
cmake -S sandbox -B build -DCMAKE_BUILD_TYPE=Release
if [ $? -ne 0 ]; then
    echo "CMake configure failed!"
    exit 1
fi

echo ""
echo "=== Step 2: CMake Build ==="
cmake --build build --config Release
if [ $? -ne 0 ]; then
    echo "CMake build failed!"
    exit 1
fi

echo ""
echo "=== Build Complete ==="
echo "Output: build/bin/"
ls -la build/bin/
