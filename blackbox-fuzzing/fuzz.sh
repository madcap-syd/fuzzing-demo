#!/bin/bash
set +e  # НЕ выходим при ошибках!

TARGET="$1"
ITERATIONS=${2:-300}

echo " Starting Black Box Fuzzing..."
echo "Target: $TARGET"
echo "Iterations: $ITERATIONS"
echo ""

CRASH_COUNT=0

for i in $(seq 1 $ITERATIONS); do
    # Generate random input
    dd if=/dev/urandom bs=1 count=$((RANDOM % 200 + 50)) of=/tmp/mutated.txt 2>/dev/null
    
    # Run target and capture exit code
    timeout 1s $TARGET /tmp/mutated.txt >/dev/null 2>&1
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 139 ] || [ $EXIT_CODE -eq 134 ] || [ $EXIT_CODE -eq 136 ]; then
        CRASH_COUNT=$((CRASH_COUNT + 1))
        echo " CRASH #$CRASH_COUNT! Exit code: $EXIT_CODE (iteration $i)"
        cp /tmp/mutated.txt crashes/crash_$CRASH_COUNT.txt
    fi
    
    # Progress
    if [ $((i % 50)) -eq 0 ]; then
        echo "Progress: $i/$ITERATIONS iterations, $CRASH_COUNT crashes found"
    fi
done

echo ""
echo "=== FUZZING COMPLETE ==="
echo "Total iterations: $ITERATIONS"
echo "Crashes found: $CRASH_COUNT"
echo "Crashes saved to: $(pwd)/crashes/"

# Return success even if crashes found
exit 0
