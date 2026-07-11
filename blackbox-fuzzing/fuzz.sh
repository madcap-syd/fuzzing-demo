#!/bin/bash

CORPUS_DIR="./corpus"
CRASHES_DIR="./crashes"
TARGET="./target"

mkdir -p $CORPUS_DIR $CRASHES_DIR

echo "AAAA" > $CORPUS_DIR/seed1.txt
echo "BBBBBBBB" > $CORPUS_DIR/seed2.txt

echo "🚀 Starting Black Box Fuzzing..."

CRASH_COUNT=0

for i in {1..300}; do
    SEED=$(ls $CORPUS_DIR | shuf -n 1)
    
    cp $CORPUS_DIR/$SEED /tmp/mutated.txt
    
    RANDOM_SIZE=$(( (RANDOM % 240) + 10 ))
    dd if=/dev/urandom bs=1 count=$RANDOM_SIZE >> /tmp/mutated.txt 2>/dev/null
    
    if [ $((RANDOM % 3)) -eq 0 ]; then
        cat /tmp/mutated.txt /tmp/mutated.txt > /tmp/mutated2.txt
        mv /tmp/mutated2.txt /tmp/mutated.txt
    fi
    
    timeout 1s $TARGET /tmp/mutated.txt > /dev/null 2>&1
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 139 ] || [ $EXIT_CODE -eq 134 ] || [ $EXIT_CODE -eq 136 ]; then
        CRASH_COUNT=$((CRASH_COUNT + 1))
        echo "💥 CRASH #$CRASH_COUNT! Exit code: $EXIT_CODE (iteration $i)"
        cp /tmp/mutated.txt $CRASHES_DIR/crash_$(printf "%03d" $CRASH_COUNT).txt
    fi
    
    if [ $((i % 50)) -eq 0 ]; then
        echo "  Progress: $i/300 | Crashes: $CRASH_COUNT"
    fi
done

echo ""
echo "✅ Fuzzing completed!"
echo "Total iterations: 300"
echo "Crashes found: $CRASH_COUNT"
ls -lh $CRASHES_DIR/
