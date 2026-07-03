#!/bin/bash
# HonggFuzz pipeline для production fuzzing

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 HONGGFUZZ PRODUCTION PIPELINE                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

DURATION=${1:-60}
TARGET="packet_parser"

echo "⏱️  Длительность: ${DURATION} сек"
echo "🎯 Цель: ${TARGET}"
echo ""

# 1. Компиляция
echo "[1/4] 🔨 Компиляция..."
cd fuzz-cpp
clang++ -fsanitize=address,undefined -O1 -g -std=c++17 \
    src/packet_parser.cpp -o hfuzzer 2>/dev/null
echo "   ✅ Скомпилировано"

# 2. Подготовка
echo ""
echo "[2/4] 📦 Подготовка workspace..."
mkdir -p hfuzz_corpus hfuzz_crashes
cp corpus/* hfuzz_corpus/ 2>/dev/null || true
echo "   ✅ Workspace готов"

# 3. Запуск
echo ""
echo "[3/4] 🚀 Запуск honggfuzz..."
timeout $DURATION honggfuzz \
    --input hfuzz_corpus \
    --output hfuzz_crashes \
    --threads 2 \
    --timeout 5 \
    --run_time $DURATION \
    -- ./hfuzzer ___FILE___ \
    2>&1 | tee ../hfuzz_run.log || true

echo "   ✅ Фаззинг завершён"

# 4. Анализ
echo ""
echo "[4/4] 📊 Анализ результатов..."
CRASH_COUNT=$(ls -1 hfuzz_crashes/*.fuzz 2>/dev/null | wc -l || echo 0)
echo "   Найдено крашей: $CRASH_COUNT"

cd ..

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ HONGGFUZZ PIPELINE ЗАВЕРШЁН                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
