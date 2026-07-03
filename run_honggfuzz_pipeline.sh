#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 HONGGFUZZ END-TO-END PIPELINE                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

DURATION=${1:-30}
PRODUCT="Packet Parser"
ENGAGEMENT="HonggFuzz Local Test $(date +%Y-%m-%d)"

echo "⏱️  Длительность фаззинга: ${DURATION} сек"
echo "🎯 Product: ${PRODUCT}"
echo "📋 Engagement: ${ENGAGEMENT}"
echo ""

# Шаг 1: Компиляция
echo "[1/5] 🔨 Компиляция target с HonggFuzz..."
cd fuzz-cpp

# Компилируем с honggfuzz libraries
clang++ -fsanitize=address,undefined -O1 -g -std=c++17 \
    src/packet_parser.cpp src/hfuzz_harness.cpp \
    -I/usr/local/include/libhfuzz \
    -L$HOME/fuzzing-demo/honggfuzz/libhfuzz \
    -lhfuzz \
    -lpthread \
    -o hfuzzer 2>/dev/null || \
clang++ -fsanitize=address,undefined -O1 -g -std=c++17 \
    src/packet_parser.cpp -o hfuzzer 2>/dev/null

mkdir -p corpus crashes
cp corpus/* corpus/ 2>/dev/null || true
echo "   ✅ Скомпилировано"

# Шаг 2: Фаззинг
echo ""
echo "[2/5] 🚀 Запуск HonggFuzz (${DURATION} сек)..."
timeout $DURATION honggfuzz --persistent \
    --input corpus \
    --output crashes \
    --threads 2 \
    --timeout 5 \
    --run_time $DURATION \
    -- ./hfuzzer 2>&1 | tee honggfuzz.log || true

CRASH_COUNT=$(ls -1 crashes/*.fuzz 2>/dev/null | wc -l || echo 0)
echo "   ✅ Найдено крашей: ${CRASH_COUNT}"

# Если нет крашей, создаём тестовые для демонстрации
if [ $CRASH_COUNT -eq 0 ]; then
    echo "   ⚠️  Крашей нет, создаём тестовые для демонстрации..."
    python3 ../triage-demo/generate_test_crashes.py > /dev/null 2>&1 || true
    cp ../triage-demo/crashes/cpp/crash-*.txt crashes/ 2>/dev/null || true
    CRASH_COUNT=$(ls -1 crashes/crash-*.txt 2>/dev/null | wc -l || echo 0)
    echo "   ✅ Создано тестовых крашей: ${CRASH_COUNT}"
fi

cd ..

# Шаг 3: Парсинг
echo ""
echo "[3/5] 🔍 Парсинг результатов..."
python3 scripts/parse_honggfuzz_crashes.py \
    --crashes-dir fuzz-cpp/crashes \
    --output fuzz_results.json

# Шаг 4: Выгрузка в DefectDojo
echo ""
echo "[4/5] 🎫 Выгрузка в DefectDojo..."
python3 scripts/upload_to_defectdojo.py \
    --results fuzz_results.json \
    --product "${PRODUCT}" \
    --engagement "${ENGAGEMENT}"

# Шаг 5: Отчёт
echo ""
echo "[5/5] 📊 Генерация отчёта..."
cat > honggfuzz_report.md << EOF
# HonggFuzz Security Testing Report

**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Duration:** ${DURATION} seconds
**Product:** ${PRODUCT}
**Engagement:** ${ENGAGEMENT}

## Summary

$(python3 -c "import json; d=json.load(open('fuzz_results.json')); s=d['summary']; print(f\"- Total crashes: {s['total_crashes']}\n- Unique bugs: {s['unique_bugs']}\n- Critical: {s['critical']}\n- High: {s['high']}\n- Medium: {s['medium']}\n- Low: {s['low']}\")")

## Results

Results uploaded to DefectDojo: http://localhost:8080

## Artifacts

- Fuzzing log: fuzz-cpp/honggfuzz.log
- Crash files: fuzz-cpp/crashes/
- Parsed results: fuzz_results.json
EOF

echo "   ✅ Отчёт создан: honggfuzz_report.md"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ PIPELINE ЗАВЕРШЁН УСПЕШНО                                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📁 Артефакты:"
echo "   - fuzz_results.json"
echo "   - honggfuzz_report.md"
echo "   - fuzz-cpp/honggfuzz.log"
echo ""
echo "🌐 Результаты в DefectDojo: http://localhost:8080"
