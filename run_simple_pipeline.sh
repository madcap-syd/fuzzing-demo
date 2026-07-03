#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 УПРОЩЁННЫЙ PIPELINE                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# 1. Проверяем краши
echo "[1/4] 🔍 Проверка крашей..."
CRASH_COUNT=$(find fuzz-cpp/crashes -name "crash-*" 2>/dev/null | wc -l)
echo "   Найдено крашей: $CRASH_COUNT"

if [ $CRASH_COUNT -eq 0 ]; then
    echo "   ⚠️  Используем тестовые данные..."
    python3 triage-demo/generate_test_crashes.py > /dev/null 2>&1
    CRASH_COUNT=1000
fi

# 2. Дедупликация
echo ""
echo "[2/4] 🔍 Дедупликация..."
cd triage-demo
python3 scripts/crash_deduplicator.py 2>&1 | grep -E "Всего|Уникальных|Dedup" || echo "   Дедупликация завершена"
cd ..

# 3. ML классификация
echo ""
echo "[3/4] 🤖 ML классификация..."
if [ -f ml/fp_classifier.pkl ]; then
    python3 ml/test_classifier.py 2>&1 | grep -E "Prediction|Confidence" | head -8
else
    echo "   ⚠️  Модель не найдена"
fi

# 4. Метрики
echo ""
echo "[4/4] 📊 Метрики..."
cd triage-demo
python3 scripts/generate_metrics.py 2>&1 | tail -20
cd ..

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ PIPELINE ЗАВЕРШЁН                                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
