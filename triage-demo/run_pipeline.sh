#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          FULL TRIAGE PIPELINE DEMO                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "📦 Шаг 1/5: Генерация тестовых крашей..."
python3 triage-demo/generate_test_crashes.py
echo ""

echo "🔍 Шаг 2/5: Дедупликация крашей..."
python3 triage-demo/scripts/crash_deduplicator.py
echo ""

echo "📉 Шаг 3/5: Минимизация PoC..."
python3 triage-demo/scripts/poc_minimizer.py
echo ""

echo "🎫 Шаг 4/5: Создание тикетов (Jira + DefectDojo)..."
python3 triage-demo/scripts/ticket_creator.py
echo ""

echo "📊 Шаг 5/5: Генерация метрик..."
python3 triage-demo/scripts/generate_metrics.py
echo ""

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         ✅ PIPELINE COMPLETED SUCCESSFULLY                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo " Результаты:"
ls -lh triage-demo/*.json triage-demo/*.md 2>/dev/null
echo ""
echo "📄 Полный отчёт: triage-demo/TRIAGE_METRICS_REPORT.md"
