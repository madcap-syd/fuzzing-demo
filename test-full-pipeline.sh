#!/bin/bash
echo "ТЕСТИРОВАНИЕ PIPELINE"
echo ""
echo "1. WHITE BOX..."
if [ -f "fuzzing-final.log" ]; then
    grep -A 5 "AddressSanitizer" fuzzing-final.log | head -10
else
    echo "Нет логов - создаём демо finding"
fi
echo ""
echo "2. DEFECTDOJO..."
export DEMO_MODE=true
python3 scripts/upload_defectdojo.py ./fuzzing-final.log ./crashes 2>/dev/null || echo "DEMO mode"
echo ""
echo "3. JIRA..."
python3 scripts/create_jira.py 2>/dev/null || echo "DEMO mode"
echo ""
echo "4. EMAIL..."
cat > email_notification.txt << 'EMAIL'
From: fuzzing-pipeline@company.com
To: security-team@company.com
Subject: Security Alert: Crash found

Pipeline: https://github.com/actions/runs/123
Jira: SEC-001

Actions:
1. Download crash file
2. Fix the bug
EMAIL
echo "Email создан: email_notification.txt"
echo ""
echo "Файлы:"
ls -lh defectdojo_findings.json jira_ticket.json email_notification.txt 2>/dev/null
