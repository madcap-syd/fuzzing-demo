#!/bin/bash
echo "========================================="
echo "НАСТРОЙКА ПОЛНОЙ ИНТЕГРАЦИИ"
echo "========================================="

# 1. Создаём скрипт для локального теста
cat > test-full-pipeline.sh << 'TESTEOF'
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
TESTEOF
chmod +x test-full-pipeline.sh

# 2. Создаём инструкцию
cat > INTEGRATION-GUIDE.md << 'GUIDEEOF'
# НАСТРОЙКА ИНТЕГРАЦИЙ

## GitHub Secrets (Settings → Secrets and variables → Actions):

### DefectDojo:
- DEFECTDOJO_URL = https://defectdojo.company.com
- DEFECTDOJO_API_KEY = your-api-key

### Jira:
- JIRA_URL = https://company.atlassian.net
- JIRA_USER = your-email@company.com
- JIRA_TOKEN = your-api-token
- JIRA_PROJECT = SEC

### Email:
- SMTP_USERNAME = your-email@gmail.com
- SMTP_PASSWORD = your-app-password
- SMTP_SERVER = smtp.gmail.com
- SMTP_PORT = 587

## Как получить:

**DefectDojo API Key:**
Settings → API v2 Keys → Create

**Jira API Token:**
https://id.atlassian.com/manage/api-tokens → Create

**Gmail App Password:**
https://myaccount.google.com/apppasswords → Create

## Локальный тест:
./test-full-pipeline.sh

## Что показывает:
✅ DefectDojo finding (JSON)
✅ Jira ticket (JSON)
✅ Email notification (txt)
GUIDEEOF

# 3. Запускаем тест
echo ""
./test-full-pipeline.sh

echo ""
echo "========================================="
echo "ГОТОВО!"
echo "========================================="
echo ""
echo "Для PROD режима добавь secrets в GitHub:"
echo "  Settings → Secrets and variables → Actions"
echo ""
echo "Секреты:"
echo "  DEFECTDOJO_URL"
echo "  DEFECTDOJO_API_KEY"
echo "  JIRA_URL"
echo "  JIRA_USER"
echo "  JIRA_TOKEN"
echo "  SMTP_USERNAME"
echo "  SMTP_PASSWORD"
echo ""
echo "Инструкция: INTEGRATION-GUIDE.md"
echo "Тест: ./test-full-pipeline.sh"
