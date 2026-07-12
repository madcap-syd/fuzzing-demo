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
