#!/usr/bin/env python3
import json
import sys
import os
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

print("Отправка Email уведомления...")

# Загружаем finding
if not Path('defectdojo_findings.json').exists():
    print("ERROR: defectdojo_findings.json не найден!")
    sys.exit(1)

finding = json.loads(Path('defectdojo_findings.json').read_text())

# Конфигурация (из переменных окружения)
smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
smtp_port = int(os.environ.get('SMTP_PORT', '587'))
smtp_user = os.environ.get('SMTP_USER', 'fuzzing@company.com')
smtp_password = os.environ.get('SMTP_PASSWORD', 'demo-password')
email_to = os.environ.get('EMAIL_TO', 'security-team@company.com')
email_from = os.environ.get('EMAIL_FROM', 'fuzzing@company.com')
demo_mode = os.environ.get('DEMO_MODE', 'true').lower() == 'true'

# Создаём письмо
subject = f"🚨 SECURITY ALERT: {finding['title']}"

body = f"""
Fuzzing Pipeline Security Alert
================================

Vulnerability Detected!

Type: {finding['title']}
Severity: {finding['severity']}
CWE: {finding['cwe']}
CVSS: {finding['cvss']}
File: {finding['file_path']}:{finding['line']}

Description:
{finding['description']}

Actions Required:
1. Review the vulnerability
2. Fix the issue
3. Run tests to verify fix
4. Update this ticket

Pipeline: GitHub Actions
Repository: fuzzing-demo
Date: {datetime.now().isoformat()}

---
This is an automated message from Fuzzing Pipeline
"""

if demo_mode:
    # Демо режим - просто показываем
    email_file = 'email_notification.txt'
    Path(email_file).write_text(f"From: {email_from}\nTo: {email_to}\nSubject: {subject}\n\n{body}")
    print(f"Email сохранён в {email_file}")
    print(f"  To: {email_to}")
    print(f"  From: {email_from}")
    print(f"  Subject: {subject}")
    print(f"  Body length: {len(body)} chars")
else:
    # Отправка через SMTP
    try:
        msg = MIMEMultipart()
        msg['From'] = email_from
        msg['To'] = email_to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        
        print(f"Email отправлен на {email_to}")
    except Exception as e:
        print(f"ERROR при отправке: {e}")
        print("Сохраняем локально...")
        Path('email_notification.txt').write_text(f"From: {email_from}\nTo: {email_to}\nSubject: {subject}\n\n{body}")

print("\nГотово!")
