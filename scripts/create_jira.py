#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from datetime import datetime

print("Создание Jira тикета...")

# Загружаем finding из DefectDojo
if not Path('defectdojo_findings.json').exists():
    print("ERROR: defectdojo_findings.json не найден!")
    sys.exit(1)

finding = json.loads(Path('defectdojo_findings.json').read_text())

# Определяем приоритет
cvss = finding.get('cvss', 9.8)
if cvss >= 9.0:
    priority = "Highest"
elif cvss >= 7.0:
    priority = "High"
elif cvss >= 4.0:
    priority = "Medium"
else:
    priority = "Low"

# Создаём тикет
ticket = {
    "fields": {
        "project": {"key": "SEC"},
        "summary": f"[FUZZING] {finding['title']}",
        "description": finding['description'],
        "issuetype": {"name": "Bug"},
        "priority": {"name": priority},
        "labels": ["security", "fuzzing", "auto-generated"],
        "components": [{"name": "Security"}]
    }
}

# Сохраняем локально
output_file = 'jira_ticket.json'
Path(output_file).write_text(json.dumps(ticket, indent=2))

print(f"Jira тикет сохранён в {output_file}")
print(f"  Project: SEC")
print(f"  Summary: {ticket['fields']['summary']}")
print(f"  Priority: {priority}")
print(f"  Type: Bug")
print(f"  Labels: {', '.join(ticket['fields']['labels'])}")
print("\nГотово!")
