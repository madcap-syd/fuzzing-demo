#!/usr/bin/env python3
"""
AUTOMATED BLACK BOX FUZZING PIPELINE
Автоматизация: fuzzing -> дедупликация -> классификация -> DefectDojo -> Jira
"""

import os
import sys
import json
import subprocess
import random
import shutil
from pathlib import Path
from collections import defaultdict
from datetime import datetime

print("=" * 70)
print("AUTOMATED BLACK BOX FUZZING PIPELINE")
print("=" * 70)

# Конфигурация
TARGET = "blackbox-target/target"
CORPUS_DIR = "blackbox-target/corpus"
CRASHES_DIR = "blackbox-target/crashes"
UNIQUE_DIR = "blackbox-target/unique"
REPORTS_DIR = "blackbox-target/reports"
ITERATIONS = 300

# Создаём директории
Path(CRASHES_DIR).mkdir(parents=True, exist_ok=True)
Path(UNIQUE_DIR).mkdir(parents=True, exist_ok=True)
Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)

# Шаг 1: Создаём corpus если нет
print("\n[1/6] Creating corpus...")
corpus_files = {
    "small.txt": "test",
    "medium.txt": "A" * 100,
    "large.txt": "B" * 200,
    "huge.txt": "C" * 500
}

for fname, content in corpus_files.items():
    fpath = Path(CORPUS_DIR) / fname
    if not fpath.exists():
        fpath.write_text(content + "\n")
        print(f"  Created: {fname}")

# Шаг 2: Компилируем target
print("\n[2/6] Building target...")
result = subprocess.run(
    ["gcc", "-O0", "-fno-stack-protector", "-z", "execstack", "-no-pie",
     "-o", "blackbox-target/target", "blackbox-target/vulnerable.c"],
    capture_output=True, text=True
)
if result.returncode == 0:
    print("  Target compiled successfully")
else:
    print(f"  ERROR: {result.stderr}")
    sys.exit(1)

# Шаг 3: Запускаем fuzzing
print(f"\n[3/6] Running Black Box Fuzzing ({ITERATIONS} iterations)...")
crash_count = 0

for i in range(1, ITERATIONS + 1):
    # Выбираем случайный seed
    seed_file = random.choice(list(Path(CORPUS_DIR).glob("*.txt")))
    
    # Копируем и мутируем
    test_file = Path("/tmp/mutated_test.txt")
    shutil.copy2(seed_file, test_file)
    
    # Добавляем случайные данные
    random_data = bytes([random.randint(0, 255) for _ in range(random.randint(50, 200))])
    with open(test_file, "ab") as f:
        f.write(random_data)
    
    # Запускаем target
    try:
        result = subprocess.run(
            ["timeout", "1s", TARGET, str(test_file)],
            capture_output=True,
            timeout=2
        )
        exit_code = result.returncode
        
        # Проверяем краш
        if exit_code in [139, 134, 136]:  # SIGSEGV, SIGABRT, SIGILL
            crash_count += 1
            crash_file = Path(CRASHES_DIR) / f"crash_{crash_count:04d}.txt"
            shutil.copy2(test_file, crash_file)
            
            if crash_count % 50 == 0:
                print(f"  Progress: {i}/{ITERATIONS} | Crashes: {crash_count}")
                
    except Exception as e:
        pass

print(f"\n  Fuzzing complete!")
print(f"  Total crashes: {crash_count}")

if crash_count == 0:
    print("\n  No crashes found. Exiting.")
    sys.exit(0)

# Шаг 4: Дедупликация
print(f"\n[4/6] Deduplicating crashes...")
size_groups = defaultdict(list)

for crash in Path(CRASHES_DIR).glob("crash_*.txt"):
    size = crash.stat().st_size
    size_groups[size].append(crash)

unique_count = 0
for size, files in size_groups.items():
    unique_file = files[0]
    unique_name = f"unique_{unique_count:04d}.txt"
    shutil.copy2(unique_file, Path(UNIQUE_DIR) / unique_name)
    
    if len(files) > 1:
        print(f"  Size {size} bytes: {len(files)} crashes -> 1 unique")
    
    unique_count += 1

duplicates = crash_count - unique_count
dedup_rate = (duplicates * 100 // crash_count) if crash_count > 0 else 0

print(f"\n  === DEDUPLICATION RESULTS ===")
print(f"  Total crashes: {crash_count}")
print(f"  Unique crashes: {unique_count}")
print(f"  Duplicates: {duplicates}")
print(f"  Deduplication rate: {dedup_rate}%")

# Шаг 5: Классификация и создание findings
print(f"\n[5/6] Classifying vulnerabilities...")
classifications = []
findings = []

for idx, unique_crash in enumerate(sorted(Path(UNIQUE_DIR).glob("unique_*.txt"))):
    size = unique_crash.stat().st_size
    
    # Классификация по размеру
    if size > 200:
        vuln_type = "Heap Buffer Overflow"
        cwe = 122
        cvss = 9.8
        severity = "Critical"
    elif size > 64:
        vuln_type = "Stack Buffer Overflow"
        cwe = 121
        cvss = 9.8
        severity = "Critical"
    elif size > 10:
        vuln_type = "Buffer Overflow"
        cwe = 120
        cvss = 8.8
        severity = "High"
    else:
        vuln_type = "Null Pointer Dereference"
        cwe = 476
        cvss = 5.5
        severity = "Medium"
    
    classification = {
        'file': unique_crash.name,
        'size': size,
        'type': vuln_type,
        'cwe': cwe,
        'cvss': cvss,
        'severity': severity
    }
    classifications.append(classification)
    
    # Создаём DefectDojo finding
    finding = {
        'title': f"[BLACK BOX] {vuln_type} - Crash #{idx+1}",
        'description': f"""## Black Box Fuzzing Finding

**Vulnerability:** {vuln_type}
**CWE:** {cwe}
**CVSS:** {cvss}
**Severity:** {severity}

### Details
- Input size: {size} bytes
- Mode: Black Box (automated fuzzing)
- Total crashes: {crash_count}
- Unique crashes: {unique_count}
- Deduplication rate: {dedup_rate}%

### Reproduction
./blackbox-target/target blackbox-target/unique/{unique_crash.name}

### Next Steps
1. Manual analysis with GDB/ASan
2. Confirm vulnerability type
3. Implement fix
""",
        'severity': severity,
        'cwe': cwe,
        'cvssv3_score': cvss,
        'file_path': 'blackbox-target/vulnerable.c',
        'active': True,
        'verified': False,
        'false_p': False,
        'duplicate': False,
        'dynamic_finding': True,
        'tags': ['blackbox', 'fuzzing', 'auto-generated', f'cwe-{cwe}']
    }
    findings.append(finding)
    
    print(f"  {unique_crash.name}: {vuln_type} (CWE-{cwe}, CVSS {cvss})")

# Сохраняем результаты
(Path(REPORTS_DIR) / 'classifications.json').write_text(
    json.dumps(classifications, indent=2)
)
(Path(REPORTS_DIR) / 'defectdojo_findings.json').write_text(
    json.dumps(findings, indent=2)
)

# Шаг 6: Создаём Jira tickets и email
print(f"\n[6/6] Creating Jira tickets and email...")

tickets = []
for finding in findings:
    ticket = {
        'project': 'SEC',
        'summary': finding['title'],
        'description': finding['description'],
        'priority': 'Highest' if finding['severity'] == 'Critical' else 'High',
        'type': 'Bug',
        'labels': ['security', 'blackbox', 'fuzzing', f"cwe-{finding['cwe']}"]
    }
    tickets.append(ticket)

(Path(REPORTS_DIR) / 'jira_tickets.json').write_text(
    json.dumps(tickets, indent=2)
)

# Email notification
email_content = f"""From: fuzzing-pipeline@company.com
To: security-team@company.com
Subject: [BLACK BOX] Automated Fuzzing Found {unique_count} Vulnerabilities

AUTOMATED BLACK BOX FUZZING RESULTS
====================================

Target: blackbox-target/vulnerable.c
Mode: Automated Black Box Fuzzing
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY:
--------
Total iterations: {ITERATIONS}
Total crashes: {crash_count}
Unique crashes: {unique_count}
Duplicates: {duplicates}
Deduplication rate: {dedup_rate}%

FINDINGS:
---------
"""

for idx, finding in enumerate(findings, 1):
    email_content += f"""
{idx}. {finding['title']}
   CWE: {finding['cwe']}
   CVSS: {finding['cvssv3_score']}
   Severity: {finding['severity']}
   File: {finding['file_path']}
"""

email_content += f"""
NEXT STEPS:
-----------
1. Review findings in DefectDojo
2. Manual analysis with GDB/ASan
3. Confirm and prioritize vulnerabilities
4. Implement fixes
5. Retest

ARTIFACTS:
----------
- Crash files: blackbox-target/crashes/
- Unique crashes: blackbox-target/unique/
- Classifications: blackbox-target/reports/classifications.json
- DefectDojo findings: blackbox-target/reports/defectdojo_findings.json
- Jira tickets: blackbox-target/reports/jira_tickets.json

---
Automated message from Black Box Fuzzing Pipeline
"""

(Path(REPORTS_DIR) / 'email_notification.txt').write_text(email_content)

# Итоговый summary
summary = {
    'timestamp': datetime.now().isoformat(),
    'target': TARGET,
    'iterations': ITERATIONS,
    'total_crashes': crash_count,
    'unique_crashes': unique_count,
    'duplicates': duplicates,
    'deduplication_rate': f"{dedup_rate}%",
    'findings_created': len(findings),
    'tickets_created': len(tickets),
    'output_dir': str(Path('blackbox-target').absolute())
}

(Path(REPORTS_DIR) / 'summary.json').write_text(
    json.dumps(summary, indent=2)
)

print("\n" + "=" * 70)
print("PIPELINE COMPLETE")
print("=" * 70)
print(f"Total crashes: {crash_count}")
print(f"Unique crashes: {unique_count}")
print(f"Deduplication rate: {dedup_rate}%")
print(f"Findings created: {len(findings)}")
print(f"Tickets created: {len(tickets)}")
print(f"\nReports: {Path(REPORTS_DIR).absolute()}")
print("=" * 70)

# Показываем результаты
print("\n=== QUICK VIEW ===")
print("\nDefectDojo Findings:")
for f in findings[:3]:
    print(f"  - {f['title']} (CVSS {f['cvssv3_score']})")

print("\nJira Tickets:")
for t in tickets[:3]:
    print(f"  - {t['summary']} ({t['priority']})")

print("\nEmail preview:")
print(email_content[:500] + "...")

print("\n✅ AUTOMATION COMPLETE!")
print("   All results saved to blackbox-target/reports/")
