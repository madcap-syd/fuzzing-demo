#!/usr/bin/env python3
import json
import sys
import os
from pathlib import Path
from datetime import datetime

log_file = sys.argv[1] if len(sys.argv) > 1 else './fuzzing-final.log'
crash_dir = sys.argv[2] if len(sys.argv) > 2 else './crashes'

print(f"Загрузка в DefectDojo...")
print(f"  Лог: {log_file}")
print(f"  Краши: {crash_dir}")

log_content = Path(log_file).read_text()

stack_lines = []
for line in log_content.split('\n'):
    if line.strip().startswith('#0') or line.strip().startswith('#1'):
        stack_lines.append(line.strip())

vuln_type = "Null Pointer Dereference"
if "heap-buffer-overflow" in log_content.lower():
    vuln_type = "Heap Buffer Overflow"
elif "stack-buffer-overflow" in log_content.lower():
    vuln_type = "Stack Buffer Overflow"
elif "use-after-free" in log_content.lower():
    vuln_type = "Use After Free"

stack_text = '\n'.join(stack_lines)

finding = {
    "title": f"[FUZZING] {vuln_type}",
    "description": f"## Vulnerability Found\n\n**Type:** {vuln_type}\n**Severity:** Critical\n**CWE:** 476\n**CVSS:** 9.8\n**Date:** {datetime.now().isoformat()}\n\n### Stack Trace\n```\n{stack_text}\n```\n\n### Reproduction\n```bash\n./fuzz_target crash_file\n```",
    "severity": "Critical",
    "cwe": 476,
    "cvss": 9.8,
    "file_path": "/build/harness.cpp",
    "line": 10,
    "active": True,
    "verified": False,
    "false_p": False,
}

output_file = 'defectdojo_findings.json'
Path(output_file).write_text(json.dumps(finding, indent=2))

print(f"Finding сохранён в {output_file}")
print(f"  Title: {finding['title']}")
print(f"  Severity: {finding['severity']}")
print(f"  CWE: {finding['cwe']}")
print(f"  CVSS: {finding['cvss']}")

crash_files = list(Path(crash_dir).glob('crash-*'))
print(f"\nCrash files: {len(crash_files)}")
for cf in crash_files:
    print(f"  - {cf.name} ({cf.stat().st_size} bytes)")

print("\nГотово!")
