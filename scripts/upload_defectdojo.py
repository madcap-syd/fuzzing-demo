#!/usr/bin/env python3
import json, sys, os, requests, hashlib, re
from pathlib import Path
from datetime import datetime

DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', '')
DEFECTDOJO_API_KEY = os.environ.get('DEFECTDOJO_API_KEY', '')
DEMO_MODE = os.environ.get('DEMO_MODE', 'true').lower() == 'true'

VULN_MAPPING = {
    'SEGV': {'title': 'Null Pointer Dereference', 'cwe': 476, 'cvss': 9.8, 'severity': 'Critical'},
    'heap-buffer-overflow': {'title': 'Heap Buffer Overflow', 'cwe': 122, 'cvss': 9.8, 'severity': 'Critical'},
    'stack-buffer-overflow': {'title': 'Stack Buffer Overflow', 'cwe': 121, 'cvss': 9.8, 'severity': 'Critical'},
    'use-after-free': {'title': 'Use After Free', 'cwe': 416, 'cvss': 9.8, 'severity': 'Critical'},
}

def parse_log(log_file):
    log_content = Path(log_file).read_text()
    stack_lines, vuln_type, crash_file_path, crash_line = [], 'SEGV', '', 0
    for line in log_content.split('\n'):
        if 'ERROR: AddressSanitizer:' in line:
            for key in VULN_MAPPING:
                if key in line.lower(): vuln_type = key; break
        if line.strip().startswith('#0') or line.strip().startswith('#1'): stack_lines.append(line.strip())
        if 'SUMMARY:' in line:
            match = re.search(r'(\S+\.cpp):(\d+)', line)
            if match: crash_file_path, crash_line = match.group(1), int(match.group(2))
    return {'vuln_type': vuln_type, 'stack_trace': '\n'.join(stack_lines), 'crash_file': crash_file_path, 'crash_line': crash_line, 'log_content': log_content}

def create_finding(parsed, crash_dir):
    vuln_info = VULN_MAPPING.get(parsed['vuln_type'], VULN_MAPPING['SEGV'])
    crash_files = list(Path(crash_dir).glob('crash-*'))
    crash_hex = crash_files[0].read_bytes().hex() if crash_files else 'N/A'
    return {
        'title': f"[FUZZING] {vuln_info['title']}",
        'description': f"## Vulnerability Found\n\n**Type:** {vuln_info['title']}\n**Severity:** {vuln_info['severity']}\n**CWE:** {vuln_info['cwe']}\n**CVSS:** {vuln_info['cvss']}\n**Date:** {datetime.now().isoformat()}\n\n### Stack Trace\n```\n{parsed['stack_trace']}\n```\n\n### Crash File\n- Name: {crash_files[0].name if crash_files else 'N/A'}\n- Size: {crash_files[0].stat().st_size if crash_files else 0} bytes\n- Hex: {crash_hex}\n\n### Reproduction\n```bash\n./fuzz_target {crash_files[0].name if crash_files else 'crash_file'}\n```",
        'severity': vuln_info['severity'], 'numerical_severity': 'S0', 'cwe': vuln_info['cwe'],
        'cvssv3_score': vuln_info['cvss'], 'file_path': parsed['crash_file'] or '/build/harness.cpp',
        'line': parsed['crash_line'] or 10, 'active': True, 'verified': False, 'false_p': False,
        'duplicate': False, 'dynamic_finding': True, 'static_finding': False,
        'impact': 'Application crash, potential code execution',
        'mitigation': 'Add null checks before pointer dereference',
        'references': f"https://cwe.mitre.org/data/definitions/{vuln_info['cwe']}.html"
    }

def send_to_defectdojo(finding):
    if not DEFECTDOJO_API_KEY: print("⚠️  DEFECTDOJO_API_KEY not set - DEMO mode"); return None
    headers = {'Authorization': f'Token {DEFECTDOJO_API_KEY}', 'Content-Type': 'application/json'}
    payload = {**finding, 'test': 1}
    try:
        response = requests.post(f'{DEFECTDOJO_URL}/api/v2/findings/', headers=headers, json=payload, timeout=30)
        if response.status_code == 201:
            finding_id = response.json().get('id')
            print(f"✅ Finding created in DefectDojo: ID {finding_id}\n   URL: {DEFECTDOJO_URL}/finding/{finding_id}")
            return finding_id
        else: print(f"❌ DefectDojo API error: {response.status_code}\n   {response.text[:200]}"); return None
    except Exception as e: print(f"❌ Connection error: {e}"); return None

if len(sys.argv) < 3: print("Usage: python3 upload_defectdojo.py <log_file> <crash_dir>"); sys.exit(1)
log_file, crash_dir = sys.argv[1], sys.argv[2]
print(f"="*60+"\n📤 DEFECTDOJO UPLOAD\n{'='*60}\nMode: {'DEMO' if DEMO_MODE else 'PROD'}\nLog: {log_file}\nCrashes: {crash_dir}\n{'='*60}")
parsed = parse_log(log_file)
print(f"\n🔍 Vulnerability type: {parsed['vuln_type']}\n   File: {parsed['crash_file']}:{parsed['crash_line']}")
finding = create_finding(parsed, crash_dir)
if DEMO_MODE:
    Path('defectdojo_findings.json').write_text(json.dumps(finding, indent=2))
    print(f"\n✅ Finding saved to defectdojo_findings.json\n   Title: {finding['title']}\n   Severity: {finding['severity']}\n   CWE: {finding['cwe']}\n   CVSS: {finding['cvssv3_score']}")
else: send_to_defectdojo(finding)
print(f"\n{'='*60}\n✅ DONE\n{'='*60}")
