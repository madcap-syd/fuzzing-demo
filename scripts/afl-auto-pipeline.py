#!/usr/bin/env python3
"""
AFL++ Automated Pipeline
Автоматизация: fuzzing -> дедупликация -> классификация -> DefectDojo -> Jira -> Email
"""

import os
import sys
import json
import subprocess
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict

class AFLAutoPipeline:
    def __init__(self, target_path, corpus_dir, output_dir, mode='qemu'):
        self.target = Path(target_path)
        self.corpus = Path(corpus_dir)
        self.output = Path(output_dir)
        self.mode = mode
        self.crashes_dir = self.output / 'crashes'
        self.unique_dir = self.output / 'unique'
        self.reports_dir = self.output / 'reports'
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        self.unique_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        print("=" * 60)
        print("AFL++ AUTOMATED PIPELINE")
        print("=" * 60)
    
    def step1_run_afl(self, timeout=300):
        print("\n[1/5] Running AFL++ fuzzing...")
        cmd = ['afl-fuzz', '-i', str(self.corpus), '-o', str(self.output), '-t', '5000', '-V', str(timeout)]
        if self.mode == 'qemu':
            cmd.append('-Q')
        cmd.extend(['--', str(self.target), '@@'])
        print(f"Command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
            print(f"AFL++ exit code: {result.returncode}")
        except subprocess.TimeoutExpired:
            print("AFL++ timeout reached (normal)")
        except FileNotFoundError:
            print("ERROR: afl-fuzz not found")
            return False
        afl_crashes = self.output / 'default' / 'crashes'
        if not afl_crashes.exists():
            print("No AFL++ crashes directory found")
            return False
        crash_files = list(afl_crashes.glob('id:*'))
        print(f"Found {len(crash_files)} crashes")
        for crash in crash_files:
            shutil.copy2(crash, self.crashes_dir / crash.name)
        return len(crash_files) > 0
    
    def step2_deduplicate(self):
        print("\n[2/5] Deduplicating crashes...")
        crashes = list(self.crashes_dir.glob('*'))
        if not crashes:
            print("No crashes to deduplicate")
            return 0
        print(f"Total crashes: {len(crashes)}")
        sig_groups = defaultdict(list)
        for crash in crashes:
            content = crash.read_bytes()
            signature = f"{len(content)}:{content[:32].hex()}"
            sig_groups[signature].append(crash)
        unique_count = 0
        for sig, files in sig_groups.items():
            unique_file = files[0]
            unique_name = f"unique_{unique_count:04d}_{unique_file.name}"
            shutil.copy2(unique_file, self.unique_dir / unique_name)
            if len(files) > 1:
                print(f"  Group {unique_count}: {len(files)} crashes -> 1 unique")
            unique_count += 1
        total = len(crashes)
        duplicates = total - unique_count
        rate = (duplicates * 100 // total) if total > 0 else 0
        print(f"\n=== DEDUPLICATION RESULTS ===")
        print(f"Total crashes: {total}")
        print(f"Unique crashes: {unique_count}")
        print(f"Duplicates: {duplicates}")
        print(f"Deduplication rate: {rate}%")
        return unique_count
    
    def step3_classify(self):
        print("\n[3/5] Classifying vulnerabilities...")
        unique_crashes = list(self.unique_dir.glob('*'))
        classifications = []
        for crash in unique_crashes:
            size = crash.stat().st_size
            if size > 200:
                vuln_type, cwe, cvss, severity = "Heap Buffer Overflow", 122, 9.8, "Critical"
            elif size > 64:
                vuln_type, cwe, cvss, severity = "Stack Buffer Overflow", 121, 9.8, "Critical"
            elif size > 10:
                vuln_type, cwe, cvss, severity = "Buffer Overflow (small)", 120, 8.8, "High"
            else:
                vuln_type, cwe, cvss, severity = "Null Pointer Dereference", 476, 5.5, "Medium"
            classifications.append({
                'file': crash.name, 'size': size, 'vuln_type': vuln_type,
                'cwe': cwe, 'cvss': cvss, 'severity': severity,
                'confidence': 'Medium', 'note': 'Black Box estimation'
            })
            print(f"  {crash.name}: {vuln_type} (CWE-{cwe}, CVSS {cvss})")
        (self.reports_dir / 'classifications.json').write_text(json.dumps(classifications, indent=2))
        return classifications
    
    def step4_create_findings(self):
        print("\n[4/5] Creating DefectDojo findings...")
        classifications_file = self.reports_dir / 'classifications.json'
        if not classifications_file.exists():
            return []
        classifications = json.loads(classifications_file.read_text())
        findings = []
        for idx, cls in enumerate(classifications):
            findings.append({
                'title': f"[BLACK BOX] {cls['vuln_type']} - Crash #{idx+1}",
                'description': f"Vulnerability: {cls['vuln_type']}\nCWE: {cls['cwe']}\nCVSS: {cls['cvss']}\nSeverity: {cls['severity']}\nFile: {cls['file']}\nSize: {cls['size']} bytes",
                'severity': cls['severity'], 'cwe': cls['cwe'], 'cvssv3_score': cls['cvss'],
                'file_path': str(self.target), 'active': True, 'verified': False,
                'false_p': False, 'duplicate': False, 'dynamic_finding': True,
                'tags': ['blackbox', 'afl', 'fuzzing']
            })
        (self.reports_dir / 'defectdojo_findings.json').write_text(json.dumps(findings, indent=2))
        print(f"Created {len(findings)} findings")
        return findings
    
    def step5_create_tickets(self):
        print("\n[5/5] Creating Jira tickets and email...")
        findings_file = self.reports_dir / 'defectdojo_findings.json'
        if not findings_file.exists():
            return []
        findings = json.loads(findings_file.read_text())
        tickets = []
        for finding in findings:
            tickets.append({
                'project': 'SEC', 'summary': finding['title'],
                'description': finding['description'],
                'priority': 'Highest' if finding['severity'] == 'Critical' else 'High',
                'type': 'Bug', 'labels': ['security', 'blackbox', 'afl']
            })
        (self.reports_dir / 'jira_tickets.json').write_text(json.dumps(tickets, indent=2))
        email = f"""From: fuzzing-pipeline@company.com
To: security-team@company.com
Subject: [BLACK BOX] AFL++ found {len(findings)} vulnerabilities

SUMMARY:
- Total crashes: {sum(1 for _ in self.crashes_dir.glob('*'))}
- Unique crashes: {len(findings)}
- Mode: AFL++ QEMU (Black Box)

FINDINGS:
"""
        for idx, f in enumerate(findings, 1):
            email += f"{idx}. {f['title']} (CWE-{f['cwe']}, CVSS {f['cvssv3_score']})\n"
        email += f"\nPipeline: https://github.com/actions/runs/{os.environ.get('GITHUB_RUN_ID', 'local')}\n"
        (self.reports_dir / 'email_notification.txt').write_text(email)
        print(f"Created {len(tickets)} tickets")
        return tickets

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 afl-auto-pipeline.py <target> <corpus> <output> [timeout]")
        sys.exit(1)
    target, corpus, output = sys.argv[1], sys.argv[2], sys.argv[3]
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 300
    pipeline = AFLAutoPipeline(target, corpus, output, mode='qemu')
    has_crashes = pipeline.step1_run_afl(timeout)
    if not has_crashes:
        print("No crashes found")
        sys.exit(0)
    unique_count = pipeline.step2_deduplicate()
    if unique_count == 0:
        print("No unique crashes")
        sys.exit(0)
    pipeline.step3_classify()
    pipeline.step4_create_findings()
    pipeline.step5_create_tickets()
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)

if __name__ == '__main__':
    main()
