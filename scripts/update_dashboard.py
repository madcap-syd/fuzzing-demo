#!/usr/bin/env python3
"""
Обновление Dashboard с поддержкой всех инструментов
"""

import json
import os

def load_all_findings():
    """Загружает findings из всех источников"""
    all_findings = []
    
    reports_dir = os.path.expanduser("~/fuzzing-demo/reports")
    
    # Semgrep
    semgrep_file = os.path.join(reports_dir, "fstec", "js", "semgrep_results.json")
    if os.path.exists(semgrep_file):
        with open(semgrep_file, 'r') as f:
            data = json.load(f)
        for result in data.get('results', []):
            all_findings.append({
                'tool': 'Semgrep',
                'name': result.get('check_id', '').split('.')[-1],
                'severity': 'High' if result.get('extra', {}).get('severity') == 'ERROR' else 'Medium',
                'file': result.get('path', ''),
                'line': result.get('start', {}).get('line', 1)
            })
    
    # Bandit
    bandit_file = os.path.join(reports_dir, "bandit", "bandit_results.json")
    if os.path.exists(bandit_file):
        with open(bandit_file, 'r') as f:
            data = json.load(f)
        for issue in data.get('results', []):
            all_findings.append({
                'tool': 'Bandit',
                'name': issue.get('test_id', ''),
                'severity': issue.get('issue_severity', 'Medium'),
                'file': os.path.basename(issue.get('filename', '')),
                'line': issue.get('line_number', 1)
            })
    
    # Trivy
    trivy_dir = os.path.join(reports_dir, "trivy")
    if os.path.exists(trivy_dir):
        for filename in os.listdir(trivy_dir):
            if filename.endswith('.json') and 'trivy_' in filename:
                with open(os.path.join(trivy_dir, filename), 'r') as f:
                    data = json.load(f)
                for result in data.get('Results', []):
                    for vuln in result.get('Vulnerabilities', []):
                        all_findings.append({
                            'tool': 'Trivy',
                            'name': vuln.get('VulnerabilityID', ''),
                            'severity': vuln.get('Severity', 'Medium'),
                            'file': result.get('Target', ''),
                            'line': 1
                        })
    
    return all_findings

def main():
    findings = load_all_findings()
    
    print("=" * 70)
    print("📊 ОБЩАЯ СТАТИСТИКА УЯЗВИМОСТЕЙ")
    print("=" * 70)
    print()
    print(f"Всего найдено: {len(findings)}")
    print()
    
    by_tool = {}
    for f in findings:
        tool = f['tool']
        by_tool[tool] = by_tool.get(tool, 0) + 1
    
    print("По инструментам:")
    for tool, count in by_tool.items():
        print(f"  - {tool}: {count}")
    print()
    
    by_severity = {}
    for f in findings:
        sev = f['severity']
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    print("По severity:")
    for sev, count in sorted(by_severity.items()):
        print(f"  - {sev}: {count}")

if __name__ == "__main__":
    main()
