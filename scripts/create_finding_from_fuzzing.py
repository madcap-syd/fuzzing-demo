#!/usr/bin/env python3
import requests
import json
from pathlib import Path
from datetime import datetime

def create_finding():
    analysis_file = Path('day1-practice/reports/llm_crash_analysis.json')
    if not analysis_file.exists():
        print("❌ Анализ краша не найден")
        return
    
    with open(analysis_file) as f:
        data = json.load(f)
    
    analysis = data['analysis']
    signature = data['signature']
    
    login_url = "http://localhost:8080/api/v2/api-token-auth/"
    login_data = {"username": "admin", "password": "TZtV5QU3g2wCmwwDlvf6TM"}
    
    response = requests.post(login_url, json=login_data)
    if response.status_code != 200:
        print("❌ Не удалось войти в DefectDojo")
        return
    
    token = response.json().get('token')
    headers = {'Authorization': f'Token {token}', 'Content-Type': 'application/json'}
    
    cvss = analysis.get('cvss', 5.0)
    severity = 'Critical' if cvss >= 9.0 else 'High' if cvss >= 7.0 else 'Medium'
    
    finding_data = {
        'title': f"[FUZZ] {analysis.get('type')} — CVSS {cvss}",
        'description': f"Automated Fuzzing Finding\n\nCrash Signature: {signature}\nType: {analysis.get('type')}\nCWE: CWE-{analysis.get('cwe', 'N/A')}\nCVSS: {cvss}\nRoot Cause: {analysis.get('root_cause', 'N/A')}\nFix: {analysis.get('fix', 'N/A')}",
        'severity': severity,
        'cwe': analysis.get('cwe', 0),
        'cvssv3_score': cvss,
        'engagement': 1,
        'unique_id_from_tool': signature,
        'vuln_id_from_tool': 'libFuzzer-heap-buffer-overflow',
        'active': True,
        'verified': False,
        'false_p': analysis.get('is_fp', False),
        'duplicate': False,
        'mitigation': analysis.get('fix', 'Add bounds checking'),
        'impact': 'Heap buffer overflow',
        'references': 'https://cwe.mitre.org/data/definitions/122.html',
        'tags': ['fuzzing', 'libFuzzer', 'asan', 'heap-buffer-overflow', 'fstec-239'],
    }
    
    url = "http://localhost:8080/api/v2/findings/"
    response = requests.post(url, headers=headers, json=finding_data)
    
    if response.status_code == 201:
        finding_id = response.json()['id']
        print(f"✅ Finding создан: ID {finding_id}")
        print(f"   URL: http://localhost:8080/finding/{finding_id}")
        print(f"   Title: {finding_data['title']}")
        print(f"   Severity: {severity}")
    else:
        print(f"❌ Ошибка: {response.status_code}")
        print(f"   {response.text[:300]}")

if __name__ == "__main__":
    create_finding()
