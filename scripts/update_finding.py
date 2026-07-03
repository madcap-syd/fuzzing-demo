#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://localhost:8080/api/v2"
USERNAME = "admin"
PASSWORD = "TZtV5QU3g2wCmwwDlvf6TM"

def get_token():
    r = requests.post(f"{BASE_URL}/api-token-auth/", json={"username": USERNAME, "password": PASSWORD})
    return r.json().get('token')

def main():
    token = get_token()
    headers = {'Authorization': f'Token {token}', 'Content-Type': 'application/json'}
    
    # Получаем test_type_id
    r = requests.get(f"{BASE_URL}/test_types/", headers=headers)
    test_type_id = r.json()['results'][0]['id']
    
    # Новые данные
    finding_data = {
        'title': '[FUZZ] heap-buffer-overflow — CVSS 9.8',
        'description': 'Automated Fuzzing Finding\n\nSignature: 51a0815d6ae93f05\nType: heap-buffer-overflow\nCWE: CWE-122\nCVSS: 9.8\nRoot Cause: packet_parser.cpp:23 in parsePacket\nFix: Add bounds checking before memcpy - validate packet.length <= 256',
        'severity': 'Critical',
        'numerical_severity': 'S0',
        'cwe': 122,
        'cvssv3_score': 9.8,
        'test': 2,
        'found_by': [test_type_id],
        'unique_id_from_tool': '51a0815d6ae93f05',
        'vuln_id_from_tool': 'libFuzzer-heap-buffer-overflow',
        'active': True,
        'verified': False,
        'false_p': False,
        'duplicate': False,
        'mitigation': 'Add bounds checking before memcpy - validate packet.length <= 256',
        'impact': 'Heap buffer overflow can lead to memory corruption and potential RCE',
        'references': 'https://cwe.mitre.org/data/definitions/122.html',
        'tags': ['fuzzing', 'libFuzzer', 'asan', 'heap-buffer-overflow', 'fstec-239', 'llm-analyzed', 'critical'],
    }
    
    # Обновляем finding ID 1
    r = requests.put(f"{BASE_URL}/findings/1/", headers=headers, json=finding_data)
    
    if r.status_code == 200:
        print(f"\n{'='*70}")
        print(f"✅ FINDING ОБНОВЛЁН!")
        print(f"{'='*70}")
        print(f"   ID:          1")
        print(f"   Title:       {finding_data['title']}")
        print(f"   Severity:    {finding_data['severity']} (S0)")
        print(f"   CWE:         CWE-122")
        print(f"   CVSS:        9.8")
        print(f"   URL:         http://localhost:8080/finding/1")
        print(f"{'='*70}\n")
    else:
        print(f"❌ Ошибка: {r.status_code}")
        print(f"   {r.text[:500]}")

if __name__ == "__main__":
    main()
