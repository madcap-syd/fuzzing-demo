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
    
    finding_data = {
        'title': '[CVE-2022-2309] Null Pointer Dereference in libxml2 2.9.14',
        'description': '## CVE-2022-2309\n\n**Description:** Null pointer dereference in libxml2 2.9.14 when processing malformed XML with DTD validation.\n\n**Affected Version:** libxml2 2.9.14\n\n**Fixed Version:** libxml2 2.9.15\n\n**CVSS:** 9.8 (Critical)\n\n**CWE:** CWE-476 (Null Pointer Dereference)\n\n**Impact:** Remote attackers can cause denial of service via crafted XML document.\n\n**PoC:**\n```xml\n<?xml version="1.0"?>\n<!DOCTYPE root [\n<!ELEMENT root ANY>\n<!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<root>&xxe;</root>\n```\n\n**Remediation:** Upgrade to libxml2 >= 2.9.15',
        'severity': 'Critical',
        'numerical_severity': 'S0',
        'cwe': 476,
        'cvssv3_score': 9.8,
        'test': 2,
        'found_by': [test_type_id],
        'unique_id_from_tool': 'CVE-2022-2309-libxml2-2.9.14',
        'vuln_id_from_tool': 'CVE-2022-2309',
        'active': True,
        'verified': True,
        'false_p': False,
        'duplicate': False,
        'mitigation': 'Upgrade libxml2 to version 2.9.15 or later',
        'impact': 'Denial of service via null pointer dereference',
        'references': 'https://nvd.nist.gov/vuln/detail/CVE-2022-2309',
        'tags': ['cve-2022-2309', 'libxml2', 'null-dereference', 'critical', 'fstec-239'],
    }
    
    r = requests.post(f"{BASE_URL}/findings/", headers=headers, json=finding_data)
    
    if r.status_code == 201:
        fid = r.json()['id']
        print(f"✅ Finding создан: ID {fid}")
        print(f"   Title: {finding_data['title']}")
        print(f"   Severity: Critical (S0)")
        print(f"   CWE: CWE-476")
        print(f"   CVSS: 9.8")
        print(f"   URL: http://localhost:8080/finding/{fid}")
    else:
        print(f"❌ Ошибка: {r.status_code}")
        print(f"   {r.text[:300]}")

if __name__ == "__main__":
    main()
