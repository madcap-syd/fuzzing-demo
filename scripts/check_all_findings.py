#!/usr/bin/env python3
import requests

BASE_URL = "http://localhost:8080/api/v2"
USERNAME = "admin"
PASSWORD = "TZtV5QU3g2wCmwwDlvf6TM"

def get_token():
    r = requests.post(f"{BASE_URL}/api-token-auth/", json={"username": USERNAME, "password": PASSWORD})
    return r.json().get('token')

def main():
    token = get_token()
    headers = {'Authorization': f'Token {token}'}
    
    print("\n" + "="*70)
    print("📊 ВСЕ FINDINGS В DEFECTDOJO")
    print("="*70 + "\n")
    
    r = requests.get(f"{BASE_URL}/findings/", headers=headers)
    if r.status_code == 200:
        findings = r.json().get('results', [])
        print(f"✅ Всего Findings: {len(findings)}\n")
        
        for f in findings:
            print(f"{'─'*70}")
            print(f"ID:              {f.get('id')}")
            print(f"Title:           {f.get('title')}")
            print(f"Severity:        {f.get('severity')}")
            print(f"Numerical:       {f.get('numerical_severity')}")
            print(f"CWE:             CWE-{f.get('cwe')}")
            print(f"CVSS:            {f.get('cvssv3_score')}")
            print(f"Active:          {f.get('active')}")
            print(f"Verified:        {f.get('verified')}")
            print(f"URL:             http://localhost:8080/finding/{f.get('id')}")
        
        print(f"\n{'─'*70}")
        print(f"\n🌐 Откройте в браузере: http://localhost:8080/finding")
    else:
        print(f"❌ Ошибка API: {r.status_code}")

if __name__ == "__main__":
    main()
