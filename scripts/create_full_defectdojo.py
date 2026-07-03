#!/usr/bin/env python3
import requests
import json
from pathlib import Path
from datetime import datetime

BASE_URL = "http://localhost:8080/api/v2"
USERNAME = "admin"
PASSWORD = "TZtV5QU3g2wCmwwDlvf6TM"

def get_token():
    r = requests.post(f"{BASE_URL}/api-token-auth/", json={"username": USERNAME, "password": PASSWORD})
    if r.status_code != 200:
        print(f"❌ Login failed: {r.status_code} {r.text}")
        return None
    return r.json().get('token')

def get_test_type_id(headers):
    """Получаем ID тестового типа"""
    r = requests.get(f"{BASE_URL}/test_types/", headers=headers)
    if r.status_code == 200:
        results = r.json().get('results', [])
        if results:
            return results[0]['id']
    return 1

def get_dojo_user_id(headers):
    """Получаем ID текущего пользователя"""
    r = requests.get(f"{BASE_URL}/users/", headers=headers)
    if r.status_code == 200:
        results = r.json().get('results', [])
        for u in results:
            if u.get('username') == USERNAME:
                return u['id']
    return 1

def create_product(headers):
    r = requests.get(f"{BASE_URL}/products/?name=libxml2+Fuzzing+Lab", headers=headers)
    if r.status_code == 200 and r.json().get('count', 0) > 0:
        pid = r.json()['results'][0]['id']
        print(f"✅ Product уже существует: ID {pid}")
        return pid
    r = requests.post(f"{BASE_URL}/products/", headers=headers, json={
        'name': 'libxml2 Fuzzing Lab',
        'description': 'Automated fuzzing lab',
        'prod_type': 1,
    })
    if r.status_code == 201:
        pid = r.json()['id']
        print(f"✅ Product создан: ID {pid}")
        return pid
    print(f"❌ Product error: {r.status_code} {r.text[:200]}")
    return None

def create_engagement(headers, product_id, user_id):
    today = datetime.now().strftime('%Y-%m-%d')
    r = requests.post(f"{BASE_URL}/engagements/", headers=headers, json={
        'name': f'Fuzzing {today}',
        'product': product_id,
        'lead': user_id,
        'target_start': today,
        'target_end': today,
        'engagement_type': 'CI/CD',
        'status': 'In Progress',
    })
    if r.status_code == 201:
        eid = r.json()['id']
        print(f"✅ Engagement создан: ID {eid}")
        return eid
    print(f"❌ Engagement error: {r.status_code} {r.text[:200]}")
    return None

def create_test(headers, engagement_id, test_type_id, user_id):
    r = requests.post(f"{BASE_URL}/tests/", headers=headers, json={
        'title': 'libFuzzer Automated Test',
        'engagement': engagement_id,
        'test_type': test_type_id,
        'lead': user_id,
        'target_start': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        'target_end': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        'description': 'Automated fuzzing with libFuzzer + ASan',
    })
    if r.status_code == 201:
        tid = r.json()['id']
        print(f"✅ Test создан: ID {tid}")
        return tid
    print(f"❌ Test error: {r.status_code} {r.text[:200]}")
    return None

def get_numerical_severity(severity):
    """Маппинг severity → numerical_severity"""
    mapping = {
        'Critical': 'S0',
        'High': 'S1',
        'Medium': 'S2',
        'Low': 'S3',
        'Info': 'S4',
    }
    return mapping.get(severity, 'S2')

def create_finding(headers, test_id, test_type_id, analysis_data):
    analysis = analysis_data['analysis']
    signature = analysis_data['signature']
    cvss = analysis.get('cvss', 5.0)
    severity = 'Critical' if cvss >= 9.0 else 'High' if cvss >= 7.0 else 'Medium'
    numerical_severity = get_numerical_severity(severity)
    
    finding_data = {
        'title': f"[FUZZ] {analysis.get('type')} — CVSS {cvss}",
        'description': f"Automated Fuzzing Finding\n\nSignature: {signature}\nType: {analysis.get('type')}\nCWE: CWE-{analysis.get('cwe')}\nCVSS: {cvss}\nRoot Cause: {analysis.get('root_cause')}\nFix: {analysis.get('fix')}",
        'severity': severity,
        'numerical_severity': numerical_severity,
        'cwe': analysis.get('cwe', 0),
        'cvssv3_score': cvss,
        'test': test_id,
        'found_by': [test_type_id],
        'unique_id_from_tool': signature,
        'vuln_id_from_tool': 'libFuzzer-heap-buffer-overflow',
        'active': True,
        'verified': False,
        'false_p': analysis.get('is_fp', False),
        'duplicate': False,
        'mitigation': analysis.get('fix', 'Add bounds checking'),
        'impact': 'Heap buffer overflow can lead to memory corruption',
        'references': 'https://cwe.mitre.org/data/definitions/122.html',
        'tags': ['fuzzing', 'libFuzzer', 'asan', 'heap-buffer-overflow', 'fstec-239'],
    }
    
    r = requests.post(f"{BASE_URL}/findings/", headers=headers, json=finding_data)
    if r.status_code == 201:
        fid = r.json()['id']
        print(f"✅ Finding создан: ID {fid}")
        print(f"   URL: http://localhost:8080/finding/{fid}")
        print(f"   Title: {finding_data['title']}")
        print(f"   Severity: {severity} ({numerical_severity})")
        print(f"   CVSS: {cvss}")
        return fid
    print(f"❌ Finding error: {r.status_code}")
    print(f"   {r.text[:500]}")
    return None

def main():
    print("🔑 Получаем токен...")
    token = get_token()
    if not token:
        return
    
    headers = {'Authorization': f'Token {token}', 'Content-Type': 'application/json'}
    print(f"✅ Токен: {token[:20]}...")
    
    print("\n🔢 Получаем Test Type ID...")
    test_type_id = get_test_type_id(headers)
    print(f"   Test Type ID: {test_type_id}")
    
    print("\n👤 Получаем User ID...")
    user_id = get_dojo_user_id(headers)
    print(f"   User ID: {user_id}")
    
    print("\n🏢 Создаём Product...")
    product_id = create_product(headers)
    if not product_id:
        return
    
    print("\n🔗 Создаём Engagement...")
    engagement_id = create_engagement(headers, product_id, user_id)
    if not engagement_id:
        return
    
    print("\n🧪 Создаём Test...")
    test_id = create_test(headers, engagement_id, test_type_id, user_id)
    if not test_id:
        return
    
    print("\n🎯 Загружаем анализ краша...")
    analysis_file = Path('day1-practice/reports/llm_crash_analysis.json')
    if not analysis_file.exists():
        print("❌ Анализ не найден. Запусти: python3 scripts/llm_crash_analysis.py")
        return
    
    with open(analysis_file) as f:
        analysis_data = json.load(f)
    
    print("\n📝 Создаём Finding...")
    finding_id = create_finding(headers, test_id, test_type_id, analysis_data)
    
    if finding_id:
        print(f"\n{'='*70}")
        print(f"🎉 ПОЛНЫЙ ЦИКЛ ЗАВЕРШЁН!")
        print(f"{'='*70}")
        print(f"   Product ID:    {product_id}")
        print(f"   Engagement ID: {engagement_id}")
        print(f"   Test ID:       {test_id}")
        print(f"   Finding ID:    {finding_id}")
        print(f"\n🌐 Открой в браузере:")
        print(f"   http://localhost:8080/finding/{finding_id}")

if __name__ == "__main__":
    main()
