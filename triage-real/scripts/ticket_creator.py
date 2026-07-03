#!/usr/bin/env python3
"""
ticket_creator.py — создание тикетов (mock Jira/DefectDojo)
"""

import json
from pathlib import Path
from datetime import datetime

class MockJira:
    """Mock Jira для демонстрации"""
    
    def __init__(self):
        self.tickets = []
        self.next_key = 1
    
    def create_ticket(self, bug: dict) -> str:
        key = f"SEC-{self.next_key:04d}"
        self.next_key += 1
        
        priority = 'Highest' if bug['cvss'] >= 9.0 else 'High' if bug['cvss'] >= 7.0 else 'Medium'
        
        ticket = {
            'key': key,
            'summary': f"[FUZZ] {bug['type']} — {bug['crash_count']} crashes",
            'priority': priority,
            'cvss': bug['cvss'],
            'cwe': bug['cwe'],
            'type': bug['type'],
            'signature': bug['signature'],
            'status': 'Open',
            'labels': ['fuzzing', 'auto-triage', bug['type']],
            'created': datetime.now().isoformat(),
        }
        
        self.tickets.append(ticket)
        return key

class MockDefectDojo:
    """Mock DefectDojo для демонстрации"""
    
    def __init__(self):
        self.findings = []
    
    def import_finding(self, bug: dict) -> str:
        finding_id = f"DD-{len(self.findings)+1:04d}"
        
        finding = {
            'id': finding_id,
            'title': f"[Fuzzing] {bug['type']} ({bug['crash_count']} crashes)",
            'severity': 'Critical' if bug['cvss'] >= 9.0 else 'High' if bug['cvss'] >= 7.0 else 'Medium',
            'cvssv3_score': bug['cvss'],
            'cwe': bug['cwe'],
            'unique_id_from_tool': bug['signature'],
            'verified': False,
            'active': True,
            'duplicate': False,
        }
        
        self.findings.append(finding)
        return finding_id

def main():
    # Загружаем результаты triage
    triage_file = Path('triage-demo/triage_results.json')
    with open(triage_file) as f:
        triage_results = json.load(f)
    
    jira = MockJira()
    dojo = MockDefectDojo()
    
    print(f"\n{'='*70}")
    print(f"🎫 СОЗДАНИЕ ТИКЕТОВ (Mock Jira + DefectDojo)")
    print(f"{'='*70}")
    
    created_jira = 0
    created_dojo = 0
    skipped_fp = 0
    
    for bug in triage_results['bugs']:
        if bug['is_fp']:
            skipped_fp += 1
            continue
        
        # Создаём тикет в Jira
        jira_key = jira.create_ticket(bug)
        created_jira += 1
        
        # Импортируем в DefectDojo
        dojo_key = dojo.import_finding(bug)
        created_dojo += 1
        
        print(f"   ✅ {jira_key} | {dojo_key} | {bug['type']:25} | CVSS {bug['cvss']} | ×{bug['crash_count']}")
    
    print(f"\n{'='*70}")
    print(f"📊 ИТОГИ:")
    print(f"   Создано тикетов Jira:      {created_jira}")
    print(f"   Импортировано в DefectDojo:{created_dojo}")
    print(f"   Пропущено FP:              {skipped_fp}")
    print(f"{'='*70}")
    
    # Сохраняем mock-результаты
    Path('triage-demo/jira_tickets.json').write_text(
        json.dumps(jira.tickets, indent=2)
    )
    Path('triage-demo/defectdojo_findings.json').write_text(
        json.dumps(dojo.findings, indent=2)
    )
    
    print(f"\n✅ Mock тикеты сохранены:")
    print(f"   triage-demo/jira_tickets.json")
    print(f"   triage-demo/defectdojo_findings.json")

if __name__ == "__main__":
    main()
