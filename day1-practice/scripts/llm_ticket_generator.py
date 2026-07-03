#!/usr/bin/env python3
"""
llm_ticket_generator.py — Ollama генерирует описание тикета для Jira
"""

import subprocess
import json
from pathlib import Path
from datetime import datetime

def generate_ticket_description(analysis: dict) -> str:
    """LLM генерирует красивое описание для Jira"""
    
    prompt = f"""Generate a professional Jira ticket description for this security bug:

Type: {analysis.get('type', 'Unknown')}
CWE: CWE-{analysis.get('cwe', 'N/A')}
CVSS: {analysis.get('cvss', 'N/A')}
Root cause: {analysis.get('root_cause', 'N/A')}
Suggested fix: {analysis.get('fix', 'N/A')}

Include:
1. h2. Summary (one line)
2. h2. Description (detailed)
3. h2. Steps to reproduce
4. h2. Impact
5. h2. Suggested fix
6. h2. References

Format in Jira markup (h2., *, {{code}}).
"""
    
    result = subprocess.run(
        ['ollama', 'run', 'qwen2.5-coder:1.5b', prompt],
        capture_output=True,
        text=True,
        timeout=60
    )
    
    return result.stdout.strip()

def main():
    analysis_file = Path('reports/llm_crash_analysis.json')
    if not analysis_file.exists():
        print("❌ Анализ краша не найден")
        return
    
    with open(analysis_file) as f:
        data = json.load(f)
    
    analysis = data['analysis']
    
    if analysis.get('is_fp', False):
        print("⚠️  Это false positive, тикет не создаём")
        return
    
    print("🎫 Генерация тикета с LLM-помощью...")
    
    description = generate_ticket_description(analysis)
    
    cvss = analysis.get('cvss', 5.0)
    priority = 'Highest' if cvss >= 9.0 else 'High' if cvss >= 7.0 else 'Medium'
    
    ticket = {
        'key': 'SEC-0001',
        'summary': f"[FUZZ] {analysis.get('type')} — CVSS {cvss}",
        'description': description,
        'priority': priority,
        'labels': [
            'fuzzing',
            'llm-analyzed',
            f"cwe-{analysis.get('cwe', 'N/A')}",
            f"cvss-{cvss}",
            'fstec-239'
        ],
        'created': datetime.now().isoformat(),
        'signature': data['signature'],
    }
    
    print(f"\n{'='*70}")
    print(f"🎫 ТИКЕТ С LLM-ОПИСАНИЕМ")
    print(f"{'='*70}")
    print(f"Key:        {ticket['key']}")
    print(f"Summary:    {ticket['summary']}")
    print(f"Priority:   {ticket['priority']}")
    print(f"Labels:     {', '.join(ticket['labels'])}")
    print(f"\nDescription (первые 500 символов):")
    print(ticket['description'][:500])
    print(f"{'='*70}")
    
    Path('reports/llm_ticket.json').write_text(json.dumps(ticket, indent=2))
    print(f"\n✅ Тикет сохранён: reports/llm_ticket.json")

if __name__ == "__main__":
    main()
