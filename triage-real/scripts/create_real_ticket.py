#!/usr/bin/env python3
"""
Создание тикета для реальной уязвимости
"""

import json
from pathlib import Path
from datetime import datetime

def main():
    # Загружаем анализ краша
    with open('triage-real/real_crash_analysis.json') as f:
        crash = json.load(f)
    
    # Создаём тикет
    ticket = {
        'key': 'SEC-0001',
        'summary': f"[FUZZ] {crash['crash_type']} in {crash['function']} — CVSS {crash['cvss']}",
        'description': f"""
h2. Fuzzing Bug Report — REAL CRASH

*Type:* {crash['crash_type']}
*CVSS:* {crash['cvss']}
*CWE:* CWE-{crash['cwe']}
*Location:* {crash['location']}
*Function:* {crash['function']}

h3. Stack Trace
{{code}}
{crash['stack_trace'][:500]}
{{code}}

h3. Reproduction
{{code}}
./fuzzer {crash['poc_file']}
{{code}}

h3. Impact
Heap buffer overflow in packet parser allows reading uninitialized memory.
Potential for information disclosure or crash (DoS).

h3. Metadata
* Found: {datetime.now().strftime('%Y-%m-%d %H:%M')}
* Fuzzer: libFuzzer + AddressSanitizer
* PoC: {crash['poc_file']}
        """,
        'priority': 'Highest' if crash['cvss'] >= 9.0 else 'High',
        'status': 'Open',
        'labels': ['fuzzing', 'real-crash', crash['crash_type'], f"cwe-{crash['cwe']}"],
        'created': datetime.now().isoformat(),
    }
    
    print(f"\n{'='*70}")
    print(f"🎫 СОЗДАНИЕ ТИКЕТА ДЛЯ РЕАЛЬНОЙ УЯЗВИМОСТИ")
    print(f"{'='*70}")
    print(f"   Key:             {ticket['key']}")
    print(f"   Summary:         {ticket['summary']}")
    print(f"   Priority:        {ticket['priority']}")
    print(f"   Type:            {crash['crash_type']}")
    print(f"   CVSS:            {crash['cvss']}")
    print(f"   CWE:             CWE-{crash['cwe']}")
    print(f"   Location:        {crash['location']}")
    print(f"{'='*70}")
    
    # Сохраняем тикет
    Path('triage-real/real_ticket.json').write_text(json.dumps(ticket, indent=2))
    
    print(f"\n✅ Тикет сохранён: triage-real/real_ticket.json")

if __name__ == "__main__":
    main()
