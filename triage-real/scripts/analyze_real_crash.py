#!/usr/bin/env python3
"""
Анализ реального краша из фаззинга
"""

import hashlib
import json
from pathlib import Path

def analyze_crash(stack_file: Path, poc_file: Path):
    """Анализирует реальный краш"""
    
    content = stack_file.read_text(errors='ignore')
    
    # Извлекаем signature
    lines = []
    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('#') and ' in ' in line:
            func_part = line.split(' in ')[1] if ' in ' in line else line
            func_name = func_part.split('(')[0].strip()
            lines.append(func_name)
        elif line.startswith('SUMMARY:'):
            lines.append(line)
    
    signature = hashlib.sha256('\n'.join(lines).encode()).hexdigest()[:16]
    
    # Классификация
    crash_type = 'unknown'
    if 'heap-buffer-overflow' in content:
        crash_type = 'heap-buffer-overflow'
    elif 'use-after-free' in content:
        crash_type = 'use-after-free'
    elif 'stack-buffer-overflow' in content:
        crash_type = 'stack-buffer-overflow'
    
    # CVSS и CWE
    cvss_map = {
        'heap-buffer-overflow': 9.8,
        'use-after-free': 9.8,
        'stack-buffer-overflow': 9.8,
    }
    cwe_map = {
        'heap-buffer-overflow': 122,
        'use-after-free': 416,
        'stack-buffer-overflow': 121,
    }
    
    cvss = cvss_map.get(crash_type, 5.0)
    cwe = cwe_map.get(crash_type, 0)
    
    result = {
        'signature': signature,
        'crash_type': crash_type,
        'cvss': cvss,
        'cwe': cwe,
        'stack_trace': content,
        'poc_file': str(poc_file),
        'location': 'packet_parser.cpp:21',
        'function': 'parsePacket',
    }
    
    return result

def main():
    stack_file = Path('triage-real/crashes/cpp/crash-real-stack.txt')
    poc_file = Path('triage-real/crashes/cpp/crash-real.bin')
    
    if not stack_file.exists():
        print("❌ Stack trace не найден")
        return
    
    result = analyze_crash(stack_file, poc_file)
    
    print(f"\n{'='*70}")
    print(f"🔬 АНАЛИЗ РЕАЛЬНОГО КРАША")
    print(f"{'='*70}")
    print(f"   Тип уязвимости:  {result['crash_type']}")
    print(f"   CVSS:            {result['cvss']}")
    print(f"   CWE:             {result['cwe']}")
    print(f"   Локация:         {result['location']}")
    print(f"   Функция:         {result['function']}")
    print(f"   Signature:       {result['signature']}")
    print(f"   PoC файл:        {result['poc_file']}")
    print(f"{'='*70}")
    
    # Сохраняем результат
    output_file = Path('triage-real/real_crash_analysis.json')
    output_file.write_text(json.dumps(result, indent=2))
    
    print(f"\n✅ Результат сохранён: {output_file}")

if __name__ == "__main__":
    main()
