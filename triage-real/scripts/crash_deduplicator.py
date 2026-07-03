#!/usr/bin/env python3
"""
crash_deduplicator.py — дедупликация крашей по stack trace signature
"""

import hashlib
import json
from pathlib import Path
from collections import defaultdict

def extract_signature(crash_file: Path) -> str:
    """Извлекает signature из краш-файла"""
    content = crash_file.read_text(errors='ignore')
    
    # Берём ключевые строки stack trace
    lines = []
    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('#') and ' in ' in line:
            # Извлекаем функцию: "#0 0x4a1234 in parse_packet(...) file.cpp:31"
            func_part = line.split(' in ')[1] if ' in ' in line else line
            # Убираем аргументы и путь: "parse_packet(unsigned char const*) packet_parser.cpp:31"
            func_name = func_part.split('(')[0].strip()
            lines.append(func_name)
        elif line.startswith('SUMMARY:'):
            lines.append(line)
    
    # Хэшируем signature
    signature_text = '\n'.join(lines)
    return hashlib.sha256(signature_text.encode()).hexdigest()[:16]

def classify_crash(content: str) -> tuple[str, bool]:
    """Классифицирует тип краша и определяет FP"""
    
    # Тип краша
    if 'heap-buffer-overflow' in content:
        crash_type = 'heap-buffer-overflow'
    elif 'use-after-free' in content:
        crash_type = 'use-after-free'
    elif 'stack-buffer-overflow' in content:
        crash_type = 'stack-buffer-overflow'
    elif 'SEGV' in content or 'null-dereference' in content:
        crash_type = 'null-dereference'
    elif 'Prototype Pollution' in content or '__proto__' in content:
        crash_type = 'prototype-pollution'
    elif 'Timeout' in content or 'redos' in content.lower():
        crash_type = 'redos'
    elif 'out-of-memory' in content:
        crash_type = 'oom'
    elif 'Assertion' in content:
        crash_type = 'assertion-failure'
    else:
        crash_type = 'unknown'
    
    # Определение FP
    is_fp = False
    if crash_type == 'oom':
        is_fp = True
    elif crash_type == 'assertion-failure':
        if 'DEBUG' in content or 'debug' in content.lower() or 'test' in content.lower():
            is_fp = True
    
    return crash_type, is_fp

def get_cvss(crash_type: str) -> float:
    cvss_map = {
        'heap-buffer-overflow': 9.8,
        'use-after-free': 9.8,
        'stack-buffer-overflow': 9.8,
        'prototype-pollution': 9.1,
        'redos': 7.5,
        'null-dereference': 5.0,
        'assertion-failure': 3.0,
        'oom': 0.0,
        'unknown': 5.0,
    }
    return cvss_map.get(crash_type, 5.0)

def get_cwe(crash_type: str) -> int:
    cwe_map = {
        'heap-buffer-overflow': 122,
        'use-after-free': 416,
        'stack-buffer-overflow': 121,
        'prototype-pollution': 1321,
        'redos': 1333,
        'null-dereference': 476,
        'assertion-failure': 617,
        'oom': 0,
    }
    return cwe_map.get(crash_type, 0)

def main():
    crashes_dir = Path('triage-demo/crashes/cpp')
    signatures = defaultdict(list)
    
    print(f" Сканируем {crashes_dir}...")
    
    for crash_file in sorted(crashes_dir.glob('*.txt')):
        content = crash_file.read_text(errors='ignore')
        signature = extract_signature(crash_file)
        crash_type, is_fp = classify_crash(content)
        
        signatures[signature].append({
            'file': str(crash_file),
            'poc': str(crash_file).replace('.txt', '.bin'),
            'type': crash_type,
            'is_fp': is_fp,
            'cvss': get_cvss(crash_type),
            'cwe': get_cwe(crash_type),
        })
    
    # Формируем результат
    unique_bugs = []
    for sig, crashes in signatures.items():
        rep = crashes[0]
        unique_bugs.append({
            'signature': sig,
            'crash_count': len(crashes),
            'type': rep['type'],
            'is_fp': rep['is_fp'],
            'cvss': rep['cvss'],
            'cwe': rep['cwe'],
            'sample_file': rep['file'],
            'poc_file': rep['poc'],
        })
    
    # Сортировка: сначала реальные баги (по CVSS), потом FP
    unique_bugs.sort(key=lambda x: (x['is_fp'], -x['cvss'], -x['crash_count']))
    
    total_crashes = sum(len(c) for c in signatures.values())
    real_bugs = [b for b in unique_bugs if not b['is_fp']]
    fp_bugs = [b for b in unique_bugs if b['is_fp']]
    
    result = {
        'timestamp': '2026-06-29T16:00:00Z',
        'total_crashes': total_crashes,
        'unique_bugs': len(unique_bugs),
        'real_bugs': len(real_bugs),
        'false_positives': len(fp_bugs),
        'dedup_ratio': round(total_crashes / max(1, len(unique_bugs)), 1),
        'fp_rate': round(len(fp_bugs) / max(1, len(unique_bugs)) * 100, 1),
        'bugs': unique_bugs,
    }
    
    # Сохраняем
    output_file = Path('triage-demo/triage_results.json')
    output_file.write_text(json.dumps(result, indent=2))
    
    # Выводим сводку
    print(f"\n{'='*70}")
    print(f"📊 РЕЗУЛЬТАТЫ ДЕДУПЛИКАЦИИ")
    print(f"{'='*70}")
    print(f"   Всего крашей:        {total_crashes:>6}")
    print(f"   Уникальных багов:    {len(unique_bugs):>6}")
    print(f"   Реальных уязвимостей:{len(real_bugs):>6}")
    print(f"   False positives:     {len(fp_bugs):>6}")
    print(f"   Dedup ratio:         {result['dedup_ratio']:>6.1f}x")
    print(f"   FP rate:             {result['fp_rate']:>6.1f}%")
    print(f"{'='*70}")
    
    print(f"\n🔴 РЕАЛЬНЫЕ УЯЗВИМОСТИ (создать тикеты):")
    for b in real_bugs:
        print(f"   [{b['cvss']}] {b['type']:25} × {b['crash_count']:>4} крашей  CWE-{b['cwe']}")
    
    print(f"\n⚪ FALSE POSITIVES (отфильтрованы):")
    for b in fp_bugs:
        print(f"   [FP]  {b['type']:25} × {b['crash_count']:>4} крашей")
    
    print(f"\n✅ Результаты сохранены: {output_file}")

if __name__ == "__main__":
    main()
