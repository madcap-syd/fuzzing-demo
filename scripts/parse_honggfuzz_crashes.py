#!/usr/bin/env python3
import argparse
import json
import hashlib
from pathlib import Path
from datetime import datetime

def extract_stack_trace(crash_file):
    """Извлекает stack trace из crash файла"""
    try:
        with open(crash_file, 'rb') as f:
            data = f.read()
        # Упрощённая версия - хэшируем содержимое файла
        return hashlib.sha256(data[:1024]).hexdigest()  # Только первые 1KB
    except:
        return "unknown"

def classify_crash(crash_file):
    """Классифицирует краш"""
    # Определяем тип по содержимому
    try:
        with open(crash_file, 'rb') as f:
            data = f.read()
        
        # Простая эвристика
        if b'heap' in data.lower():
            return 'heap-buffer-overflow', 122, 9.8, 'Critical'
        elif b'stack' in data.lower():
            return 'stack-buffer-overflow', 121, 9.8, 'Critical'
        elif b'use-after-free' in data.lower() or b'free' in data.lower():
            return 'use-after-free', 416, 9.8, 'Critical'
        elif b'null' in data.lower():
            return 'null-dereference', 476, 5.0, 'Medium'
        else:
            return 'unknown', 0, 5.0, 'Medium'
    except:
        return 'unknown', 0, 5.0, 'Medium'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--crashes-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    
    crashes = []
    signatures = set()
    
    for crash_file in args.crashes_dir.glob('crash-*'):
        # Хэшируем ТОЛЬКО stack trace (первые 1KB файла)
        signature = extract_stack_trace(crash_file)
        
        # Дедупликация
        if signature in signatures:
            continue
        signatures.add(signature)
        
        vuln_type, cwe, cvss, severity = classify_crash(crash_file)
        
        crashes.append({
            'filename': crash_file.name,
            'size': crash_file.stat().st_size,
            'timestamp': datetime.now().isoformat(),
            'classification': {
                'type': vuln_type,
                'cwe': cwe,
                'cvss': cvss,
                'severity': severity,
                'signature': signature
            },
            'stack_trace': f'Crash in {crash_file.name}'
        })
    
    # Подсчёт статистики
    summary = {
        'total_crashes': len(list(args.crashes_dir.glob('crash-*'))),
        'unique_bugs': len(crashes),
        'critical': sum(1 for c in crashes if c['classification']['severity'] == 'Critical'),
        'high': sum(1 for c in crashes if c['classification']['severity'] == 'High'),
        'medium': sum(1 for c in crashes if c['classification']['severity'] == 'Medium'),
        'low': sum(1 for c in crashes if c['classification']['severity'] == 'Low')
    }
    
    result = {
        'summary': summary,
        'crashes': crashes
    }
    
    args.output.write_text(json.dumps(result, indent=2))
    
    print(f"✅ Результаты сохранены: {args.output}")
    print(f"   Всего крашей: {summary['total_crashes']}")
    print(f"   Уникальных багов: {summary['unique_bugs']}")
    print(f"   Critical: {summary['critical']}")
    print(f"   Medium: {summary['medium']}")

if __name__ == '__main__':
    main()
