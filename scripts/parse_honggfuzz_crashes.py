#!/usr/bin/env python3
"""
Парсер результатов HonggFuzz для выгрузки в DefectDojo

Извлекает:
- Список крашей
- Stack traces
- Типы уязвимостей
- CVSS/CWE классификацию
"""

import argparse
import json
import hashlib
import re
from pathlib import Path
from datetime import datetime

def extract_stack_trace(crash_file: Path) -> str:
    """Извлекает stack trace из файла краша"""
    try:
        content = crash_file.read_text(errors='ignore')
        
        # Ищем stack trace паттерны
        if 'AddressSanitizer' in content or 'ERROR:' in content:
            return content
        
        # Если это бинарный файл, создаём placeholder
        return f"Binary crash file: {crash_file.name}\nSize: {crash_file.stat().st_size} bytes"
    
    except Exception as e:
        return f"Error reading crash file: {e}"

def classify_crash(stack_trace: str) -> dict:
    """Классифицирует тип уязвимости"""
    
    # Тип уязвимости
    crash_type = "unknown"
    cwe = 0
    cvss = 5.0
    
    if 'heap-buffer-overflow' in stack_trace:
        crash_type = "heap-buffer-overflow"
        cwe = 122
        cvss = 9.8
    elif 'stack-buffer-overflow' in stack_trace:
        crash_type = "stack-buffer-overflow"
        cwe = 121
        cvss = 9.8
    elif 'use-after-free' in stack_trace:
        crash_type = "use-after-free"
        cwe = 416
        cvss = 9.8
    elif 'double-free' in stack_trace:
        crash_type = "double-free"
        cwe = 415
        cvss = 9.8
    elif 'null-dereference' in stack_trace or 'SEGV' in stack_trace:
        crash_type = "null-dereference"
        cwe = 476
        cvss = 5.0
    elif 'integer-overflow' in stack_trace:
        crash_type = "integer-overflow"
        cwe = 190
        cvss = 7.5
    elif 'memory-leak' in stack_trace:
        crash_type = "memory-leak"
        cwe = 401
        cvss = 3.0
    
    # Вычисляем signature для дедупликации
    signature = hashlib.sha256(stack_trace.encode()).hexdigest()[:16]
    
    return {
        'type': crash_type,
        'cwe': cwe,
        'cvss': cvss,
        'signature': signature,
        'severity': 'Critical' if cvss >= 9.0 else 'High' if cvss >= 7.0 else 'Medium' if cvss >= 4.0 else 'Low'
    }

def parse_crashes(crashes_dir: Path) -> list:
    """Парсит все краши в директории"""
    
    crashes = []
    
    if not crashes_dir.exists():
        print(f"⚠️  Директория не найдена: {crashes_dir}")
        return crashes
    
    crash_files = list(crashes_dir.glob('*.fuzz')) + list(crashes_dir.glob('crash-*'))
    
    print(f"🔍 Найдено крашей: {len(crash_files)}")
    
    for crash_file in crash_files:
        stack_trace = extract_stack_trace(crash_file)
        classification = classify_crash(stack_trace)
        
        crash_info = {
            'file': str(crash_file),
            'filename': crash_file.name,
            'size': crash_file.stat().st_size,
            'stack_trace': stack_trace[:2000],  # Ограничиваем размер
            'classification': classification,
            'timestamp': datetime.now().isoformat()
        }
        
        crashes.append(crash_info)
        print(f"  ✅ {crash_file.name}: {classification['type']} (CVSS {classification['cvss']})")
    
    return crashes

def generate_summary(crashes: list) -> dict:
    """Генерирует сводку по результатам"""
    
    if not crashes:
        return {
            'total_crashes': 0,
            'unique_bugs': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_type': {}
        }
    
    # Подсчитываем уникальные баги по signature
    unique_signatures = set(c['classification']['signature'] for c in crashes)
    
    # Подсчитываем по severity
    severity_counts = {
        'Critical': sum(1 for c in crashes if c['classification']['severity'] == 'Critical'),
        'High': sum(1 for c in crashes if c['classification']['severity'] == 'High'),
        'Medium': sum(1 for c in crashes if c['classification']['severity'] == 'Medium'),
        'Low': sum(1 for c in crashes if c['classification']['severity'] == 'Low')
    }
    
    # Подсчитываем по типу
    type_counts = {}
    for c in crashes:
        crash_type = c['classification']['type']
        type_counts[crash_type] = type_counts.get(crash_type, 0) + 1
    
    return {
        'total_crashes': len(crashes),
        'unique_bugs': len(unique_signatures),
        'critical': severity_counts['Critical'],
        'high': severity_counts['High'],
        'medium': severity_counts['Medium'],
        'low': severity_counts['Low'],
        'by_type': type_counts,
        'timestamp': datetime.now().isoformat()
    }

def main():
    parser = argparse.ArgumentParser(description='Parse HonggFuzz crashes')
    parser.add_argument('--crashes-dir', type=Path, required=True, help='Directory with crash files')
    parser.add_argument('--output', type=Path, required=True, help='Output JSON file')
    
    args = parser.parse_args()
    
    print(f"🔍 Парсинг крашей из: {args.crashes_dir}")
    
    crashes = parse_crashes(args.crashes_dir)
    summary = generate_summary(crashes)
    
    result = {
        'summary': summary,
        'crashes': crashes
    }
    
    args.output.write_text(json.dumps(result, indent=2))
    
    print(f"\n📊 Результаты:")
    print(f"   Всего крашей: {summary['total_crashes']}")
    print(f"   Уникальных багов: {summary['unique_bugs']}")
    print(f"   Critical: {summary['critical']}")
    print(f"   High: {summary['high']}")
    print(f"   Medium: {summary['medium']}")
    print(f"   Low: {summary['low']}")
    print(f"\n✅ Результаты сохранены: {args.output}")

if __name__ == '__main__':
    main()
