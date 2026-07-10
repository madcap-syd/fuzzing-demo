#!/usr/bin/env python3
"""Дедупликация крашей по хэшу stack trace"""

import hashlib
import json
import sys
from pathlib import Path

CRASHES_DB = "crashes_db.json"

def load_db():
    if Path(CRASHES_DB).exists():
        return json.loads(Path(CRASHES_DB).read_text())
    return {}

def save_db(db):
    Path(CRASHES_DB).write_text(json.dumps(db, indent=2))

def extract_stack_trace(log_file):
    """Извлекаем stack trace из лога"""
    stack = []
    with open(log_file) as f:
        for line in f:
            if '#0' in line or '#1' in line or '#2' in line:
                # Извлекаем имя функции и файл
                if 'in ' in line:
                    func_info = line.split('in ')[1].strip()
                    stack.append(func_info)
    return stack[:3]  # Берём первые 3 фрейма

def compute_hash(stack):
    """Вычисляем хэш stack trace"""
    stack_str = '|'.join(stack)
    return hashlib.sha256(stack_str.encode()).hexdigest()[:16]

def deduplicate(crash_dir):
    """Проверяем краши на дубликаты"""
    db = load_db()
    unique_crashes = []
    duplicates = []
    
    crash_files = list(Path(crash_dir).glob('crash-*'))
    
    for crash_file in crash_files:
        # Для демо используем имя файла как хэш
        # В реальности нужно парсить логи
        crash_hash = crash_file.stem.replace('crash-', '')
        
        if crash_hash in db:
            duplicates.append(crash_file)
            print(f"⚠️  Duplicate: {crash_file.name} (hash: {crash_hash})")
        else:
            unique_crashes.append(crash_file)
            db[crash_hash] = {
                'file': crash_file.name,
                'first_seen': '2026-07-10',
                'count': 1
            }
            print(f"✅ New unique crash: {crash_file.name}")
    
    save_db(db)
    
    print(f"\n Summary:")
    print(f"  Total crashes: {len(crash_files)}")
    print(f"  Unique: {len(unique_crashes)}")
    print(f"  Duplicates: {len(duplicates)}")
    
    return unique_crashes

if __name__ == '__main__':
    crash_dir = sys.argv[1] if len(sys.argv) > 1 else './crashes'
    deduplicate(crash_dir)
