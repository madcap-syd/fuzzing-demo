#!/usr/bin/env python3
"""
Дедупликация крашей через Ollama LLM
=====================================
Использует Ollama для анализа stack trace и определения уникальности краша.
"""

import json
import sys
import os
import hashlib
import requests
from pathlib import Path

OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3.2')
DEMO_MODE = os.environ.get('DEMO_MODE', 'true').lower() == 'true'

CRASHES_DB = "crashes_db.json"

def load_db():
    """Загружаем базу известных крашей"""
    if Path(CRASHES_DB).exists():
        return json.loads(Path(CRASHES_DB).read_text())
    return {}

def save_db(db):
    """Сохраняем базу крашей"""
    Path(CRASHES_DB).write_text(json.dumps(db, indent=2))

def compute_stack_hash(stack_trace):
    """Вычисляем хэш stack trace"""
    return hashlib.sha256(stack_trace.encode()).hexdigest()[:16]

def ask_ollama(new_crash, existing_crashes):
    """Спрашиваем Ollama: это дубликат или новый краш?"""
    
    if not existing_crashes:
        return False, "No existing crashes"
    
    prompt = f"""
You are a security analyst. Analyze these two crash stack traces and determine if they are the SAME bug or DIFFERENT bugs.

CRASH 1 (NEW):
{new_crash}

CRASH 2 (EXISTING):
{existing_crashes[0] if existing_crashes else 'None'}

Answer ONLY with:
- "DUPLICATE" if they are the same bug
- "NEW" if they are different bugs
- "REASON" in one line explaining why
"""
    
    if DEMO_MODE:
        print("🤖 [DEMO MODE] Ollama analysis...")
        print(f"   Prompt length: {len(prompt)} chars")
        # В демо режиме просто возвращаем NEW
        return False, "DEMO: Assuming new crash"
    
    try:
        response = requests.post(
            f'{OLLAMA_URL}/api/generate',
            json={
                'model': OLLAMA_MODEL,
                'prompt': prompt,
                'stream': False
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()['response']
            print(f"🤖 Ollama response: {result}")
            
            if 'DUPLICATE' in result.upper():
                return True, result
            else:
                return False, result
        else:
            print(f"⚠️  Ollama API error: {response.status_code}")
            return False, "Ollama unavailable"
            
    except Exception as e:
        print(f"⚠️  Ollama error: {e}")
        return False, f"Error: {e}"

def deduplicate_crash(stack_trace, crash_file):
    """Дедуплицируем краш"""
    
    db = load_db()
    crash_hash = compute_stack_hash(stack_trace)
    
    print(f"\n🔍 Analyzing crash: {crash_file}")
    print(f"   Hash: {crash_hash}")
    
    # Проверяем по хэшу
    if crash_hash in db:
        print(f"   ✅ Hash match found in DB")
        return True, db[crash_hash]
    
    # Если хэш новый - спрашиваем Ollama
    existing_traces = [v['stack_trace'] for v in db.values()]
    
    is_duplicate, reason = ask_ollama(stack_trace, existing_traces)
    
    if is_duplicate:
        print(f"   ⚠️  Ollama says: DUPLICATE")
        print(f"   Reason: {reason}")
        return True, None
    else:
        print(f"   ✅ Ollama says: NEW")
        print(f"   Reason: {reason}")
        
        # Добавляем в базу
        db[crash_hash] = {
            'stack_trace': stack_trace,
            'crash_file': crash_file,
            'first_seen': '2026-07-11',
            'reason': reason
        }
        save_db(db)
        
        return False, None

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 deduplicate_ollama.py <log_file> <crash_dir>")
        sys.exit(1)
    
    log_file = Path(sys.argv[1])
    crash_dir = Path(sys.argv[2])
    
    print("=" * 60)
    print("🤖 OLLAMA DEDUPLICATION")
    print("=" * 60)
    print(f"Mode: {'DEMO' if DEMO_MODE else 'PROD'}")
    print(f"Ollama URL: {OLLAMA_URL}")
    print(f"Model: {OLLAMA_MODEL}")
    print("=" * 60)
    
    # Читаем stack trace из лога
    log_content = log_file.read_text()
    
    stack_lines = []
    for line in log_content.split('\n'):
        if line.strip().startswith('#0') or line.strip().startswith('#1') or line.strip().startswith('#2'):
            stack_lines.append(line.strip())
    
    stack_trace = '\n'.join(stack_lines)
    
    if not stack_trace:
        print("❌ No stack trace found in log")
        sys.exit(1)
    
    print(f"\n📋 Stack trace ({len(stack_lines)} frames):")
    for line in stack_lines[:3]:
        print(f"   {line}")
    
    # Находим crash файлы
    crash_files = list(crash_dir.glob('crash-*'))
    
    if not crash_files:
        print("❌ No crash files found")
        sys.exit(1)
    
    print(f"\n📦 Found {len(crash_files)} crash file(s)")
    
    # Дедуплицируем каждый краш
    unique_crashes = []
    duplicates = []
    
    for crash_file in crash_files:
        is_dup, existing = deduplicate_crash(stack_trace, crash_file.name)
        
        if is_dup:
            duplicates.append(crash_file)
        else:
            unique_crashes.append(crash_file)
    
    # Итоги
    print(f"\n{'=' * 60}")
    print("📊 DEDUPLICATION SUMMARY")
    print('=' * 60)
    print(f"Total crashes: {len(crash_files)}")
    print(f"Unique: {len(unique_crashes)}")
    print(f"Duplicates: {len(duplicates)}")
    print('=' * 60)
    
    if unique_crashes:
        print(f"\n✅ Unique crashes to process:")
        for cf in unique_crashes:
            print(f"   - {cf.name}")
    
    if duplicates:
        print(f"\n⚠️  Duplicates (ignored):")
        for cf in duplicates:
            print(f"   - {cf.name}")

if __name__ == '__main__':
    main()
