#!/usr/bin/env python3
"""
OLLAMA-POWERED DEDUPLICATION
Использует локальную LLM для умной дедупликации крашей
"""

import os
import sys
import json
import subprocess
import hashlib
from pathlib import Path
from collections import defaultdict

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    print("⚠️  Ollama не установлена. Установи: pip install ollama")

class OllamaDedup:
    def __init__(self, model="llama3.2"):
        self.model = model
        self.crash_cache = {}
        
        if OLLAMA_AVAILABLE:
            print(f"🦙 Ollama initialized (model: {model})")
        else:
            print("⚠️  Working without Ollama (fallback to hash-based dedup)")
    
    def analyze_crash(self, crash_file):
        """
        Использует Ollama для анализа краш-файла
        Возвращает: тип уязвимости, CWE, описание
        """
        crash_path = Path(crash_file)
        crash_content = crash_path.read_bytes()
        
        # Создаём hex dump для анализа (первые 256 байт)
        hex_dump = crash_content[:256].hex()
        
        if OLLAMA_AVAILABLE:
            prompt = f"""
Analyze this fuzzer crash input (hex dump):
{hex_dump}

Determine:
1. What type of vulnerability this might trigger (Buffer Overflow, Null Pointer, etc.)
2. Estimate CWE number
3. Is this similar to a stack-based or heap-based overflow?
4. Brief description

Answer in JSON format:
{{
    "vuln_type": "...",
    "cwe": 120,
    "category": "stack/heap/other",
    "description": "..."
}}
"""
            try:
                response = ollama.chat(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}]
                )
                
                # Парсим ответ LLM
                answer = response['message']['content'].strip()
                
                # Извлекаем JSON из ответа
                if "```json" in answer:
                    answer = answer.split("```json")[1].split("```")[0].strip()
                elif "```" in answer:
                    answer = answer.split("```")[1].split("```")[0].strip()
                
                analysis = json.loads(answer)
                
                return {
                    'vuln_type': analysis.get('vuln_type', 'Unknown'),
                    'cwe': analysis.get('cwe', 0),
                    'category': analysis.get('category', 'other'),
                    'description': analysis.get('description', ''),
                    'source': 'ollama'
                }
                
            except Exception as e:
                print(f"⚠️  Ollama error: {e}")
                # Fallback к простому анализу
                return self.simple_analyze(crash_content)
        else:
            # Fallback без Ollama
            return self.simple_analyze(crash_content)
    
    def simple_analyze(self, crash_content):
        """Простой анализ без LLM (fallback)"""
        size = len(crash_content)
        
        if size > 200:
            vuln_type = "Heap Buffer Overflow"
            cwe = 122
        elif size > 64:
            vuln_type = "Stack Buffer Overflow"
            cwe = 121
        elif size > 10:
            vuln_type = "Buffer Overflow"
            cwe = 120
        else:
            vuln_type = "Null Pointer Dereference"
            cwe = 476
        
        return {
            'vuln_type': vuln_type,
            'cwe': cwe,
            'category': 'stack' if size < 200 else 'heap',
            'description': f'Input size: {size} bytes',
            'source': 'simple'
        }
    
    def semantic_dedup(self, crashes_dir):
        """
        Умная дедупликация с помощью Ollama
        Группирует краши по СМЫСЛУ (не только по хэшу)
        """
        crashes = list(Path(crashes_dir).glob('crash_*.txt'))
        print(f"\n🔍 Analyzing {len(crashes)} crashes with Ollama...")
        
        # Анализируем каждый краш
        crash_analyses = []
        for i, crash in enumerate(crashes):
            if i % 50 == 0:
                print(f"  Progress: {i}/{len(crashes)}")
            
            analysis = self.analyze_crash(crash)
            analysis['file'] = str(crash)
            analysis['size'] = crash.stat().st_size
            crash_analyses.append(analysis)
        
        # Группируем по семантике (vuln_type + category + size_range)
        semantic_groups = defaultdict(list)
        for analysis in crash_analyses:
            # Создаём семантический ключ
            size_range = (analysis['size'] // 50) * 50  # Группируем по 50 байт
            key = f"{analysis['vuln_type']}_{analysis['category']}_{size_range}"
            semantic_groups[key].append(analysis)
        
        print(f"\n=== SEMANTIC DEDUPLICATION RESULTS ===")
        print(f"Total crashes: {len(crashes)}")
        print(f"Semantic groups: {len(semantic_groups)}")
        print("")
        
        # Показываем группы
        unique_bugs = []
        for key, group in semantic_groups.items():
            vuln_type, category, size_range = key.split('_')
            
            print(f"🐛 Bug Group: {vuln_type} ({category}, ~{size_range} bytes)")
            print(f"   Crashes: {len(group)}")
            print(f"   CWE: {group[0]['cwe']}")
            print(f"   Description: {group[0]['description']}")
            print(f"   Analysis source: {group[0]['source']}")
            print("")
            
            unique_bugs.append({
                'bug_id': f"BUG-{len(unique_bugs)+1}",
                'vuln_type': vuln_type,
                'category': category,
                'size_range': int(size_range),
                'crash_count': len(group),
                'cwe': group[0]['cwe'],
                'description': group[0]['description'],
                'sample_files': [g['file'] for g in group[:3]]  # Первые 3 файла
            })
        
        return unique_bugs
    
    def generate_jira_ticket(self, bug):
        """Генерирует тикет для Jira с описанием от Ollama"""
        
        if OLLAMA_AVAILABLE:
            # Используем Ollama для генерации красивого описания
            prompt = f"""
Generate a professional Jira ticket description for this security bug:

Vulnerability: {bug['vuln_type']}
Category: {bug['category']}
CWE: {bug['cwe']}
Crashes found: {bug['crash_count']}
Size range: ~{bug['size_range']} bytes
Description: {bug['description']}

Create a detailed description including:
- Impact
- Reproduction steps
- Recommended fix
- Priority justification

Format as markdown.
"""
            try:
                response = ollama.chat(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}]
                )
                
                detailed_desc = response['message']['content']
                
            except Exception as e:
                detailed_desc = bug['description']
        else:
            detailed_desc = bug['description']
        
        ticket = {
            'project': 'SEC',
            'summary': f"[BLACK BOX] {bug['vuln_type']} - {bug['crash_count']} crashes",
            'description': detailed_desc,
            'priority': 'Highest' if bug['cwe'] in [120, 121, 122] else 'High',
            'type': 'Bug',
            'labels': [
                'security',
                'blackbox',
                f"cwe-{bug['cwe']}",
                bug['category'],
                'ollama-analyzed' if OLLAMA_AVAILABLE else 'simple-analyzed'
            ],
            'custom_fields': {
                'crash_count': bug['crash_count'],
                'size_range': bug['size_range'],
                'analysis_method': bug.get('source', 'unknown')
            }
        }
        
        return ticket


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ollama-dedup.py <crashes_dir> [model]")
        print("Example: python3 ollama-dedup.py blackbox-target/crashes llama3.2")
        sys.exit(1)
    
    crashes_dir = sys.argv[1]
    model = sys.argv[2] if len(sys.argv) > 2 else "llama3.2"
    
    dedup = OllamaDedup(model=model)
    
    # Семантическая дедупликация
    unique_bugs = dedup.semantic_dedup(crashes_dir)
    
    # Создаём отчёты
    reports_dir = Path(crashes_dir).parent / 'reports'
    reports_dir.mkdir(exist_ok=True)
    
    # Сохраняем баги
    bugs_file = reports_dir / 'ollama_bugs.json'
    bugs_file.write_text(json.dumps(unique_bugs, indent=2))
    print(f"\n✅ Bugs saved to {bugs_file}")
    
    # Генерируем Jira тикеты
    tickets = []
    for bug in unique_bugs:
        ticket = dedup.generate_jira_ticket(bug)
        tickets.append(ticket)
    
    tickets_file = reports_dir / 'ollama_jira_tickets.json'
    tickets_file.write_text(json.dumps(tickets, indent=2))
    print(f"✅ Jira tickets saved to {tickets_file}")
    
    # Показываем статистику
    print("\n=== OLLAMA DEDUP STATISTICS ===")
    print(f"Analysis model: {model}")
    print(f"Ollama available: {OLLAMA_AVAILABLE}")
    print(f"Total crashes analyzed: {sum(b['crash_count'] for b in unique_bugs)}")
    print(f"Unique bugs found: {len(unique_bugs)}")
    print(f"Deduplication rate: {100 - (len(unique_bugs) * 100 // sum(b['crash_count'] for b in unique_bugs))}%")
    print("=" * 40)


if __name__ == '__main__':
    main()
