#!/usr/bin/env python3
"""
LLM-based crash analyzer using Ollama
Анализирует краши и генерирует описания + рекомендации по исправлению
"""

import json
import requests
import argparse
from pathlib import Path
from datetime import datetime

class LLMAnalyzer:
    def __init__(self, ollama_url="http://localhost:11434", model="qwen2.5-coder:3b"):
        self.ollama_url = ollama_url
        self.model = model
    
    def analyze_crash(self, crash_data):
        """Анализирует один краш через LLM"""
        
        prompt = f"""Ты - эксперт по безопасности C++ кода. Проанализируй следующий краш и предоставь:

1. Тип уязвимости (heap-buffer-overflow, use-after-free, null-dereference, stack-buffer-overflow, integer-overflow)
2. CWE номер
3. CVSS score (0.0-10.0)
4. Severity (Critical, High, Medium, Low)
5. Подробное описание уязвимости (2-3 предложения)
6. Рекомендацию по исправлению (конкретный код)
7. Потенциальное влияние (RCE, DoS, Info Leak)

Данные краша:
- Файл: {crash_data['filename']}
- Размер: {crash_data['size']} байт
- Stack trace: {crash_data.get('stack_trace', 'N/A')}

Ответь в формате JSON:
{{
  "type": "...",
  "cwe": ...,
  "cvss": ...,
  "severity": "...",
  "description": "...",
  "fix_recommendation": "...",
  "impact": "..."
}}"""

        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                response_text = result.get('response', '')
                
                # Парсим JSON из ответа
                try:
                    # Ищем JSON в ответе
                    json_start = response_text.find('{')
                    json_end = response_text.rfind('}') + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = response_text[json_start:json_end]
                        analysis = json.loads(json_str)
                        return analysis
                except json.JSONDecodeError:
                    print(f"⚠️  Не удалось распарсить JSON для {crash_data['filename']}")
                    return None
            
        except Exception as e:
            print(f"❌ Ошибка LLM анализа: {e}")
            return None
    
    def analyze_all_crashes(self, crashes, limit=10):
        """Анализирует все краши через LLM"""
        
        results = []
        print(f"🤖 Анализируем {min(limit, len(crashes))} крашей через LLM...")
        
        for i, crash in enumerate(crashes[:limit]):
            print(f"  [{i+1}/{limit}] {crash['filename']}...", end=' ')
            analysis = self.analyze_crash(crash)
            
            if analysis:
                crash['llm_analysis'] = analysis
                results.append(crash)
                print(f"✅ {analysis['type']} (CVSS {analysis['cvss']})")
            else:
                print("❌ Ошибка")
        
        return results

def main():
    parser = argparse.ArgumentParser(description='LLM crash analyzer')
    parser.add_argument('--input', type=Path, required=True, help='JSON файл с крашами')
    parser.add_argument('--output', type=Path, required=True, help='Выходной JSON файл')
    parser.add_argument('--limit', type=int, default=10, help='Максимум крашей для анализа')
    parser.add_argument('--model', type=str, default='qwen2.5-coder:3b', help='Ollama модель')
    args = parser.parse_args()
    
    # Загружаем краши
    with open(args.input) as f:
        data = json.load(f)
    
    crashes = data.get('crashes', [])
    
    # Анализируем через LLM
    analyzer = LLMAnalyzer(model=args.model)
    analyzed = analyzer.analyze_all_crashes(crashes, limit=args.limit)
    
    # Сохраняем результаты
    output_data = {
        'summary': {
            'total_analyzed': len(analyzed),
            'critical': sum(1 for c in analyzed if c['llm_analysis']['severity'] == 'Critical'),
            'high': sum(1 for c in analyzed if c['llm_analysis']['severity'] == 'High'),
            'medium': sum(1 for c in analyzed if c['llm_analysis']['severity'] == 'Medium'),
            'low': sum(1 for c in analyzed if c['llm_analysis']['severity'] == 'Low')
        },
        'crashes': analyzed
    }
    
    with open(args.output, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n✅ Результаты сохранены: {args.output}")
    print(f"   Проанализировано: {len(analyzed)}")
    print(f"   Critical: {output_data['summary']['critical']}")
    print(f"   High: {output_data['summary']['high']}")

if __name__ == '__main__':
    main()
