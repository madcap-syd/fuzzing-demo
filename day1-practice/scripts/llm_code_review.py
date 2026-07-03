#!/usr/bin/env python3
"""
llm_code_review.py — Ollama анализирует код на уязвимости
"""

import subprocess
import json
from pathlib import Path

def analyze_with_ollama(code: str) -> dict:
    """Отправляет код в Ollama для анализа"""
    
    prompt = f"""You are a security expert. Analyze this C++ code for vulnerabilities:

{code}

Find:
1. Buffer overflows
2. Integer overflows
3. Use-after-free
4. Null pointer dereferences

For each vulnerability found:
- Line number
- Type (CWE)
- Severity (CVSS 0-10)
- Description
- How to fix

Return JSON format:
{{
  "vulnerabilities": [
    {{
      "line": 123,
      "type": "buffer-overflow",
      "cwe": 122,
      "cvss": 9.8,
      "description": "...",
      "fix": "..."
    }}
  ]
}}
"""
    
    result = subprocess.run(
        ['ollama', 'run', 'qwen2.5-coder:1.5b', prompt],
        capture_output=True,
        text=True,
        timeout=120
    )
    
    output = result.stdout.strip()
    
    # Ищем JSON в ответе
    start = output.find('{')
    end = output.rfind('}') + 1
    if start >= 0 and end > start:
        json_str = output[start:end]
        try:
            return json.loads(json_str)
        except:
            return {"error": "Failed to parse JSON", "raw": output}
    
    return {"error": "No JSON found", "raw": output}

def main():
    code_file = Path('src/packet_parser.cpp')
    code = code_file.read_text()
    
    print("🔍 LLM анализирует код на уязвимости...")
    print(f"   Файл: {code_file}")
    print(f"   Размер: {len(code)} байт")
    
    result = analyze_with_ollama(code)
    
    print(f"\n{'='*70}")
    print(f"📊 РЕЗУЛЬТАТЫ LLM CODE REVIEW")
    print(f"{'='*70}")
    
    if 'vulnerabilities' in result:
        vulns = result['vulnerabilities']
        print(f"   Найдено уязвимостей: {len(vulns)}")
        
        for i, vuln in enumerate(vulns, 1):
            print(f"\n   [{i}] {vuln.get('type', 'Unknown')}")
            print(f"       Строка: {vuln.get('line', 'N/A')}")
            print(f"       CWE: {vuln.get('cwe', 'N/A')}")
            print(f"       CVSS: {vuln.get('cvss', 'N/A')}")
            print(f"       Описание: {vuln.get('description', 'N/A')[:100]}")
        
        # Сохраняем результат
        Path('reports/llm_code_review.json').write_text(json.dumps(result, indent=2))
        print(f"\n✅ Результат сохранён: reports/llm_code_review.json")
    else:
        print(f"   Ошибка: {result.get('error', 'Unknown')}")
        print(f"   Raw output: {result.get('raw', '')[:200]}")

if __name__ == "__main__":
    main()
