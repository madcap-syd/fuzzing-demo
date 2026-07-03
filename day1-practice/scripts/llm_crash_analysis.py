#!/usr/bin/env python3
"""
llm_crash_analysis.py — Ollama анализирует stack trace краша
ИСПРАВЛЕНО: обрезаем stack trace до 10 строк, чтобы не было таймаута
"""

import subprocess
import json
import hashlib
from pathlib import Path

def truncate_stack_trace(stack_trace: str, max_lines: int = 15) -> str:
    """Обрезает stack trace до ключевых строк"""
    lines = stack_trace.split('\n')
    important_lines = []
    
    for line in lines:
        line = line.strip()
        # Берём только важные строки
        if any(x in line for x in ['ERROR:', 'SUMMARY:', 'READ of size', 'WRITE of size', 
                                     'in parsePacket', 'in processPacket', 'in LLVMFuzzer',
                                     'packet_parser.cpp', '#0 ', '#1 ', '#2 ']):
            important_lines.append(line)
            if len(important_lines) >= max_lines:
                break
    
    return '\n'.join(important_lines)

def analyze_crash_with_ollama(stack_trace: str) -> dict:
    """Отправляет ОБРЕЗАННЫЙ stack trace в Ollama"""
    
    # Обрезаем stack trace!
    truncated = truncate_stack_trace(stack_trace)
    
    prompt = f"""Analyze this ASan crash. Return ONLY JSON, no other text:

{truncated}

JSON format:
{{"type":"heap-buffer-overflow","cwe":122,"cvss":9.8,"is_fp":false,"fp_reason":"","root_cause":"packet_parser.cpp:23","fix":"Check length before memcpy","severity":"Critical"}}"""
    
    try:
        result = subprocess.run(
            ['ollama', 'run', 'qwen2.5-coder:1.5b', prompt],
            capture_output=True,
            text=True,
            timeout=60  # Уменьшаем таймаут
        )
        
        output = result.stdout.strip()
        
        # Ищем JSON
        start = output.find('{')
        end = output.rfind('}') + 1
        if start >= 0 and end > start:
            return json.loads(output[start:end])
        
        return {"error": "No JSON", "raw": output[:200]}
    except subprocess.TimeoutExpired:
        return {"error": "Timeout", "raw": "LLM took too long"}
    except Exception as e:
        return {"error": str(e), "raw": ""}

def compute_signature(stack_trace: str) -> str:
    """Вычисляет signature краша"""
    lines = []
    for line in stack_trace.split('\n'):
        line = line.strip()
        if line.startswith('#') and ' in ' in line:
            func = line.split(' in ')[1].split('(')[0].strip()
            lines.append(func)
        elif line.startswith('SUMMARY:'):
            lines.append(line)
    
    return hashlib.sha256('\n'.join(lines).encode()).hexdigest()[:16]

def main():
    stack_file = Path('crashes/crash-stack.txt')
    
    if not stack_file.exists():
        print("❌ Stack trace не найден")
        return
    
    print("🔍 LLM анализирует краш (обрезанный stack trace)...")
    
    stack_trace = stack_file.read_text(errors='ignore')
    signature = compute_signature(stack_trace)
    
    # Показываем, что отправляем в LLM
    truncated = truncate_stack_trace(stack_trace)
    print(f"   Оригинальный размер: {len(stack_trace)} байт")
    print(f"   Обрезанный размер: {len(truncated)} байт")
    
    analysis = analyze_crash_with_ollama(stack_trace)
    
    print(f"\n{'='*70}")
    print(f"📊 LLM-АНАЛИЗ КРАША")
    print(f"{'='*70}")
    print(f"   Signature:     {signature}")
    print(f"   Type:          {analysis.get('type', 'Unknown')}")
    print(f"   CWE:           CWE-{analysis.get('cwe', 'N/A')}")
    print(f"   CVSS:          {analysis.get('cvss', 'N/A')}")
    print(f"   Severity:      {analysis.get('severity', 'N/A')}")
    print(f"   Is FP:         {analysis.get('is_fp', False)}")
    print(f"   Root cause:    {analysis.get('root_cause', 'N/A')}")
    print(f"   Fix:           {analysis.get('fix', 'N/A')}")
    print(f"{'='*70}")
    
    result = {
        'signature': signature,
        'analysis': analysis,
    }
    Path('reports/llm_crash_analysis.json').write_text(
        json.dumps(result, indent=2)
    )
    
    print(f"\n✅ Результат сохранён: reports/llm_crash_analysis.json")

if __name__ == "__main__":
    main()
