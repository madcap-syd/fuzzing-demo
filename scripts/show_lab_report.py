#!/usr/bin/env python3
import json
from pathlib import Path

def main():
    print("\n" + "="*70)
    print("🎯 FUZZING LAB - ИТОГОВЫЙ ОТЧЁТ")
    print("="*70 + "\n")
    
    # LLM анализ
    analysis_file = Path('day1-practice/reports/llm_crash_analysis.json')
    if analysis_file.exists():
        with open(analysis_file) as f:
            data = json.load(f)
        
        analysis = data['analysis']
        print("📋 LLM АНАЛИЗ КРАША:")
        print(f"   Signature:     {data.get('signature', 'N/A')}")
        print(f"   Type:          {analysis.get('type', 'N/A')}")
        print(f"   CWE:           CWE-{analysis.get('cwe', 'N/A')}")
        print(f"   CVSS:          {analysis.get('cvss', 'N/A')}")
        print(f"   Severity:      {analysis.get('severity', 'N/A')}")
        print(f"   Root Cause:    {analysis.get('root_cause', 'N/A')}")
        print(f"   Fix:           {analysis.get('fix', 'N/A')}")
        print(f"   Is FP:         {analysis.get('is_fp', False)}")
        print()
    
    # DefectDojo finding
    finding_file = Path('day1-practice/reports/defectdojo_finding.json')
    if finding_file.exists():
        with open(finding_file) as f:
            finding = json.load(f)
        
        print("🎫 DEFECTDOJO FINDING:")
        print(f"   ID:            {finding.get('finding_id', 'N/A')}")
        print(f"   URL:           {finding.get('url', 'N/A')}")
        print(f"   Created:       {finding.get('created', 'N/A')}")
        print(f"   Title:         {finding.get('data', {}).get('title', 'N/A')}")
        print(f"   Severity:      {finding.get('data', {}).get('severity', 'N/A')}")
        print()
    
    print("="*70)
    print("✅ ДЕНЬ 1 ЗАВЕРШЁН!")
    print("="*70)
    print("\n📚 Что сделано:")
    print("   ✅ Развёрнут DefectDojo")
    print("   ✅ Скомпилирован уязвимый код")
    print("   ✅ Запущен фаззинг (libFuzzer + ASan)")
    print("   ✅ Найден краш (heap-buffer-overflow)")
    print("   ✅ LLM проанализировал stack trace")
    print("   ✅ Создан Finding в DefectDojo")
    print("   ✅ Интеграция через API работает")
    print("\n📅 День 2:")
    print("   • Реальный CVE (libxml2)")
    print("   • Production pipeline")
    print("   • Git + CI/CD")
    print("   • ФСТЭК-отчёт")
    print()

if __name__ == "__main__":
    main()
