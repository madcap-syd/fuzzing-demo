#!/usr/bin/env python3
"""
Bandit Python SAST scanner
Интеграция с ФСТЕК-отчётностью
"""

import subprocess
import json
import os
from datetime import datetime

def run_bandit_scan(target_dir, output_file):
    """Запускает Bandit сканирование"""
    
    print("=" * 70)
    print("🔍 BANDIT PYTHON SAST SCAN")
    print("=" * 70)
    print()
    
    config_file = os.path.join(os.path.dirname(target_dir), 'bandit.yaml')
    
    cmd = [
        'bandit',
        '-r', target_dir,
        '-c', config_file if os.path.exists(config_file) else None,
        '-f', 'json',
        '-o', output_file,
        '-lll'  # Show all issues (low, medium, high)
    ]
    
    # Убираем None из команд
    cmd = [arg for arg in cmd if arg is not None]
    
    print(f"📂 Сканируем: {target_dir}")
    print(f"📝 Результат: {output_file}")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode in [0, 1]:  # 1 = issues found
            print("✅ Сканирование завершено")
            
            # Читаем результаты
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            stats = data.get('stats', {})
            print(f"\n📊 Результаты:")
            print(f"   Всего файлов: {stats.get('files', 0)}")
            print(f"   Всего найдено: {stats.get('SEVERITY', {}).get('UNDEFINED', 0)}")
            print(f"   High: {stats.get('SEVERITY', {}).get('HIGH', 0)}")
            print(f"   Medium: {stats.get('SEVERITY', {}).get('MEDIUM', 0)}")
            print(f"   Low: {stats.get('SEVERITY', {}).get('LOW', 0)}")
            
            return data
        else:
            print(f"❌ Ошибка: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        print("❌ Таймаут сканирования (5 минут)")
        return None
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return None

def generate_fstec_report(bandit_data, output_file):
    """Генерирует ФСТЕК-отчёт для Bandit"""
    
    if not bandit_data:
        return
    
    issues = bandit_data.get('results', [])
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# ОТЧЁТ BANDIT PYTHON SAST\n\n")
        f.write(f"**Дата:** {datetime.now().strftime('%d.%m.%Y %H:%M')}\n")
        f.write("**Инструмент:** Bandit (Python SAST)\n")
        f.write("**Соответствие:** ФСТЕК № 239, ГОСТ Р 56939-2024\n\n")
        
        f.write("## СТАТИСТИКА\n\n")
        stats = bandit_data.get('stats', {})
        f.write(f"- Всего файлов просканировано: {stats.get('files', 0)}\n")
        f.write(f"- Всего найдено уязвимостей: {len(issues)}\n\n")
        
        f.write("## ВЫЯВЛЕННЫЕ УЯЗВИМОСТИ\n\n")
        f.write("| № | Severity | CWE | Test ID | Файл | Строка | Описание |\n")
        f.write("|---|----------|-----|---------|------|--------|----------|\n")
        
        for i, issue in enumerate(issues, 1):
            severity = issue.get('issue_severity', 'INFO')
            cwe = issue.get('issue_cwe', {}).get('id', 0)
            test_id = issue.get('test_id', '')
            filename = os.path.basename(issue.get('filename', ''))
            line = issue.get('line_number', 0)
            description = issue.get('issue_text', '')
            
            f.write(f"| {i} | {severity} | CWE-{cwe} | {test_id} | {filename} | {line} | {description[:50]}... |\n")
        
        f.write("\n## ЗАКЛЮЧЕНИЕ\n\n")
        
        high_count = sum(1 for i in issues if i.get('issue_severity') == 'HIGH')
        medium_count = sum(1 for i in issues if i.get('issue_severity') == 'MEDIUM')
        
        if high_count > 0:
            f.write(f"⚠️ **Обнаружено {high_count} уязвимостей высокого уровня!**\n\n")
            f.write("**Рекомендации:**\n")
            f.write("1. Немедленно устранить критические уязвимости\n")
            f.write("2. Провести повторное сканирование\n")
        elif medium_count > 0:
            f.write(f"⚠️ Обнаружено {medium_count} уязвимостей среднего уровня.\n\n")
            f.write("**Рекомендации:**\n")
            f.write("1. Устранить уязвимости в ближайший релиз\n")
        else:
            f.write("✅ Критические уязвимости не обнаружены.\n")
    
    print(f"✅ ФСТЕК-отчёт сохранён: {output_file}")

def main():
    project_dir = os.path.expanduser("~/fuzzing-demo")
    reports_dir = os.path.join(project_dir, "reports", "bandit")
    
    os.makedirs(reports_dir, exist_ok=True)
    
    # Сканируем Python код
    scripts_dir = os.path.join(project_dir, "scripts")
    output_json = os.path.join(reports_dir, "bandit_results.json")
    output_report = os.path.join(reports_dir, "BANDIT_FSTEC_REPORT.md")
    
    bandit_data = run_bandit_scan(scripts_dir, output_json)
    
    if bandit_data:
        generate_fstec_report(bandit_data, output_report)
        
        print("\n" + "=" * 70)
        print("✅ BANDIT SCAN ЗАВЕРШЁН")
        print("=" * 70)

if __name__ == "__main__":
    main()
