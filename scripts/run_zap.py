#!/usr/bin/env python3
"""
OWASP ZAP Web Vulnerability Scanner
Интеграция с ФСТЕК-отчётностью
"""

import subprocess
import json
import os
import time
from datetime import datetime

def run_zap_scan(target_url, output_dir):
    """Запускает OWASP ZAP сканирование через Docker"""
    
    print("=" * 70)
    print(f"🔍 OWASP ZAP SCAN: {target_url}")
    print("=" * 70)
    print()
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Базовая команда для ZAP
    cmd = [
        'docker', 'run', '--rm', '-u', 'zap',
        '-v', f"{output_dir}:/zap/wrk/:rw",
        '-t', 'owasp/zap2docker-stable',
        'zap-baseline.py',
        '-t', target_url,
        '-r', 'zap_report.html',
        '-J', 'zap_report.json',
        '-w', 'zap_report.md',
        '-I'  # Don't fail on warnings
    ]
    
    print(f"🌐 Целевой URL: {target_url}")
    print(f"📁 Результат: {output_dir}")
    print()
    print("⏳ Запуск ZAP (это займёт 5-10 минут)...")
    print()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        
        print("✅ Сканирование завершено")
        
        # Читаем JSON отчёт
        json_file = os.path.join(output_dir, 'zap_report.json')
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                data = json.load(f)
            return data
        else:
            print("⚠️  JSON отчёт не найден")
            return None
            
    except subprocess.TimeoutExpired:
        print("❌ Таймаут сканирования (15 минут)")
        return None
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return None

def generate_fstec_report(zap_data, output_file):
    """Генерирует ФСТЕК-отчёт для ZAP"""
    
    if not zap_data:
        return
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# ОТЧЁТ OWASP ZAP WEB SCAN\n\n")
        f.write(f"**Дата:** {datetime.now().strftime('%d.%m.%Y %H:%M')}\n")
        f.write("**Инструмент:** OWASP ZAP (Web Application Scanner)\n")
        f.write("**Соответствие:** ФСТЕК № 239, ГОСТ Р 56939-2024\n\n")
        
        alerts = zap_data.get('site', [{}])[0].get('alerts', []) if zap_data.get('site') else []
        
        # Считаем по уровням риска
        risk_levels = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            if risk in risk_levels:
                risk_levels[risk] += 1
        
        f.write("## СТАТИСТИКА\n\n")
        f.write(f"- Всего найдено: {len(alerts)}\n")
        f.write(f"- High: {risk_levels['High']}\n")
        f.write(f"- Medium: {risk_levels['Medium']}\n")
        f.write(f"- Low: {risk_levels['Low']}\n")
        f.write(f"- Informational: {risk_levels['Informational']}\n\n")
        
        f.write("## ВЫЯВЛЕННЫЕ УЯЗВИМОСТИ\n\n")
        f.write("| № | Risk | Alert | CWE | Description |\n")
        f.write("|---|------|-------|-----|-------------|\n")
        
        for i, alert in enumerate(alerts, 1):
            risk = alert.get('risk', 'Info')
            name = alert.get('alert', 'Unknown')
            cwe = alert.get('cweid', 0)
            desc = alert.get('desc', '')[:100]
            
            f.write(f"| {i} | {risk} | {name} | CWE-{cwe} | {desc}... |\n")
        
        f.write("\n## ЗАКЛЮЧЕНИЕ\n\n")
        
        if risk_levels['High'] > 0:
            f.write(f"⚠️ **Обнаружено {risk_levels['High']} уязвимостей высокого уровня!**\n\n")
            f.write("**Рекомендации:**\n")
            f.write("1. Немедленно устранить критические уязвимости\n")
            f.write("2. Провести повторное сканирование\n")
            f.write("3. Не допускать к промышленной эксплуатации\n")
        elif risk_levels['Medium'] > 0:
            f.write(f"⚠️ Обнаружено {risk_levels['Medium']} уязвимостей среднего уровня.\n\n")
            f.write("**Рекомендации:**\n")
            f.write("1. Устранить уязвимости в ближайший релиз\n")
            f.write("2. Провести повторное сканирование\n")
        else:
            f.write("✅ Критические уязвимости не обнаружены.\n")
    
    print(f"✅ ФСТЕК-отчёт сохранён: {output_file}")

def main():
    project_dir = os.path.expanduser("~/fuzzing-demo")
    reports_dir = os.path.join(project_dir, "reports", "zap")
    
    print("=" * 70)
    print("🔍 OWASP ZAP WEB VULNERABILITY SCANNER")
    print("=" * 70)
    print()
    print("⚠️  Для сканирования веб-приложения укажите URL:")
    print("   python3 scripts/run_zap.py http://localhost:5000")
    print()
    print("Или запустите с параметром:")
    print("   python3 scripts/run_zap.py <URL>")
    print()
    
    # Если есть аргумент командной строки - используем его
    import sys
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        # По умолчанию сканируем наш Dashboard
        target_url = "http://localhost:5000"
    
    zap_output = os.path.join(reports_dir, "zap_results")
    zap_report = os.path.join(reports_dir, "ZAP_FSTEC_REPORT.md")
    
    zap_data = run_zap_scan(target_url, zap_output)
    
    if zap_data:
        generate_fstec_report(zap_data, zap_report)
        
        print("\n" + "=" * 70)
        print("✅ OWASP ZAP SCAN ЗАВЕРШЁН")
        print("=" * 70)
        print(f"\n📄 HTML отчёт: {os.path.join(zap_output, 'zap_report.html')}")
        print(f"📄 Markdown: {os.path.join(zap_output, 'zap_report.md')}")
    else:
        print("\n⚠️  ZAP сканирование не выполнено")
        print("   Убедитесь, что Docker запущен и целевой URL доступен")

if __name__ == "__main__":
    main()
