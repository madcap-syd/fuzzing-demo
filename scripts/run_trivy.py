#!/usr/bin/env python3
"""
Trivy Container & Filesystem Scanner
Интеграция с ФСТЕК-отчётностью
"""

import subprocess
import json
import os
from datetime import datetime

def run_trivy_image_scan(image_name, output_file):
    """Сканирует Docker образ"""
    
    print("=" * 70)
    print(f"🔍 TRIVY DOCKER IMAGE SCAN: {image_name}")
    print("=" * 70)
    print()
    
    cmd = [
        'trivy', 'image',
        '--format', 'json',
        '--output', output_file,
        '--severity', 'CRITICAL,HIGH,MEDIUM',
        image_name
    ]
    
    print(f"📦 Сканируем образ: {image_name}")
    print(f"📝 Результат: {output_file}")
    print()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode in [0, 1, 2]:  # 1+ = vulnerabilities found
            print("✅ Сканирование завершено")
            
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            # Считаем уязвимости
            total = 0
            critical = 0
            high = 0
            medium = 0
            
            for result_item in data.get('Results', []):
                for vuln in result_item.get('Vulnerabilities', []):
                    total += 1
                    severity = vuln.get('Severity', '')
                    if severity == 'CRITICAL':
                        critical += 1
                    elif severity == 'HIGH':
                        high += 1
                    elif severity == 'MEDIUM':
                        medium += 1
            
            print(f"\n📊 Результаты:")
            print(f"   Всего: {total}")
            print(f"   Critical: {critical}")
            print(f"   High: {high}")
            print(f"   Medium: {medium}")
            
            return data
        else:
            print(f"❌ Ошибка: {result.stderr}")
            return None
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return None

def run_trivy_fs_scan(target_dir, output_file):
    """Сканирует файловую систему"""
    
    print("=" * 70)
    print(f"🔍 TRIVY FILESYSTEM SCAN: {target_dir}")
    print("=" * 70)
    print()
    
    cmd = [
        'trivy', 'fs',
        '--format', 'json',
        '--output', output_file,
        '--severity', 'CRITICAL,HIGH,MEDIUM',
        '--skip-dirs', 'node_modules,.git,__pycache__',
        target_dir
    ]
    
    print(f"📂 Сканируем: {target_dir}")
    print()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode in [0, 1, 2]:
            print("✅ Сканирование завершено")
            
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            return data
        else:
            print(f"❌ Ошибка: {result.stderr}")
            return None
            
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return None

def generate_fstec_report(trivy_data, output_file, scan_type="Image"):
    """Генерирует ФСТЕК-отчёт"""
    
    if not trivy_data:
        return
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# ОТЧЁТ TRIVY {scan_type.upper()} SCAN\n\n")
        f.write(f"**Дата:** {datetime.now().strftime('%d.%m.%Y %H:%M')}\n")
        f.write("**Инструмент:** Trivy (Container/Filesystem Scanner)\n")
        f.write("**Соответствие:** ФСТЕК № 239, ГОСТ Р 56939-2024\n\n")
        
        total_vulns = 0
        critical = 0
        high = 0
        medium = 0
        
        f.write("## ВЫЯВЛЕННЫЕ УЯЗВИМОСТИ\n\n")
        f.write("| № | Severity | CVE | Package | Version | Файл |\n")
        f.write("|---|----------|-----|---------|---------|------|\n")
        
        i = 1
        for result in trivy_data.get('Results', []):
            target = result.get('Target', '')
            for vuln in result.get('Vulnerabilities', []):
                total_vulns += 1
                severity = vuln.get('Severity', '')
                if severity == 'CRITICAL':
                    critical += 1
                elif severity == 'HIGH':
                    high += 1
                elif severity == 'MEDIUM':
                    medium += 1
                
                f.write(f"| {i} | {severity} | {vuln.get('VulnerabilityID', 'N/A')} | "
                       f"{vuln.get('PkgName', 'N/A')} | {vuln.get('InstalledVersion', 'N/A')} | "
                       f"{target} |\n")
                i += 1
        
        f.write(f"\n## СТАТИСТИКА\n\n")
        f.write(f"- Всего найдено: {total_vulns}\n")
        f.write(f"- Critical: {critical}\n")
        f.write(f"- High: {high}\n")
        f.write(f"- Medium: {medium}\n\n")
        
        f.write("## ЗАКЛЮЧЕНИЕ\n\n")
        
        if critical > 0:
            f.write(f"⚠️ **Обнаружено {critical} критических уязвимостей!**\n\n")
            f.write("**Рекомендации:**\n")
            f.write("1. Немедленно обновить уязвимые пакеты\n")
            f.write("2. Пересобрать образ/приложение\n")
            f.write("3. Провести повторное сканирование\n")
        elif high > 0:
            f.write(f"⚠️ Обнаружено {high} уязвимостей высокого уровня.\n\n")
            f.write("**Рекомендации:**\n")
            f.write("1. Запланировать обновление пакетов\n")
            f.write("2. Провести повторное сканирование\n")
        else:
            f.write("✅ Критические уязвимости не обнаружены.\n")
    
    print(f"✅ ФСТЕК-отчёт сохранён: {output_file}")

def main():
    project_dir = os.path.expanduser("~/fuzzing-demo")
    reports_dir = os.path.join(project_dir, "reports", "trivy")
    
    os.makedirs(reports_dir, exist_ok=True)
    
    # Сканируем filesystem
    fs_output = os.path.join(reports_dir, "trivy_fs_results.json")
    fs_report = os.path.join(reports_dir, "TRIVY_FS_FSTEC_REPORT.md")
    
    fs_data = run_trivy_fs_scan(project_dir, fs_output)
    if fs_data:
        generate_fstec_report(fs_data, fs_report, "Filesystem")
    
    # Сканируем Docker образы (если есть)
    print("\n" + "=" * 70)
    print(" СКАНИРОВАНИЕ DOCKER ОБРАЗОВ")
    print("=" * 70)
    
    # Проверяем, есть ли образы
    result = subprocess.run(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'], 
                          capture_output=True, text=True)
    images = result.stdout.strip().split('\n')
    
    for image in images:
        if image and 'faraday' not in image.lower():  # Пропускаем faraday
            image_output = os.path.join(reports_dir, f"trivy_image_{image.replace('/', '_').replace(':', '_')}.json")
            image_report = os.path.join(reports_dir, f"TRIVY_IMAGE_{image.replace('/', '_').replace(':', '_')}_FSTEC_REPORT.md")
            
            image_data = run_trivy_image_scan(image, image_output)
            if image_data:
                generate_fstec_report(image_data, image_report, "Image")
    
    print("\n" + "=" * 70)
    print("✅ TRIVY SCAN ЗАВЕРШЁН")
    print("=" * 70)

if __name__ == "__main__":
    main()
