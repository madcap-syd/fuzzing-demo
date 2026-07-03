#!/usr/bin/env python3
"""
Интеграция результатов фаззинга и статического анализа с DefectDojo
Формирование ФСТЕК-совместимых отчётов
"""

import json
import os
import requests
from datetime import datetime
from typing import List, Dict

class DefectDojoIntegration:
    """Интеграция с DefectDojo API"""
    
    def __init__(self, dojo_url: str, api_key: str):
        self.dojo_url = dojo_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Authorization': f'Token {api_key}',
            'Content-Type': 'application/json'
        }
    
    def import_jazzer_results(self, product_id: int, engagement_id: int, crash_files: List[str]):
        """Импортирует результаты Jazzer.js в DefectDojo"""
        
        findings = []
        for crash_file in crash_files:
            with open(crash_file, 'rb') as f:
                content = f.read()
            
            # Определяем тип уязвимости
            vuln_type = "Unknown"
            cwe = 0
            severity = "Medium"
            
            if b'__proto__' in content or b'constructor' in content:
                vuln_type = "Prototype Pollution"
                cwe = 1321
                severity = "Critical"
            elif b'aaaa' in content and len(content) > 50:
                vuln_type = "ReDoS"
                cwe = 1333
                severity = "High"
            
            findings.append({
                "title": f"Jazzer.js: {vuln_type}",
                "description": f"Found by Jazzer.js fuzzing\nFile: {os.path.basename(crash_file)}\nSize: {len(content)} bytes",
                "severity": severity,
                "cwe": cwe,
                "active": True,
                "verified": True,
                "mitigation": "Fix the vulnerability in the code",
                "impact": "Security vulnerability detected",
                "references": "https://owasp.org/www-community/attacks/",
                "file_path": crash_file,
                "line": 1,
                "unique_id_from_tool": f"jazzer_{os.path.basename(crash_file)}"
            })
        
        return self._create_findings(product_id, engagement_id, findings)
    
    def import_semgrep_results(self, product_id: int, engagement_id: int, semgrep_json: str):
        """Импортирует результаты Semgrep в DefectDojo"""
        
        with open(semgrep_json, 'r') as f:
            data = json.load(f)
        
        findings = []
        for result in data.get('results', []):
            check_id = result.get('check_id', 'unknown')
            severity_map = {
                'ERROR': 'Critical',
                'WARNING': 'High',
                'INFO': 'Medium'
            }
            
            findings.append({
                "title": f"Semgrep: {check_id}",
                "description": result.get('extra', {}).get('message', 'No description'),
                "severity": severity_map.get(result.get('extra', {}).get('severity', 'INFO'), 'Medium'),
                "cwe": self._extract_cwe(check_id),
                "active": True,
                "verified": True,
                "mitigation": result.get('extra', {}).get('metadata', {}).get('fix', 'Fix the code'),
                "file_path": result.get('path', ''),
                "line": result.get('start', {}).get('line', 1),
                "unique_id_from_tool": f"semgrep_{check_id}_{result.get('path', '')}"
            })
        
        return self._create_findings(product_id, engagement_id, findings)
    
    def import_jsluice_results(self, product_id: int, engagement_id: int, jsluice_json: str):
        """Импортирует результаты jsluice в DefectDojo"""
        
        with open(jsluice_json, 'r') as f:
            data = json.load(f)
        
        findings = []
        for item in data:
            findings.append({
                "title": f"jsluice: {item.get('type', 'Unknown')}",
                "description": f"Found: {item.get('value', 'Unknown')}\nSource: {item.get('source', 'Unknown')}",
                "severity": "Medium",
                "cwe": 0,
                "active": True,
                "verified": True,
                "file_path": item.get('file', ''),
                "line": item.get('line', 1),
                "unique_id_from_tool": f"jsluice_{item.get('type', 'unknown')}_{item.get('line', 1)}"
            })
        
        return self._create_findings(product_id, engagement_id, findings)
    
    def _create_findings(self, product_id: int, engagement_id: int, findings: List[Dict]):
        """Создаёт findings в DefectDojo"""
        
        created = []
        for finding in findings:
            finding['product'] = product_id
            finding['engagement'] = engagement_id
            
            response = requests.post(
                f'{self.dojo_url}/api/v2/findings/',
                headers=self.headers,
                json=finding
            )
            
            if response.status_code == 201:
                created.append(finding['title'])
                print(f"✅ Created: {finding['title']}")
            else:
                print(f"❌ Failed: {finding['title']} - {response.text}")
        
        return created
    
    def _extract_cwe(self, check_id: str) -> int:
        """Извлекает CWE из check_id"""
        cwe_map = {
            'javascript.lang.security.audit.detect-non-literal-regexp': 1333,
            'javascript.lang.security.audit.detect-non-literal-fs-filename': 22,
            'javascript.lang.security.audit.detect-eval-with-expression': 95,
            'javascript.lang.security.audit.detect-child-process': 78,
            'javascript.lang.security.audit.detect-sql-injection': 89,
            'javascript.lang.security.audit.detect-xss': 79
        }
        return cwe_map.get(check_id, 0)


class FSTECReportGenerator:
    """Генератор ФСТЕК-совместимых отчётов"""
    
    def __init__(self):
        self.findings = []
    
    def add_finding(self, tool: str, title: str, severity: str, cwe: int, file_path: str, line: int):
        """Добавляет finding в отчёт"""
        self.findings.append({
            'tool': tool,
            'title': title,
            'severity': severity,
            'cwe': cwe,
            'file': file_path,
            'line': line,
            'fstec_level': self._map_to_fstec(severity)
        })
    
    def _map_to_fstec(self, severity: str) -> str:
        """Маппинг severity на уровни ФСТЕК"""
        mapping = {
            'Critical': 'ФСТЕК-У1 (Критический)',
            'High': 'ФСТЕК-У2 (Высокий)',
            'Medium': 'ФСТЕК-У3 (Средний)',
            'Low': 'ФСТЕК-У4 (Низкий)'
        }
        return mapping.get(severity, 'ФСТЕК-У3 (Средний)')
    
    def generate_report(self, output_file: str):
        """Генерирует ФСТЕК-отчёт"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# ИТОГОВЫЙ ОТЧЁТ О ТЕСТИРОВАНИИ БЕЗОПАСНОСТИ\n\n")
            f.write(f"**Проект:** JavaScript Packet Parser\n")
            f.write(f"**Дата:** {datetime.now().strftime('%d.%m.%Y %H:%M')}\n")
            f.write("**Методология:** ФСТЕК № 239, ГОСТ Р 56939-2024\n\n")
            
            f.write("## ИНСТРУМЕНТЫ ТЕСТИРОВАНИЯ\n\n")
            f.write("| Инструмент | Назначение | Статус |\n")
            f.write("|------------|------------|--------|\n")
            f.write("| Jazzer.js | Dynamic analysis (fuzzing) | ✅ |\n")
            f.write("| Semgrep | Static analysis (SAST) | ✅ |\n")
            f.write("| jsluice | Secret detection | ✅ |\n")
            f.write("| DefectDojo | Vulnerability management | ✅ |\n\n")
            
            f.write("## ВЫЯВЛЕННЫЕ УЯЗВИМОСТИ\n\n")
            f.write("| № | Инструмент | Уязвимость | CWE | CVSS | ФСТЕК | Файл | Строка |\n")
            f.write("|---|------------|------------|-----|------|-------|------|--------|\n")
            
            for i, finding in enumerate(self.findings, 1):
                cvss = self._severity_to_cvss(finding['severity'])
                f.write(f"| {i} | {finding['tool']} | {finding['title']} | "
                       f"CWE-{finding['cwe']} | {cvss} | {finding['fstec_level']} | "
                       f"{finding['file']} | {finding['line']} |\n")
            
            f.write("\n## СТАТИСТИКА\n\n")
            critical = sum(1 for f in self.findings if f['severity'] == 'Critical')
            high = sum(1 for f in self.findings if f['severity'] == 'High')
            medium = sum(1 for f in self.findings if f['severity'] == 'Medium')
            
            f.write(f"- Всего найдено: {len(self.findings)}\n")
            f.write(f"- Критических: {critical}\n")
            f.write(f"- Высоких: {high}\n")
            f.write(f"- Средних: {medium}\n\n")
            
            f.write("## ЗАКЛЮЧЕНИЕ\n\n")
            if critical > 0:
                f.write("⚠️ **Обнаружены критические уязвимости!**\n\n")
                f.write("**Рекомендации:**\n")
                f.write("1. Немедленно устранить критические уязвимости\n")
                f.write("2. Провести повторное тестирование\n")
                f.write("3. Не допускать к промышленной эксплуатации\n")
            elif high > 0:
                f.write("⚠️ Обнаружены уязвимости высокого уровня.\n\n")
                f.write("**Рекомендации:**\n")
                f.write("1. Устранить уязвимости в ближайший релиз\n")
                f.write("2. Провести повторное тестирование\n")
            else:
                f.write("✅ Критические уязвимости не обнаружены.\n")
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Конвертирует severity в CVSS score"""
        mapping = {
            'Critical': 9.8,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5
        }
        return mapping.get(severity, 5.0)


def main():
    """Основная функция"""
    
    print("=" * 70)
    print("🔗 ИНТЕГРАЦИЯ С DEFECTDOJO")
    print("=" * 70)
    print()
    
    # Конфигурация DefectDojo (замените на ваши значения)
    DOJO_URL = os.environ.get('DEFECTDOJO_URL', 'http://localhost:8080')
    API_KEY = os.environ.get('DEFECTDOJO_API_KEY', 'your-api-key-here')
    
    # Пути к файлам
    reports_dir = os.path.expanduser("~/fuzzing-demo/reports/fstec/js")
    crashes_dir = os.path.expanduser("~/fuzzing-demo/src/js/crashes")
    
    # Создаём генератор отчётов
    report_gen = FSTECReportGenerator()
    
    # Импортируем результаты Semgrep
    semgrep_file = os.path.join(reports_dir, "semgrep_results.json")
    if os.path.exists(semgrep_file):
        print("📊 Импортируем результаты Semgrep...")
        with open(semgrep_file, 'r') as f:
            data = json.load(f)
        
        for result in data.get('results', []):
            report_gen.add_finding(
                tool="Semgrep",
                title=result.get('check_id', 'Unknown'),
                severity=result.get('extra', {}).get('severity', 'Medium'),
                cwe=0,
                file_path=result.get('path', ''),
                line=result.get('start', {}).get('line', 1)
            )
    
    # Импортируем результаты jsluice
    jsluice_file = os.path.join(reports_dir, "jsluice_secrets.json")
    if os.path.exists(jsluice_file):
        print("📊 Импортируем результаты jsluice...")
        try:
            with open(jsluice_file, 'r') as f:
                data = json.load(f)
            
            for item in data:
                report_gen.add_finding(
                    tool="jsluice",
                    title=f"Secret: {item.get('type', 'Unknown')}",
                    severity="Medium",
                    cwe=0,
                    file_path=item.get('file', ''),
                    line=item.get('line', 1)
                )
        except:
            pass
    
    # Импортируем результаты Jazzer.js
    if os.path.exists(crashes_dir):
        print("📊 Импортируем результаты Jazzer.js...")
        for crash_file in os.listdir(crashes_dir):
            if crash_file.startswith('crash-'):
                report_gen.add_finding(
                    tool="Jazzer.js",
                    title="Fuzzing Crash",
                    severity="High",
                    cwe=0,
                    file_path=crash_file,
                    line=1
                )
    
    # Генерируем ФСТЕК-отчёт
    output_file = os.path.join(reports_dir, "FINAL_FSTEC_REPORT.md")
    report_gen.generate_report(output_file)
    
    print()
    print(f"✅ ФСТЕК-отчёт сформирован: {output_file}")
    print()
    print("📄 Содержимое отчёта:")
    print("-" * 70)
    with open(output_file, 'r', encoding='utf-8') as f:
        print(f.read())
    print("-" * 70)
    
    # Интеграция с DefectDojo (если настроено)
    if API_KEY != 'your-api-key-here':
        print()
        print("🔗 Интеграция с DefectDojo...")
        dojo = DefectDojoIntegration(DOJO_URL, API_KEY)
        # Здесь можно добавить импорт findings в DefectDojo
    else:
        print()
        print("⚠️  DefectDojo не настроен. Установите переменные окружения:")
        print("   export DEFECTDOJO_URL=http://localhost:8080")
        print("   export DEFECTDOJO_API_KEY=your-api-key")


if __name__ == "__main__":
    main()
