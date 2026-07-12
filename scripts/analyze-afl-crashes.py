#!/usr/bin/env python3
"""
Анализ крашей от AFL++
Группирует по размеру и создаёт отчёт
"""

import os
import sys
import json
from pathlib import Path
from collections import defaultdict

def analyze_crashes(crash_dir):
    """Анализируем краши"""
    crash_path = Path(crash_dir)
    
    if not crash_path.exists():
        print(f"Directory {crash_dir} not found")
        return []
    
    crashes = list(crash_path.glob('*'))
    
    # Группируем по размеру
    size_groups = defaultdict(list)
    for crash in crashes:
        if crash.is_file():
            size = crash.stat().st_size
            size_groups[size].append(crash)
    
    print(f"Total crashes: {len(crashes)}")
    print(f"Unique sizes: {len(size_groups)}")
    print("")
    
    # Выбираем по одному из каждой группы
    unique_crashes = []
    for size, files in size_groups.items():
        unique_crashes.append(files[0])
        print(f"Size {size:4d} bytes: {len(files)} crashes → 1 unique")
    
    return unique_crashes

def create_report(unique_crashes, output_file="afl-analysis.json"):
    """Создаём отчёт"""
    report = {
        "total_crashes": sum(len(files) for files in []),
        "unique_crashes": len(unique_crashes),
        "crashes": [
            {
                "file": str(crash.name),
                "size": crash.stat().st_size
            }
            for crash in unique_crashes
        ]
    }
    
    Path(output_file).write_text(json.dumps(report, indent=2))
    print(f"\nReport saved to {output_file}")
    
    return report

if __name__ == "__main__":
    crash_dir = sys.argv[1] if len(sys.argv) > 1 else "crashes/default/crashes"
    
    print("=" * 60)
    print("AFL++ CRASH ANALYSIS")
    print("=" * 60)
    print("")
    
    unique = analyze_crashes(crash_dir)
    create_report(unique)
    
    print("")
    print("=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
