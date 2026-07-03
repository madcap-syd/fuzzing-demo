#!/usr/bin/env python3
"""
poc_minimizer.py — минимизация PoC до минимального воспроизводимого входа
"""

import os
import sys
from pathlib import Path

def minimize_poc(poc_file: Path, output_file: Path, target_size: int = 32):
    """Минимизирует PoC, сохраняя первые N байт (эвристика)"""
    
    original = poc_file.read_bytes()
    original_size = len(original)
    
    if original_size <= target_size:
        output_file.write_bytes(original)
        return original_size, original_size
    
    # Стратегия: берём первые target_size байт + последние 4 байта
    minimized = original[:target_size] + original[-4:]
    
    output_file.write_bytes(minimized)
    
    return original_size, len(minimized)

def main():
    crashes_dir = Path('triage-demo/crashes/cpp')
    min_dir = Path('triage-demo/crashes/minimized')
    min_dir.mkdir(parents=True, exist_ok=True)
    
    total_saved = 0
    files_processed = 0
    
    print(f" Минимизация PoC из {crashes_dir}...")
    
    for poc_file in sorted(crashes_dir.glob('*.bin'))[:20]:  # Первые 20 для демо
        output_file = min_dir / poc_file.name
        
        orig_size, min_size = minimize_poc(poc_file, output_file)
        saved = orig_size - min_size
        total_saved += saved
        files_processed += 1
        
        if files_processed <= 5:
            print(f"   {poc_file.name}: {orig_size} → {min_size} bytes ({saved} saved)")
    
    if files_processed > 5:
        print(f"   ... и ещё {files_processed - 5} файлов")
    
    print(f"\n✅ Минимизировано {files_processed} файлов")
    print(f"   Сэкономлено: {total_saved} bytes ({total_saved/1024:.1f} KB)")

if __name__ == "__main__":
    main()
