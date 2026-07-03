#!/usr/bin/env python3
"""
Генератор обучающих данных для ML-классификатора FP

Создаём синтетические данные на основе реальных паттернов:
- 500 TP (true positive) крашей
- 500 FP (false positive) крашей

Признаки (features) для ML:
1. stack_trace_length — длина stack trace
2. has_our_code — % фреймов из нашего кода
3. has_test_keyword — есть ли 'test' в stack trace
4. has_debug_keyword — есть ли 'debug' в stack trace
5. has_memory_keyword — есть ли 'memory' в stack trace
6. crash_type_encoded — тип краша (one-hot encoding)
7. file_extension — расширение файла (.cpp, .js, .test)
8. function_depth — глубина вложенности функций
"""

import random
import json
import numpy as np
from pathlib import Path

def generate_tp_sample():
    """Генерирует пример true positive (реальная уязвимость)"""
    crash_types = ['heap-buffer-overflow', 'use-after-free', 'stack-buffer-overflow', 'null-dereference']
    
    return {
        'stack_trace_length': random.randint(5, 15),
        'has_our_code': random.uniform(0.6, 1.0),  # 60-100% наш код
        'has_test_keyword': random.uniform(0.0, 0.1),  # редко test
        'has_debug_keyword': random.uniform(0.0, 0.1),  # редко debug
        'has_memory_keyword': random.uniform(0.3, 0.8),
        'crash_type_heap': 1 if random.random() > 0.5 else 0,
        'crash_type_uaf': 1 if random.random() > 0.7 else 0,
        'crash_type_stack': 1 if random.random() > 0.7 else 0,
        'crash_type_null': 1 if random.random() > 0.6 else 0,
        'file_extension_cpp': 1 if random.random() > 0.3 else 0,
        'file_extension_js': 1 if random.random() > 0.7 else 0,
        'function_depth': random.randint(3, 10),
        'label': 0  # 0 = TP (не FP)
    }

def generate_fp_sample():
    """Генерирует пример false positive (ложное срабатывание)"""
    fp_types = ['oom', 'debug_assert', 'test_timeout']
    fp_type = random.choice(fp_types)
    
    if fp_type == 'oom':
        return {
            'stack_trace_length': random.randint(2, 5),  # короткий stack
            'has_our_code': random.uniform(0.0, 0.3),  # мало нашего кода
            'has_test_keyword': random.uniform(0.0, 0.2),
            'has_debug_keyword': random.uniform(0.0, 0.2),
            'has_memory_keyword': random.uniform(0.8, 1.0),  # много memory
            'crash_type_heap': 0,
            'crash_type_uaf': 0,
            'crash_type_stack': 0,
            'crash_type_null': 0,
            'file_extension_cpp': 1 if random.random() > 0.5 else 0,
            'file_extension_js': 1 if random.random() > 0.5 else 0,
            'function_depth': random.randint(1, 3),  # малая глубина
            'label': 1  # 1 = FP
        }
    elif fp_type == 'debug_assert':
        return {
            'stack_trace_length': random.randint(3, 8),
            'has_our_code': random.uniform(0.2, 0.5),
            'has_test_keyword': random.uniform(0.3, 0.6),
            'has_debug_keyword': random.uniform(0.7, 1.0),  # много debug
            'has_memory_keyword': random.uniform(0.1, 0.4),
            'crash_type_heap': 0,
            'crash_type_uaf': 0,
            'crash_type_stack': 0,
            'crash_type_null': 0,
            'file_extension_cpp': 1,
            'file_extension_js': 0,
            'function_depth': random.randint(2, 5),
            'label': 1
        }
    else:  # test_timeout
        return {
            'stack_trace_length': random.randint(8, 20),  # длинный stack
            'has_our_code': random.uniform(0.1, 0.4),
            'has_test_keyword': random.uniform(0.7, 1.0),  # много test
            'has_debug_keyword': random.uniform(0.2, 0.5),
            'has_memory_keyword': random.uniform(0.2, 0.5),
            'crash_type_heap': 0,
            'crash_type_uaf': 0,
            'crash_type_stack': 0,
            'crash_type_null': 0,
            'file_extension_cpp': 0,
            'file_extension_js': 1,
            'function_depth': random.randint(5, 15),
            'label': 1
        }

def main():
    random.seed(42)
    np.random.seed(42)
    
    # Генерируем 500 TP + 500 FP = 1000 примеров
    data = []
    for _ in range(500):
        data.append(generate_tp_sample())
    for _ in range(500):
        data.append(generate_fp_sample())
    
    # Перемешиваем
    random.shuffle(data)
    
    # Сохраняем
    output_file = Path('ml/training_data.json')
    output_file.write_text(json.dumps(data, indent=2))
    
    print(f"✅ Обучающие данные сгенерированы: {output_file}")
    print(f"   Всего примеров: {len(data)}")
    print(f"   TP (реальные баги): {sum(1 for d in data if d['label'] == 0)}")
    print(f"   FP (ложные срабатывания): {sum(1 for d in data if d['label'] == 1)}")

if __name__ == "__main__":
    main()
