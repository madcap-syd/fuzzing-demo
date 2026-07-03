#!/usr/bin/env python3
"""
Генератор тестовых крашей для демонстрации triage pipeline
Имитирует результат ночного фаззинга: 1000 крашей, 30 уникальных багов
"""

import os
import random
import json
from pathlib import Path

# Шаблоны stack traces для разных типов багов
STACK_TRACES = {
    'heap-buffer-overflow': [
        "#0 0x4a1234 in parse_packet(unsigned char const*, unsigned long) packet_parser.cpp:31",
        "#1 0x4a1567 in LLVMFuzzerTestOneInput fuzz/harness.cpp:12",
        "#2 0x4b2345 in fuzzer::Fuzzer::ExecuteCallback",
        "#3 0x4b3456 in fuzzer::Fuzzer::RunOne",
        "SUMMARY: AddressSanitizer: heap-buffer-overflow packet_parser.cpp:31 in parse_packet",
    ],
    'use-after-free': [
        "#0 0x4a1234 in process_connection(Connection*) net.cpp:145",
        "#1 0x4a1567 in handle_request(Request*) server.cpp:89",
        "#2 0x4b2345 in LLVMFuzzerTestOneInput fuzz/harness.cpp:18",
        "SUMMARY: AddressSanitizer: use-after-free net.cpp:145 in process_connection",
    ],
    'stack-buffer-overflow': [
        "#0 0x4a1234 in decode_header(char const*) codec.cpp:67",
        "#1 0x4a1567 in parse_message(unsigned char const*) parser.cpp:42",
        "#2 0x4b2345 in LLVMFuzzerTestOneInput fuzz/harness.cpp:15",
        "SUMMARY: AddressSanitizer: stack-buffer-overflow codec.cpp:67 in decode_header",
    ],
    'null-dereference': [
        "#0 0x4a1234 in get_user(UserDB*, int) db.cpp:23",
        "#1 0x4a1567 in handle_login(Request*) auth.cpp:56",
        "SUMMARY: AddressSanitizer: SEGV db.cpp:23 in get_user",
    ],
    'assertion-failure-test': [
        "#0 0x4a1234 in __assert_fail",
        "#1 0x4a1567 in test_helper() test_utils.cpp:15",
        "SUMMARY: Assertion `x > 0' failed",
    ],
    'prototype-pollution': [
        '    at Object.<anonymous> (packet_parser.js:80)',
        '    at exports.fuzz (harness.js:12)',
        '    at runFuzzer (node_modules/@jazzer.js/core/dist/index.js:145)',
        'Error: Prototype Pollution via __proto__ assignment',
    ],
    'redos': [
        '    at RegExp.exec (<anonymous>)',
        '    at validate (validator.js:23)',
        'TimeoutError: Fuzzer timed out after 10000ms',
    ],
}

# FP-паттерны (должны быть отфильтрованы)
FP_STACK_TRACES = {
    'oom': [
        "SUMMARY: AddressSanitizer: out-of-memory",
        "#0 0x4a1234 in operator new(unsigned long)",
    ],
    'assert-debug': [
        "#0 0x4a1234 in __assert_fail",
        "#1 0x4a1567 in debug_check() debug.cpp:10",
        "SUMMARY: Assertion failed in DEBUG build only",
    ],
}

def generate_crash(crash_type: str, variant: int) -> tuple[str, bytes]:
    """Генерирует краш-файл с stack trace"""
    
    if crash_type in FP_STACK_TRACES:
        stack = FP_STACK_TRACES[crash_type]
    else:
        stack = STACK_TRACES[crash_type]
    
    # Создаём содержимое краш-файла (имитация libFuzzer output)
    content = f"=={os.getpid()}==ERROR: AddressSanitizer\n"
    content += "\n".join(stack) + "\n"
    content += f"\nTest unit written to crash-{variant}.bin\n"
    
    # Генерируем "PoC" — случайные байты + паттерн уязвимости
    if crash_type == 'prototype-pollution':
        poc = b'{"__proto__":{"polluted":true}}' + os.urandom(random.randint(10, 100))
    elif crash_type == 'redos':
        poc = b'a' * random.randint(100, 1000)
    elif crash_type == 'heap-buffer-overflow':
        poc = b'\x41' * random.randint(16, 512)
    else:
        poc = os.urandom(random.randint(16, 256))
    
    return content, poc

def main():
    output_dir = Path('triage-demo/crashes/cpp')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Конфигурация: сколько крашей каждого типа генерировать
    # Имитирует реальное распределение: много дубликатов одного бага
    distribution = {
        # Реальные баги (TP)
        'heap-buffer-overflow': 150,   # 1 баг, 150 крашей
        'use-after-free': 80,          # 1 баг, 80 крашей
        'stack-buffer-overflow': 45,   # 1 баг, 45 крашей
        'null-dereference': 200,       # 1 баг, 200 крашей
        'prototype-pollution': 120,    # 1 баг, 120 крашей
        'redos': 60,                   # 1 баг, 60 крашей
        # False positives
        'oom': 180,                    # FP
        'assert-debug': 165,           # FP
    }
    
    total = 0
    for crash_type, count in distribution.items():
        for i in range(count):
            content, poc = generate_crash(crash_type, total)
            
            # Сохраняем stack trace (для triage)
            trace_file = output_dir / f"crash-{total:04d}.txt"
            trace_file.write_text(content)
            
            # Сохраняем PoC
            poc_file = output_dir / f"crash-{total:04d}.bin"
            poc_file.write_bytes(poc)
            
            total += 1
    
    print(f"✅ Сгенерировано {total} крашей в {output_dir}")
    print(f"   Реальных багов: 6 типов")
    print(f"   False positives: 2 типа (OOM, debug assert)")
    print(f"   Ожидаемый dedup ratio: ~{total/8:.0f}x")

if __name__ == "__main__":
    main()
