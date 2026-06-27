#!/usr/bin/env python3
"""
Генерация fuzzing harness с помощью Ollama
С постобработкой и защитой от галлюцинаций
"""

import os
import re
import requests
import json
import subprocess

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:1.5b"

def read_source_code():
    source_file = os.path.expanduser("~/fuzzing-demo/src/packet_parser.h")
    with open(source_file, 'r') as f:
        return f.read()

def generate_prompt(source_code):
    prompt = f"""You are a C++ security engineer. Generate a libFuzzer harness.

HEADER FILE:
{source_code}

TASK: Create a file harness.cpp with function LLVMFuzzerTestOneInput.

STRICT RULES:
1. Output ONLY valid C++ code, NO markdown, NO explanations
2. Include: cstdint, cstddef, string, packet_parser.h
3. Function signature: extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
4. Inside: create Packet, call parse_packet, if OK call process_packet
5. Return 0
6. Start with #include, end with closing brace

YOUR OUTPUT:"""
    return prompt

def postprocess_code(raw_code):
    code = raw_code
    # Удаляем markdown блоки
    code = re.sub(r'^```(?:cpp|c\+\+)?\s*\n', '', code, flags=re.MULTILINE)
    code = re.sub(r'\n```\s*$', '', code, flags=re.MULTILINE)
    code = re.sub(r'```', '', code)
    
    # Ищем начало кода (первый #include)
    lines = code.split('\n')
    start_idx = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('#include'):
            start_idx = i
            break
    
    # Ищем конец кода (последняя закрывающая скобка)
    end_idx = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() == '}':
            end_idx = i + 1
            break
    
    clean_code = '\n'.join(lines[start_idx:end_idx])
    return clean_code.strip()

def validate_code(code):
    required = ['#include', 'LLVMFuzzerTestOneInput', 'parse_packet', 'return 0']
    missing = [r for r in required if r not in code]
    if missing:
        print(f"⚠️  В коде отсутствуют: {missing}")
        return False
    if re.search(r'[а-яА-ЯёЁ]', code):
        print("⚠️  В коде обнаружена кириллица (галлюцинации)")
        return False
    return True

def call_ollama_streaming(prompt):
    print(f"🤖 Модель: {MODEL}")
    print("⏳ Генерирую код...")
    print("-" * 70)
    
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": True,
        "options": {
            "temperature": 0.0,
            "num_predict": 500,
        }
    }
    
    try:
        response = requests.post(
            OLLAMA_URL, 
            json=payload, 
            stream=True,
            timeout=600
        )
        response.raise_for_status()
        
        generated_code = ""
        token_count = 0
        
        for line in response.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                    token = data.get('response', '')
                    generated_code += token
                    token_count += 1
                    if token_count % 5 == 0:
                        print(token, end='', flush=True)
                    if data.get('done', False):
                        break
                except json.JSONDecodeError:
                    continue
        
        print("\n" + "-" * 70)
        print(f"✅ Сгенерировано {token_count} токенов")
        return generated_code
        
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        return None

def save_harness(code, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        f.write(code)
    print(f"💾 Harness сохранён: {output_file}")

def compile_harness(harness_file):
    print("\n🔨 Компиляция harness...")
    project_root = os.path.expanduser("~/fuzzing-demo")
    source_file = os.path.join(project_root, "src", "packet_parser.cpp")
    output_binary = os.path.join(project_root, "fuzz_libfuzzer_llm")
    
    cmd = (
        f"clang++ -fsanitize=fuzzer,address,undefined -O1 -g -std=c++17 "
        f"-I{os.path.join(project_root, 'src')} "
        f"{harness_file} {source_file} -o {output_binary}"
    )
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"✅ Компиляция успешна!")
        return output_binary
    else:
        print("❌ Ошибка компиляции:")
        print(result.stderr[:500])
        return None

def main():
    print("=" * 70)
    print("🚀 Генерация fuzzing harness (Ollama + Postprocessing)")
    print("=" * 70)
    
    print("\n📖 Читаю packet_parser.h...")
    source_code = read_source_code()
    print(f"✅ Прочитано {len(source_code)} байт")
    
    prompt = generate_prompt(source_code)
    raw_code = call_ollama_streaming(prompt)
    
    if not raw_code:
        print("\n⚠️  Генерация не удалась.")
        return
    
    print("\n🧹 Постобработка кода...")
    clean_code = postprocess_code(raw_code)
    
    if not validate_code(clean_code):
        print("⚠️  Код не прошёл валидацию.")
        print("\n📄 Сырой ответ LLM:")
        print("-" * 70)
        print(raw_code[:500])
        print("-" * 70)
        return
    
    project_root = os.path.expanduser("~/fuzzing-demo")
    harness_file = os.path.join(project_root, "fuzz", "harness_llm.cpp")
    save_harness(clean_code, harness_file)
    
    binary = compile_harness(harness_file)
    
    if binary:
        print("\n" + "=" * 70)
        print("✅ ГОТОВО!")
        print("\n📄 Сгенерированный harness:")
        print("-" * 70)
        print(clean_code)
        print("-" * 70)
        print(f"\n🎯 Запуск фаззинга:")
        print(f"   ./fuzz_libfuzzer_llm corpus/ -max_total_time=60")

if __name__ == "__main__":
    main()
