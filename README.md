# Security Fuzzing Pipeline

Автоматизированный pipeline для security fuzzing с использованием Docker, libFuzzer и GitHub Actions.

## Архитектура

Двухконтурная система fuzzing:

- КОНТУР 1: PR-Check (10 минут)
  - Docker контейнер с libFuzzer
  - Лимиты: 1GB RAM, 2 CPU
  - Корпус из репозитория
  - Краши -> артефакты GitHub Actions
  - OK -> Merge разрешён
  - CRASH -> Merge заблокирован

- КОНТУР 2: Nightly Deep Fuzzing (4 часа)
  - Расширенный корпус
  - 4 потока параллельно
  - Coverage merge

## Docker

### Локальный запуск

Собрать образ:
  docker build -t fuzzing-demo:latest .

Запустить fuzzing (60 секунд):
  docker run --rm --memory=1g --cpus=2 -v $(pwd)/corpus:/corpus -v $(pwd)/crashes:/crashes fuzzing-demo:latest

Проверить краши:
  ls -la crashes/

### Структура Dockerfile

- Stage 1 (builder): Компиляция с ASan + libFuzzer
- Stage 2 (runtime): Минимальный образ только с бинарником и корпусом

## GitHub Actions

Pipeline автоматически запускается при:
- Push в main
- Pull Request в main
- Nightly schedule (2:00 UTC)

### Jobs

1. Build: Сборка Docker образа
2. PR-Check: 10 минут fuzzing, проверка крашей
3. Nightly: 4 часа глубокого fuzzing (по расписанию)

## Структура проекта

.
├── Dockerfile                    # Multi-stage build
├── .github/workflows/
│   └── fuzzing.yml              # GitHub Actions pipeline
├── harness.cpp                   # Fuzzer harness
├── corpus/                       # Базовый корпус
│   ├── input1.txt
│   ├── input2.txt
│   └── input3.txt
├── crashes/                      # Найденные краши
└── README.md

## Пример найденной уязвимости

Format String Vulnerability (HTB r0bob1rd challenge):

Input:  %x.%x.%x.%x
Output: f7e6c000.f7e6c000.f7e6c000.41414141

Анализ:
- printf(buffer) вместо printf("%s", buffer)
- Раскрытие стека
- Возможность перезаписи GOT
- Получение shell

Время обнаружения: 3 минуты

## Метрики

- PR-Check время: 10 минут
- Nightly время: 4 часа
- Лимиты ресурсов: 1GB RAM, 2 CPU
- Покрытие: Растёт с каждым прогоном (coverage-guided)

## Технологии

- libFuzzer — coverage-guided fuzzing
- Docker — изоляция и воспроизводимость
- GitHub Actions — CI/CD оркестрация
- ASan — AddressSanitizer для детекции memory bugs

## Лицензия

MIT
