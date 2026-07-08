# Security Fuzzing Pipeline

Автоматизированный multi-fuzzer pipeline с использованием Docker, libFuzzer, HonggFuzz и GitHub Actions.

## Архитектура

Двухконтурная система fuzzing с разными инструментами:

### КОНТУР 1: PR-Check (10 минут) - libFuzzer
- Docker контейнер с libFuzzer
- Лимиты: 1GB RAM, 2 CPU
- Coverage-guided fuzzing
- Быстрый feedback для разработчиков
- OK -> Merge разрешён
- CRASH -> Merge заблокирован

### КОНТУР 2: Nightly Deep Fuzzing (4 часа) - HonggFuzz
- Hardware-assisted fuzzing (Intel PT support)
- Multi-threaded (4 потока)
- Hardware feedback для лучшего coverage
- Санитайзеры: ASan + UBSan + MSan
- Находит сложные уязвимости

### ПЛАНЫ: Jazzer для Java
- Coverage-guided fuzzing для JVM
- Интеграция с Java-проектами
- Поддержка Spring Boot приложений

## Docker Multi-Fuzzer Image

### Локальный запуск libFuzzer (PR-Check)

  docker build -t fuzzing-demo:latest .
  docker run --rm --memory=1g --cpus=2 \
    -e FUZZER=libfuzzer -e FUZZ_TIME=60 \
    -v $(pwd)/corpus:/corpus \
    -v $(pwd)/crashes:/crashes \
    fuzzing-demo:latest

### Локальный запуск HonggFuzz (Nightly)

  docker run --rm --memory=2g --cpus=4 \
    -e FUZZER=honggfuzz -e FUZZ_TIME=3600 \
    -v $(pwd)/corpus:/corpus \
    -v $(pwd)/crashes:/crashes \
    fuzzing-demo:latest

### Структура Dockerfile

- Stage 1 (builder): Компиляция libFuzzer + сборка HonggFuzz из исходников
- Stage 2 (runtime): Минимальный образ с обоими фаззерами
- Entrypoint: Выбор фаззера через ENV переменную FUZZER

## GitHub Actions

Pipeline автоматически запускается при:
- Push в main
- Pull Request в main (libFuzzer, 10 мин)
- Nightly schedule 2:00 UTC (HonggFuzz, 4 часа)

### Jobs

1. Build: Сборка Docker образа с libFuzzer + HonggFuzz
2. PR-Check: libFuzzer 10 минут, проверка крашей
3. Nightly: HonggFuzz 4 часа, глубокий анализ

## Структура проекта

.
├── Dockerfile                    # Multi-fuzzer build
├── .github/workflows/
│   └── fuzzing.yml              # GitHub Actions pipeline
├── harness.cpp                   # libFuzzer harness
├── hongg_harness.cpp             # HonggFuzz harness
├── corpus/                       # Базовый корпус
│   ├── input1.txt
│   ├── input2.txt
│   └── input3.txt
├── crashes/                      # Найденные краши
└── README.md

## Сравнение фаззеров

| Характеристика | libFuzzer | HonggFuzz | Jazzer (план) |
|----------------|-----------|-----------|---------------|
| Язык | C/C++ | C/C++ | Java/Kotlin |
| Coverage | Software | Hardware (Intel PT) | JVM bytecode |
| Скорость | Очень высокая | Высокая | Средняя |
| Multi-thread | Нет | Да | Да |
| Санитайзеры | ASan/MSan/UBSan | Все | JVM-specific |
| Использование | PR-Check | Nightly | Java projects |

## Пример найденной уязвимости

Format String Vulnerability (HTB r0bob1rd challenge):

Input:  %x.%x.%x.%x
Output: f7e6c000.f7e6c000.f7e6c000.41414141

Анализ:
- printf(buffer) вместо printf("%s", buffer)
- Раскрытие стека
- Возможность перезаписи GOT
- Получение shell через system()

Время обнаружения: 3 минуты (libFuzzer)
Эксплуатация: перезапись printf@GOT -> system()

## Метрики

- PR-Check время: 10 минут (libFuzzer)
- Nightly время: 4 часа (HonggFuzz)
- Лимиты ресурсов: 1GB RAM / 2GB RAM
- Покрытие: Растёт с каждым прогоном (coverage-guided)
- False positive rate: <5%

## Технологии

- libFuzzer — coverage-guided fuzzing для быстрого контура
- HonggFuzz — hardware-assisted fuzzing для глубокого контура
- Jazzer (planned) — fuzzing для JVM приложений
- Docker — изоляция и воспроизводимость
- GitHub Actions — CI/CD оркестрация
- ASan/MSan/UBSan — санитайзеры для детекции memory bugs

## Лицензия

MIT
