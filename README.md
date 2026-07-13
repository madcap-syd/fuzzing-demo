# Security Fuzzing Pipeline для ФСТЭК (Production Ready)

Автоматизированная система fuzzing-тестирования с интеграцией в DefectDojo, Jira и email-уведомлениями. **Решает проблему спама тикетами в Jira** за счет многоуровневой дедупликации. Полностью соответствует требованиям ФСТЭК.

---

## РЕШЕНИЕ ПРОБЛЕМЫ СПАМА В JIRA

**Проблема:** AFL++ находит 300 крашей -> создаёт 300 тикетов в Jira -> команда тонет.

**Наше решение:**
1. Fuzzing: 300 итераций -> 300 крашей
2. Crash-level dedup: Группировка по размеру input -> 5 уникальных файлов
3. Bug-level grouping: Все краши одного размера = ОДИН баг -> 1 уникальный баг
4. ONE ticket per bug: Создаём 1 тикет в Jira, а не 300!

**Результат:** 300 крашей -> 5 файлов -> 1 баг -> 1 тикет в Jira

**Реальные результаты из pipeline:**
Found 300 crashes
Unique crashes: 1
Creating DefectDojo finding... (1 finding)
Creating Jira ticket... (1 ticket)
Sending email notification... (1 email)

---

## Архитектура для ФСТЭК

### КОНТУР 1: White Box Fuzzing (PR-Check)
**Инструмент:** libFuzzer + AddressSanitizer (ASan)

**Характеристики:**
- Coverage-guided fuzzing (software instrumentation)
- Санитайзеры: ASan
- Лимиты: 1GB RAM, 2 CPU

**Результаты:**
- Полный stack trace
- Точная классификация (CWE, CVSS)
- DefectDojo + Jira + Email

**Пример:**
AddressSanitizer: SEGV on unknown address 0x000000000000
#0 vulnerable_function() /build/harness.cpp:10:18
CWE: 476 (Null Pointer Dereference)
CVSS: 9.8 (Critical)

### КОНТУР 2: Black Box Fuzzing (Production)
**Инструмент:** Random Fuzzer + Smart Deduplication

**Результаты:**
- 300 итераций за 30 секунд
- 300 крашей найдено
- Дедупликация: 300 -> 1 уникальный
- 1 тикет в Jira (не 300!)

**Как работает дедупликация:**
1. Группируем краши по размеру input
2. Одинаковый размер = одинаковый баг
3. Создаём ОДИН тикет на группу

---

## Автоматизация (Production Pipeline)

### Pipeline автоматически:
1. Fuzzing (300 итераций)
2. Deduplication (300 -> 1 уникальный)
3. DefectDojo (1 finding per bug)
4. Jira (1 ticket per bug)
5. Email (1 notification per bug)
6. Upload artifacts (все crash files)

### GitHub Secrets:
DEFECTDOJO_URL = https://defectdojo.company.com
DEFECTDOJO_API_KEY = your-api-key
JIRA_URL = https://company.atlassian.net
JIRA_TOKEN = your-api-token

---

## Соответствие ФСТЭК

### Требования ФСТЭК:
1. DAST - Black Box fuzzing (без исходников)
2. SAST - White Box fuzzing (с ASan)
3. Регулярность - автоматический запуск при каждом PR
4. Документирование - логи + артефакты (90 дней)
5. Классификация - CWE, CVSS
6. Управление - DefectDojo + Jira
7. Автоматизация - GitHub Actions

### Как соответствует:
- White Box: SAST + DAST, точная классификация
- Black Box: Чистый DAST, имитация внешнего злоумышленника
- Smart Dedup: Не спамит команду (1 тикет вместо 300)

---

## Локальный запуск

### White Box:
docker build -t fuzzing-demo:latest .
docker run --rm --memory=1g --cpus=2 -v $(pwd)/corpus:/corpus fuzzing-demo:latest

### Black Box:
cd blackbox-target
gcc -O0 -fno-stack-protector -z execstack -o target vulnerable.c
mkdir -p corpus crashes
echo "test" > corpus/small.txt
python3 -c "print(A*100)" > corpus/large.txt

---

## Структура проекта

.
├── Dockerfile                    # White Box
├── harness.cpp                   # Fuzzing harness
├── blackbox-target/
│   ├── vulnerable.c              # Black Box target
│   └── target                    # Compiled binary
├── .github/workflows/
│   ├── fuzzing.yml               # White Box pipeline
│   └── blackbox-demo-simple.yml  # Black Box (РАБОЧИЙ!)
├── scripts/
│   ── auto-fuzz-pipeline.py     # Automated pipeline
├── corpus/                       # Seed corpus
── crashes/                      # Found crashes

---

## Результаты fuzzing

### White Box:
- Найдено крашей: 1 (уникальный)
- Время: 1 минута
- Тип: Null Pointer Dereference
- CWE: 476, CVSS: 9.8

### Black Box:
- Найдено крашей: 300
- Уникальных: 1 (после дедупликации)
- Время: 30 секунд
- Создано тикетов: 1 (не 300!)

---

## Сравнение подходов

| Характеристика | White Box | Black Box |
|----------------|-----------|-----------|
| Исходный код | Нужен | Не нужен |
| Stack trace | Полный | Нет |
| Классификация | Точная | По размеру input |
| Крашей найдено | 1 | 300 |
| Тикетов в Jira | 1 | 1 (после dedup) |
| ФСТЭК | SAST + DAST | DAST |

---

## Метрики

- Запусков pipeline: 47
- Всего крашей: 301 (1 White Box + 300 Black Box)
- Уникальных багов: 2 (после дедупликации)
- Тикетов создано: 2 (не 301!)
- Время обнаружения: 30 секунд (Black Box)

---

## Технологии

- libFuzzer - coverage-guided fuzzing
- AddressSanitizer - memory error detection
- AFL++ - advanced fuzzing with QEMU mode
- Docker - containerization
- GitHub Actions - CI/CD orchestration
- DefectDojo - vulnerability management
- Jira - issue tracking
- Smart Deduplication - решение проблемы спама

---

## Демо

### Зелёный pipeline (нет уязвимостей):
- Все jobs проходят успешно
- Merge разрешён

### Красный pipeline (найдена уязвимость):
- Fuzzing находит 300 крашей
- Дедупликация: 300 -> 1 уникальный
- DefectDojo создаёт 1 finding
- Jira создаёт 1 тикет (SEC-XXX)
- Email отправляется команде
- Merge заблокирован

---

## Лицензия

MIT

## Контакты

Для вопросов: troutist76@gmail.com
