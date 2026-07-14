# 🛡️ Security Fuzzing Pipeline (Production Ready)

Автоматизированная система fuzzing-тестирования (SAST/DAST) на базе **GitHub Actions + Self-Hosted Runner**. Решает проблему спама тикетами за счет быстрой локальной дедупликации. Полностью соответствует требованиям ФСТЭК по безопасности и изоляции данных.

## 🎯 РЕШЕНИЕ ПРОБЛЕМЫ СПАМА В JIRA

**Проблема:** Инструменты фаззинга (AFL++) находят сотни сырых крашей. Создание тикета на каждый краш парализует работу команды разработки.

**Наше решение (Secure Local Deduplication):**
1. **Fuzzing:** AFL++ находит N сырых крашей (например, 4).
2. **Local Dedup:** Мгновенная группировка по криптографическому хэшу (MD5) и размеру файла.
3. **Результат:** N сырых крашей → **1 уникальный баг** → **1 тикет в Jira**.

> 🔒 **Безопасность превыше всего:** В отличие от AI-решений, наша базовая дедупликация работает **локально на самописном раннере**. Данные о крашах (артефакты) **никогда не покидают периметр компании**, что критически важно для compliance (ФСТЭК, GDPR). *(Скрипты для опционального AI-анализа через Ollama доступны в папке scripts/ для закрытых контуров).*

---

## 🏗️ Архитектура для ФСТЭК

### КОНТУР 1: White Box Fuzzing (SAST + DAST)
* **Инструмент:** libFuzzer + AddressSanitizer (ASan)
* **Требования:** Наличие исходного кода.
* **Результат:** Точный stack trace, классификация CWE/CVSS, мгновенное обнаружение ошибок работы с памятью.

### КОНТУР 2: Black Box Fuzzing (DAST) 🚀 *(Основной фокус)*
* **Инструмент:** AFL++ в режиме эмуляции QEMU (-Q).
* **Инфраструктура:** **GitHub Self-Hosted Runner** + **Docker** (aflplusplus/aflplusplus:latest).
* **Преимущества:** 
  - Фаззинг скомпилированных бинарников **без исходного кода**.
  - Мгновенный старт (0 минут на сборку AFL++ благодаря кэшированному Docker-образу).
  - Изолированное выполнение на выделенном железе компании.

---

## ⚙️ Автоматизация (Production Pipeline)

При каждом push в main или вручную (workflow_dispatch) запускается пайплайн, который:
1. 🚀 Разворачивает окружение в Docker-контейнере на Self-Hosted Runner (время старта: ~10 сек).
2. 🛠️ Компилирует target без защит (-fno-stack-protector -z execstack -no-pie) для имитации уязвимой production-среды.
3. ️ Запускает AFL++ QEMU fuzzing (например, на 180 секунд).
4. 🧹 **Автоматически дедуплицирует** найденные краши (MD5 + Size).
5. 📦 Сохраняет уникальные краши и JSON-отчет в **Artifacts** (хранение 30 дней).
6. 🔔 *(Опционально)* Создает тикеты в Jira, отправляет отчет в DefectDojo и шлет Email (при настройке GitHub Secrets).

---

## ✅ Соответствие требованиям ФСТЭК

| Требование | Реализация в проекте |
| :--- | :--- |
| **DAST (Black Box)** | AFL++ в QEMU mode фаззит готовый бинарник без исходников. |
| **SAST (White Box)** | libFuzzer + AddressSanitizer для анализа кода. |
| **Регулярность** | Автоматический запуск через GitHub Actions (CI/CD). |
| **Документирование** | Логи пайплайна + сохранение артефактов (краш-файлов) на 30 дней. |
| **Изоляция данных** | **Self-Hosted Runner**. Данные не уходят в публичные облачные раннеры или внешние AI API. |
| **Управление уязвимостями** | Готовые скрипты интеграции с DefectDojo и Jira. |

---

## 🚀 Локальный запуск (для тестирования)

# 1. Перейти в директорию Black Box target
cd blackbox-target

# 2. Скомпилировать уязвимый бинарник (имитация production)
gcc -O0 -fno-stack-protector -z execstack -no-pie -o target vulnerable.c
strip target

# 3. Создать начальный корпус (seed)
mkdir -p corpus
echo "test" > corpus/seed1.txt
echo "AAAA" > corpus/seed2.txt

# 4. Запустить AFL++ вручную (например, на 60 секунд)
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
timeout 60s afl-fuzz -i corpus -o afl_out -Q -- ./target @@

---

##  Структура проекта

.
├── .github/workflows/
│   ├── 01-whitebox-fuzzing.yml   # White Box (libFuzzer + ASan)
│   └── 02-blackbox-aflpp.yml     # Black Box (AFL++ QEMU + Docker + Local Dedup) 
├── blackbox-target/
│   ├── vulnerable.c              # Исходный код для компиляции
│   ├── corpus/                   # Seed-файлы для фаззинга
│   ├── afl_out/                  # Результаты работы AFL++ (игнорируется в git)
│   └── unique_crashes/           # Уникальные краши после дедупликации
├── scripts/
│   ├── create_jira_tickets.py    # (Опц.) Скрипт для создания тикетов
│   ├── upload_defectdojo.py      # (Опц.) Скрипт для загрузки в DefectDojo
│   └── send_email_notification.py# (Опц.) Скрипт для email-уведомлений
└── README.md

---

## 📊 Реальные результаты (из последнего запуска)

* **Время выполнения пайплайна:** ~3 минуты 30 секунд (включая скачивание Docker-образа).
* **Найдено сырых крашей:** 4
* **Уникальных крашей (после дедупликации):** 1-2 (в зависимости от мутаций).
* **Создано тикетов:** 1 (вместо 4).
* **Статус:** ✅ Pipeline passed, Artifacts uploaded.

---

## ️ Технологии

* **AFL++** (Advanced Fuzzing) с поддержкой **QEMU mode** для Black Box тестирования.
* **Docker** (aflplusplus/aflplusplus:latest) для мгновенного и предсказуемого развертывания.
* **GitHub Actions + Self-Hosted Runner** для безопасного, быстрого и неограниченного по времени выполнения.
* **Bash/Python** для надежной локальной дедупликации (MD5 + File Size).
* *(Опционально)* Интеграция с **Jira**, **DefectDojo**, **SMTP**.

---

## 🔐 Настройка интеграций (GitHub Secrets)

Для включения автоматического создания тикетов и отчетов, добавьте следующие переменные в Settings -> Secrets -> Actions вашего репозитория:

JIRA_URL=https://your-company.atlassian.net
JIRA_TOKEN=your_personal_access_token
JIRA_PROJECT=SEC

DD_URL=https://defectdojo.your-company.com
DD_API_KEY=your_defectdojo_api_key

EMAIL_RECIPIENTS=security-team@your-company.com

*Если секреты не настроены, пайплайн успешно завершится, сохранив артефакты, но пропустит шаги интеграции (Safe Fallback).*

---

##  Контакты и Лицензия

* **Лицензия:** MIT
* **Автор/Контакты:** troutist76@gmail.com
