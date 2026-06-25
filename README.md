# Fuzzing Demo - Тестовое приложение для демонстрации CI/CD фаззинга

## Описание
Парсер кастомного бинарного протокола с намеренными уязвимостями для демонстрации возможностей фаззинга.

## Структура
- `src/` - исходный код парсера
- `fuzz/` - harness'ы для фаззинга
- `.gitlab-ci.yml` - CI/CD конфигурация

## Уязвимости
1. Нет проверки размера перед чтением заголовка
2. Нет проверки payload_size на разумность
3. Нет проверки границ при копировании payload
4. Обработка payload без валидации
5. Не проверяем размер payload перед обработкой

## Сборка

    mkdir build && cd build
    cmake ..
    make

## Запуск

    ./packet_app test_packet.bin

## Фаззинг

### libFuzzer (быстрый тест)

    clang++ -fsanitize=fuzzer,address,undefined -O1 -g -std=c++17 \
        fuzz/harness.cpp src/packet_parser.cpp -o fuzz_libfuzzer
    ./fuzz_libfuzzer corpus/ -max_total_time=120

### AFL++ (глубокий анализ)

    afl-clang-fast++ -O1 -g -std=c++17 \
        fuzz/afl_harness.cpp src/packet_parser.cpp -o fuzz_afl
    afl-fuzz -i corpus/ -o afl_findings/ -t 1000 -- ./fuzz_afl @@
