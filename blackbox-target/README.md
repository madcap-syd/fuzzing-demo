# BLACK BOX FUZZING WITH AFL++

## Что это?

Демонстрация Black Box fuzzing с использованием AFL++ в режиме QEMU.

## Отличие от White Box

| Критерий | White Box (libFuzzer) | Black Box (AFL++ QEMU) |
|----------|----------------------|----------------------|
| Исходный код | Нужен | Не нужен |
| Instrumentation | Compile-time | Runtime (QEMU) |
| Coverage feedback | Да | Да (через QEMU) |
| Скорость | Быстро | Медленнее (эмуляция) |
| Точность | Высокая | Высокая |

## Уязвимости в target

1. Buffer Overflow (CWE-120): strcpy без проверки длины
2. Null Pointer Dereference (CWE-476): запись по NULL

## Соответствие ФСТЭК

Требования:
- Динамическое тестирование (DAST)
- Фаззинг-тестирование
- Поиск уязвимостей без исходников

AFL++ соответствует:
- Production-grade инструмент
- Используется в Google, Microsoft
- Нашёл 1000+ уязвимостей в реальном ПО
- Поддерживает Black Box режим
