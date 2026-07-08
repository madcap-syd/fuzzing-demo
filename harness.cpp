#include <cstdint>
#include <cstddef>
#include <cstring>

// Безопасная функция для демо (не крашится)
void safe_function(const uint8_t *data, size_t size) {
    if (size >= 4) {
        // Просто проверяем данные без краша
        if (data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
            // Нормальная обработка, без краша
            volatile int x = 42;
            (void)x;
        }
    }
}

// Точка входа для libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    safe_function(data, size);
    return 0;
}
