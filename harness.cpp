#include <cstdint>
#include <cstddef>

// Уязвимая функция для демонстрации fuzzing
void vulnerable_function(const uint8_t *data, size_t size) {
    if (size >= 4) {
        // Уязвимость: null pointer dereference
        if (data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
            volatile int *ptr = nullptr;
            *ptr = 42;  // SEGV!
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    vulnerable_function(data, size);
    return 0;
}
