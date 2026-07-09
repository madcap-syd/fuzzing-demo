#include <cstdint>
#include <cstddef>
#include <cstring>

// Уязвимая функция для демонстрации fuzzing
void vulnerable_function(const uint8_t *data, size_t size) {
    if (size >= 4) {
        // Уязвимость: buffer overflow при определённых входных данных
        if (data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
            // Trigger crash - null pointer dereference
            volatile int *ptr = nullptr;
            *ptr = 42;  // SEGV!
        }
        
        // Ещё одна уязвимость: buffer overflow
        if (size > 8) {
            uint32_t length = *(const uint32_t*)data;
            if (length > 1024 && length < size) {
                char buffer[256];
                memcpy(buffer, data + 4, length);  // Heap buffer overflow!
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    vulnerable_function(data, size);
    return 0;
}
