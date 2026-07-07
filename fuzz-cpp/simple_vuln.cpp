#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Уязвимость 1: Heap Buffer Overflow
void heap_overflow(const uint8_t* data, size_t size) {
    char buffer[64];
    if (size > 0) {
        memcpy(buffer, data, size);  // ❌ Нет проверки size!
        printf("Processed: %s\n", buffer);
    }
}

// Уязвимость 2: Stack Buffer Overflow
void stack_overflow(const char* input) {
    char buffer[32];
    strcpy(buffer, input);  // ❌ Нет ограничения!
}

// Уязвимость 3: Integer Overflow
void int_overflow(size_t width, size_t height) {
    size_t size = width * height;  // ❌ Может переполниться!
    char* buffer = new char[size];
    buffer[0] = 'A';
    delete[] buffer;
}

// Уязвимость 4: Use-After-Free
void use_after_free() {
    int* ptr = new int(42);
    delete ptr;
    printf("%d\n", *ptr);  // ❌ UAF!
}

// Уязвимость 5: Null Pointer Dereference
void null_deref(int* data) {
    if (data[0] > 0) {
        printf("%d\n", data[0]);  // ❌ data может быть nullptr
    }
}

// Harness для LibFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8) return 0;
    
    // Пробуем разные уязвимости
    heap_overflow(data, size);
    
    if (size >= 4) {
        uint32_t value = *(uint32_t*)data;
        if (value > 1000) {
            stack_overflow((const char*)data);
        }
    }
    
    if (size >= 8) {
        size_t w = *(size_t*)data;
        size_t h = *(size_t*)(data + 4);
        int_overflow(w, h);
    }
    
    if (size >= 16 && data[0] == 'A') {
        use_after_free();
    }
    
    if (size >= 16 && data[0] == 'B') {
        null_deref(nullptr);
    }
    
    return 0;
}
