#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Уязвимость 1: Heap Buffer Overflow (CWE-122)
void heap_overflow(const uint8_t* data, size_t size) {
    char* buffer = new char[16];
    if (data[0] == 'A' && size > 16) {
        memcpy(buffer, data, size);  // ПЕРЕПОЛНЕНИЕ!
    }
    delete[] buffer;
}

// Уязвимость 2: Null Pointer Dereference (CWE-476)
void null_deref(const uint8_t* data, size_t size) {
    if (data[0] == 'B' && size > 4) {
        int* ptr = nullptr;
        volatile int x = ptr[0];  // SEGFAULT!
    }
}

// Уязвимость 3: Use-After-Free (CWE-416)
void use_after_free(const uint8_t* data, size_t size) {
    if (data[0] == 'C' && size > 4) {
        int* ptr = new int(42);
        delete ptr;
        volatile int x = *ptr;  // UAF!
    }
}

// Уязвимость 4: Stack Buffer Overflow (CWE-121)
void stack_overflow(const uint8_t* data, size_t size) {
    if (data[0] == 'D' && size > 32) {
        char buffer[16];
        strcpy(buffer, (const char*)data);  // ПЕРЕПОЛНЕНИЕ СТЕКА!
    }
}

// Уязвимость 5: Integer Overflow (CWE-190)
void int_overflow(const uint8_t* data, size_t size) {
    if (size >= 8) {
        uint32_t w = *(uint32_t*)data;
        uint32_t h = *(uint32_t*)(data + 4);
        if (w > 0 && h > 0) {
            size_t total = w * h;  // МОЖЕТ ПЕРЕПОЛНИТЬСЯ!
            if (total < 1000) {
                char* buf = new char[total];
                buf[0] = 'X';
                delete[] buf;
            }
        }
    }
}

// Harness для LibFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    
    switch (data[0]) {
        case 'A': heap_overflow(data, size); break;
        case 'B': null_deref(data, size); break;
        case 'C': use_after_free(data, size); break;
        case 'D': stack_overflow(data, size); break;
        default: int_overflow(data, size); break;
    }
    return 0;
}
