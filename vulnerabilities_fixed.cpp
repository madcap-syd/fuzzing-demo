#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <climits>

// 1. Heap Buffer Overflow - ИСПРАВЛЕНО
void heap_overflow_demo_fixed() {
    printf("\n=== 1. Heap Buffer Overflow (FIXED) ===\n");
    char* buffer = new char[64];
    
    // ИСПРАВЛЕНИЕ: проверяем длину
    size_t max_len = 64;
    size_t write_len = 100;
    
    if (write_len > max_len) {
        printf("️  Попытка записать %zu байт в буфер %zu байт\n", write_len, max_len);
        write_len = max_len;
        printf("✅ Обрезаем до %zu байт\n", write_len);
    }
    
    memset(buffer, 'A', write_len);
    printf("✅ Записано безопасно\n");
    
    delete[] buffer;
}

// 2. Stack Buffer Overflow - ИСПРАВЛЕНО
void stack_overflow_demo_fixed(const char* input) {
    printf("\n=== 2. Stack Buffer Overflow (FIXED) ===\n");
    char buffer[64];
    
    // ИСПОЛЬЗУЕМ strncpy
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    printf("✅ Buffer: %.20s...\n", buffer);
}

// 3. Use-After-Free - ИСПРАВЛЕНО
void uaf_demo_fixed() {
    printf("\n=== 3. Use-After-Free (FIXED) ===\n");
    int* ptr = new int(42);
    printf("Значение: %d\n", *ptr);
    
    delete ptr;
    ptr = nullptr;  // ИСПРАВЛЕНИЕ: обнуляем!
    
    if (ptr != nullptr) {
        printf("Значение после free: %d\n", *ptr);
    } else {
        printf("✅ Указатель обнулён, использование предотвращено\n");
    }
}

// 4. Integer Overflow - ИСПРАВЛЕНО
void integer_overflow_demo_fixed(uint32_t a, uint32_t b) {
    printf("\n=== 4. Integer Overflow (FIXED) ===\n");
    
    // ИСПРАВЛЕНИЕ: проверяем overflow
    if (a != 0 && b > UINT32_MAX / a) {
        printf("️  Overflow: %u * %u > UINT32_MAX\n", a, b);
        printf("✅ Операция отменена\n");
        return;
    }
    
    uint32_t result = a * b;
    printf("✅ %u * %u = %u\n", a, b, result);
}

// 5. Null Pointer Dereference - ИСПРАВЛЕНО
void null_deref_demo_fixed() {
    printf("\n=== 5. Null Pointer Dereference (FIXED) ===\n");
    int* ptr = nullptr;
    
    // ИСПРАВЛЕНИЕ: проверяем
    if (ptr != nullptr) {
        *ptr = 42;
        printf("Значение: %d\n", *ptr);
    } else {
        printf("✅ Указатель null, операция пропущена\n");
    }
}

int main(int argc, char** argv) {
    printf("🛡️  Vulnerability Demo (FIXED)\n");
    if (argc < 2) {
        printf("Usage: %s <1|2|3|4|5>\n", argv[0]);
        return 1;
    }
    int choice = atoi(argv[1]);
    switch(choice) {
        case 1: heap_overflow_demo_fixed(); break;
        case 2: stack_overflow_demo_fixed(argv[2]); break;
        case 3: uaf_demo_fixed(); break;
        case 4: integer_overflow_demo_fixed(65536, 65536); break;
        case 5: null_deref_demo_fixed(); break;
        default: printf("Invalid choice\n");
    }
    return 0;
}
