#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstdio>

// 1. Heap Buffer Overflow (CWE-122)
void heap_overflow_demo() {
    printf("\n=== 1. Heap Buffer Overflow ===\n");
    char* buffer = new char[64];
    memset(buffer, 'A', 100);
    delete[] buffer;
}

// 2. Stack Buffer Overflow (CWE-121)
void stack_overflow_demo(const char* input) {
    printf("\n=== 2. Stack Buffer Overflow ===\n");
    char buffer[64];
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

// 3. Use-After-Free (CWE-416)
void uaf_demo() {
    printf("\n=== 3. Use-After-Free ===\n");
    int* ptr = new int(42);
    delete ptr;
    printf("Value after free: %d\n", *ptr);
}

// 4. Integer Overflow (CWE-190)
void integer_overflow_demo(uint32_t a, uint32_t b) {
    printf("\n=== 4. Integer Overflow ===\n");
    size_t result = a * b;
    printf("%u * %u = %zu\n", a, b, result);
}

// 5. Null Pointer Dereference (CWE-476)
void null_deref_demo() {
    printf("\n=== 5. Null Pointer Dereference ===\n");
    int* ptr = nullptr;
    *ptr = 42;
}

int main(int argc, char** argv) {
    printf(" Vulnerability Demo\n");
    if (argc < 2) {
        printf("Usage: %s <1|2|3|4|5>\n", argv[0]);
        return 1;
    }
    int choice = atoi(argv[1]);
    switch(choice) {
        case 1: heap_overflow_demo(); break;
        case 2: stack_overflow_demo(argv[2]); break;
        case 3: uaf_demo(); break;
        case 4: integer_overflow_demo(65536, 65536); break;
        case 5: null_deref_demo(); break;
        default: printf("Invalid choice\n");
    }
    return 0;
}
