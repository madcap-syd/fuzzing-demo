#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Уязвимость 1: Buffer Overflow
void process_data(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // ← Нет проверки длины!
    printf("Processed: %s\n", buffer);
}

// Уязвимость 2: Null Pointer Dereference
void check_data(char *data) {
    if (strlen(data) > 4) {
        if (data[0] == 'C' && data[1] == 'R' && 
            data[2] == 'A' && data[3] == 'S' && data[4] == 'H') {
            volatile int *ptr = NULL;
            *ptr = 42;  // ← Null pointer dereference!
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *data = malloc(size + 1);
    fread(data, 1, size, f);
    data[size] = '\0';
    fclose(f);
    
    process_data(data);
    check_data(data);
    
    free(data);
    return 0;
}
