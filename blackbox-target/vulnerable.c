#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(char *input) {
    // Гарантированный краш при определённом паттерне
    if (strlen(input) > 4) {
        if (input[0] == 'C' && input[1] == 'R' && 
            input[2] == 'A' && input[3] == 'S' && input[4] == 'H') {
            // Null pointer dereference - ТОЧНО крашит!
            volatile int *ptr = NULL;
            *ptr = 42;
        }
    }
    
    // Buffer overflow - может крашить
    char buffer[64];
    strcpy(buffer, input);
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *data = malloc(size + 1);
    fread(data, 1, size, f);
    data[size] = '\0';
    fclose(f);
    
    vulnerable_function(data);
    free(data);
    return 0;
}
