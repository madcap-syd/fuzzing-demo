#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_data(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Buffer overflow!
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
    
    process_data(data);
    free(data);
    return 0;
}
