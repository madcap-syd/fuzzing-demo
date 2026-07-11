#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_input(const char *input, size_t len) {
    char buffer[64];
    
    if (len > 0) {
        memcpy(buffer, input, len);  // Buffer overflow если len > 64
        buffer[len] = '\0';
        printf("Processed: %s\n", buffer);
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
    
    char *data = malloc(size);
    fread(data, 1, size, f);
    fclose(f);
    
    process_input(data, size);
    
    free(data);
    return 0;
}
