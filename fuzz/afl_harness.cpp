#include "../src/packet_parser.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    // Читаем файл
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);
    
    // Парсим пакет
    Packet packet;
    ParseResult result = parse_packet(data.data(), data.size(), packet);
    
    if (result == ParseResult::OK) {
        std::string processed = process_packet(packet);
        (void)processed.size();
    }
    
    return 0;
}
