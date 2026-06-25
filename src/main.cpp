#include "packet_parser.h"
#include <iostream>
#include <fstream>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }
    
    // Читаем файл
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << argv[1] << std::endl;
        return 1;
    }
    
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
    
    // Парсим пакет
    Packet packet;
    ParseResult result = parse_packet(data.data(), data.size(), packet);
    
    if (result != ParseResult::OK) {
        std::cerr << "Parse error: " << static_cast<int>(result) << std::endl;
        return 1;
    }
    
    // Обрабатываем
    std::string processed = process_packet(packet);
    std::cout << "Processed " << processed.size() << " bytes" << std::endl;
    
    return 0;
}
