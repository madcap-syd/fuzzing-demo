#include "../src/packet_parser.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    Packet packet;
    
    // Парсим пакет
    ParseResult result = parse_packet(Data, Size, packet);
    
    // Если парсинг успешен, обрабатываем
    if (result == ParseResult::OK) {
        std::string processed = process_packet(packet);
        // Используем результат, чтобы компилятор не оптимизировал
        (void)processed.size();
    }
    
    return 0;
}
