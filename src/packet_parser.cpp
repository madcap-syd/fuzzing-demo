#include "packet_parser.h"
#include <cstring>
#include <stdexcept>

// УЯЗВИМОСТЬ #1: Нет проверки размера перед чтением заголовка
ParseResult parse_packet(const uint8_t* data, size_t size, Packet& out_packet) {
    if (size < sizeof(PacketHeader)) {
        return ParseResult::PARSE_ERROR;
    }
    
    // Читаем заголовок
    memcpy(&out_packet.header, data, sizeof(PacketHeader));
    
    // Проверка магического числа
    if (out_packet.header.magic != 0xDEADBEEF) {
        return ParseResult::INVALID_MAGIC;
    }
    
    // Проверка версии
    if (out_packet.header.version > 2) {
        return ParseResult::INVALID_VERSION;
    }
    
    // УЯЗВИМОСТЬ #2: Нет проверки payload_size на разумность
    uint32_t payload_size = out_packet.header.payload_size;
    
    // УЯЗВИМОСТЬ #3: Нет проверки, что payload_size <= size - sizeof(header)
    if (payload_size > 0) {
        out_packet.payload.resize(payload_size);
        // Копируем payload (может выйти за границы!)
        memcpy(out_packet.payload.data(), 
               data + sizeof(PacketHeader), 
               payload_size);
    }
    
    return ParseResult::OK;
}

// УЯЗВИМОСТЬ #4: Обработка payload без валидации
std::string process_packet(const Packet& packet) {
    std::string result;
    
    // УЯЗВИМОСТЬ #5: Не проверяем размер payload перед обработкой
    for (size_t i = 0; i < packet.payload.size(); i++) {
        // "Обработка" данных
        result += static_cast<char>(packet.payload[i] ^ 0x42);
    }
    
    return result;
}
