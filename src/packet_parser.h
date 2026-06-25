#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <vector>

// Структура заголовка пакета
struct PacketHeader {
    uint32_t magic;        // Магическое число: 0xDEADBEEF
    uint16_t version;      // Версия протокола
    uint16_t flags;        // Флаги
    uint32_t payload_size; // Размер payload
};

// Структура пакета
struct Packet {
    PacketHeader header;
    std::vector<uint8_t> payload;
};

// Результат парсинга
enum class ParseResult {
    OK,
    INVALID_MAGIC,
    INVALID_VERSION,
    PAYLOAD_TOO_LARGE,
    PARSE_ERROR
};

// Функция парсинга пакета
ParseResult parse_packet(const uint8_t* data, size_t size, Packet& out_packet);

// Функция обработки пакета
std::string process_packet(const Packet& packet);

#endif // PACKET_PARSER_H
