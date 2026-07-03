#include <cstdint>
#include <cstring>
#include <stdexcept>

struct Packet {
    uint32_t magic;
    uint16_t version;
    uint16_t length;
    uint8_t data[256];
};

// Уязвимость 1: Buffer overflow
bool parsePacket(const uint8_t* input, size_t size, Packet& packet) {
    if (size < 8) return false;
    
    packet.magic = *(uint32_t*)(input);
    packet.version = *(uint16_t*)(input + 4);
    packet.length = *(uint16_t*)(input + 6);
    
    // BUG: Нет проверки packet.length перед копированием!
    memcpy(packet.data, input + 8, packet.length);  // Heap buffer overflow
    
    return true;
}

// Уязвимость 2: Integer overflow
bool processPacket(Packet& packet) {
    if (packet.magic != 0xDEADBEEF) return false;
    
    // BUG: Integer overflow при умножении
    size_t bufferSize = packet.length * 1024;
    uint8_t* buffer = new uint8_t[bufferSize];  // Может быть очень большим!
    
    // Используем buffer...
    memset(buffer, 0, bufferSize);
    delete[] buffer;
    
    return true;
}

// Harness для libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Packet packet;
    memset(&packet, 0, sizeof(packet));
    
    if (parsePacket(data, size, packet)) {
        processPacket(packet);
    }
    
    return 0;
}
