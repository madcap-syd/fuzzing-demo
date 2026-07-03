#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

// Объявляем функции из packet_parser.cpp
struct Packet {
    uint32_t magic;
    uint16_t version;
    uint16_t length;
    uint8_t data[256];
};

extern bool parsePacket(const uint8_t* input, size_t size, Packet& packet);
extern bool processPacket(Packet& packet);

// HonggFuzz persistent mode
extern "C" void HF_ITER(const uint8_t** buf, size_t* len);

int main() {
    for (;;) {
        const uint8_t* data;
        size_t size;
        
        // Получаем input от honggfuzz
        HF_ITER(&data, &size);
        
        // Выполняем fuzzing
        Packet packet;
        memset(&packet, 0, sizeof(packet));
        
        if (size >= 8) {
            if (parsePacket(data, size, packet)) {
                processPacket(packet);
            }
        }
    }
    return 0;
}
