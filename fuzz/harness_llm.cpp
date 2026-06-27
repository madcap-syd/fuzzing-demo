#include <cstdint>
#include <cstddef>
#include <string>
#include "packet_parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    Packet packet;
    ParseResult parse_result = parse_packet(Data, Size, packet);

    if (parse_result == ParseResult::OK) {
        std::string processed_data = process_packet(packet);
        // Process the processed data as needed
    }

    return 0;
}