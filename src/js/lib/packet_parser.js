/**
 * @fileoverview Парсер бинарных пакетов для Node.js
 * @note Соответствует требованиям ФСТЕК № 239
 */

'use strict';

class PacketParser {
    static MAGIC = 0xDEADBEEF;
    static MAX_VERSION = 2;
    static MAX_PAYLOAD_SIZE = 65535;
    static HEADER_SIZE = 16;

    static parse(buffer) {
        if (!Buffer.isBuffer(buffer)) {
            throw new TypeError('Input must be a Buffer (ФСТЕК-1.3)');
        }

        if (buffer.length < this.HEADER_SIZE) {
            throw new RangeError(`Buffer too small: ${buffer.length} < ${this.HEADER_SIZE} (ФСТЕК-1.3)`);
        }

        const magic = buffer.readUInt32LE(0);
        const version = buffer.readUInt16LE(4);
        const flags = buffer.readUInt16LE(6);
        const payloadSize = buffer.readUInt32LE(8);
        const checksum = buffer.readUInt32LE(12);

        if (magic !== this.MAGIC) {
            throw new Error(`Invalid magic: 0x${magic.toString(16)} (ФСТЕК-1.1)`);
        }

        if (version > this.MAX_VERSION) {
            throw new Error(`Invalid version: ${version} (ФСТЕК-1.1)`);
        }

        if (payloadSize > this.MAX_PAYLOAD_SIZE) {
            throw new RangeError(`Payload too large: ${payloadSize} (ФСТЕК-1.3)`);
        }

        const availableData = buffer.length - this.HEADER_SIZE;
        if (payloadSize > availableData) {
            throw new RangeError(`Payload exceeds buffer: ${payloadSize} > ${availableData} (ФСТЕК-1.3)`);
        }

        const payload = buffer.slice(this.HEADER_SIZE, this.HEADER_SIZE + payloadSize);

        const expectedChecksum = this.calculateChecksum(payload);
        if (checksum !== expectedChecksum) {
            throw new Error(`Invalid checksum (ФСТЕК-1.1)`);
        }

        return {
            magic,
            version,
            flags,
            payloadSize,
            payload,
            checksum,
            isValid: true
        };
    }

    static process(packet) {
        console.log(`[AUDIT] Processing packet v${packet.version}, ${packet.payloadSize} bytes`);

        let result = '';

        try {
            const payloadStr = packet.payload.toString('utf8');

            // УЯЗВИМОСТЬ #1: Prototype Pollution
            if (payloadStr.startsWith('{')) {
                try {
                    const parsed = JSON.parse(payloadStr);

                    if (typeof parsed === 'object' && parsed !== null) {
                        for (const key in parsed) {
                            // НЕТ ПРОВЕРКИ на __proto__, constructor, prototype!
                            global[key] = parsed[key];
                        }
                    }

                    result = `JSON processed: ${Object.keys(parsed).length} keys`;
                } catch (e) {
                    result = 'Invalid JSON payload';
                }
            } else {
                // УЯЗВИМОСТЬ #2: ReDoS
                const vulnerableRegex = /^(a+)+$/;
                if (vulnerableRegex.test(payloadStr)) {
                    result = `String matched: ${payloadStr.length} chars`;
                } else {
                    result = `Plain text: ${payloadStr.substring(0, 50)}`;
                }
            }
        } catch (error) {
            result = `Error: ${error.message}`;
        }

        console.log(`[AUDIT] Processing complete`);
        return result;
    }

    /**
     * Вычисляет контрольную сумму (ИСПРАВЛЕНО для unsigned 32-bit)
     * @param {Buffer} data - Данные
     * @returns {number} Контрольная сумма (unsigned 32-bit)
     */
    static calculateChecksum(data) {
        let sum = 0;
        for (let i = 0; i < data.length; i++) {
            sum += data[i];
            // >>> 0 преобразует в unsigned 32-bit
            sum = ((sum << 3) | (sum >>> 29)) >>> 0;
        }
        return sum;
    }
}

module.exports = PacketParser;
