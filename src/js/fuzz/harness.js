/**
 * @fileoverview Fuzzing harness для Jazzer.js
 * @note Соответствует требованиям ФСТЕК № 239
 * 
 * Использует FuzzedDataProvider для генерации структурированных данных
 */

const { FuzzedDataProvider } = require('@jazzer.js/core');
const PacketParser = require('../lib/packet_parser');

/**
 * Главная функция фаззинга
 * @param {Buffer} data - Входные данные от фаззера
 */
exports.fuzz = function(data) {
    // Используем FuzzedDataProvider для структурированной генерации
    const provider = new FuzzedDataProvider(data);

    try {
        // Генерируем размер буфера (16-512 байт)
        const bufferSize = provider.consumeIntegralInRange(16, 512);
        const buffer = Buffer.alloc(bufferSize);

        // Заполняем буфер данными из провайдера
        for (let i = 0; i < bufferSize; i++) {
            buffer[i] = provider.consumeIntegralInRange(0, 255);
        }

        // ФСТЕК-1.1: Парсим пакет
        const packet = PacketParser.parse(buffer);

        // ФСТЕК-1.2: Обрабатываем пакет
        if (packet && packet.isValid) {
            PacketParser.process(packet);
        }

    } catch (error) {
        // Игнорируем ожидаемые ошибки валидации (ФСТЕК-1.3)
        if (error.message && error.message.includes('ФСТЕК')) {
            return;
        }
        // Пробрасываем неожиданные ошибки (фаззер их поймает)
        throw error;
    }
};
