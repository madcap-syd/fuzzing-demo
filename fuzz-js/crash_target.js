// Фазз таргет БЕЗ try/catch — чтобы Jazzer видел краши
const { merge, queryUser, validateEmail, readFile, renderHTML } = require('./vulnerable');

module.exports.fuzz = function(data) {
    const input = data.toString('utf8');
    
    // Prototype Pollution — выбрасываем ошибку если обнаружен
    if (input.includes('__proto__')) {
        const target = {};
        const source = JSON.parse(`{"${input}": "polluted"}`);
        merge(target, source);
        // Проверяем pollution
        if (target.polluted === 'polluted') {
            throw new Error('Prototype Pollution detected!');
        }
    }
    
    // Path Traversal — выбрасываем ошибку
    if (input.includes('../')) {
        readFile(input);  // Должен выбросить ошибку
    }
    
    // ReDoS — если слишком долго, Jazzer сам детектит timeout
    if (input.includes('@') && input.length > 50) {
        validateEmail(input);
    }
};
