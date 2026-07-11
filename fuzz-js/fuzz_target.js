const { merge, queryUser, validateEmail, readFile, renderHTML } = require('./vulnerable');

module.exports.fuzz = function(data) {
    const input = data.toString('utf8');
    
    try {
        // Prototype Pollution
        if (input.includes(':')) {
            const parts = input.split(':');
            if (parts.length === 2) {
                const target = {};
                const source = JSON.parse(`{"${parts[0]}": "${parts[1]}"}`);
                merge(target, source);
            }
        }
        
        // SQL Injection
        if (input.length > 0 && input.length < 100) {
            queryUser(input);
        }
        
        // ReDoS
        if (input.includes('@')) {
            validateEmail(input);
        }
        
        // Path Traversal
        readFile(input);
        
        // XSS
        renderHTML(input);
        
    } catch (e) {
        // Игнорируем
    }
};
