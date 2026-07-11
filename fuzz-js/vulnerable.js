// Уязвимость 1: Prototype Pollution
function merge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            target[key] = source[key];
        } else if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Уязвимость 2: SQL Injection (симуляция)
function queryUser(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return query;
}

// Уязвимость 3: ReDoS
function validateEmail(email) {
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
}

// Уязвимость 4: Path Traversal (симуляция)
function readFile(filename) {
    if (filename.includes('..')) {
        throw new Error('Path traversal detected: ' + filename);
    }
    return 'Reading: ' + filename;
}

// Уязвимость 5: XSS (симуляция)
function renderHTML(input) {
    return '<div>' + input + '</div>';
}

module.exports = { merge, queryUser, validateEmail, readFile, renderHTML };
