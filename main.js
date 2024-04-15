const crypto = require('crypto');

function hashPassword(password) {
    const hash = crypto.createHash('sha256');
    hash.update(password);
    return hash.digest('hex');
}

const Password = 'parol';
const hashedPassword = hashPassword(Password);
console.log('Пароль:', Password);
console.log('Хеш пароля:', hashedPassword);