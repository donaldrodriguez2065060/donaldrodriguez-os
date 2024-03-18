// crypticUtils.js

const crypto = require('crypto');
const randomstring = require('randomstring');

// Function to generate a random string of specified length
function generateRandomString(length) {
    return randomstring.generate(length);
}

// Function to generate a random hexadecimal string of specified byte length
function generateRandomHex(lengthInBytes) {
    return crypto.randomBytes(lengthInBytes).toString('hex');
}

// Function to hash a string using SHA-256 algorithm
function sha256Hash(input) {
    const hash = crypto.createHash('sha256');
    hash.update(input);
    return hash.digest('hex');
}

// Function to encrypt a string using AES-256-CBC algorithm
function aes256Encrypt(text, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Function to decrypt a string using AES-256-CBC algorithm
function aes256Decrypt(encryptedText, key, iv) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = {
    generateRandomString,
    generateRandomHex,
    sha256Hash,
    aes256Encrypt,
    aes256Decrypt
};
