# Donaldrodriguez-os

A Node.js module containing cryptographic utility functions.

## Installation
 
You can install this module via npm: `npm install donaldrodriguez-os`

## Usage

```javascript
const crypticUtils = require('cryptic-utils');

// Generate a random string
const randomString = crypticUtils.generateRandomString(10);
console.log('Random String:', randomString);

// Generate a random hexadecimal string
const randomHex = crypticUtils.generateRandomHex(16);
console.log('Random Hex:', randomHex);

// Hash a string using SHA-256
const hashedString = crypticUtils.sha256Hash('hello world');
console.log('SHA-256 Hash:', hashedString);

// Encrypt using AES-256-CBC
const key = '0123456789abcdef0123456789abcdef';
const iv = 'abcdef0123456789';
const encryptedText = crypticUtils.aes256Encrypt('hello world', key, iv);
console.log('AES-256-CBC Encrypted:', encryptedText);

// Decrypt using AES-256-CBC
const decryptedText = crypticUtils.aes256Decrypt(encryptedText, key, iv);
console.log('AES-256-CBC Decrypted:', decryptedText);
```