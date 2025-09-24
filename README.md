# Laravel Node Encryption

[![npm version](https://badge.fury.io/js/laravel-node-encryption.svg)](https://badge.fury.io/js/laravel-node-encryption)
[![Tests](https://github.com/Rene-Roscher/laravel-node-encryption/actions/workflows/test.yml/badge.svg)](https://github.com/Rene-Roscher/laravel-node-encryption/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Laravel-compatible encryption/decryption for Node.js. Fully compatible with Laravel's built-in encryption.

## Features

- ✅ 100% Laravel compatible (8.x - 11.x)
- ✅ Zero configuration (auto-detects `APP_KEY`)
- ✅ AES-256-CBC encryption with HMAC-SHA256
- ✅ No dependencies (optional `php-serialize` for complex objects)

## Installation

```bash
npm install laravel-node-encryption
```

## Quick Start

```javascript
const { LaravelEncrypter } = require('laravel-node-encryption');

// Automatically uses process.env.APP_KEY
const encrypter = new LaravelEncrypter();

// Encrypt data
const encrypted = encrypter.encrypt('Hello Laravel!');

// Decrypt data from Laravel
const decrypted = encrypter.decrypt(laravelEncryptedString);
```

## API

### `new LaravelEncrypter(key?, cipher?)`

- `key` - Encryption key (defaults to `process.env.APP_KEY`)
- `cipher` - Cipher method (default: `'aes-256-cbc'`)

### Methods

- `encrypt(value)` - Encrypts any value
- `decrypt(payload)` - Decrypts Laravel-encrypted payload
- `encryptString(value)` - Encrypts string without serialization
- `decryptString(payload)` - Decrypts string without deserialization

## Laravel Integration

### PHP (Laravel)
```php
use Illuminate\Support\Facades\Crypt;

// Encrypt
$encrypted = Crypt::encrypt('Hello from Laravel!');

// Decrypt from Node.js
$decrypted = Crypt::decrypt($fromNodeJs);
```

### Node.js
```javascript
const { LaravelEncrypter } = require('laravel-node-encryption');
const encrypter = new LaravelEncrypter();

// Decrypt from Laravel
const decrypted = encrypter.decrypt(fromLaravel);

// Encrypt for Laravel
const encrypted = encrypter.encrypt('Hello from Node.js!');
```

## Environment Setup

Set your Laravel APP_KEY in environment:

```bash
APP_KEY='base64:your-app-key-here' node app.js
```

Or in `.env`:
```
APP_KEY=base64:your-app-key-here
```

## Advanced Usage

### With explicit key
```javascript
const encrypter = new LaravelEncrypter('base64:your-key-here');
```

### Express.js middleware
```javascript
app.post('/decrypt', (req, res) => {
    try {
        const decrypted = encrypter.decrypt(req.body.encrypted);
        res.json({ data: decrypted });
    } catch (error) {
        res.status(400).json({ error: 'Invalid encrypted data' });
    }
});
```

## Compatibility

| Laravel | Node.js | Status |
|---------|---------|--------|
| 11.x    | 18+     | ✅     |
| 10.x    | 16+     | ✅     |
| 9.x     | 14+     | ✅     |
| 8.x     | 14+     | ✅     |

## License

MIT © René Roscher
