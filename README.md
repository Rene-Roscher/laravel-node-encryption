# Laravel Node Encryption

[![npm version](https://badge.fury.io/js/laravel-node-encryption.svg)](https://badge.fury.io/js/laravel-node-encryption)
[![CI](https://github.com/Rene-Roscher/laravel-node-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/Rene-Roscher/laravel-node-encryption/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**🔐 Bidirectional encryption between Laravel (PHP) and Node.js**

Share encrypted data seamlessly between your Laravel backend and Node.js services. Encrypt in Laravel, decrypt in Node.js - or vice versa!

## Why This Package?

Perfect for microservices, APIs, and hybrid applications where you need to:
- 🔄 **Share encrypted data** between Laravel and Node.js applications
- 🔒 **Encrypt in Laravel**, decrypt in Node.js (and vice versa!)
- 🚀 **Build microservices** that share encrypted tokens, sessions, or sensitive data
- 🛡️ **Maintain security** across different technology stacks

## Features

- ✅ **Fully bidirectional** - Encrypt/decrypt in both directions
- ✅ **100% Laravel compatible** (8.x - 12.x)
- ✅ **Zero configuration** - Auto-detects `APP_KEY`
- ✅ **Production ready** - Battle-tested AES-256-CBC with HMAC-SHA256
- ✅ **No dependencies** - Lightweight with optional `php-serialize`

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

## Bidirectional Encryption Examples

### 🔄 Laravel → Node.js
```php
// Laravel: Encrypt data
use Illuminate\Support\Facades\Crypt;

$userData = ['id' => 1, 'email' => 'user@example.com'];
$encrypted = Crypt::encrypt($userData);

// Send $encrypted to Node.js service...
```

```javascript
// Node.js: Decrypt data from Laravel
const { LaravelEncrypter } = require('laravel-node-encryption');
const encrypter = new LaravelEncrypter();

const userData = encrypter.decrypt(encryptedFromLaravel);
console.log(userData); // { id: 1, email: 'user@example.com' }
```

### 🔄 Node.js → Laravel
```javascript
// Node.js: Encrypt data
const encrypter = new LaravelEncrypter();
const token = { userId: 1, expires: '2024-12-31' };
const encrypted = encrypter.encrypt(token);

// Send encrypted to Laravel...
```

```php
// Laravel: Decrypt data from Node.js
use Illuminate\Support\Facades\Crypt;

$token = Crypt::decrypt($encryptedFromNode);
// $token = ['userId' => 1, 'expires' => '2024-12-31']
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

## Real-World Use Cases

### 🔐 Secure API Tokens
Share authentication tokens between Laravel API and Node.js microservices:
```javascript
// Node.js: Create encrypted token
const token = encrypter.encrypt({ userId: 123, scope: 'api' });
// Laravel can decrypt and validate this token
```

### 🍪 Cross-Platform Sessions
Share session data between Laravel web app and Node.js real-time service:
```php
// Laravel: Encrypt session
$sessionData = Crypt::encrypt(session()->all());
// Node.js WebSocket server can decrypt and use session
```

### 📧 Queue Messages
Encrypt sensitive job payloads between Laravel and Node.js workers:
```javascript
// Node.js: Encrypt job payload
const job = encrypter.encrypt({ email: 'user@example.com', action: 'welcome' });
// Laravel queue worker decrypts and processes
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

| Laravel | Node.js | PHP    | Status |
|---------|---------|--------|--------|
| 12.x    | 18+     | 8.3+   | ✅     |
| 11.x    | 18+     | 8.2+   | ✅     |
| 10.x    | 16+     | 8.1+   | ✅     |
| 9.x     | 14+     | 8.0+   | ✅     |
| 8.x     | 14+     | 7.3+   | ✅     |

## License

MIT © René Roscher
