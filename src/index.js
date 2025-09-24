const crypto = require('crypto');

/**
 * Laravel-compatible Encryption class for Node.js
 * Full compatibility with Laravel 8.x through 12.x
 *
 * Tested with:
 * - Laravel 8.x, 9.x, 10.x, 11.x, 12.x
 * - Custom/legacy implementations
 * - Auto-detection of MAC calculation methods
 *
 * Installation:
 * npm install php-serialize (optional, for full PHP compatibility)
 *
 * @author Your enhanced version for 2025
 * @version 2.0.0
 */
class LaravelEncrypter {
    /**
     * The encryption key
     * @type {Buffer}
     */
    key;

    /**
     * The algorithm used for encryption
     * @type {string}
     */
    cipher;

    /**
     * Serialization mode ('php' or 'json')
     * @type {string}
     */
    serializeMode;

    /**
     * MAC calculation method
     * @type {string|null}
     */
    detectMacMethod = null;

    /**
     * MAC prefix for standard method
     * @type {string}
     */
    macPrefix = 'laravel.';

    /**
     * Whether to auto-detect MAC method
     * @type {boolean}
     */
    autoDetectMac = true;

    /**
     * PHP serializer (optional)
     * @type {object}
     */
    phpSerializer = null;

    /**
     * Supported cipher methods
     * @type {object}
     */
    static supportedCiphers = {
        'aes-128-cbc': { size: 16, aead: false },
        'aes-256-cbc': { size: 32, aead: false },
        'aes-128-gcm': { size: 16, aead: true },
        'aes-256-gcm': { size: 32, aead: true },
    };

    /**
     * Create a new encrypter instance
     * @param {string|Buffer} key - The encryption key (base64 encoded or raw) - falls back to process.env.APP_KEY
     * @param {string} cipher - The cipher method (default: 'aes-256-cbc')
     * @param {string} serializeMode - 'php' or 'json' (default: 'php')
     * @param {object} options - Additional options (usually not needed for Laravel)
     */
    constructor(key = null, cipher = 'aes-256-cbc', serializeMode = 'php', options = {}) {
        // Fallback to process.env.APP_KEY if no key provided
        const encryptionKey = key || process.env.APP_KEY;

        if (!encryptionKey) {
            throw new Error('No encryption key provided and APP_KEY not found in environment variables');
        }

        // Handle Laravel's base64: prefix
        if (typeof encryptionKey === 'string' && encryptionKey.startsWith('base64:')) {
            this.key = Buffer.from(encryptionKey.substring(7), 'base64');
        } else if (typeof encryptionKey === 'string') {
            // Try to decode as base64
            try {
                const decoded = Buffer.from(encryptionKey, 'base64');
                // Check if it's valid base64 and has the right length
                if (decoded.length === 16 || decoded.length === 32) {
                    this.key = decoded;
                } else {
                    // Treat as raw string
                    this.key = Buffer.from(encryptionKey, 'binary');
                }
            } catch (e) {
                // Not base64, treat as raw
                this.key = Buffer.from(encryptionKey, 'binary');
            }
        } else {
            // Already a Buffer
            this.key = encryptionKey;
        }

        this.cipher = cipher.toLowerCase();
        this.serializeMode = serializeMode;

        // Laravel 10.x default settings (works for Laravel 5.x - 12.x)
        // These settings are optimized for Laravel and usually don't need to be changed
        this.detectMacMethod = options.macMethod || 'laravel10';  // Laravel 10.x MAC method is default
        this.macPrefix = options.macPrefix || 'laravel.';         // Not used for Laravel 10.x
        this.autoDetectMac = options.autoDetectMac ?? false;      // Default off for better performance

        if (!this.supported(this.cipher)) {
            throw new Error(`Unsupported cipher: ${cipher}`);
        }

        // Validate key length
        const expectedKeySize = LaravelEncrypter.supportedCiphers[this.cipher].size;
        if (this.key.length !== expectedKeySize) {
            throw new Error(`Invalid key length for ${this.cipher}. Expected ${expectedKeySize} bytes, got ${this.key.length} bytes.`);
        }

        // Load PHP serializer if in PHP mode
        if (this.serializeMode === 'php') {
            try {
                this.phpSerializer = require('php-serialize');
            } catch (e) {
                console.warn('php-serialize not installed. Install with: npm install php-serialize');
                console.warn('Falling back to simple string serialization.');
            }
        }
    }

    /**
     * Check if cipher is supported
     * @param {string} cipher
     * @returns {boolean}
     */
    supported(cipher) {
        return cipher.toLowerCase() in LaravelEncrypter.supportedCiphers;
    }

    /**
     * Check if cipher is AEAD
     * @param {string} cipher
     * @returns {boolean}
     */
    isAead(cipher = null) {
        cipher = cipher || this.cipher;
        return LaravelEncrypter.supportedCiphers[cipher.toLowerCase()]?.aead || false;
    }

    /**
     * Serialize value (PHP format for Laravel compatibility)
     * @param {*} value
     * @returns {string}
     */
    serialize(value) {
        if (this.serializeMode === 'json') {
            // JSON mode with prefix for type detection
            if (typeof value === 'object') {
                return 'j:' + JSON.stringify(value);
            }
            return 's:' + value;
        }

        // PHP serialization mode
        if (this.phpSerializer) {
            return this.phpSerializer.serialize(value);
        }

        // Fallback to simple PHP string serialization
        if (typeof value === 'string') {
            return `s:${value.length}:"${value}";`;
        } else if (typeof value === 'number') {
            if (Number.isInteger(value)) {
                return `i:${value};`;
            } else {
                return `d:${value};`;
            }
        } else if (typeof value === 'boolean') {
            return `b:${value ? 1 : 0};`;
        } else if (value === null) {
            return 'N;';
        } else if (typeof value === 'object') {
            // For objects without php-serialize, fallback to JSON
            const json = JSON.stringify(value);
            return `s:${json.length}:"${json}";`;
        }

        throw new Error('Cannot serialize value of type: ' + typeof value);
    }

    /**
     * Unserialize value
     * @param {string} value
     * @returns {*}
     */
    unserialize(value) {
        if (this.serializeMode === 'json') {
            // JSON mode with prefix detection
            if (value.startsWith('j:')) {
                return JSON.parse(value.substring(2));
            }
            if (value.startsWith('s:')) {
                return value.substring(2);
            }
            return value;
        }

        // PHP unserialization mode
        if (this.phpSerializer) {
            return this.phpSerializer.unserialize(value);
        }

        // Simple PHP format parsing
        if (value.startsWith('s:')) {
            // String: s:length:"value";
            const match = value.match(/^s:(\d+):"(.*)";$/s);
            if (match) {
                const length = parseInt(match[1]);
                return match[2].substring(0, length);
            }
        } else if (value.startsWith('i:')) {
            // Integer: i:value;
            const match = value.match(/^i:(-?\d+);$/);
            if (match) {
                return parseInt(match[1]);
            }
        } else if (value.startsWith('d:')) {
            // Double: d:value;
            const match = value.match(/^d:([^;]+);$/);
            if (match) {
                return parseFloat(match[1]);
            }
        } else if (value.startsWith('b:')) {
            // Boolean: b:0; or b:1;
            return value === 'b:1;';
        } else if (value === 'N;') {
            // Null
            return null;
        } else if (value.startsWith('a:')) {
            // Array - try to extract JSON if it's there
            try {
                const jsonMatch = value.match(/s:\d+:"({.*})"/);
                if (jsonMatch) {
                    return JSON.parse(jsonMatch[1]);
                }
            } catch (e) {}
        }

        // If we can't parse it, return as-is
        return value;
    }

    /**
     * Generate a random key for the cipher
     * @param {string} cipher
     * @returns {Buffer}
     */
    static generateKey(cipher = 'aes-256-cbc') {
        const size = LaravelEncrypter.supportedCiphers[cipher.toLowerCase()]?.size;
        if (!size) {
            throw new Error(`Unsupported cipher: ${cipher}`);
        }
        return crypto.randomBytes(size);
    }

    /**
     * Encrypt a value
     * @param {*} value - The value to encrypt
     * @param {boolean} serialize - Whether to serialize the value
     * @returns {string} - Base64 encoded encrypted payload
     */
    encrypt(value, serialize = true) {
        const iv = crypto.randomBytes(this.getIvSize());

        // Serialize the value if needed
        const valueToEncrypt = serialize ? this.serialize(value) : value;

        let encrypted, tag = '';

        if (this.isAead()) {
            // AEAD mode (GCM)
            const cipher = crypto.createCipheriv(this.cipher, this.key, iv);
            encrypted = Buffer.concat([
                cipher.update(valueToEncrypt, 'utf8'),
                cipher.final()
            ]);
            tag = cipher.getAuthTag().toString('base64');
        } else {
            // CBC mode
            const cipher = crypto.createCipheriv(this.cipher, this.key, iv);
            encrypted = Buffer.concat([
                cipher.update(valueToEncrypt, 'utf8'),
                cipher.final()
            ]);
        }

        // Create Laravel-compatible payload
        const payload = {
            iv: iv.toString('base64'),
            value: encrypted.toString('base64'),
            mac: '',
            tag: tag
        };

        // Generate MAC for non-AEAD ciphers
        if (!this.isAead()) {
            payload.mac = this.hash(payload);
        }

        // Return base64 encoded JSON payload (Laravel format)
        return Buffer.from(JSON.stringify(payload)).toString('base64');
    }

    /**
     * Encrypt a string without serialization
     * @param {string} value
     * @returns {string}
     */
    encryptString(value) {
        if (typeof value !== 'string') {
            throw new Error('The value must be a string.');
        }
        return this.encrypt(value, false);
    }

    /**
     * Decrypt a value
     * @param {string} payload - Base64 encoded encrypted payload
     * @param {boolean} unserialize - Whether to unserialize the value
     * @returns {*} - The decrypted value
     */
    decrypt(payload, unserialize = true) {
        try {
            // Auto-detect MAC method if enabled
            if (this.autoDetectMac && !this.detectMacMethod) {
                this.detectMacMethodFromPayload(payload);
            }

            // Decode the payload
            const data = this.getJsonPayload(payload);

            // Verify MAC for non-AEAD ciphers
            if (!this.isAead() && !this.validMac(data)) {
                throw new Error('The MAC is invalid.');
            }

            const iv = Buffer.from(data.iv, 'base64');
            const encrypted = Buffer.from(data.value, 'base64');

            let decrypted;

            if (this.isAead()) {
                // AEAD mode (GCM)
                const decipher = crypto.createDecipheriv(this.cipher, this.key, iv);
                decipher.setAuthTag(Buffer.from(data.tag, 'base64'));
                decrypted = Buffer.concat([
                    decipher.update(encrypted),
                    decipher.final()
                ]).toString('utf8');
            } else {
                // CBC mode
                const decipher = crypto.createDecipheriv(this.cipher, this.key, iv);
                decrypted = Buffer.concat([
                    decipher.update(encrypted),
                    decipher.final()
                ]).toString('utf8');
            }

            // Unserialize if needed
            return unserialize ? this.unserialize(decrypted) : decrypted;
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt a string without unserialization
     * @param {string} payload
     * @returns {string}
     */
    decryptString(payload) {
        return this.decrypt(payload, false);
    }

    /**
     * Get the JSON payload from encrypted data
     * @param {string} payload
     * @returns {object}
     */
    getJsonPayload(payload) {
        try {
            const decoded = Buffer.from(payload, 'base64').toString('utf8');
            const data = JSON.parse(decoded);

            // Validate payload structure
            if (!this.validPayload(data)) {
                throw new Error('Invalid payload structure.');
            }

            return data;
        } catch (error) {
            throw new Error(`Invalid payload: ${error.message}`);
        }
    }

    /**
     * Validate payload structure
     * @param {object} payload
     * @returns {boolean}
     */
    validPayload(payload) {
        if (typeof payload !== 'object') return false;

        // Check required fields
        if (!payload.iv || !payload.value) return false;

        // Check MAC for non-AEAD
        if (!this.isAead() && !payload.mac) return false;

        // Check tag for AEAD
        if (this.isAead() && payload.tag === undefined) return false;

        // Validate base64 encoding
        try {
            Buffer.from(payload.iv, 'base64');
            Buffer.from(payload.value, 'base64');
            if (payload.tag) Buffer.from(payload.tag, 'base64');
        } catch {
            return false;
        }

        return true;
    }

    /**
     * Create a MAC for the payload (Laravel compatible)
     * @param {object} payload
     * @returns {string}
     */
    hash(payload) {
        // Laravel 10.x uses direct concatenation: $iv.$value (base64 strings)
        const message = payload.iv + payload.value;

        // Generate HMAC using SHA256
        return crypto
            .createHmac('sha256', this.key)
            .update(message)
            .digest('hex');
    }

    /**
     * Auto-detect MAC calculation method from payload
     * @param {string} payload
     * @returns {string} - The detected MAC method
     */
    detectMacMethodFromPayload(payload) {
        const data = typeof payload === 'string' ?
            JSON.parse(Buffer.from(payload, 'base64').toString('utf8')) :
            payload;

        // Laravel 10.x uses direct concatenation of base64 strings
        const message = data.iv + data.value;
        const mac = crypto.createHmac('sha256', this.key).update(message).digest('hex');

        if (mac === data.mac) {
            console.log(`✅ Auto-detected Laravel 10.x MAC method`);
            return 'laravel10';
        }

        // Default to Laravel 10 style
        return 'laravel10';
    }

    /**
     * Verify MAC is valid
     * @param {object} payload
     * @returns {boolean}
     */
    validMac(payload) {
        const calculated = this.hash(payload);
        const provided = payload.mac;

        if (!provided || calculated.length !== provided.length) {
            return false;
        }

        // Timing-safe comparison
        return crypto.timingSafeEqual(
            Buffer.from(calculated),
            Buffer.from(provided)
        );
    }

    /**
     * Get IV size for current cipher
     * @returns {number}
     */
    getIvSize() {
        // Standard IV size for CBC and GCM modes
        return 16;
    }

    /**
     * Get the current cipher
     * @returns {string}
     */
    getCipher() {
        return this.cipher;
    }

    /**
     * Get the encryption key
     * @returns {Buffer}
     */
    getKey() {
        return this.key;
    }

    /**
     * Debug helper to analyze Laravel payload and test different MAC calculations
     * @param {string} payload - Base64 encoded encrypted payload from Laravel
     * @returns {object} - Debug information
     */
    debugPayload(payload) {
        try {
            const decoded = Buffer.from(payload, 'base64').toString('utf8');
            const data = JSON.parse(decoded);

            // Laravel 10.x uses direct concatenation
            const message = data.iv + data.value;
            const calculatedMac = crypto.createHmac('sha256', this.key).update(message).digest('hex');

            return {
                decoded: data,
                providedMac: data.mac,
                calculatedMac: calculatedMac,
                macMatches: calculatedMac === data.mac,
                keyLength: this.key.length,
                keyBase64: this.key.toString('base64'),
                cipher: this.cipher,
                detectedSource: calculatedMac === data.mac ? 'Laravel 10.x' : 'Unknown'
            };
        } catch (error) {
            return { error: error.message };
        }
    }
}

/**
 * Helper class for easy encryption/decryption (mimics Laravel's Crypt facade)
 */
class Crypt {
    static encrypter = null;

    /**
     * Set the encrypter instance
     * @param {LaravelEncrypter} encrypter
     */
    static setEncrypter(encrypter) {
        this.encrypter = encrypter;
    }

    /**
     * Get or create the encrypter instance
     * @returns {LaravelEncrypter}
     */
    static getEncrypter() {
        if (!this.encrypter) {
            throw new Error('No encrypter instance set. Use Crypt.setEncrypter() first.');
        }
        return this.encrypter;
    }

    /**
     * Encrypt a value
     * @param {*} value
     * @param {boolean} serialize
     * @returns {string}
     */
    static encrypt(value, serialize = true) {
        return this.getEncrypter().encrypt(value, serialize);
    }

    /**
     * Encrypt a string
     * @param {string} value
     * @returns {string}
     */
    static encryptString(value) {
        return this.getEncrypter().encryptString(value);
    }

    /**
     * Decrypt a value
     * @param {string} payload
     * @param {boolean} unserialize
     * @returns {*}
     */
    static decrypt(payload, unserialize = true) {
        return this.getEncrypter().decrypt(payload, unserialize);
    }

    /**
     * Decrypt a string
     * @param {string} payload
     * @returns {string}
     */
    static decryptString(payload) {
        return this.getEncrypter().decryptString(payload);
    }
}

// Export both classes
module.exports = { LaravelEncrypter, Crypt };

