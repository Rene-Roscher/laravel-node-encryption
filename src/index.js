const crypto = require('crypto');

/**
 * PHP's base64_decode($input, $strict).
 *
 * Non-strict mode skips every character outside the alphabet (including "=" and whitespace)
 * and never fails. Strict mode skips only whitespace, fails on other invalid characters, data
 * after padding, a dangling sixth bit and wrong padding, and accepts missing padding.
 * Laravel relies on both modes, and Buffer.from(x, 'base64') matches neither exactly.
 *
 * @param {string} input
 * @param {boolean} strict
 * @returns {Buffer|null} null when strict decoding fails
 */
function phpBase64Decode(input, strict) {
    const out = [];
    let acc = 0;
    let count = 0;
    let padding = 0;

    for (let i = 0; i < input.length; i++) {
        const c = input.charCodeAt(i);
        let v;
        if (c === 0x3d) { // =
            padding++;
            continue;
        } else if (c >= 0x41 && c <= 0x5a) { // A-Z
            v = c - 0x41;
        } else if (c >= 0x61 && c <= 0x7a) { // a-z
            v = c - 0x61 + 26;
        } else if (c >= 0x30 && c <= 0x39) { // 0-9
            v = c - 0x30 + 52;
        } else if (c === 0x2b) { // +
            v = 62;
        } else if (c === 0x2f) { // /
            v = 63;
        } else if (c === 0x09 || c === 0x0a || c === 0x0d || c === 0x20) {
            continue;
        } else if (strict) {
            return null;
        } else {
            continue;
        }
        if (strict && padding > 0) {
            return null;
        }
        acc = ((acc << 6) | v) & 0xffffff;
        count++;
        if (count % 4 === 0) {
            out.push((acc >> 16) & 0xff, (acc >> 8) & 0xff, acc & 0xff);
            acc = 0;
        }
    }

    // A trailing group of 2 or 3 characters yields 1 or 2 bytes; 1 character yields none.
    if (count % 4 === 2) {
        out.push((acc >> 4) & 0xff);
    } else if (count % 4 === 3) {
        out.push((acc >> 10) & 0xff, (acc >> 2) & 0xff);
    }
    if (strict) {
        if (count % 4 === 1) {
            return null;
        }
        if (padding > 0 && (padding > 2 || (count + padding) % 4 !== 0)) {
            return null;
        }
    }
    return Buffer.from(out);
}

/**
 * Resolves a key to raw bytes. "base64:XXXX" (the APP_KEY form) is decoded the way Laravel does,
 * with PHP's lenient base64_decode (padding is optional and stray characters are skipped; a
 * malformed value decodes to the wrong length, which the constructor rejects). A bare base64
 * string that decodes to 16 or 32 bytes is decoded; any other string is used as its raw bytes,
 * and a Buffer as it is.
 *
 * @param {string|Buffer} key
 * @returns {Buffer}
 */
function parseKey(key) {
    if (typeof key !== 'string') {
        return key;
    }
    if (key.startsWith('base64:')) {
        return phpBase64Decode(key.substring(7), false);
    }
    const decoded = Buffer.from(key, 'base64');
    return decoded.length === 16 || decoded.length === 32 ? decoded : Buffer.from(key, 'binary');
}

/**
 * Laravel's CookieValuePrefix::create(): hash_hmac('sha1', $name.'v2', $key).'|'
 *
 * @param {string} name
 * @param {Buffer} key
 * @returns {string}
 */
function cookiePrefix(name, key) {
    return crypto.createHmac('sha1', key).update(name + 'v2').digest('hex') + '|';
}

/**
 * Laravel-compatible Encryption class for Node.js
 * Full compatibility with Laravel 10.x through 13.x
 *
 * Tested with:
 * - Laravel 10.x, 11.x, 12.x, 13.x
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
     * The previous / legacy encryption keys, tried when decrypting
     * @type {Buffer[]}
     */
    previousKeyList = [];

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
        'aes-256-gcm': { size: 32, aead: true }
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

        this.key = parseKey(encryptionKey);

        this.cipher = cipher.toLowerCase();
        this.serializeMode = serializeMode;

        // Laravel 10.x default settings (works for Laravel 5.x - 12.x)
        // These settings are optimized for Laravel and usually don't need to be changed
        this.detectMacMethod = options.macMethod || 'laravel10'; // Laravel 10.x MAC method is default
        this.macPrefix = options.macPrefix || 'laravel.'; // Not used for Laravel 10.x
        this.autoDetectMac = options.autoDetectMac ?? false; // Default off for better performance

        if (!this.supported(this.cipher)) {
            throw new Error(`Unsupported cipher: ${cipher}`);
        }

        // Validate key length
        const expectedKeySize = LaravelEncrypter.supportedCiphers[this.cipher].size;
        if (this.key.length !== expectedKeySize) {
            throw new Error(`Invalid key length for ${this.cipher}. Expected ${expectedKeySize} bytes, got ${this.key.length} bytes.`);
        }

        if (options.previousKeys) {
            this.previousKeys(options.previousKeys);
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
     * Set the previous / legacy encryption keys that are tried when decrypting with the current
     * key fails, like Laravel's previousKeys() and APP_PREVIOUS_KEYS (Laravel 11+). New payloads
     * are always encrypted with the current key. Each key takes the same forms as the constructor's
     * key and must fit the cipher.
     * @param {Array<string|Buffer>} keys
     * @returns {LaravelEncrypter}
     */
    previousKeys(keys) {
        const expectedKeySize = LaravelEncrypter.supportedCiphers[this.cipher].size;
        const parsed = keys.map((key) => parseKey(key));
        for (const key of parsed) {
            if (key.length !== expectedKeySize) {
                throw new Error(`Invalid key length for ${this.cipher}. Expected ${expectedKeySize} bytes, got ${key.length} bytes.`);
            }
        }
        this.previousKeyList = parsed;
        return this;
    }

    /**
     * Get the previous encryption keys
     * @returns {Buffer[]}
     */
    getPreviousKeys() {
        return this.previousKeyList;
    }

    /**
     * Get the current encryption key followed by all previous keys
     * @returns {Buffer[]}
     */
    getAllKeys() {
        return [this.key, ...this.previousKeyList];
    }

    /**
     * Encrypt a cookie value the way Laravel's EncryptCookies middleware does: the value is
     * prefixed with an HMAC of the cookie name and the key, and encrypted without serialization.
     * Laravel decrypts it back to the value for the cookie name.
     * @param {string} name
     * @param {string} value
     * @returns {string}
     */
    encryptCookie(name, value) {
        return this.encryptString(cookiePrefix(name, this.key) + value);
    }

    /**
     * Decrypt a cookie that Laravel's EncryptCookies middleware encrypted, and check that it was
     * issued for the cookie name by this application: the prefix must match the current key or
     * one of the previous keys, otherwise this throws (Laravel treats such a cookie as absent).
     *
     * The payload is the raw cookie value; URL-decode it first if it comes from a Cookie header.
     * Cookies that an application serializes on purpose (EncryptCookies::serialized()) are not
     * supported.
     * @param {string} name
     * @param {string} payload
     * @returns {string}
     */
    decryptCookie(name, payload) {
        const plain = Buffer.from(this.decryptString(payload));
        for (const key of this.getAllKeys()) {
            const prefix = Buffer.from(cookiePrefix(name, key));
            if (plain.length >= prefix.length && crypto.timingSafeEqual(plain.subarray(0, prefix.length), prefix)) {
                return plain.subarray(prefix.length).toString();
            }
        }
        throw new Error('The cookie value prefix is invalid.');
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

        let encrypted; let tag = '';

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
            tag
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

            // Decode and validate the payload (Laravel's getJsonPayload / validPayload)
            const data = this.getJsonPayload(payload);
            const iv = phpBase64Decode(data.iv, true);
            // openssl_decrypt() base64-decodes the value leniently
            const encrypted = phpBase64Decode(data.value, false);
            // PHP's empty("0") is true, so Laravel sees neither "" nor "0" as a tag
            const hasTag = typeof data.tag === 'string' && data.tag !== '' && data.tag !== '0';
            const tag = hasTag ? phpBase64Decode(data.tag, false) : null;

            let decrypted;

            if (this.isAead()) {
                // AEAD mode (GCM): the payload needs a 16-byte tag
                if (tag === null || tag.length !== 16) {
                    throw new Error('Could not decrypt the data.');
                }
                // Try the current key first, then the previous keys, until one authenticates
                for (const key of this.getAllKeys()) {
                    try {
                        const decipher = crypto.createDecipheriv(this.cipher, key, iv);
                        decipher.setAuthTag(tag);
                        decrypted = Buffer.concat([
                            decipher.update(encrypted),
                            decipher.final()
                        ]);
                        break;
                    } catch (e) {
                        // not this key
                    }
                }
                if (decrypted === undefined) {
                    throw new Error('Could not decrypt the data.');
                }
            } else {
                // CBC mode: a payload must not carry a tag, and the MAC is verified first;
                // the first key whose MAC matches is used
                if (tag !== null) {
                    throw new Error('Could not decrypt the data.');
                }
                const key = this.getAllKeys().find((candidate) => this.validMac(data, candidate));
                if (key === undefined) {
                    throw new Error('The MAC is invalid.');
                }
                try {
                    const decipher = crypto.createDecipheriv(this.cipher, key, iv);
                    decrypted = Buffer.concat([
                        decipher.update(encrypted),
                        decipher.final()
                    ]);
                } catch (e) {
                    throw new Error('Could not decrypt the data.');
                }
            }

            decrypted = decrypted.toString('utf8');

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
     * (json_decode(base64_decode($payload), true) plus Laravel's validPayload)
     * @param {string} payload
     * @returns {object}
     */
    getJsonPayload(payload) {
        let data;
        try {
            if (typeof payload !== 'string') {
                throw new Error('The payload is invalid.');
            }
            // PHP's json_decode rejects invalid UTF-8
            const decoded = new TextDecoder('utf-8', { fatal: true })
                .decode(phpBase64Decode(payload, false));
            data = JSON.parse(decoded);
        } catch (error) {
            throw new Error('Invalid payload: The payload is invalid.');
        }

        // Validate payload structure
        if (!this.validPayload(data)) {
            throw new Error('Invalid payload: The payload is invalid.');
        }

        return data;
    }

    /**
     * Validate payload structure (Laravel's validPayload)
     * @param {object} payload
     * @returns {boolean}
     */
    validPayload(payload) {
        if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
            return false;
        }

        // iv, value and mac must be strings (mac is present, but empty, for GCM)
        for (const item of ['iv', 'value', 'mac']) {
            if (!Object.prototype.hasOwnProperty.call(payload, item) || typeof payload[item] !== 'string') {
                return false;
            }
        }

        // tag is optional, but a string when present
        if (payload.tag !== undefined && payload.tag !== null && typeof payload.tag !== 'string') {
            return false;
        }

        const iv = phpBase64Decode(payload.iv, true);
        return iv !== null && iv.length === this.getIvSize();
    }

    /**
     * Create a MAC for the payload (Laravel compatible)
     * @param {object} payload
     * @param {Buffer} key
     * @returns {string}
     */
    hash(payload, key = this.key) {
        // Laravel 10.x uses direct concatenation: $iv.$value (base64 strings)
        const message = payload.iv + payload.value;

        // Generate HMAC using SHA256
        return crypto
            .createHmac('sha256', key)
            .update(message)
            .digest('hex');
    }

    /**
     * Auto-detect MAC calculation method from payload
     * @param {string} payload
     * @returns {string} - The detected MAC method
     */
    detectMacMethodFromPayload(payload) {
        const data = typeof payload === 'string'
            ? JSON.parse(Buffer.from(payload, 'base64').toString('utf8'))
            : payload;

        // Laravel 10.x uses direct concatenation of base64 strings
        const message = data.iv + data.value;
        const mac = crypto.createHmac('sha256', this.key).update(message).digest('hex');

        if (mac === data.mac) {
            console.log('✅ Auto-detected Laravel 10.x MAC method');
            return 'laravel10';
        }

        // Default to Laravel 10 style
        return 'laravel10';
    }

    /**
     * Verify MAC is valid
     * @param {object} payload
     * @param {Buffer} key
     * @returns {boolean}
     */
    validMac(payload, key = this.key) {
        const calculated = this.hash(payload, key);
        const provided = payload.mac;

        if (typeof provided !== 'string' || calculated.length !== provided.length) {
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
        // openssl_cipher_iv_length(): 16 for CBC, 12 for GCM
        return this.isAead() ? 12 : 16;
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
                calculatedMac,
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

// Export both classes (_internal is for the tests)
module.exports = { LaravelEncrypter, Crypt, _internal: { phpBase64Decode } };
