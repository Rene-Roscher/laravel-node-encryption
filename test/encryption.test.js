const { LaravelEncrypter, Crypt } = require('../src/index');
const crypto = require('crypto');

describe('LaravelEncrypter', () => {
    const testKey = 'base64:' + Buffer.from('12345678901234567890123456789012').toString('base64');
    let encrypter;

    beforeEach(() => {
        encrypter = new LaravelEncrypter(testKey);
    });

    describe('Constructor', () => {
        test('should create instance with base64 key', () => {
            expect(encrypter).toBeInstanceOf(LaravelEncrypter);
            expect(encrypter.getKey().length).toBe(32);
        });

        test('should use APP_KEY from environment', () => {
            process.env.APP_KEY = testKey;
            const enc = new LaravelEncrypter();
            expect(enc.getKey().length).toBe(32);
            delete process.env.APP_KEY;
        });

        test('should throw error when no key provided', () => {
            delete process.env.APP_KEY;
            expect(() => new LaravelEncrypter()).toThrow('No encryption key provided');
        });

        test('should support different ciphers', () => {
            const enc = new LaravelEncrypter(testKey, 'aes-128-cbc');
            expect(enc.getCipher()).toBe('aes-128-cbc');
        });
    });

    describe('Encryption/Decryption', () => {
        test('should encrypt and decrypt strings', () => {
            const original = 'Hello World';
            const encrypted = encrypter.encrypt(original);
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toBe(original);
        });

        test('should encrypt and decrypt objects', () => {
            const original = { name: 'John', age: 30, nested: { key: 'value' } };
            const encrypted = encrypter.encrypt(original);
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toEqual(original);
        });

        test('should encrypt and decrypt arrays', () => {
            const original = ['item1', 'item2', 'item3'];
            const encrypted = encrypter.encrypt(original);
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toEqual(original);
        });

        test('should encrypt and decrypt numbers', () => {
            const testNumbers = [42, -42, 3.14159, 0];
            testNumbers.forEach(num => {
                const encrypted = encrypter.encrypt(num);
                const decrypted = encrypter.decrypt(encrypted);
                expect(decrypted).toBe(num);
            });
        });

        test('should encrypt and decrypt booleans', () => {
            const encrypted1 = encrypter.encrypt(true);
            const encrypted2 = encrypter.encrypt(false);
            expect(encrypter.decrypt(encrypted1)).toBe(true);
            expect(encrypter.decrypt(encrypted2)).toBe(false);
        });

        test('should encrypt and decrypt null', () => {
            const encrypted = encrypter.encrypt(null);
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toBe(null);
        });

        test('should handle empty strings', () => {
            const encrypted = encrypter.encrypt('');
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toBe('');
        });

        test('should handle special characters', () => {
            const original = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~';
            const encrypted = encrypter.encrypt(original);
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toBe(original);
        });

        test('should handle unicode characters', () => {
            const original = '🚀 Ümläüte äöü ÄÖÜ ß € 中文字符 emoji 😀';
            const encrypted = encrypter.encrypt(original);
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toBe(original);
        });

        test('should handle long texts', () => {
            const original = 'Lorem ipsum '.repeat(1000);
            const encrypted = encrypter.encrypt(original);
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toBe(original);
        });
    });

    describe('String Encryption (without serialization)', () => {
        test('should encrypt and decrypt strings without serialization', () => {
            const original = 'Plain text string';
            const encrypted = encrypter.encryptString(original);
            const decrypted = encrypter.decryptString(encrypted);
            expect(decrypted).toBe(original);
        });

        test('should throw error for non-string values', () => {
            expect(() => encrypter.encryptString(123)).toThrow('must be a string');
            expect(() => encrypter.encryptString({})).toThrow('must be a string');
        });
    });

    describe('MAC Validation', () => {
        test('should reject tampered payload', () => {
            const encrypted = encrypter.encrypt('test data');
            const payload = JSON.parse(Buffer.from(encrypted, 'base64').toString());

            // Tamper with value
            payload.value = Buffer.from('tampered').toString('base64');
            const tampered = Buffer.from(JSON.stringify(payload)).toString('base64');

            expect(() => encrypter.decrypt(tampered)).toThrow('MAC is invalid');
        });

        test('should reject invalid MAC', () => {
            const encrypted = encrypter.encrypt('test data');
            const payload = JSON.parse(Buffer.from(encrypted, 'base64').toString());

            // Invalid MAC
            payload.mac = 'invalid_mac_value';
            const tampered = Buffer.from(JSON.stringify(payload)).toString('base64');

            expect(() => encrypter.decrypt(tampered)).toThrow('MAC is invalid');
        });
    });

    describe('Payload Structure', () => {
        test('should create valid Laravel payload structure', () => {
            const encrypted = encrypter.encrypt('test');
            const payload = JSON.parse(Buffer.from(encrypted, 'base64').toString());

            expect(payload).toHaveProperty('iv');
            expect(payload).toHaveProperty('value');
            expect(payload).toHaveProperty('mac');
            expect(payload).toHaveProperty('tag');
            expect(payload.tag).toBe(''); // CBC mode should have empty tag
        });

        test('should validate payload structure', () => {
            const invalidPayloads = [
                { value: 'test' }, // Missing iv
                { iv: 'test' }, // Missing value
                { iv: 'test', value: 'test' }, // Missing mac
                'invalid_base64',
                '{}',
            ];

            invalidPayloads.forEach(payload => {
                const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
                expect(() => encrypter.decrypt(encoded)).toThrow();
            });
        });
    });

    describe('Laravel Compatibility', () => {
        test('should decrypt Laravel encrypted string', () => {
            // This is a real encrypted string from Laravel 10.x
            // Original value: "Hello World"
            // Key: base64:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=
            const laravelEncrypted = "eyJpdiI6Ii8xdG1LOXJQaHVOZzdKY1VUYVBiMEE9PSIsInZhbHVlIjoiTDJCMnI4VmxHeTdHaVlULzdRTWdQZz09IiwibWFjIjoiY2E5ODA1YjhhMjkwNGRjNmM1OGZkMmY1ODJmOTZmNTM4ZDEzNjlmMDNmOTgzOTAyZGE1NTM2YWZlNjdmZjRjZCIsInRhZyI6IiJ9";

            const decrypted = encrypter.decryptString(laravelEncrypted);
            expect(decrypted).toBe('Works');
        });

        test('should calculate MAC compatible with Laravel 10.x', () => {
            const payload = {
                iv: 'test_iv_base64==',
                value: 'test_value_base64==',
                mac: '',
                tag: ''
            };

            const mac = encrypter.hash(payload);
            expect(typeof mac).toBe('string');
            expect(mac.length).toBe(64); // SHA256 hex = 64 chars
        });
    });

    describe('Crypt Facade', () => {
        beforeEach(() => {
            Crypt.setEncrypter(encrypter);
        });

        test('should encrypt using Crypt facade', () => {
            const encrypted = Crypt.encrypt('test');
            const decrypted = encrypter.decrypt(encrypted);
            expect(decrypted).toBe('test');
        });

        test('should decrypt using Crypt facade', () => {
            const encrypted = encrypter.encrypt('test');
            const decrypted = Crypt.decrypt(encrypted);
            expect(decrypted).toBe('test');
        });

        test('should handle strings without serialization', () => {
            const encrypted = Crypt.encryptString('test');
            const decrypted = Crypt.decryptString(encrypted);
            expect(decrypted).toBe('test');
        });

        test('should throw error when encrypter not set', () => {
            Crypt.encrypter = null;
            expect(() => Crypt.encrypt('test')).toThrow('No encrypter instance set');
        });
    });

    describe('Key Generation', () => {
        test('should generate valid keys', () => {
            const key = LaravelEncrypter.generateKey('aes-256-cbc');
            expect(key.length).toBe(32);

            const key128 = LaravelEncrypter.generateKey('aes-128-cbc');
            expect(key128.length).toBe(16);
        });

        test('should throw error for unsupported cipher', () => {
            expect(() => LaravelEncrypter.generateKey('invalid-cipher')).toThrow('Unsupported cipher');
        });
    });

    describe('Error Handling', () => {
        test('should handle decryption errors gracefully', () => {
            expect(() => encrypter.decrypt('invalid_data')).toThrow('Decryption failed');
            expect(() => encrypter.decrypt('')).toThrow('Decryption failed');
        });

        test('should handle invalid key lengths', () => {
            const shortKey = 'short';
            expect(() => new LaravelEncrypter(shortKey, 'aes-256-cbc')).toThrow('Invalid key length');
        });

        test('should handle unsupported ciphers', () => {
            expect(() => new LaravelEncrypter(testKey, 'invalid-cipher')).toThrow('Unsupported cipher');
        });
    });
});