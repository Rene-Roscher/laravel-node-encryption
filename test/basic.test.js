const { LaravelEncrypter } = require('../src/index');

describe('LaravelEncrypter Basic Tests', () => {
    test('should create instance with key', () => {
        const key = 'base64:' + Buffer.from('12345678901234567890123456789012').toString('base64');
        const encrypter = new LaravelEncrypter(key);
        expect(encrypter).toBeInstanceOf(LaravelEncrypter);
    });

    test('should encrypt and decrypt string', () => {
        const key = 'base64:' + Buffer.from('12345678901234567890123456789012').toString('base64');
        const encrypter = new LaravelEncrypter(key);

        const original = 'Hello World';
        const encrypted = encrypter.encrypt(original);
        const decrypted = encrypter.decrypt(encrypted);

        expect(decrypted).toBe(original);
    });
});
