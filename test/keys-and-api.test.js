const { LaravelEncrypter, Crypt, _internal } = require('../src/index');
const { ALL_CIPHERS, keySize, newEnc, unwrap } = require('./helpers');

const RAW32 = Buffer.alloc(32, 0x2b);

describe('keys', () => {
    const originalKey = process.env.APP_KEY;
    afterEach(() => {
        if (originalKey === undefined) delete process.env.APP_KEY;
        else process.env.APP_KEY = originalKey;
    });

    test('accepts the APP_KEY base64: form, a bare base64 key, a raw string and a Buffer', () => {
        const rawText = 'this-is-a-32-byte-raw-secret-key';
        const reference = new LaravelEncrypter(RAW32);
        const payload = reference.encryptString('x');

        for (const key of [`base64:${RAW32.toString('base64')}`, RAW32.toString('base64'), RAW32]) {
            expect(new LaravelEncrypter(key).decryptString(payload)).toBe('x');
        }
        const raw = new LaravelEncrypter(rawText);
        expect(raw.getKey().toString()).toBe(rawText);
        expect(new LaravelEncrypter('0123456789abcdef', 'aes-128-cbc').getKey().length).toBe(16);
        expect(new LaravelEncrypter(RAW32.subarray(0, 16).toString('base64'), 'aes-128-cbc').getKey().length).toBe(16);
    });

    test('falls back to process.env.APP_KEY', () => {
        process.env.APP_KEY = `base64:${RAW32.toString('base64')}`;
        const payload = new LaravelEncrypter(RAW32).encryptString('x');
        expect(new LaravelEncrypter().decryptString(payload)).toBe('x');
    });

    test('requires a key', () => {
        delete process.env.APP_KEY;
        expect(() => new LaravelEncrypter()).toThrow(/No encryption key provided/);
        expect(() => new LaravelEncrypter('')).toThrow(/No encryption key provided/);
    });

    test('rejects keys of the wrong size', () => {
        expect(() => new LaravelEncrypter(`base64:${Buffer.alloc(16).toString('base64')}`)).toThrow(/Invalid key length/);
        expect(() => new LaravelEncrypter('base64:!!!not base64!!!')).toThrow(/Invalid key length/);
        expect(() => new LaravelEncrypter('too short')).toThrow(/Invalid key length/);
    });

    test('cipher names are case-insensitive and unsupported ones are rejected', () => {
        expect(new LaravelEncrypter(RAW32, 'AES-256-CBC').getCipher()).toBe('aes-256-cbc');
        expect(new LaravelEncrypter(RAW32.subarray(0, 16), 'Aes-128-Gcm').getCipher()).toBe('aes-128-gcm');
        for (const bad of ['aes-192-cbc', 'aes-256-ecb', 'aes-256-ctr', 'des', '']) {
            expect(() => new LaravelEncrypter(RAW32, bad)).toThrow(/Unsupported cipher/);
        }
    });

    test('generateKey produces keys that fit the cipher', () => {
        for (const cipher of ALL_CIPHERS) {
            const a = LaravelEncrypter.generateKey(cipher);
            expect(a.length).toBe(keySize(cipher));
            expect(a.equals(LaravelEncrypter.generateKey(cipher))).toBe(false);
            const enc = new LaravelEncrypter(a, cipher);
            expect(enc.decryptString(enc.encryptString('x'))).toBe('x');
        }
        expect(() => LaravelEncrypter.generateKey('nope')).toThrow(/Unsupported cipher/);
    });

    test('supported() and isAead() describe the ciphers', () => {
        const enc = newEnc('aes-256-cbc');
        expect(ALL_CIPHERS.every((c) => enc.supported(c))).toBe(true);
        expect(enc.supported('AES-256-CBC')).toBe(true);
        expect(enc.supported('aes-512-cbc')).toBe(false);
        expect(ALL_CIPHERS.map((c) => enc.isAead(c))).toEqual([false, false, true, true]);
        expect(enc.isAead()).toBe(false);
        expect(newEnc('aes-256-gcm').isAead()).toBe(true);
        expect(enc.isAead('nope')).toBe(false);
    });

    test('getIvSize follows openssl_cipher_iv_length', () => {
        expect(ALL_CIPHERS.map((c) => newEnc(c).getIvSize())).toEqual([16, 16, 12, 12]);
    });
});

describe('encryptString', () => {
    test('only takes strings', () => {
        const enc = newEnc('aes-256-cbc');
        for (const bad of [1, null, undefined, {}, ['a'], true]) {
            expect(() => enc.encryptString(bad)).toThrow('The value must be a string.');
        }
    });
});

describe('Crypt facade', () => {
    afterEach(() => { Crypt.encrypter = null; });

    test('requires an encrypter', () => {
        expect(() => Crypt.encrypt('x')).toThrow(/No encrypter instance set/);
        expect(() => Crypt.getEncrypter()).toThrow(/No encrypter instance set/);
    });

    test('delegates to the encrypter', () => {
        const enc = newEnc('aes-256-gcm');
        Crypt.setEncrypter(enc);
        expect(Crypt.getEncrypter()).toBe(enc);

        expect(Crypt.decrypt(Crypt.encrypt({ a: [1, 2] }))).toEqual({ a: [1, 2] });
        expect(Crypt.decryptString(Crypt.encryptString('plain'))).toBe('plain');
        expect(Crypt.decrypt(Crypt.encrypt('plain', false), false)).toBe('plain');
        // interoperable with the instance itself
        expect(enc.decryptString(Crypt.encryptString('shared'))).toBe('shared');
    });
});

describe('MAC helpers', () => {
    const enc = newEnc('aes-256-cbc');

    test('detectMacMethodFromPayload recognises Laravel payloads', () => {
        const log = jest.spyOn(console, 'log').mockImplementation(() => {});
        expect(enc.detectMacMethodFromPayload(enc.encryptString('x'))).toBe('laravel10');
        expect(log).toHaveBeenCalledWith(expect.stringContaining('Auto-detected'));
        log.mockClear();
        const forged = Buffer.from(JSON.stringify({ ...unwrap(enc.encryptString('x')), mac: 'bad' })).toString('base64');
        expect(enc.detectMacMethodFromPayload(forged)).toBe('laravel10');
        expect(log).not.toHaveBeenCalled();
        log.mockRestore();
    });

    test('debugPayload explains a payload', () => {
        const info = enc.debugPayload(enc.encryptString('x'));
        expect(info).toMatchObject({ macMatches: true, keyLength: 32, cipher: 'aes-256-cbc', detectedSource: 'Laravel 10.x' });
        const bad = Buffer.from(JSON.stringify({ ...unwrap(enc.encryptString('x')), mac: 'bad' })).toString('base64');
        expect(enc.debugPayload(bad)).toMatchObject({ macMatches: false, detectedSource: 'Unknown' });
        expect(enc.debugPayload('garbage')).toHaveProperty('error');
    });

    test('autoDetectMac option runs detection while decrypting', () => {
        const log = jest.spyOn(console, 'log').mockImplementation(() => {});
        // The constructor always sets a MAC method, so clear it to reach the detection path.
        const auto = new LaravelEncrypter(RAW32, 'aes-256-cbc', 'php', { autoDetectMac: true });
        auto.detectMacMethod = null;
        expect(auto.decryptString(auto.encryptString('x'))).toBe('x');
        expect(log).toHaveBeenCalled();
        log.mockRestore();
    });

    test('validMac needs a string mac of the right length', () => {
        const p = unwrap(enc.encryptString('x'));
        expect(enc.validMac(p)).toBe(true);
        expect(enc.validMac({ ...p, mac: undefined })).toBe(false);
        expect(enc.validMac({ ...p, mac: 5 })).toBe(false);
        expect(enc.validMac({ ...p, mac: p.mac.slice(1) })).toBe(false);
    });
});

describe('hostile serialized data', () => {
    const enc = newEnc('aes-256-cbc');

    test('deep nesting is an ordinary error, not a crash', () => {
        const deep = 'a:1:{i:0;'.repeat(200000) + 'N;' + '}'.repeat(200000);
        expect(() => enc.decrypt(enc.encryptString(deep))).toThrow(/Decryption failed/);
    });

    test.each([
        'a:9223372036854775807:{}',
        'a:4000000000:{i:0;N;}',
        'S:1:"a";'
    ])('malformed %j is an ordinary error', (serialized) => {
        expect(() => enc.decrypt(enc.encryptString(serialized))).toThrow(/Decryption failed/);
    });
});

describe('serialize modes', () => {
    test('json mode round-trips (not PHP-compatible)', () => {
        const enc = new LaravelEncrypter(RAW32, 'aes-256-cbc', 'json');
        for (const v of [{ a: 1, b: [1, 2] }, [1, 'two'], 'text']) {
            expect(enc.decrypt(enc.encrypt(v))).toEqual(v);
        }
        expect(enc.decryptString(enc.encrypt({ a: 1 }))).toBe('j:{"a":1}');
        expect(enc.decryptString(enc.encrypt('text'))).toBe('s:text');
        expect(enc.unserialize('plain')).toBe('plain');
    });

    describe('without php-serialize', () => {
        let fallback;
        let warn;
        beforeAll(() => {
            warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
            jest.isolateModules(() => {
                jest.doMock('php-serialize', () => { throw new Error('missing'); });
                const mod = require('../src/index');
                fallback = new mod.LaravelEncrypter(RAW32, 'aes-256-cbc');
            });
        });
        afterAll(() => {
            jest.dontMock('php-serialize');
            warn.mockRestore();
        });

        test('warns once per encrypter', () => {
            expect(warn).toHaveBeenCalledWith(expect.stringContaining('php-serialize not installed'));
        });

        test('scalars use the PHP format', () => {
            expect(fallback.serialize('héllo')).toBe('s:5:"héllo";');
            expect(fallback.serialize(7)).toBe('i:7;');
            expect(fallback.serialize(2.5)).toBe('d:2.5;');
            expect(fallback.serialize(true)).toBe('b:1;');
            expect(fallback.serialize(false)).toBe('b:0;');
            expect(fallback.serialize(null)).toBe('N;');
            for (const v of ['text', 7, -3, 2.5, true, false, null]) {
                expect(fallback.decrypt(fallback.encrypt(v))).toEqual(v);
            }
        });

        test('unserialize reads scalars and returns anything else as-is', () => {
            expect(fallback.unserialize('s:2:"ab";')).toBe('ab');
            expect(fallback.unserialize('i:-5;')).toBe(-5);
            expect(fallback.unserialize('d:1.5;')).toBe(1.5);
            expect(fallback.unserialize('b:0;')).toBe(false);
            expect(fallback.unserialize('b:1;')).toBe(true);
            expect(fallback.unserialize('N;')).toBeNull();
            expect(fallback.unserialize('weird')).toBe('weird');
            expect(fallback.unserialize('a:1:{i:0;i:1;}')).toBe('a:1:{i:0;i:1;}');
        });

        test('objects fall back to JSON inside a PHP string (not PHP-array compatible)', () => {
            expect(fallback.serialize({ a: 1 })).toBe('s:7:"{"a":1}";');
            expect(fallback.unserialize('a:1:{s:7:"{"a":1}";}')).toEqual({ a: 1 });
        });

        test('unsupported values throw', () => {
            expect(() => fallback.serialize(undefined)).toThrow(/Cannot serialize/);
            expect(() => fallback.serialize(() => 1)).toThrow(/Cannot serialize/);
        });
    });
});

describe('PHP base64_decode semantics', () => {
    const { phpBase64Decode } = _internal;
    const text = (b) => (b === null ? null : b.toString('latin1'));

    // [input, strict result (null when PHP returns false), non-strict result]
    test.each([
        ['', '', ''],
        ['A', null, ''],
        ['AA', '\x00', '\x00'],
        ['AAAA', '\x00\x00\x00', '\x00\x00\x00'],
        ['QQ==', 'A', 'A'],
        ['QQ=', null, 'A'],
        ['QQ', 'A', 'A'],
        ['Q', null, ''],
        ['QUJD', 'ABC', 'ABC'],
        ['QU JD', 'ABC', 'ABC'],
        ['QUJD=', null, 'ABC'],
        ['QUJD====', null, 'ABC'],
        ['QQ==QQ==', null, 'A\x04\x10'],
        ['QQ=Q', null, 'A\x04'],
        ['Q=Q=', null, 'A'],
        ['QR==', 'A', 'A'],
        ['QUJ*', null, 'AB'],
        ['!!', null, ''],
        ['A=', null, ''],
        ['AA=', null, '\x00'],
        ['AAA==', null, '\x00\x00'],
        ['====', null, ''],
        ['QUI=\n', 'AB', 'AB'],
        ['Zm9v\nYmFy', 'foobar', 'foobar']
    ])('%j', (input, strict, loose) => {
        // expected values are PHP's base64_decode($s, true) and base64_decode($s)
        expect(text(phpBase64Decode(input, true))).toBe(strict);
        expect(text(phpBase64Decode(input, false))).toBe(loose);
    });

    test('agrees with Buffer on canonical input', () => {
        for (let len = 0; len < 40; len++) {
            const data = Buffer.from(Array.from({ length: len }, (_, i) => (i * 37 + 11) & 0xff));
            const encoded = data.toString('base64');
            expect(phpBase64Decode(encoded, true).equals(data)).toBe(true);
            expect(phpBase64Decode(encoded, false).equals(data)).toBe(true);
        }
    });
});
