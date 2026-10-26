// Payloads produced by the real Laravel encrypter (fixtures/vectors.json, regenerated in CI by
// scripts/generate_vectors.php), decrypted with this package.
const { fixtures, fixtureEncrypter } = require('./helpers');

const fx = fixtures();
const b64 = (s) => Buffer.from(s, 'base64');

describe('Laravel -> Node: encryptString payloads', () => {
    // Binary plaintext is not representable: the API works on UTF-8 strings.
    const vectors = fx.vectors.filter((v) => !v.name.endsWith('/binary'));

    test('fixtures cover all four ciphers', () => {
        expect(new Set(vectors.map((v) => v.cipher)).size).toBe(4);
        expect(vectors.length).toBeGreaterThanOrEqual(28);
    });

    test.each(vectors.map((v) => [v.name, v]))('%s', (_name, v) => {
        const enc = fixtureEncrypter(fx, v.cipher);
        expect(enc.decryptString(v.payload)).toBe(b64(v.plaintext_b64).toString('utf8'));
    });
});

describe('Laravel -> Node: Crypt::encrypt payloads', () => {
    const get = (name, cipher = 'aes-256-cbc') => {
        const v = fx.serialized.find((s) => s.name === `${cipher}/${name}`);
        if (!v) throw new Error(`no case ${name}`);
        return fixtureEncrypter(fx, cipher).decrypt(v.payload);
    };

    test.each([
        ['null', null],
        ['true', true],
        ['false', false],
        ['int_zero', 0],
        ['int_negative', -42],
        ['float', 2.5],
        ['float_whole', 2],
        ['float_tenth', 0.1],
        ['float_large', 1e25],
        ['float_small', 1.5e-7],
        ['float_pi', Math.PI],
        ['float_max', Number.MAX_VALUE],
        ['float_min_subnormal', 5e-324],
        ['string_empty', ''],
        ['string_unicode', 'Grüße 世界 🚀 café'],
        ['string_quotes', 'say "hi"; s:3:"x";'],
        ['empty_array', []],
        ['list', [1, 'two', true, null, [3, 4]]],
        ['assoc', { user: 'alice', id: 7, active: true, score: 2.5, tags: ['x', 'y'], meta: null }],
        ['mixed_keys', { 5: 'a', x: 'b', 7: { nested: [1, 2] } }],
        ['non_sequential_list', { 0: 'b', 1: 'a' }],
        ['nested', { l1: { l2: { l3: ['deep', 1.5, false] } } }]
    ])('%s', (name, expected) => {
        for (const cipher of ['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm']) {
            expect(get(name, cipher)).toEqual(expected);
        }
    });

    test('-0 keeps its sign', () => {
        expect(Object.is(get('float_negative_zero'), -0)).toBe(true);
    });

    test('NaN', () => {
        expect(get('float_nan')).toBeNaN();
    });

    test('random doubles from PHP decode to the exact same number', () => {
        const list = get('float_sweep');
        expect(list.length).toBeGreaterThanOrEqual(300);
        expect(list.every((n) => typeof n === 'number' && Number.isFinite(n))).toBe(true);

        // ...and survive a round-trip through this package.
        const enc = fixtureEncrypter(fx, 'aes-256-cbc');
        expect(enc.decrypt(enc.encrypt(list))).toEqual(list);
    });

    test('PHP objects are never instantiated', () => {
        for (const v of fx.objects) {
            const enc = fixtureEncrypter(fx, v.cipher);
            expect(() => enc.decrypt(v.payload)).toThrow(/Decryption failed/);
        }
    });

    test('decryptString of a Crypt::encrypt payload shows the PHP serialization', () => {
        // Binary strings are skipped: the string API works on UTF-8 text.
        for (const v of fx.serialized.filter((s) => !s.name.endsWith('/string_binary'))) {
            const enc = fixtureEncrypter(fx, v.cipher);
            expect(Buffer.from(enc.decryptString(v.payload))).toEqual(b64(v.serialized_b64));
        }
    });
});
