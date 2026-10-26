const crypto = require('crypto');
const { LaravelEncrypter } = require('../src/index');
const {
    ALL_CIPHERS, isCbc, keySize, rawKey, newEnc, unwrap, edit, flipFirst, cbcPayload
} = require('./helpers');

describe.each(ALL_CIPHERS)('%s', (cipher) => {
    const enc = newEnc(cipher);

    test('round-trips strings', () => {
        const long = 'line of text 0123456789\n'.repeat(500);
        for (const input of [
            '', 'x', 'Hello, World!', 'Grüße 世界 🚀 café',
            // around the 16-byte block boundary, where padding changes
            '0123456789abcde', '0123456789abcdef', '0123456789abcdef0', long
        ]) {
            expect(enc.decryptString(enc.encryptString(input))).toBe(input);
        }
    });

    test('round-trips values', () => {
        const value = { user: 'alice', id: 7, active: true, score: 2.5, tags: ['x', 'y'], meta: null };
        expect(enc.decrypt(enc.encrypt(value))).toEqual(value);
        for (const v of [null, true, false, 0, -42, 2.5, 'text', '', [], [1, 'two', [3]], { a: { b: { c: 1 } } }]) {
            expect(enc.decrypt(enc.encrypt(v))).toEqual(v);
        }
    });

    test('encrypt/decrypt serialize like Crypt::encrypt, the string methods do not', () => {
        expect(enc.decryptString(enc.encrypt('hello'))).toBe('s:5:"hello";');
        expect(() => enc.decrypt(enc.encryptString('hello'))).toThrow(/Decryption failed/);
        // serialize=false is the same as encryptString
        expect(enc.decrypt(enc.encrypt('plain', false), false)).toBe('plain');
    });

    test('uses a fresh IV for every encryption', () => {
        const a = enc.encryptString('same');
        const b = enc.encryptString('same');
        expect(a).not.toBe(b);
        expect(unwrap(a).iv).not.toBe(unwrap(b).iv);
    });

    test('payload layout matches Laravel', () => {
        const payload = enc.encryptString('hello');
        const json = Buffer.from(payload, 'base64').toString();

        // field order of json_encode(['iv', 'value', 'mac', 'tag'])
        const positions = ['"iv"', '"value"', '"mac"', '"tag"'].map((f) => json.indexOf(f));
        expect([...positions].sort((a, b) => a - b)).toEqual(positions);
        expect(positions[0]).toBeGreaterThanOrEqual(0);

        const p = unwrap(payload);
        const iv = Buffer.from(p.iv, 'base64');
        const value = Buffer.from(p.value, 'base64');
        if (isCbc(cipher)) {
            expect(iv.length).toBe(16);
            expect(value.length).toBe(16); // "hello" + PKCS#7 padding
            expect(p.tag).toBe('');
            // mac = lower-case hex HMAC-SHA256(base64(iv) . base64(value), key)
            const expected = crypto.createHmac('sha256', rawKey(cipher)).update(p.iv + p.value).digest('hex');
            expect(p.mac).toBe(expected);
        } else {
            expect(iv.length).toBe(12);
            expect(value.length).toBe(5); // stream mode, no padding
            expect(Buffer.from(p.tag, 'base64').length).toBe(16);
            expect(p.mac).toBe('');
        }
    });

    test('rejects tampering with every authenticated field', () => {
        const payload = enc.encryptString('a secret payload');
        const fields = isCbc(cipher) ? ['iv', 'value', 'mac'] : ['iv', 'value', 'tag'];
        for (const field of fields) {
            const bad = edit(payload, (p) => { p[field] = flipFirst(p[field]); });
            expect(() => enc.decryptString(bad)).toThrow(/Decryption failed/);
        }
    });

    test('rejects a wrong key', () => {
        const payload = enc.encryptString('secret');
        const other = newEnc(cipher, 0x7a);
        expect(() => other.decryptString(payload)).toThrow(isCbc(cipher) ? /The MAC is invalid/ : /Could not decrypt/);
    });

    test('rejects a payload for the other mode (different IV length)', () => {
        const other = newEnc(isCbc(cipher) ? cipher.replace('cbc', 'gcm') : cipher.replace('gcm', 'cbc'));
        expect(() => enc.decryptString(other.encryptString('x'))).toThrow(/The payload is invalid/);
    });

    test('is safe to share between concurrent calls', () => {
        return Promise.all(Array.from({ length: 8 }, (_, i) => {
            const text = `message ${i}`;
            return Promise.resolve().then(() => enc.decryptString(enc.encryptString(text)));
        })).then((results) => {
            expect(results).toEqual(Array.from({ length: 8 }, (_, i) => `message ${i}`));
        });
    });

    test('requires a key of the right size', () => {
        const size = keySize(cipher);
        expect(() => new LaravelEncrypter(Buffer.alloc(size), cipher)).not.toThrow();
        for (const bad of [1, size - 1, size + 1, 64]) {
            expect(() => new LaravelEncrypter(Buffer.alloc(bad), cipher)).toThrow(/Invalid key length/);
        }
    });
});

describe('CBC specifics', () => {
    const cbcCiphers = ['aes-128-cbc', 'aes-256-cbc'];

    test.each(cbcCiphers)('%s: a tampered value or mac is an invalid MAC', (cipher) => {
        const enc = newEnc(cipher);
        const payload = enc.encryptString('a secret payload');
        for (const field of ['value', 'mac']) {
            const bad = edit(payload, (p) => { p[field] = flipFirst(p[field]); });
            expect(() => enc.decryptString(bad)).toThrow('Decryption failed: The MAC is invalid.');
        }
        // hash_equals is case-sensitive
        const upper = edit(payload, (p) => { p.mac = p.mac.toUpperCase(); });
        expect(() => enc.decryptString(upper)).toThrow(/The MAC is invalid/);
    });

    test.each(cbcCiphers)('%s: fields Laravel does not authenticate are ignored', (cipher) => {
        const enc = newEnc(cipher);
        const payload = enc.encryptString('x');
        expect(enc.decryptString(edit(payload, (p) => { p.extra = 'ignored'; }))).toBe('x');
        expect(enc.decryptString(edit(payload, (p) => { delete p.tag; }))).toBe('x');
        expect(enc.decryptString(edit(payload, (p) => { p.tag = null; }))).toBe('x');
        // PHP's empty("0") is true, so a "0" tag counts as no tag
        expect(enc.decryptString(edit(payload, (p) => { p.tag = '0'; }))).toBe('x');
    });

    test.each(cbcCiphers)('%s: a CBC payload must not carry a tag', (cipher) => {
        const enc = newEnc(cipher);
        const bad = edit(enc.encryptString('x'), (p) => { p.tag = Buffer.alloc(16).toString('base64'); });
        expect(() => enc.decryptString(bad)).toThrow(/Could not decrypt the data/);
    });

    test.each(cbcCiphers)('%s: a value that is not base64 fails the MAC', (cipher) => {
        const enc = newEnc(cipher);
        const bad = edit(enc.encryptString('x'), (p) => { p.value = '***'; });
        expect(() => enc.decryptString(bad)).toThrow(/The MAC is invalid/);
    });

    test.each(cbcCiphers)('%s: an authenticated payload with bad padding is a decrypt error', (cipher) => {
        const enc = newEnc(cipher);
        for (const value of [Buffer.alloc(0), Buffer.alloc(15), Buffer.alloc(16)]) {
            const payload = cbcPayload(rawKey(cipher), Buffer.alloc(16), value);
            expect(() => enc.decryptString(payload)).toThrow(/Could not decrypt the data/);
        }
    });
});

describe('GCM specifics', () => {
    const gcmCiphers = ['aes-128-gcm', 'aes-256-gcm'];

    test.each(gcmCiphers)('%s: a tampered value or tag fails authentication', (cipher) => {
        const enc = newEnc(cipher);
        const payload = enc.encryptString('a secret payload');
        for (const field of ['value', 'tag']) {
            const bad = edit(payload, (p) => { p[field] = flipFirst(p[field]); });
            expect(() => enc.decryptString(bad)).toThrow(/Could not decrypt the data/);
        }
    });

    test.each(gcmCiphers)('%s: empty plaintext is a valid payload', (cipher) => {
        const enc = newEnc(cipher);
        const payload = enc.encryptString('');
        expect(unwrap(payload).value).toBe('');
        expect(enc.decryptString(payload)).toBe('');
    });

    test.each(gcmCiphers)('%s: the mac field must exist but is not checked', (cipher) => {
        const enc = newEnc(cipher);
        const payload = enc.encryptString('x');
        expect(enc.decryptString(edit(payload, (p) => { p.mac = 'whatever'; }))).toBe('x');
        expect(() => enc.decryptString(edit(payload, (p) => { delete p.mac; }))).toThrow(/The payload is invalid/);
    });

    test.each(gcmCiphers)('%s: a GCM payload needs a 16-byte tag', (cipher) => {
        const enc = newEnc(cipher);
        const payload = enc.encryptString('x');
        const tag = Buffer.from(unwrap(payload).tag, 'base64');
        const bad = ['', tag.subarray(0, 15).toString('base64'), '!!!', null];
        for (const value of bad) {
            const edited = edit(payload, (p) => { p.tag = value; });
            expect(() => enc.decryptString(edited)).toThrow(/Could not decrypt the data/);
        }
        const missing = edit(payload, (p) => { delete p.tag; });
        expect(() => enc.decryptString(missing)).toThrow(/Could not decrypt the data/);
    });

    test.each(gcmCiphers)('%s: the value is decoded leniently like openssl_decrypt does', (cipher) => {
        // Characters outside the base64 alphabet are skipped; the tag authenticates the decoded
        // bytes, not the text.
        const enc = newEnc(cipher);
        const payload = enc.encryptString('hello');
        const value = unwrap(payload).value;
        const noisy = edit(payload, (p) => { p.value = `${value.slice(0, 2)}\n${value.slice(2, 4)}*${value.slice(4)}`; });
        expect(enc.decryptString(noisy)).toBe('hello');
        const bad = edit(payload, (p) => { p.value = flipFirst(value); });
        expect(() => enc.decryptString(bad)).toThrow(/Could not decrypt the data/);
    });
});

describe('malformed payloads', () => {
    const enc = newEnc('aes-256-cbc');
    const valid = enc.encryptString('x');
    const wrapText = (s) => Buffer.from(s).toString('base64');

    const cases = {
        empty: '',
        'not base64': 'not base64!!',
        'not json': 'Zm9vYmFy',
        'json null': wrapText('null'),
        'json list': wrapText('[]'),
        'json string': wrapText('"a string"'),
        'empty object': wrapText('{}'),
        'only iv': wrapText('{"iv":"x"}'),
        'numeric iv': wrapText('{"iv":1,"value":"x","mac":"x"}'),
        'missing mac': edit(valid, (p) => { delete p.mac; }),
        'null mac': edit(valid, (p) => { p.mac = null; }),
        'numeric value': edit(valid, (p) => { p.value = 5; }),
        'array iv': edit(valid, (p) => { p.iv = ['a']; }),
        'numeric tag': edit(valid, (p) => { p.tag = 5; }),
        'iv not base64': edit(valid, (p) => { p.iv = '***'; }),
        'iv too short': edit(valid, (p) => { p.iv = Buffer.alloc(15).toString('base64'); }),
        'iv too long': edit(valid, (p) => { p.iv = Buffer.alloc(17).toString('base64'); }),
        truncated: valid.slice(0, valid.length / 2),
        'invalid utf-8': Buffer.concat([Buffer.from('{"iv":"'), Buffer.from([0xff]), Buffer.from('","value":"x","mac":"x"}')]).toString('base64'),
        'upper-case field names': wrapText('{"IV":"x","VALUE":"x","MAC":"x"}')
    };

    test.each(Object.entries(cases))('%s is rejected as an invalid payload', (_name, payload) => {
        expect(() => enc.decryptString(payload)).toThrow(/The payload is invalid/);
        expect(() => enc.decrypt(payload)).toThrow(/Decryption failed/);
    });

    test.each([undefined, null, 5, {}, []])('non-string payload %p is rejected', (payload) => {
        expect(() => enc.decryptString(payload)).toThrow(/The payload is invalid/);
    });

    test('unusual but valid encodings are accepted, like PHP does', () => {
        expect(enc.decryptString(` ${valid}\n`)).toBe('x');
        expect(enc.decryptString(valid.replace(/=+$/, ''))).toBe('x');
    });
});

describe('arbitrary input', () => {
    // The decrypter must reject, never crash on, arbitrary input: random garbage, and valid
    // payloads with bytes changed, inserted or cut.
    test('never throws anything but an Error', () => {
        let state = 0x2545f491n;
        const next = () => {
            state = (state * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
            return Number(state >> 33n);
        };
        for (const cipher of ALL_CIPHERS) {
            const enc = newEnc(cipher);
            const valid = enc.encrypt(['a', 'b']);
            const attempt = (payload) => {
                for (const fn of [(p) => enc.decrypt(p), (p) => enc.decryptString(p)]) {
                    try {
                        fn(payload);
                    } catch (e) {
                        expect(e).toBeInstanceOf(Error);
                    }
                }
            };
            for (let i = 0; i < 1500; i++) {
                const b = [...valid];
                for (let n = next() % 4; n > 0; n--) {
                    const at = next() % b.length;
                    const op = next() % 3;
                    if (op === 0) b[at] = String.fromCharCode(next() & 0x7f);
                    else if (op === 1) b.splice(at, 0, String.fromCharCode(65 + (next() % 26)));
                    else if (at > 0) b.length = at;
                }
                attempt(b.join(''));
            }
            for (let i = 0; i < 500; i++) {
                const g = Buffer.from(Array.from({ length: next() % 200 }, () => next() & 0x7f));
                attempt(g.toString('latin1'));
                attempt(g.toString('base64'));
            }
        }
    });
});
