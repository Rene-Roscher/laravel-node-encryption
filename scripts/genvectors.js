// Emits Node-encrypted Laravel payloads as JSON on stdout. CI pipes this into
// scripts/verify_node_vectors.php, which decrypts each with the real Laravel encrypter and
// asserts equality: the Node -> Laravel direction (the PHP-generated fixtures cover
// Laravel -> Node).
//
// "string" vectors use encryptString / decryptString; "serialized" vectors use encrypt /
// decrypt (the PHP-serialize path) and build the values named in scripts/cases.php that
// JavaScript can represent: it has no separate integer type, no 64-bit integers, no binary
// strings in the string API and no ordered array/list distinction beyond arrays vs objects.
//
// The app-layer vectors cover random keys, cookies, Eloquent encrypted casts and encrypted
// sessions.
const crypto = require('crypto');
const { LaravelEncrypter } = require('../src/index');

const key = Buffer.alloc(32, 0x2b);

const plaintexts = {
    simple: 'Hello from Node',
    empty: '',
    unicode: 'Grüße 世界 🚀 café',
    json: '{"user":"alice","id":7,"active":true}',
    multiline: 'first line\nsecond line\n',
    block_aligned: 'a'.repeat(32),
    long: 'The quick brown fox 0123456789 '.repeat(50)
};

const cases = {
    null: null,
    true: true,
    false: false,
    int_zero: 0,
    int_negative: -42,
    float: 2.5,
    float_whole: 2,
    float_tenth: 0.1,
    float_large: 1e25,
    float_small: 1.5e-7,
    float_pi: Math.PI,
    float_max: Number.MAX_VALUE,
    float_min_subnormal: 5e-324,
    string_empty: '',
    string_unicode: 'Grüße 世界 🚀 café',
    string_quotes: 'say "hi"; s:3:"x";',
    list: [1, 'two', true, null, [3, 4]],
    empty_array: [],
    assoc: { user: 'alice', id: 7, active: true, score: 2.5, tags: ['x', 'y'], meta: null },
    mixed_keys: { 5: 'a', x: 'b', 7: { nested: [1, 2] } },
    non_sequential_list: { 1: 'a', 0: 'b' },
    nested: { l1: { l2: { l3: ['deep', 1.5, false] } } }
};

const vectors = [];
for (const cipher of ['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm']) {
    const size = cipher.includes('128') ? 16 : 32;
    const enc = new LaravelEncrypter(key.subarray(0, size), cipher);

    for (const [name, text] of Object.entries(plaintexts)) {
        vectors.push({
            kind: 'string',
            name: `${cipher}/${name}`,
            cipher,
            plaintext_b64: Buffer.from(text).toString('base64'),
            payload: enc.encryptString(text)
        });
    }
    for (const [name, value] of Object.entries(cases)) {
        vectors.push({
            kind: 'serialized',
            name: `${cipher}/${name}`,
            case: name,
            cipher,
            payload: enc.encrypt(value)
        });
    }
}

for (const cipher of ['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm']) {
    const size = cipher.includes('128') ? 16 : 32;
    const b64 = (text) => Buffer.from(text).toString('base64');

    // Random keys: every byte value can appear in a key.
    for (let i = 0; i < 6; i++) {
        const randomKey = crypto.randomBytes(size);
        const enc = new LaravelEncrypter(randomKey, cipher);
        ['Hello, World!', '', 'Grüße 世界 🚀 café'].forEach((text, n) => {
            vectors.push({
                kind: 'random_key',
                name: `${cipher}/key${i}/${n}`,
                cipher,
                key_b64: randomKey.toString('base64'),
                plaintext_b64: b64(text),
                payload: enc.encryptString(text)
            });
        });
    }

    const enc = new LaravelEncrypter(key.subarray(0, size), cipher);

    // Cookies, as EncryptCookies expects them.
    for (const [name, value] of [
        ['laravel_session', '0123456789abcdef0123456789abcdef01234567'],
        ['XSRF-TOKEN', ''],
        ['a b', 'with|pipe|chars'],
        ['küche', 'Grüße 世界']
    ]) {
        vectors.push({
            kind: 'cookie',
            name: `${cipher}/cookie/${name}`,
            cipher,
            cookie_name: name,
            value_b64: b64(value),
            payload: enc.encryptCookie(name, value)
        });
    }

    // Eloquent casts: encrypted values are Crypt::encryptString() of the value or its JSON.
    for (const [attribute, plain] of [
        ['plain', 'hello wörld'],
        ['list', '{"x":1,"y":[1,2],"z":"ü"}'],
        ['object', '{"k":"v","n":3}'],
        ['collection', '[1,"two",3.5]']
    ]) {
        vectors.push({
            kind: 'cast',
            name: `${cipher}/cast/${attribute}`,
            cipher,
            attribute,
            plaintext_b64: b64(plain),
            payload: enc.encryptString(plain)
        });
    }

    // Encrypted sessions: Crypt::encrypt() of the serialized attributes.
    const attributes = { user_id: 7, cart: { apple: 2, pear: 1 }, name: 'Grüße' };
    for (const [serialization, inner] of [['php', enc.serialize(attributes)], ['json', JSON.stringify(attributes)]]) {
        vectors.push({
            kind: 'session',
            name: `${cipher}/session/${serialization}`,
            cipher,
            serialization,
            payload: enc.encrypt(inner)
        });
    }
}

process.stdout.write(JSON.stringify({ key_b64: key.toString('base64'), vectors }) + '\n');
