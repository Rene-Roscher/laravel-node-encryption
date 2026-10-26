const crypto = require('crypto');
const { LaravelEncrypter } = require('../src/index');

const ALL_CIPHERS = ['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm'];

const isCbc = (cipher) => cipher.endsWith('-cbc');
const keySize = (cipher) => (cipher.includes('128') ? 16 : 32);
const rawKey = (cipher, byte = 0x2b) => Buffer.alloc(keySize(cipher), byte);

/** An encrypter for the fixed 0x2b test key, sized for the cipher. */
const newEnc = (cipher, byte = 0x2b) => new LaravelEncrypter(rawKey(cipher, byte), cipher);

const unwrap = (payload) => JSON.parse(Buffer.from(payload, 'base64').toString());
const wrap = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64');

/** Re-encodes payload after applying edit to its JSON fields. */
function edit(payload, fn) {
    const obj = unwrap(payload);
    fn(obj);
    return wrap(obj);
}

/** Changes the first character so the value stays plausible base64/hex. */
const flipFirst = (s) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);

/** Builds a payload with a valid MAC (CBC) for arbitrary iv/value, which needs the key. */
function cbcPayload(key, ivBytes, valueBytes) {
    const iv = ivBytes.toString('base64');
    const value = valueBytes.toString('base64');
    const mac = crypto.createHmac('sha256', key).update(iv + value).digest('hex');
    return wrap({ iv, value, mac, tag: '' });
}

/** Loads fixtures/vectors.json, produced by the real Laravel encrypter. */
function fixtures() {
    const fx = require('../fixtures/vectors.json');
    return fx;
}

/** Encrypter for a fixture vector's cipher, using the fixture key truncated to its size. */
function fixtureEncrypter(fx, cipher) {
    const key = Buffer.from(fx.key_b64, 'base64');
    return new LaravelEncrypter(key.subarray(0, keySize(cipher)), cipher);
}

module.exports = {
    ALL_CIPHERS,
    isCbc,
    keySize,
    rawKey,
    newEnc,
    unwrap,
    wrap,
    edit,
    flipFirst,
    cbcPayload,
    fixtures,
    fixtureEncrypter
};
