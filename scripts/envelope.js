// Prints, as JSON on stdout, Interop Envelope tokens made by this package, for
// bin/verify-tokens.php of the laravel-interop package to judge with the real Laravel encrypter:
//
//   verdicts: every document of fixtures/envelope-vectors.json, encrypted here. PHP has to reach
//             the verdict the vector names.
//   sealed:   tokens made by Envelope.seal for each of the vector file's seal cases. PHP has to
//             open them and read back what was sealed.
const { LaravelEncrypter, Envelope } = require('../src/index');
const fixtures = require('../fixtures/envelope-vectors.json');

const key = Buffer.from(fixtures.key_b64, 'base64');
const encrypterFor = (cipher) => new LaravelEncrypter(key.subarray(0, cipher.includes('128') ? 16 : 32), cipher);

const verdicts = fixtures.vectors
    .filter((v) => v.plaintext_b64 !== undefined && v.key === 'current' && v.expect !== 'decrypt_error')
    // encrypt() takes a Buffer, so documents that are not UTF-8 work too
    .map((v) => ({ ...v, token: encrypterFor(v.cipher).encrypt(Buffer.from(v.plaintext_b64, 'base64'), false) }));

const sealed = [];
for (const cipher of ['aes-256-cbc', 'aes-128-gcm']) {
    for (const c of fixtures.seal_cases) {
        const options = { scope: c.scope, data: c.data, now: c.now };
        if (c.expiry.in !== undefined) options.expiresIn = c.expiry.in;
        else if (c.expiry.at !== undefined) options.expiresAt = c.expiry.at;
        else options.neverExpires = true;
        if (c.not_before !== undefined) options.notBefore = c.not_before;
        sealed.push({ cipher, name: c.name, token: Envelope.seal(encrypterFor(cipher), options), case: c });
    }
}

process.stdout.write(JSON.stringify({ key_b64: fixtures.key_b64, verdicts, sealed }) + '\n');
