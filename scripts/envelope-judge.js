// Reads tokens as the implementations print them (see scripts/envelope.js) on stdin and prints, as
// JSON on stdout, what this package makes of each one. e2e/compare.php of the laravel-interop
// package holds the result against what the tokens should give.
const fs = require('fs');
const { LaravelEncrypter, Envelope } = require('../src/index');

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const key = Buffer.from(input.key_b64, 'base64');

const judge = (cipher, token, scope, leeway, now) => {
    const encrypter = new LaravelEncrypter(key.subarray(0, cipher.includes('128') ? 16 : 32), cipher);
    try {
        const o = Envelope.open(encrypter, token, { scope, leeway, now });
        return { verdict: 'ok', iat: o.issuedAt, nbf: o.notBefore, exp: o.expiresAt, data: o.data };
    } catch (error) {
        return { verdict: Envelope.verdict(error) };
    }
};

const verdicts = input.verdicts.map((v) => judge(v.cipher, v.token, v.scope, v.leeway, v.now));
const sealed = input.sealed.map((s) =>
    // Open it once it is valid, so the check is about the fields and not the clock.
    judge(s.cipher, s.token, s.case.scope, 0, Math.max(s.case.now + 1, s.case.not_before || 0)));

process.stdout.write(JSON.stringify({ verdicts, sealed }) + '\n');
