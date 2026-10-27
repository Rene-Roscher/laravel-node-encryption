// Emits valid and mutated payloads together with this package's verdict on each, as JSON on
// stdout. CI pipes this into scripts/verify_mutations.php, which asks the real Laravel
// encrypter about the same payloads: both must accept and reject exactly the same ones, and
// return the same plaintext for the accepted ones. Laravel versions that have
// Encrypter::appearsEncrypted() are also asked whether each payload looks encrypted.
const { LaravelEncrypter } = require('../src/index');

const key = Buffer.alloc(32, 0x2b);

// xorshift64: deterministic, so a failing case is reproducible.
let state = 0x123456789abcdef1n;
const mask = (1n << 64n) - 1n;
function next() {
    state ^= (state << 13n) & mask;
    state ^= state >> 7n;
    state ^= (state << 17n) & mask;
    return Number(state % 1000000007n);
}

const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64');

// Field values that exercise PHP's loose typing: null, empty, "0", numbers, arrays, short or
// invalid base64.
const odd = [null, '', '0', 5, true, [], 'AAAA', '***', 'AAAAAAAAAAAAAAAAAAAAAA=='];

const cases = [];
for (const cipher of ['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm']) {
    const size = cipher.includes('128') ? 16 : 32;
    const enc = new LaravelEncrypter(key.subarray(0, size), cipher);

    for (const text of ['', 'hello', '0123456789abcdef']) {
        const valid = enc.encryptString(text);
        const base = JSON.parse(Buffer.from(valid, 'base64').toString());

        const payloads = [valid, ` ${valid}\n`, valid.replace(/=+$/, '')];

        // Field-level edits: odd values, removal, upper case, an extra character.
        for (const field of ['iv', 'value', 'mac', 'tag']) {
            for (const o of odd) {
                payloads.push(encode({ ...base, [field]: o }));
            }
            const removed = { ...base };
            delete removed[field];
            payloads.push(encode(removed));
            payloads.push(encode({ ...base, [field]: base[field].toUpperCase() }));
            payloads.push(encode({ ...base, [field]: base[field] + 'A' }));
        }

        // Byte-level edits of the outer base64 text.
        for (let i = 0; i < 600; i++) {
            const b = [...valid];
            const at = next() % b.length;
            switch (next() % 5) {
            case 0:
                b[at] = 'ABCxyz09+/=!\n '[next() % 14];
                break;
            case 1:
                b.splice(at, 1);
                break;
            case 2:
                b.length = at;
                break;
            case 3:
                b.splice(at, 0, ' \n=*'[next() % 4]);
                break;
            default: {
                const other = next() % b.length;
                [b[at], b[other]] = [b[other], b[at]];
            }
            }
            payloads.push(b.join(''));
        }

        for (const payload of payloads) {
            let plain = null;
            try {
                plain = enc.decryptString(payload);
            } catch (e) {
                // rejected
            }
            cases.push({ cipher, payload, plain, appears: LaravelEncrypter.appearsEncrypted(payload) });
        }
    }
}

process.stdout.write(JSON.stringify({ key_b64: key.toString('base64'), cases }) + '\n');
