/**
 * Interop Envelope v1: a JSON document with a scope, timestamps and data, encrypted with
 * encryptString. The encryption authenticates it, so neither the scope nor the timestamps can be
 * changed without the key. The rene-roscher/laravel-interop package for Laravel, and the Rust and
 * Go packages, read and write the same format.
 *
 * The plaintext is {"typ":"env","v":1,"iat":…,"nbf":…,"exp":…,"scope":…,"data":…}. Opening checks,
 * in this order, and the first failure wins: the structure, the version, the scope, nbf and exp.
 * A token is valid for nbf - leeway <= now < exp + leeway. Timestamps are Unix seconds.
 */

const TYPE = 'env';
const VERSION = 1;
const MAX_SAFE = 2 ** 53;

/**
 * Why an envelope is unusable. `kind` is the verdict name all implementations share: `invalid`,
 * `unsupported_version`, `scope_mismatch`, `not_yet_valid` or `expired`. A token that does not
 * decrypt is not an EnvelopeError: open() lets the encrypter's error through.
 */
class EnvelopeError extends Error {
    constructor(kind, message) {
        super(message);
        this.name = 'EnvelopeError';
        this.kind = kind;
    }
}

const invalid = () => new EnvelopeError('invalid', 'The payload is not a valid envelope.');

const unixSeconds = (value, name) => {
    const seconds = value instanceof Date ? Math.floor(value.getTime() / 1000) : value;
    if (!Number.isSafeInteger(seconds)) {
        throw new TypeError(`${name} must be a whole number of seconds or a Date`);
    }
    return seconds;
};

/**
 * Reads a version or timestamp field. Any JSON number without a fractional part is accepted,
 * because JavaScript cannot tell 1 from 1.0; everything else is invalid. An absent optional field
 * is undefined.
 */
function integer(document, name, required) {
    if (!Object.prototype.hasOwnProperty.call(document, name)) {
        if (required) throw invalid();
        return undefined;
    }
    const value = document[name];
    if (typeof value !== 'number' || !Number.isInteger(value) || Math.abs(value) >= MAX_SAFE) {
        throw invalid();
    }
    return value;
}

class Envelope {
    /**
     * Seals data for a scope.
     *
     * @param {LaravelEncrypter} encrypter
     * @param {object} options
     * @param {string} options.scope - What the envelope may be used for, for example "password-reset".
     * @param {*} options.data - Anything JSON.stringify accepts, except undefined.
     * @param {number} [options.expiresIn] - Valid for this many seconds after it is sealed.
     * @param {number|Date} [options.expiresAt] - Valid until this Unix time (seconds) or Date.
     * @param {boolean} [options.neverExpires] - Valid forever. One of the three expiry options has
     *     to be given, so that a token never lives forever by accident.
     * @param {number|Date} [options.notBefore] - Not valid before this time.
     * @param {number} [options.now] - Overrides the current Unix time, for tests.
     * @returns {string}
     */
    static seal(encrypter, options) {
        const { scope, data, expiresIn, expiresAt, neverExpires, notBefore, now } = options || {};
        if (typeof scope !== 'string' || scope === '') {
            throw new TypeError('scope must be a non-empty string');
        }
        if (data === undefined) {
            throw new TypeError('data is required (use null for nothing)');
        }
        const chosen = [expiresIn !== undefined, expiresAt !== undefined, neverExpires === true];
        if (chosen.filter(Boolean).length !== 1) {
            throw new TypeError('choose exactly one of expiresIn, expiresAt and neverExpires: true');
        }

        const issuedAt = now === undefined ? Math.floor(Date.now() / 1000) : unixSeconds(now, 'now');
        let exp;
        if (expiresIn !== undefined) {
            if (!Number.isSafeInteger(expiresIn) || expiresIn < 1) {
                throw new TypeError('expiresIn must be a whole number of seconds, at least 1');
            }
            exp = issuedAt + expiresIn;
        } else if (expiresAt !== undefined) {
            exp = unixSeconds(expiresAt, 'expiresAt');
            if (exp <= 0) throw new TypeError('expiresAt must be a positive Unix timestamp');
        }

        const document = { typ: TYPE, v: VERSION, iat: issuedAt };
        if (notBefore !== undefined) document.nbf = unixSeconds(notBefore, 'notBefore');
        if (exp !== undefined) document.exp = exp;
        document.scope = scope;
        document.data = data;
        return encrypter.encryptString(JSON.stringify(document));
    }

    /**
     * Verifies and opens an envelope.
     *
     * @param {LaravelEncrypter} encrypter
     * @param {string} token
     * @param {object} options
     * @param {string} options.scope - The scope the envelope has to have been sealed for.
     * @param {number} [options.leeway] - Seconds of clock difference to tolerate on both time checks.
     * @param {number} [options.now] - Overrides the current Unix time, for tests.
     * @returns {{scope: string, data: *, issuedAt: number, notBefore: ?number, expiresAt: ?number}}
     * @throws {EnvelopeError} the envelope is unusable
     * @throws {Error} the token does not decrypt (the encrypter's error)
     */
    static open(encrypter, token, options) {
        const { scope, leeway = 0, now } = options || {};
        if (typeof scope !== 'string') {
            throw new TypeError('scope must be a string');
        }
        if (!Number.isSafeInteger(leeway) || leeway < 0) {
            throw new TypeError('leeway must be a whole number of seconds');
        }

        const plaintext = encrypter.decryptBuffer(token);
        let document;
        try {
            // PHP's json_decode rejects invalid UTF-8 and a byte order mark
            document = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext));
        } catch (e) {
            throw invalid();
        }
        if (document === null || typeof document !== 'object' || Array.isArray(document) || document.typ !== TYPE) {
            throw invalid();
        }

        if (integer(document, 'v', true) !== VERSION) {
            throw new EnvelopeError('unsupported_version', 'The envelope version is not supported.');
        }
        const issuedAt = integer(document, 'iat', true);
        const notBefore = integer(document, 'nbf', false);
        const expiresAt = integer(document, 'exp', false);
        if (typeof document.scope !== 'string' || document.scope === '' ||
            !Object.prototype.hasOwnProperty.call(document, 'data')) {
            throw invalid();
        }

        if (document.scope !== scope) {
            throw new EnvelopeError('scope_mismatch', 'The envelope was issued for another scope.');
        }

        const at = now === undefined ? Math.floor(Date.now() / 1000) : unixSeconds(now, 'now');
        if (notBefore !== undefined && at < notBefore - leeway) {
            throw new EnvelopeError('not_yet_valid', 'The envelope is not valid yet.');
        }
        if (expiresAt !== undefined && at >= expiresAt + leeway) {
            throw new EnvelopeError('expired', 'The envelope has expired.');
        }

        return {
            scope: document.scope,
            data: document.data,
            issuedAt,
            notBefore: notBefore === undefined ? null : notBefore,
            expiresAt: expiresAt === undefined ? null : expiresAt
        };
    }

    /**
     * The verdict name of an error thrown by open(): the EnvelopeError's kind, or `decrypt_error`
     * for anything else (the token did not decrypt).
     * @param {Error} error
     * @returns {string}
     */
    static verdict(error) {
        return error instanceof EnvelopeError ? error.kind : 'decrypt_error';
    }
}

module.exports = { Envelope, EnvelopeError };
