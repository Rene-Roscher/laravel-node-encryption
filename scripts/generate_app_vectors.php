<?php

declare(strict_types=1);

// Generates Laravel -> Node test vectors for the parts of Laravel that sit on top of the
// Encrypter, built with the REAL Laravel classes, written to fixtures/app-vectors.json:
//
//   random_keys:  encryptString with random keys instead of the fixed test key
//   cookies:      what EncryptCookies sends: encrypt(CookieValuePrefix . value, false)
//   casts:        Eloquent encrypted, encrypted:array, :object and :collection attributes
//   sessions:     what session.encrypt stores: EncryptedStore's encrypt($serializedData)
//
// test/app-layer.test.js decrypts them.

require __DIR__.'/../vendor/autoload.php';

use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Encryption\Encrypter;
use Illuminate\Session\EncryptedStore;

require __DIR__.'/app_classes.php';

$ciphers = ['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm'];
$sizeOf = fn (string $cipher): int => str_contains($cipher, '128') ? 16 : 32;

$fixedKey = str_repeat("\x2b", 32);
$oldKey = str_repeat("\x7a", 32);

$randomKeys = [];
$cookies = [];
$casts = [];
$sessions = [];

foreach ($ciphers as $cipher) {
    $size = $sizeOf($cipher);

    // Random keys: every byte value can appear in a key.
    for ($i = 0; $i < 6; $i++) {
        $key = random_bytes($size);
        $enc = new Encrypter($key, $cipher);
        foreach (['Hello, World!', '', 'Grüße 世界 🚀 café', str_repeat('x', 100)] as $n => $plaintext) {
            $randomKeys[] = [
                'name' => "{$cipher}/key{$i}/{$n}",
                'cipher' => $cipher,
                'key_b64' => base64_encode($key),
                'plaintext_b64' => base64_encode($plaintext),
                'payload' => $enc->encryptString($plaintext),
            ];
        }
    }

    $enc = new Encrypter(substr($fixedKey, 0, $size), $cipher);
    $old = new Encrypter(substr($oldKey, 0, $size), $cipher);

    // Cookies, as EncryptCookies::encrypt() builds them (cookies are not serialized by default).
    $names = ['laravel_session', 'XSRF-TOKEN', 'remember_web_59ba36addc2b2f9401580f014c7f58ea4e30989d', 'a b', 'küche'];
    $values = [bin2hex(random_bytes(20)), '', 'with|pipe|chars', 'Grüße 世界', '{"json":true}'];
    foreach ($names as $i => $name) {
        $value = $values[$i];
        foreach (['current' => $enc, 'previous' => $old] as $which => $encrypter) {
            $cookies[] = [
                'name' => "{$cipher}/{$which}/{$name}",
                'cipher' => $cipher,
                'key' => $which,
                'cookie_name' => $name,
                'value_b64' => base64_encode($value),
                'payload' => $encrypter->encrypt(CookieValuePrefix::create($name, $encrypter->getKey()).$value, false),
            ];
        }
    }

    // Eloquent encrypted casts.
    Model::encryptUsing($enc);
    $model = new CastModel([
        'plain' => 'hello wörld',
        'list' => ['x' => 1, 'y' => [1, 2], 'z' => 'ü'],
        'object' => (object) ['k' => 'v', 'n' => 3],
        'collection' => collect([1, 'two', 3.5]),
    ]);
    $expectedJson = [
        'plain' => 'hello wörld',
        'list' => json_encode(['x' => 1, 'y' => [1, 2], 'z' => 'ü']),
        'object' => json_encode(['k' => 'v', 'n' => 3]),
        'collection' => json_encode([1, 'two', 3.5]),
    ];
    foreach ($model->getAttributes() as $attribute => $payload) {
        $casts[] = [
            'name' => "{$cipher}/{$attribute}",
            'cipher' => $cipher,
            'attribute' => $attribute,
            'plaintext_b64' => base64_encode($expectedJson[$attribute]),
            'payload' => $payload,
        ];
    }

    // Encrypted session payloads.
    $serializations = ['php'];
    if ((new ReflectionMethod(EncryptedStore::class, '__construct'))->getNumberOfParameters() >= 5) {
        $serializations[] = 'json';
    }
    foreach ($serializations as $serialization) {
        $handler = new MemorySessionHandler();
        $store = $serialization === 'php'
            ? new EncryptedStore('session', $handler, $enc)
            : new EncryptedStore('session', $handler, $enc, null, $serialization);
        $store->start();
        $store->put('user_id', 7);
        $store->put('cart', ['apple' => 2, 'pear' => 1]);
        $store->put('name', 'Grüße');
        $store->save();

        $sessions[] = [
            'name' => "{$cipher}/{$serialization}",
            'cipher' => $cipher,
            'serialization' => $serialization,
            'token' => $store->token(),
            'payload' => $handler->data,
            // What the payload decrypts to with Crypt::decrypt(): the serialized attributes.
            'inner_b64' => base64_encode($enc->decrypt($handler->data)),
        ];
    }
}

file_put_contents(
    __DIR__.'/../fixtures/app-vectors.json',
    json_encode([
        'laravel' => \Composer\InstalledVersions::getVersion('illuminate/encryption'),
        'key_b64' => base64_encode($fixedKey),
        'previous_key_b64' => base64_encode($oldKey),
        'random_keys' => $randomKeys,
        'cookies' => $cookies,
        'casts' => $casts,
        'sessions' => $sessions,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n"
);

fwrite(STDERR, 'Wrote '.(count($randomKeys) + count($cookies) + count($casts) + count($sessions))." app-layer vectors to fixtures/app-vectors.json\n");
