<?php

declare(strict_types=1);

// Generates Laravel -> Node test vectors with the REAL Laravel Encrypter, written to
// fixtures/vectors.json. test/laravel-vectors.test.js decrypts them.
//
//   string:      Crypt::encryptString(plaintext)
//   serialized:  Crypt::encrypt(value); the PHP serialize() output is stored so the Rust
//                codec can be compared with PHP byte for byte.

require __DIR__.'/../vendor/autoload.php';

use Illuminate\Encryption\Encrypter;

$rawKey = str_repeat("\x2b", 32); // fixed, reproducible

$plaintexts = [
    'simple' => 'Hello, World!',
    'empty' => '',
    'unicode' => 'Grüße 世界 🚀 café',
    'json' => json_encode(['user' => 'alice', 'id' => 7, 'active' => true, 'tags' => ['x', 'y']]),
    'multiline' => "first line\nsecond line\n\tindented\n",
    'binary' => "\x00\x01\xff\xfe\x80\x7f",
    'block_aligned' => str_repeat('a', 32),
    'long' => str_repeat('The quick brown fox 0123456789 ', 50),
];

// Random doubles over the whole range, to compare float formatting with PHP's serialize().
$sweep = [];
while (count($sweep) < 300) {
    $d = unpack('d', random_bytes(8))[1];
    if (is_finite($d)) {
        $sweep[] = $d;
    }
}
for ($i = 0; $i < 200; $i++) {
    $sweep[] = (random_int(1, PHP_INT_MAX) / PHP_INT_MAX) * (10 ** random_int(-8, 20)) * (random_int(0, 1) ? 1 : -1);
}
$sweep = array_merge($sweep, [1e15, 1e16, 1e17, 1e18, 1e21, 123456789012345678.0, 0.0001, 0.00001, 100.0, 1.5e300, -2.5e-300]);

$cases = require __DIR__.'/cases.php';
$cases['float_sweep'] = $sweep;

$vectors = [];
$serialized = [];
foreach (['aes-128-cbc', 'aes-256-cbc', 'aes-128-gcm', 'aes-256-gcm'] as $cipher) {
    $size = str_contains($cipher, '128') ? 16 : 32;
    $enc = new Encrypter(substr($rawKey, 0, $size), $cipher);

    foreach ($plaintexts as $name => $pt) {
        $vectors[] = [
            'name' => "{$cipher}/{$name}",
            'cipher' => $cipher,
            'plaintext_b64' => base64_encode($pt),
            'payload' => $enc->encryptString($pt),
        ];
    }

    foreach ($cases as $name => $value) {
        $serialized[] = [
            'name' => "{$cipher}/{$name}",
            'cipher' => $cipher,
            'serialized_b64' => base64_encode(serialize($value)),
            'payload' => $enc->encrypt($value),
        ];
    }
}

// Objects are read-only in Node.
$cipher = 'aes-256-cbc';
$enc = new Encrypter($rawKey, $cipher);
$object = new stdClass();
$object->a = 1;
$object->b = ['two'];
$objects = [[
    'name' => 'stdClass',
    'cipher' => $cipher,
    'serialized_b64' => base64_encode(serialize($object)),
    'payload' => $enc->encrypt($object),
]];

@mkdir(__DIR__.'/../fixtures', 0o755, true);
file_put_contents(
    __DIR__.'/../fixtures/vectors.json',
    json_encode([
        'laravel' => \Composer\InstalledVersions::getVersion('illuminate/encryption'),
        'key_b64' => base64_encode($rawKey),
        'vectors' => $vectors,
        'serialized' => $serialized,
        'objects' => $objects,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n"
);

fwrite(STDERR, 'Wrote '.(count($vectors) + count($serialized) + count($objects))." Laravel vectors to fixtures/vectors.json\n");
