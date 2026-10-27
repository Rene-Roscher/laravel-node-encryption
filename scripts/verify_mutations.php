<?php

declare(strict_types=1);

// Reads the JSON produced by `node scripts/mutations.js` on STDIN and decrypts each
// payload with the REAL Laravel Encrypter. This implementation's verdict (plaintext, or null for a
// rejection) must match Laravel's for every payload, valid or mutated. Exits non-zero on any
// difference.

require __DIR__.'/../vendor/autoload.php';

use Illuminate\Encryption\Encrypter;

$data = json_decode(stream_get_contents(STDIN), true);

if (! is_array($data) || ! isset($data['key_b64'], $data['cases'])) {
    fwrite(STDERR, "Invalid input JSON\n");
    exit(2);
}

$rawKey = base64_decode($data['key_b64']);
$hasAppearsEncrypted = method_exists(Encrypter::class, 'appearsEncrypted'); // Laravel 12+
$accepted = 0;
$differences = 0;

foreach ($data['cases'] as $case) {
    $size = str_contains($case['cipher'], '128') ? 16 : 32;
    $enc = new Encrypter(substr($rawKey, 0, $size), $case['cipher']);

    try {
        $laravel = @$enc->decryptString($case['payload']);
    } catch (\Throwable) {
        $laravel = null;
    }

    if ($laravel !== null) {
        $accepted++;
    }
    if ($hasAppearsEncrypted && Encrypter::appearsEncrypted($case['payload']) !== $case['appears']) {
        $differences++;
        if ($differences <= 10) {
            fwrite(STDERR, "DIFF appearsEncrypted [{$case['cipher']}] laravel=".var_export(Encrypter::appearsEncrypted($case['payload']), true)
                .' impl='.var_export($case['appears'], true).' payload='.substr((string) base64_decode($case['payload']), 0, 200)."\n");
        }
    }
    if ($laravel !== $case['plain']) {
        $differences++;
        if ($differences <= 10) {
            fwrite(STDERR, "DIFF [{$case['cipher']}] laravel=".var_export($laravel, true).' impl='.var_export($case['plain'], true)
                .' payload='.substr((string) base64_decode($case['payload']), 0, 200)."\n");
        }
    }
}

$total = count($data['cases']);
if ($differences > 0) {
    fwrite(STDERR, "{$differences}/{$total} payload(s) were judged differently by this implementation and Laravel\n");
    exit(1);
}
if ($accepted === 0 || $accepted === $total) {
    fwrite(STDERR, "Degenerate input: {$accepted}/{$total} accepted\n");
    exit(1);
}
fwrite(STDERR, "This implementation and Laravel agree on all {$total} payloads ({$accepted} accepted)\n");
