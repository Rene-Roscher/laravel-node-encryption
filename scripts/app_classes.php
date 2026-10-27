<?php

declare(strict_types=1);

// Laravel classes shared by generate_app_vectors.php and verify_node_vectors.php.

use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Encryption\Encrypter;

/**
 * What EncryptCookies does with a decrypted cookie: check the prefix against the key (and, from
 * Laravel 11, the previous keys) and strip it. Null when the prefix does not match.
 */
function validate_cookie(string $name, string $value, Encrypter $encrypter): ?string
{
    $keys = method_exists($encrypter, 'getAllKeys') ? $encrypter->getAllKeys() : $encrypter->getKey();

    return CookieValuePrefix::validate($name, $value, $keys);
}

class CastModel extends Model
{
    protected $guarded = [];

    protected $casts = [
        'plain' => 'encrypted',
        'list' => 'encrypted:array',
        'object' => 'encrypted:object',
        'collection' => 'encrypted:collection',
    ];
}

/** Keeps what the session store writes, and serves it back when asked. */
class MemorySessionHandler implements SessionHandlerInterface
{
    public string $data = '';

    public function open($path, $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read($id): string|false
    {
        return $this->data;
    }

    public function write($id, $data): bool
    {
        $this->data = $data;

        return true;
    }

    public function destroy($id): bool
    {
        return true;
    }

    public function gc($max): int|false
    {
        return 0;
    }
}
