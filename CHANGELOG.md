# Changelog

All notable changes to this project will be documented in this file.

## 1.0.0 (2025-09-24)


### Features

* add Laravel 12 support and fix Laravel 7 compatibility ([46121ee](https://github.com/Rene-Roscher/laravel-node-encryption/commit/46121ee7ff475443145b30c81b590e5caf195fcb))
* comprehensive bidirectional encryption tests for all data types ([0c20c21](https://github.com/Rene-Roscher/laravel-node-encryption/commit/0c20c2130602e487c2536ab55878cce20f047d2b))
* extend support to Laravel 7, 8, and 9 ([c2ee643](https://github.com/Rene-Roscher/laravel-node-encryption/commit/c2ee64320847e98b4d5b0a3535329a7e7798dbf6))


### Bug Fixes

* correct Laravel version syntax in CI ([c66d324](https://github.com/Rene-Roscher/laravel-node-encryption/commit/c66d324f253c79f24d16b797b1d06929ae76110a))
* handle ESM modules in Laravel 11 tests ([5e0a307](https://github.com/Rene-Roscher/laravel-node-encryption/commit/5e0a30758fe24274067b2219dfa5a6e2ea6c1625))
* remove Laravel 7 support due to compatibility issues ([ec0401e](https://github.com/Rene-Roscher/laravel-node-encryption/commit/ec0401ea664d40067e9060021e1a1e1cc306732d))
* resolve all ESLint errors ([fde6498](https://github.com/Rene-Roscher/laravel-node-encryption/commit/fde64988db701f96e85e444d7d41b281361b529d))

## 1.0.0 (2025-09-24)


### Features

* add Laravel 12 support and fix Laravel 7 compatibility ([2cb65ca](https://github.com/Rene-Roscher/laravel-node-encryption/commit/2cb65ca5f2ed7398c2ffa51d05e9334cbe2c1964))
* comprehensive bidirectional encryption tests for all data types ([4823c38](https://github.com/Rene-Roscher/laravel-node-encryption/commit/4823c38f4dddcaf8f217e9a5dff667066b2eeac5))
* extend support to Laravel 7, 8, and 9 ([0245a66](https://github.com/Rene-Roscher/laravel-node-encryption/commit/0245a6617f2d267e6e67f86cc27eedda56d86584))


### Bug Fixes

* correct Laravel version syntax in CI ([623142c](https://github.com/Rene-Roscher/laravel-node-encryption/commit/623142cf4609d25df9ea9ddc2cc5d389e959f406))
* handle ESM modules in Laravel 11 tests ([4e49b21](https://github.com/Rene-Roscher/laravel-node-encryption/commit/4e49b21b5524fbf1222acb64f3b4de3039bb810e))
* remove Laravel 7 support due to compatibility issues ([fe04b8f](https://github.com/Rene-Roscher/laravel-node-encryption/commit/fe04b8fa8c0149144a54f4797302d1fe15ffaba8))

## [1.0.0] - 2024-01-24

### Added
- Initial release
- Full Laravel encryption/decryption compatibility (Laravel 8.x - 11.x)
- Automatic APP_KEY detection from environment variables
- Support for AES-256-CBC and AES-128-CBC encryption
- PHP serialization support (optional with php-serialize package)
- Comprehensive test suite
- GitHub Actions for CI/CD
- Support for strings, numbers, objects, arrays, booleans, and null values
- HMAC-SHA256 authentication for data integrity
- Crypt facade for Laravel-like API

### Security
- Secure key handling with automatic base64 decoding
- Timing-safe MAC comparison
- Proper IV generation for each encryption

### Tested With
- Node.js 16.x, 18.x, 20.x
- Laravel 8.x, 9.x, 10.x, 11.x
- Windows, macOS, Linux
