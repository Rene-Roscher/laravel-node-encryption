# Changelog

All notable changes to this project will be documented in this file.

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