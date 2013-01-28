php-authenticated-encryption-helper
===================================

A helper that uses OpenSSL for Authenticated Encryption in PHP for consistant implementation of Encrypt Then Mac using

- Key Generation: PBKDF2
- Encryption:     OpenSSL, AES CBC Random IV
- Secure MAC:     HMAC sha256
- PRG:            OpenSSL, "random_pseudo_bytes"

Requires:
=========
- OpenSSL
- PHP 5.3+ (tested using 5.4)

Notes:
======
- Plaintext Keys are 64 Bytes (char) / 512 bits
- When Encrypted they are 224 Bytes (char), ie. DB Storage = VARCHAR(225)