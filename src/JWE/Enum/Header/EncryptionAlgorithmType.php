<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWE\Enum\Header;

enum EncryptionAlgorithmType: string
{
    case XCP = 'XChaCha20-Poly1305';
}
