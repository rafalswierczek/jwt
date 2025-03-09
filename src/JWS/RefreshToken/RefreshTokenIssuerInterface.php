<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\RefreshToken;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Model\RefreshToken;

interface RefreshTokenIssuerInterface
{
    /**
     * @return string Compact refresh token with format: base64AlgorithmName.base64ExpireTimestamp.base64RandomBinary.base64Signature
     */
    public function generateCompactRefreshToken(
        AlgorithmType $algorithmType,
        \DateTimeImmutable $expiredAt,
        string $randomBinary,
        string $secret
    ): string;

    public function generateRefreshToken(
        AlgorithmType $algorithmType,
        \DateTimeImmutable $expiredAt,
        string $randomBinary,
        string $secret
    ): RefreshToken;
}
