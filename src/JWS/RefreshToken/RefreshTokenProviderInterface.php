<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\RefreshToken;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Model\RefreshToken;

interface RefreshTokenProviderInterface
{
    /**
     * @return string Compact refresh token with format: base64AlgorithmName.base64ExpireTimestamp.base64Signature
     */
    public function generateCompactRefreshToken(AlgorithmType $algorithmType, \DateTimeImmutable $expiredAt, string $secret): string;

    public function generateRefreshToken(AlgorithmType $algorithmType, \DateTimeImmutable $expiredAt, string $secret): RefreshToken;
}
