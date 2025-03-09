<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\RefreshToken;

use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Model\RefreshToken;
use rafalswierczek\JWT\JWS\Serializer\RefreshTokenSerializerInterface;

final class RefreshTokenIssuer implements RefreshTokenIssuerInterface
{
    public function __construct(
        private AlgorithmProviderInterface $algorithmProvider,
        private RefreshTokenSerializerInterface $refreshTokenSerializer,
    ) {
    }

    public function generateCompactRefreshToken(
        AlgorithmType $algorithmType,
        \DateTimeImmutable $expiredAt,
        string $randomBinary,
        string $secret
    ): string {
        $refreshToken = $this->generateRefreshToken($algorithmType, $expiredAt, $randomBinary, $secret);

        return $this->refreshTokenSerializer->compactSerializeRefreshToken($refreshToken);
    }

    public function generateRefreshToken(
        AlgorithmType $algorithmType,
        \DateTimeImmutable $expiredAt,
        string $randomBinary,
        string $secret,
    ): RefreshToken {
        $algorithm = $this->algorithmProvider->getAlgorithm($algorithmType);

        $signature = $algorithm->createRefreshTokenSignature($expiredAt, $randomBinary, $secret);

        return new RefreshToken($algorithmType, $expiredAt, $randomBinary, $signature);
    }
}
