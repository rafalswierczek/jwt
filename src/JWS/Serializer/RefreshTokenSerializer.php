<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Exception\InvalidRefreshTokenCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidRefreshTokenException;
use rafalswierczek\JWT\JWS\Model\RefreshToken;
use rafalswierczek\JWT\Shared\Base64;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class RefreshTokenSerializer implements RefreshTokenSerializerInterface
{
    public function compactSerializeRefreshToken(RefreshToken $refreshToken): string
    {
        $base64Algorithm = Base64::urlEncode($refreshToken->algorithmType->name);
        $base64ExipredAt = Base64::urlEncode((string) $refreshToken->expiredAt->getTimestamp());
        $base64RandomBinary = Base64::urlEncode($refreshToken->randomBinary);
        $base64Signature = Base64::urlEncode($refreshToken->signature);

        return sprintf('%s.%s.%s.%s', $base64Algorithm, $base64ExipredAt, $base64RandomBinary, $base64Signature);
    }

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidRefreshTokenCompactException
     * @throws InvalidRefreshTokenException
     */
    public function compactDeserializeRefreshToken(string $compactRefreshToken): RefreshToken
    {
        $base64UrlParts = explode('.', $compactRefreshToken);

        if (4 !== count($base64UrlParts)) {
            throw new InvalidRefreshTokenCompactException('Compact serialized refresh token must contain 4 elements. Invalid refresh token: ' . $compactRefreshToken);
        }

        $algorithmName = Base64::urlDecode($base64UrlParts[0]);
        $expiredAtTimestamp = (int) Base64::urlDecode($base64UrlParts[1]);
        $randomBinary = Base64::urlDecode($base64UrlParts[2]);
        $signature = Base64::urlDecode($base64UrlParts[3]);

        $algorithmType = AlgorithmType::tryFromName($algorithmName) ?? throw new InvalidRefreshTokenException("Invalid algorithm name: $algorithmName");
        $expireAt = (new \DateTimeImmutable())->setTimestamp($expiredAtTimestamp);

        return new RefreshToken($algorithmType, $expireAt, $randomBinary, $signature);
    }
}
