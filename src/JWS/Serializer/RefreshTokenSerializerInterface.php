<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidRefreshTokenCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidRefreshTokenException;
use rafalswierczek\JWT\JWS\Model\RefreshToken;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

interface RefreshTokenSerializerInterface
{
    public function compactSerializeRefreshToken(RefreshToken $refreshToken): string;

    /**
     * @param string $compactRefreshToken Compact refresh token with format: base64AlgorithmName.base64ExpireTimestamp.base64RandomBinary.base64Signature
     *
     * @throws InvalidBase64InputException
     * @throws InvalidRefreshTokenCompactException
     * @throws InvalidRefreshTokenException
     */
    public function compactDeserializeRefreshToken(string $compactRefreshToken): RefreshToken;
}
