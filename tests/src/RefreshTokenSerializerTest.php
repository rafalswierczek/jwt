<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Serializer\RefreshTokenSerializer;
use rafalswierczek\JWT\Shared\Base64;

class RefreshTokenSerializerTest extends TestCase
{
    private RefreshTokenSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new RefreshTokenSerializer();
    }

    public function testCompactSerializeRefreshToken(): void
    {
        $refreshToken = JWSModel::getRefreshToken();

        $expectedCompactRefreshToken = sprintf(
            '%s.%s.%s',
            Base64::urlEncode($refreshToken->algorithmType->name),
            Base64::urlEncode((string) $refreshToken->expiredAt->getTimestamp()),
            Base64::urlEncode($refreshToken->signature),
        );

        $actualCompactRefreshToken = $this->serializer->compactSerializeRefreshToken($refreshToken);

        self::assertSame($expectedCompactRefreshToken, $actualCompactRefreshToken);
    }

    public function testCompactDeserializeRefreshToken(): void
    {
        $expectedRefreshToken = JWSModel::getRefreshToken();

        $compactRefreshToken = $this->serializer->compactSerializeRefreshToken($expectedRefreshToken);

        $actualRefreshToken = $this->serializer->compactDeserializeRefreshToken($compactRefreshToken);

        self::assertSame($expectedRefreshToken->algorithmType, $actualRefreshToken->algorithmType);
        self::assertSame($expectedRefreshToken->expiredAt->getTimestamp(), $actualRefreshToken->expiredAt->getTimestamp());
        self::assertSame($expectedRefreshToken->signature, $actualRefreshToken->signature);
    }
}
