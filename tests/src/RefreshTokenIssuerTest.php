<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Model\RefreshToken;
use rafalswierczek\JWT\JWS\RefreshToken\RefreshTokenIssuer;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\RefreshTokenSerializer;

final class RefreshTokenIssuerTest extends TestCase
{
    private AlgorithmProvider $algorithmProvider;

    private RefreshTokenSerializer $refreshTokenSerializer;

    private RefreshTokenIssuer $refreshTokenProvider;

    protected function setUp(): void
    {
        $algorithmProvider = new AlgorithmProvider(new JWSHeaderSerializer(), new JWSPayloadSerializer());
        $refreshTokenSerializer = new RefreshTokenSerializer();

        $this->algorithmProvider = $algorithmProvider;
        $this->refreshTokenSerializer = $refreshTokenSerializer;
        $this->refreshTokenProvider = new RefreshTokenIssuer($algorithmProvider, $refreshTokenSerializer);
    }

    #[DataProvider('algorithmProvider')]
    public function testGetRefreshToken(AlgorithmType $algorithmType): void
    {
        $expiredAt = new \DateTimeImmutable();
        $randomBinary = random_bytes(16);
        $secret = JWSModel::getSecret($algorithmType);

        $algorithm = $this->algorithmProvider->getAlgorithm($algorithmType);
        $signature = $algorithm->createRefreshTokenSignature($expiredAt, $randomBinary, $secret);

        $expectedRefreshToken = new RefreshToken($algorithmType, $expiredAt, $randomBinary, $signature);

        $actualRefreshToken = $this->refreshTokenProvider->generateRefreshToken($algorithmType, $expiredAt, $randomBinary, $secret);

        self::assertSame(
            $this->refreshTokenSerializer->compactSerializeRefreshToken($expectedRefreshToken),
            $this->refreshTokenSerializer->compactSerializeRefreshToken($actualRefreshToken),
        );
    }

    #[DataProvider('algorithmProvider')]
    public function testGetCompactRefreshToken(AlgorithmType $algorithmType): void
    {
        $expiredAt = new \DateTimeImmutable();
        $randomBinary = random_bytes(16);
        $secret = JWSModel::getSecret($algorithmType);

        $algorithm = $this->algorithmProvider->getAlgorithm($algorithmType);
        $signature = $algorithm->createRefreshTokenSignature($expiredAt, $randomBinary, $secret);

        $expectedCompactRefreshToken = $this->refreshTokenSerializer->compactSerializeRefreshToken(new RefreshToken($algorithmType, $expiredAt, $randomBinary, $signature));

        $actualCompactRefreshToken = $this->refreshTokenProvider->generateCompactRefreshToken($algorithmType, $expiredAt, $randomBinary, $secret);

        self::assertSame($expectedCompactRefreshToken, $actualCompactRefreshToken);
    }

    /**
     * @return array<array<AlgorithmType>>
     */
    public static function algorithmProvider(): iterable
    {
        foreach (AlgorithmType::cases() as $algorithmType) {
            yield [$algorithmType];
        }
    }
}
