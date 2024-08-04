<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Exception\RefreshTokenCompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\RefreshTokenHasExpiredException;
use rafalswierczek\JWT\JWS\RefreshToken\RefreshTokenProvider;
use rafalswierczek\JWT\JWS\RefreshToken\RefreshTokenProviderInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\RefreshTokenSerializer;
use rafalswierczek\JWT\JWS\Verifier\RefreshTokenVerifier;
use rafalswierczek\JWT\JWS\Verifier\RefreshTokenVerifierInterface;
use rafalswierczek\JWT\Shared\Base64;

final class RefreshTokenVerifierTest extends TestCase
{
    private RefreshTokenVerifierInterface $verifier;

    private RefreshTokenProviderInterface $refreshTokenProvider;

    protected function setUp(): void
    {
        $algorithmProvider = new AlgorithmProvider(new JWSHeaderSerializer(), new JWSPayloadSerializer());
        $serializer = new RefreshTokenSerializer();
        $refreshTokenProvider = new RefreshTokenProvider($algorithmProvider, $serializer);
        $verifier = new RefreshTokenVerifier($serializer, $algorithmProvider);

        $this->verifier = $verifier;
        $this->refreshTokenProvider = $refreshTokenProvider;
    }

    #[DataProvider('algorithmProvider')]
    public function testVerifySuccess(AlgorithmType $algorithmType): void
    {
        $this->expectNotToPerformAssertions();

        $refreshToken = $this->refreshTokenProvider->generateRefreshToken($algorithmType, new \DateTimeImmutable('+5 minutes'), 'secret');

        $this->verifier->verify($refreshToken, 'secret');
    }

    #[DataProvider('algorithmProvider')]
    public function testCompromisedSignature(AlgorithmType $algorithmType): void
    {
        $compactRefreshToken = $this->refreshTokenProvider->generateCompactRefreshToken($algorithmType, new \DateTimeImmutable('+5 minutes'), 'secret');

        $compactRefreshTokenHacked = $this->changeExpirationTime($compactRefreshToken);

        $this->verifier->verifyCompactRefreshToken($compactRefreshToken, 'secret');

        $this->expectException(RefreshTokenCompromisedSignatureException::class);
        $this->expectExceptionMessage("Signature of following refresh token is compromised: $compactRefreshTokenHacked");

        $this->verifier->verifyCompactRefreshToken($compactRefreshTokenHacked, 'secret');
    }

    #[DataProvider('algorithmProvider')]
    public function testTokenHasExpired(AlgorithmType $algorithmType): void
    {
        $compactRefreshToken = $this->refreshTokenProvider->generateCompactRefreshToken($algorithmType, new \DateTimeImmutable('-30 minutes'), 'secret');

        $this->expectException(RefreshTokenHasExpiredException::class);
        $this->expectExceptionMessage("This refresh token has expired: $compactRefreshToken");

        $this->verifier->verifyCompactRefreshToken($compactRefreshToken, 'secret');
    }

    private function changeExpirationTime(string $compactRefreshToken): string
    {
        $compactRefreshTokenArray = explode('.', $compactRefreshToken);

        $newExpiredAt = (new \DateTime('+99 days'))->getTimestamp();

        $compactRefreshTokenArray[1] = Base64::urlEncode((string) $newExpiredAt);

        return implode('.', $compactRefreshTokenArray);
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
