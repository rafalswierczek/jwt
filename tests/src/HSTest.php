<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializerInterface;

class HSTest extends TestCase
{
    #[DataProvider('algorithmProvider')]
    public function testCreateTokenSignature(AlgorithmType $algorithmType, string $hashingAlgorithm, int $signatureLength): void
    {
        $header = JWSModel::getHeader();
        $payload = JWSModel::getPayload();

        $headerSerializer = new JWSHeaderSerializer();
        $base64Header = $headerSerializer->base64Encode($header);

        $payloadSerializer = new JWSPayloadSerializer();
        $base64Payload = $payloadSerializer->base64Encode($payload);

        $algorithm = new $algorithmType->value($headerSerializer, $payloadSerializer);

        $expectedSignature = hash_hmac($hashingAlgorithm, sprintf('%s.%s', $base64Header, $base64Payload), 'secret');

        $actualSignature = $algorithm->createTokenSignature($header, $payload, 'secret');

        self::assertSame($expectedSignature, (string) $actualSignature);
        self::assertSame($signatureLength, strlen((string) $actualSignature));
    }

    #[DataProvider('algorithmProvider')]
    public function testCreateRefreshTokenSignature(AlgorithmType $algorithmType, string $hashingAlgorithm, int $signatureLength): void
    {
        $headerSerializer = self::createMock(JWSHeaderSerializerInterface::class);

        $payloadSerializer = self::createMock(JWSPayloadSerializerInterface::class);

        $algorithm = new $algorithmType->value($headerSerializer, $payloadSerializer);

        $expiredAt = new \DateTimeImmutable();

        $expectedSignature = hash_hmac($hashingAlgorithm, sprintf('%s.%s', $algorithmType->name, $expiredAt->getTimestamp()), 'secret');

        $actualSignature = $algorithm->createRefreshTokenSignature($expiredAt, 'secret');

        self::assertSame($expectedSignature, $actualSignature);
        self::assertSame($signatureLength, strlen($actualSignature));
    }

    /**
     * @return array<array{algorithmType: AlgorithmType, hashingAlgorithm: string, signatureLength: int}>
     */
    public static function algorithmProvider(): array
    {
        return [
            [
                'algorithmType' => AlgorithmType::HS256,
                'hashingAlgorithm' => 'sha256',
                'signatureLength' => 64,
            ],
            [
                'algorithmType' => AlgorithmType::HS512,
                'hashingAlgorithm' => 'sha512',
                'signatureLength' => 128,
            ],
        ];
    }
}
