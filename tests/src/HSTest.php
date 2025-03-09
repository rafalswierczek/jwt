<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\AlgorithmInterface;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Exception\InvalidKeySizeException;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializerInterface;

class HSTest extends TestCase
{
    #[DataProvider('algorithmProvider')]
    public function testCreateTokenSignature(AlgorithmType $algorithmType, string $hashingAlgorithm, int $keySize, int $signatureLength): void
    {
        $header = JWSModel::getHeader();
        $payload = JWSModel::getPayload();

        $headerSerializer = new JWSHeaderSerializer();
        $base64Header = $headerSerializer->base64Encode($header);

        $payloadSerializer = new JWSPayloadSerializer();
        $base64Payload = $payloadSerializer->base64Encode($payload);

        $algorithm = new $algorithmType->value($headerSerializer, $payloadSerializer);
        $secret = random_bytes(max(1, $keySize));

        $expectedSignature = hash_hmac($hashingAlgorithm, sprintf('%s.%s', $base64Header, $base64Payload), $secret);

        $actualSignature = $algorithm->createTokenSignature($header, $payload, $secret);

        self::assertSame($expectedSignature, (string) $actualSignature);
        self::assertSame($signatureLength, strlen((string) $actualSignature));
    }

    #[DataProvider('algorithmProvider')]
    public function testCreateRefreshTokenSignature(AlgorithmType $algorithmType, string $hashingAlgorithm, int $keySize, int $signatureLength): void
    {
        $headerSerializer = self::createMock(JWSHeaderSerializerInterface::class);

        $payloadSerializer = self::createMock(JWSPayloadSerializerInterface::class);

        /** @var AlgorithmInterface $algorithm */
        $algorithm = new $algorithmType->value($headerSerializer, $payloadSerializer);

        $expiredAt = new \DateTimeImmutable();
        $randomBinary = random_bytes(16);
        $secret = random_bytes(max(1, $keySize));

        $expectedSignature = hash_hmac($hashingAlgorithm, sprintf('%s.%d.%s', $algorithmType->name, $expiredAt->getTimestamp(), $randomBinary), $secret);

        $actualSignature = $algorithm->createRefreshTokenSignature($expiredAt, $randomBinary, $secret);

        self::assertSame($expectedSignature, $actualSignature);
        self::assertSame($signatureLength, strlen($actualSignature));
    }

    #[DataProvider('algorithmProvider')]
    public function testInvalidKeySize(AlgorithmType $algorithmType, string $hashingAlgorithm, int $keySize, int $signatureLength): void
    {
        $headerSerializer = self::createMock(JWSHeaderSerializerInterface::class);

        $payloadSerializer = self::createMock(JWSPayloadSerializerInterface::class);

        /** @var AlgorithmInterface $algorithm */
        $algorithm = new $algorithmType->value($headerSerializer, $payloadSerializer);

        $expiredAt = new \DateTimeImmutable();
        $randomBinary = random_bytes(16);
        $invalidKeySize = 1;
        $secret = random_bytes($invalidKeySize);

        $this->expectException(InvalidKeySizeException::class);
        $this->expectExceptionMessage("{$algorithmType->name} algorithm requires {$keySize} bytes of key size. {$invalidKeySize} bytes given.");

        $algorithm->createRefreshTokenSignature($expiredAt, $randomBinary, $secret);
    }

    /**
     * @return array<array{
     *     algorithmType: AlgorithmType,
     *     hashingAlgorithm: string,
     *     keySize: int,
     *     signatureLength: int
     * }>
     */
    public static function algorithmProvider(): array
    {
        return [
            [
                'algorithmType' => AlgorithmType::HS256,
                'hashingAlgorithm' => 'sha256',
                'keySize' => 64,
                'signatureLength' => 64,
            ],
            [
                'algorithmType' => AlgorithmType::HS512,
                'hashingAlgorithm' => 'sha512',
                'keySize' => 128,
                'signatureLength' => 128,
            ],
        ];
    }
}
