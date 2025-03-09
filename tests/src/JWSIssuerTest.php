<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuer;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuerInterface;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSSignatureSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSUnprotectedHeaderSerializer;

class JWSIssuerTest extends TestCase
{
    private JWSIssuerInterface $issuer;

    private JWSSerializerInterface $serializer;

    private AlgorithmProvider $algorithmProvider;

    protected function setUp(): void
    {
        $headerSerializer = new JWSHeaderSerializer();
        $payloadSerializer = new JWSPayloadSerializer();
        $serializer = new JWSSerializer($headerSerializer, $payloadSerializer, new JWSSignatureSerializer(), new JWSUnprotectedHeaderSerializer());
        $algorithmProvider = new AlgorithmProvider($headerSerializer, $payloadSerializer);
        $issuer = new JWSIssuer($algorithmProvider, $serializer);

        $this->serializer = $serializer;
        $this->issuer = $issuer;
        $this->algorithmProvider = $algorithmProvider;
    }

    #[DataProvider('algorithmProvider')]
    public function testGetCompactJWS(AlgorithmType $algorithmType): void
    {
        $algorithm = $this->algorithmProvider->getAlgorithm($algorithmType);
        $header = JWSModel::getHeader($algorithmType);
        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret($algorithmType);
        $signature = $algorithm->createTokenSignature($header, $payload, $secret);

        $expectedCompactJWS = $this->serializer->compactSerializeJWS(new JWS($header, $payload, $signature));

        $compactJWS = $this->issuer->generateCompactJWS($header, $payload, $secret);

        $this->assertSame($expectedCompactJWS, $compactJWS);
    }

    #[DataProvider('algorithmProvider')]
    public function testGetJsonJWS(AlgorithmType $algorithmType): void
    {
        $algorithm = $this->algorithmProvider->getAlgorithm($algorithmType);
        $header = JWSModel::getHeader($algorithmType);
        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret($algorithmType);
        $unprotectedHeader = JWSModel::getUnprotectedHeader();
        $signature = $algorithm->createTokenSignature($header, $payload, $secret);

        $expectedJsonJWS = $this->serializer->jsonSerializeJWS(new JWS($header, $payload, $signature, $unprotectedHeader));

        $jsonJWS = $this->issuer->generateJsonJWS($header, $payload, $secret, $unprotectedHeader);

        $this->assertSame($expectedJsonJWS, $jsonJWS);
    }

    #[DataProvider('algorithmProvider')]
    public function testGetJWS(AlgorithmType $algorithmType): void
    {
        $algorithm = $this->algorithmProvider->getAlgorithm($algorithmType);
        $header = JWSModel::getHeader($algorithmType);
        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret($algorithmType);
        $signature = $algorithm->createTokenSignature($header, $payload, $secret);

        $expectedJWS = new JWS($header, $payload, $signature);

        $jws = $this->issuer->generateJWS($header, $payload, $secret);

        $this->assertSame(
            $this->serializer->compactSerializeJWS($expectedJWS),
            $this->serializer->compactSerializeJWS($jws),
        );
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
