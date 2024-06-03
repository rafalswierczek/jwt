<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Enum\Header\TokenType;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\Shared\Base64;

class JWSHeaderSerializerTest extends TestCase
{
    private JWSHeaderSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new JWSHeaderSerializer();
    }

    public function testSerializeHeader(): void
    {
        $jsonHeader = $this->serializer->jsonSerialize(JWSModel::getHeader());

        $expectedJson = sprintf('{"typ":"%s","alg":"%s"}', TokenType::JWS->name, AlgorithmType::HS256->name);

        $this->assertSame($expectedJson, $jsonHeader);
    }

    public function testDeserializeHeader(): void
    {
        $jsonHeader = sprintf('{"typ":"%s","alg":"%s"}', TokenType::JWS->name, AlgorithmType::HS256->name);

        $header = $this->serializer->jsonDeserialize($jsonHeader);

        $expectedHeader = JWSModel::getHeader();

        $this->assertSame($expectedHeader->tokenType, $header->tokenType);
        $this->assertSame($expectedHeader->algorithmType, $header->algorithmType);
    }

    public function testDeserializeHeaderInvalidType(): void
    {
        $jsonHeader = sprintf('{"typ":"x","alg":"%s"}', AlgorithmType::HS256->name);

        $this->expectException(InvalidJWSHeaderException::class);
        $this->expectExceptionMessage('Invalid header type: x');

        $this->serializer->jsonDeserialize($jsonHeader);
    }

    public function testDeserializeHeaderInvalidAlgorithm(): void
    {
        $jsonHeader = sprintf('{"typ":"%s","alg":"x"}', TokenType::JWS->name);

        $this->expectException(InvalidJWSHeaderException::class);
        $this->expectExceptionMessage('Invalid header algorithm: x');

        $this->serializer->jsonDeserialize($jsonHeader);
    }

    public function testDeserializeHeaderMissingTypKey(): void
    {
        $jsonHeader = sprintf('{"alg":"%s"}', AlgorithmType::HS256->name);

        $this->expectException(InvalidJWSHeaderException::class);
        $this->expectExceptionMessage("Cannot find 'typ' key in JSON header");

        $this->serializer->jsonDeserialize($jsonHeader);
    }

    public function testDeserializeHeaderMissingAlgKey(): void
    {
        $jsonHeader = sprintf('{"typ":"%s"}', TokenType::JWS->name);

        $this->expectException(InvalidJWSHeaderException::class);
        $this->expectExceptionMessage("Cannot find 'alg' key in JSON header");

        $this->serializer->jsonDeserialize($jsonHeader);
    }

    public function testDeserializeHeaderInvalidFormat(): void
    {
        $jsonHeader = 'x';

        $this->expectException(InvalidJWSHeaderException::class);
        $this->expectExceptionMessage('Invalid header format');

        $this->serializer->jsonDeserialize($jsonHeader);
    }

    public function testBase64Encode(): void
    {
        $header = JWSModel::getHeader();

        $base64UrlHeader = $this->serializer->base64Encode($header);

        $expectedBase64UrlHeader = Base64::UrlEncode((string) json_encode([
            'typ' => $header->tokenType->name,
            'alg' => $header->algorithmType->name,
        ]));

        $this->assertSame($expectedBase64UrlHeader, $base64UrlHeader);
    }

    public function testBase64Decode(): void
    {
        $expectedHeader = JWSModel::getHeader();

        $base64UrlHeader = $this->serializer->base64Encode($expectedHeader);

        $header = $this->serializer->base64Decode($base64UrlHeader);

        $this->assertSame($expectedHeader->tokenType, $header->tokenType);
        $this->assertSame($expectedHeader->algorithmType, $header->algorithmType);
    }
}
