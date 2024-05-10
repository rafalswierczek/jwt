<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Enum\Header\TokenType;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;

class JWSHeaderSerializerTest extends TestCase
{
    private JWSHeaderSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new JWSHeaderSerializer();
    }

    public function testSerializeHeader(): void
    {
        $header = new JWSHeader(TokenType::JWS, AlgorithmType::HS256);

        $jsonHeader = $this->serializer->jsonSerialize($header);

        $expectedJson = sprintf('{"typ":"%s","alg":"%s"}', TokenType::JWS->name, AlgorithmType::HS256->name);

        $this->assertSame($expectedJson, $jsonHeader);
    }

    public function testDeserializeHeader(): void
    {
        $jsonHeader = sprintf('{"typ":"%s","alg":"%s"}', TokenType::JWS->name, AlgorithmType::HS256->name);

        $header = $this->serializer->jsonDeserialize($jsonHeader);

        $expectedHeader = new JWSHeader(TokenType::JWS, AlgorithmType::HS256);

        $this->assertSame($expectedHeader->getTokenType(), $header->getTokenType());
        $this->assertSame($expectedHeader->getAlgorithmType(), $header->getAlgorithmType());
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
}
