<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWS\Enum\Header\Type;
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
        $header = new JWSHeader(Type::JWS, Algorithm::HS256);

        $jsonHeader = $this->serializer->jsonSerialize($header);

        $expectedJson = sprintf('{"typ":"%s","alg":"%s"}', Type::JWS->name, Algorithm::HS256->name);

        $this->assertSame($expectedJson, $jsonHeader);
    }

    public function testDeserializeHeader(): void
    {
        $jsonHeader = sprintf('{"typ":"%s","alg":"%s"}', Type::JWS->name, Algorithm::HS256->name);

        $header = $this->serializer->jsonDeserialize($jsonHeader);

        $expectedHeader = new JWSHeader(Type::JWS, Algorithm::HS256);

        $this->assertSame($expectedHeader->getType(), $header->getType());
        $this->assertSame($expectedHeader->getAlgorithm(), $header->getAlgorithm());
    }

    public function testDeserializeHeaderInvalidType(): void
    {
        $jsonHeader = sprintf('{"typ":"x","alg":"%s"}', Algorithm::HS256->name);

        $this->expectException(InvalidJWSHeaderException::class);
        $this->expectExceptionMessage('Invalid header type: x');

        $this->serializer->jsonDeserialize($jsonHeader);
    }

    public function testDeserializeHeaderInvalidAlgorithm(): void
    {
        $jsonHeader = sprintf('{"typ":"%s","alg":"x"}', Type::JWS->name);

        $this->expectException(InvalidJWSHeaderException::class);
        $this->expectExceptionMessage('Invalid header algorithm: x');

        $this->serializer->jsonDeserialize($jsonHeader);
    }

    public function testDeserializeHeaderMissingTypKey(): void
    {
        $jsonHeader = sprintf('{"alg":"%s"}', Algorithm::HS256->name);

        $this->expectException(InvalidJWSHeaderException::class);
        $this->expectExceptionMessage("Cannot find 'typ' key in JSON header");

        $this->serializer->jsonDeserialize($jsonHeader);
    }

    public function testDeserializeHeaderMissingAlgKey(): void
    {
        $jsonHeader = sprintf('{"typ":"%s"}', Type::JWS->name);

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
