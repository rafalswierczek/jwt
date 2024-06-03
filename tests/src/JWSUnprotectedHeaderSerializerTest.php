<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Serializer\JWSUnprotectedHeaderSerializer;
use rafalswierczek\JWT\Shared\Base64;

class JWSUnprotectedHeaderSerializerTest extends TestCase
{
    private JWSUnprotectedHeaderSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new JWSUnprotectedHeaderSerializer();
    }

    public function testBase64EncodeUnprotectedHeader(): void
    {
        $header = JWSModel::getUnprotectedHeader();

        $base64UrlUnprotectedHeader = $this->serializer->base64Encode($header);

        $expectedBase64UrlUnprotectedHeader = Base64::urlEncode((string) json_encode($header->data));

        $this->assertSame($expectedBase64UrlUnprotectedHeader, $base64UrlUnprotectedHeader);
    }

    public function testBase64DecodeUnprotectedHeader(): void
    {
        $expectedHeader = JWSModel::getUnprotectedHeader();

        $base64UrlUnprotectedHeader = $this->serializer->base64Encode($expectedHeader);

        $unprotectedHeader = $this->serializer->base64Decode($base64UrlUnprotectedHeader);

        $this->assertSame($expectedHeader->data, $unprotectedHeader->data);
    }
}
