<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Serializer\JWSSignatureSerializer;
use rafalswierczek\JWT\Shared\Base64;

class JWSSignatureSerializerTest extends TestCase
{
    private JWSSignatureSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new JWSSignatureSerializer();
    }

    public function testBase64EncodeSignature(): void
    {
        $signature = JWSModel::getSignature();

        $base64UrlSignature = $this->serializer->base64Encode($signature);

        $expectedBase64UrlSignature = Base64::UrlEncode((string) $signature);

        $this->assertSame($expectedBase64UrlSignature, $base64UrlSignature);
    }

    public function testBase64DecodeSignature(): void
    {
        $expectedSignature = JWSModel::getSignature();

        $base64UrlSignature = $this->serializer->base64Encode($expectedSignature);

        $signature = $this->serializer->base64Decode($base64UrlSignature);

        $this->assertSame((string) $expectedSignature, (string) $signature);
    }
}
