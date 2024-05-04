<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\Shared\Base64;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

class Base64Test extends TestCase
{
    public function testEncodeUrlBinaryToGetUrlSafeEncodedString(): void
    {
        $binaryThatShouldProduceUrlUnsafeString = $this->getBinary();

        $encoded = base64_encode($binaryThatShouldProduceUrlUnsafeString);
        $urlEncoded = Base64::urlEncode($binaryThatShouldProduceUrlUnsafeString);

        self::assertSame($this->getBase64EncodedUrlUnsafeString(), $encoded);
        self::assertSame($this->getBase64UrlEncodedUrlSafeString(), $urlEncoded);
    }

    public function testDecodeUrlSafeString(): void
    {
        $base64UrlEncoded = $this->getBase64UrlEncodedUrlSafeString();

        $decoded = base64_decode($base64UrlEncoded);
        $urlDecoded = Base64::urlDecode($base64UrlEncoded);

        self::assertNotSame($decoded, $urlDecoded);
        self::assertSame($this->getBinary(), $urlDecoded);
    }

    public function testDecodeUrlUnsafeString(): void
    {
        $base64Encoded = $this->getBase64EncodedUrlUnsafeString();

        $decoded = base64_decode($base64Encoded);
        $urlDecoded = Base64::urlDecode($base64Encoded);

        self::assertSame($decoded, $urlDecoded);
        self::assertSame($this->getBinary(), $urlDecoded);
    }

    public function testUrlDecodeForInvalidData(): void
    {
        $this->expectException(InvalidBase64InputException::class);

        Base64::urlDecode('a');
    }

    public function testEncodeAndDecode(): void
    {
        $binary = random_bytes(8);

        $base64 = Base64::urlEncode($binary);

        $this->assertSame($binary, Base64::urlDecode($base64));
    }

    private function getBase64EncodedUrlUnsafeString(): string
    {
        return 'dmFsdWV3d++/vXZhbHVldw==';
    }

    private function getBase64UrlEncodedUrlSafeString(): string
    {
        return 'dmFsdWV3d--_vXZhbHVldw';
    }

    private function getBinary(): string
    {
        return 'valueww�valuew';
    }
}
