<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\Shared\Base64;

class Base64Test extends TestCase
{
    public function testUrlEncode(): void
    {
        $this->assertSame($this->getBase64UrlEncodedPayload(), Base64::urlEncode($this->getPayload()));
    }

    public function testUrlDecodeAgainstDecode(): void
    {
        $this->assertSame($this->getPayload(), Base64::urlDecode($this->getBase64UrlEncodedPayload()));
    }

    public function testUrlDecodeForInvalidData(): void
    {
        $this->expectException(\Exception::class);

        Base64::urlDecode('a');
    }

    public function testEncodeAndDecode(): void
    {
        $binary = random_bytes(8);

        $base64 = Base64::urlEncode($binary);

        $this->assertSame($binary, Base64::urlDecode($base64));
    }

    private function getBase64UrlEncodedPayload(): string
    {
        return 'ew0KICAgICAgICAgICAgInN1YiI6ICIxMjM0NTY3ODkwIiwNCiAgICAgICAgICAgICJpYXQiOiAxNTE2MjM5MDIyLA0KICAgICAgICAgICAgInVzZXIiOiB7DQogICAgICAgICAgICAgICAgIm5hbWUiOiAiSm9obiBEb2UiLA0KICAgICAgICAgICAgICAgICJoYXNoIjogIu-_vV_vv70iDQogICAgICAgICAgICB9DQogICAgICAgIH0';
    }

    private function getPayload(): string
    {
        return '{
            "sub": "1234567890",
            "iat": 1516239022,
            "user": {
                "name": "John Doe",
                "hash": "�_�"
            }
        }';
    }
}
