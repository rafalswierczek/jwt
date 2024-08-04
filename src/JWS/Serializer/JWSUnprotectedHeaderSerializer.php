<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Model\JWSUnprotectedHeader;
use rafalswierczek\JWT\Shared\Base64;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class JWSUnprotectedHeaderSerializer implements JWSUnprotectedHeaderSerializerInterface
{
    public function base64Encode(JWSUnprotectedHeader $header): string
    {
        return Base64::urlEncode((string) json_encode($header->data));
    }

    /**
     * @throws InvalidBase64InputException
     */
    public function base64Decode(string $base64UrlUnprotectedHeader): JWSUnprotectedHeader
    {
        /** @var array<string, string> $data */
        $data = json_decode(Base64::urlDecode($base64UrlUnprotectedHeader), true);

        return new JWSUnprotectedHeader($data);
    }
}
