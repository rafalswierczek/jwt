<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Model\JWSSignature;
use rafalswierczek\JWT\Shared\Base64;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class JWSSignatureSerializer implements JWSSignatureSerializerInterface
{
    public function base64Encode(JWSSignature $signature): string
    {
        return Base64::UrlEncode((string) $signature);
    }

    /**
     * @throws InvalidBase64InputException
     */
    public function base64Decode(string $base64UrlSignature): JWSSignature
    {
        return new JWSSignature(Base64::UrlDecode($base64UrlSignature));
    }
}
