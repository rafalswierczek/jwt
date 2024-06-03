<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Model\JWSSignature;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

interface JWSSignatureSerializerInterface
{
    public function base64Encode(JWSSignature $signature): string;

    /**
     * @throws InvalidBase64InputException
     */
    public function base64Decode(string $base64UrlSignature): JWSSignature;
}
