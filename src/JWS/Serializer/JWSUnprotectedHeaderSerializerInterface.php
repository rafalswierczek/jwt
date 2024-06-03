<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Model\JWSUnprotectedHeader;

interface JWSUnprotectedHeaderSerializerInterface
{
    public function base64Encode(JWSUnprotectedHeader $header): string;

    public function base64Decode(string $base64UrlUnprotectedHeader): JWSUnprotectedHeader;
}
