<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Issuer;

use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSUnprotectedHeader;

interface JWSIssuerInterface
{
    public function getCompactJWS(JWSHeader $header, JWSPayload $payload, string $secret): string;

    public function getJsonJWS(JWSHeader $header, JWSPayload $payload, string $secret, ?JWSUnprotectedHeader $unprotectedHeader = null): string;

    public function getJWS(JWSHeader $header, JWSPayload $payload, string $secret, ?JWSUnprotectedHeader $unprotectedHeader = null): JWS;
}
