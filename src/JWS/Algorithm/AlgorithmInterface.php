<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm;

use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;

interface AlgorithmInterface
{
    public function createSignature(JWSHeader $header, JWSPayload $payload, string $secret): JWSSignature;
}
