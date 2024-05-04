<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm;

use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;

final class HS256 extends AbstractAlgorithm
{
    public function createSignature(JWSHeader $header, JWSPayload $payload, string $secret): JWSSignature
    {
        $signature = hash_hmac(
            'sha256',
            $this->getHeaderAndPayloadCombined($header, $payload),
            $secret
        );

        return new JWSSignature($signature);
    }
}
