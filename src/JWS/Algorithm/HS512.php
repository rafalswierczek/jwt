<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm;

use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;

final class HS512 extends AbstractAlgorithm
{
    public function createTokenSignature(JWSHeader $header, JWSPayload $payload, string $secret): JWSSignature
    {
        $signature = hash_hmac(
            'sha512',
            $this->getJWSInput($header, $payload),
            $secret
        );

        return new JWSSignature($signature);
    }

    public function createRefreshTokenSignature(\DateTimeImmutable $expiredAt, string $secret): string
    {
        return hash_hmac(
            'sha512',
            $this->getRefreshTokenInput($expiredAt),
            $secret
        );
    }
}
