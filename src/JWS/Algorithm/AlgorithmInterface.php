<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm;

use rafalswierczek\JWT\JWS\Exception\InvalidKeySizeException;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;

interface AlgorithmInterface
{
    /** @throws InvalidKeySizeException */
    public function createTokenSignature(JWSHeader $header, JWSPayload $payload, string $secret): JWSSignature;

    /** @throws InvalidKeySizeException */
    public function createRefreshTokenSignature(\DateTimeImmutable $expiredAt, string $randomBinary, string $secret): string;
}
