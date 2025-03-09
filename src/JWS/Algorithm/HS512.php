<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;

final class HS512 extends AbstractAlgorithm
{
    /**
     * https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2A
     * A key of the same size as the hash output or larger MUST be used with this algorithm.
     *
     * https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512.-ctor?view=net-9.0
     * However, the recommended size is 128 bytes.
     */
    private const int KEY_SIZE = 128;

    public function createTokenSignature(JWSHeader $header, JWSPayload $payload, string $secret): JWSSignature
    {
        $this->validateSecretKey(AlgorithmType::HS512, $secret, self::KEY_SIZE);

        $signature = hash_hmac(
            'sha512',
            $this->getJWSInput($header, $payload),
            $secret
        );

        return new JWSSignature($signature);
    }

    public function createRefreshTokenSignature(\DateTimeImmutable $expiredAt, string $randomBinary, string $secret): string
    {
        $this->validateSecretKey(AlgorithmType::HS512, $secret, self::KEY_SIZE);

        return hash_hmac(
            'sha512',
            $this->getRefreshTokenInput($expiredAt, $randomBinary),
            $secret
        );
    }
}
