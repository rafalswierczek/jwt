<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use rafalswierczek\JWT\JWS\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWS\Enum\Header\Type;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;
use rafalswierczek\JWT\JWS\Model\JWSUnprotectedHeader;

abstract class JWSModel
{
    public static function getSecret(): string
    {
        return 'secret';
    }

    public static function getHeader(Algorithm $algorithm = Algorithm::HS256): JWSHeader
    {
        return new JWSHeader(Type::JWS, $algorithm);
    }

    public static function getPayload(): JWSPayload
    {
        return new JWSPayload(
            id: '0789d6cb-a511-4e23-a702-c1f5d3f02bf7',
            issuer: 'auth server',
            subject: 'user',
            issuedAt: new \DateTimeImmutable(),
            expirationTime: new \DateTimeImmutable('+30 minutes'),
            notBefore: new \DateTimeImmutable('+5 minutes'),
            audience: ['JWT verifier server 1', 'JWT verifier server 2'],
            data: [
                'user' => ['id' => 'a3c33869-f649-4383-87b3-5f73227c70a3'],
            ],
        );
    }

    public static function getSignature(): JWSSignature
    {
        return new JWSSignature('hash');
    }

    public static function getUnprotectedHeader(): JWSUnprotectedHeader
    {
        return new JWSUnprotectedHeader(['key' => 'example value']);
    }

    public static function getJws(bool $includeUnprotectedHeader = false): JWS
    {
        return new JWS(
            self::getHeader(),
            self::getPayload(),
            self::getSignature(),
            $includeUnprotectedHeader ? self::getUnprotectedHeader() : null,
        );
    }
}
