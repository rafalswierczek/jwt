<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Enum\Header\TokenType;
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

    public static function getHeader(AlgorithmType $algorithmType = AlgorithmType::HS256): JWSHeader
    {
        return new JWSHeader(TokenType::JWS, $algorithmType);
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
            audience: ['Resource server 1', 'Resource server 2'],
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

    public static function getJWS(): JWS
    {
        return new JWS(
            self::getHeader(),
            self::getPayload(),
            self::getSignature(),
        );
    }

    public static function getJWSWithUnprotectedHeader(): JWS
    {
        return new JWS(
            self::getHeader(),
            self::getPayload(),
            self::getSignature(),
            self::getUnprotectedHeader(),
        );
    }
}
