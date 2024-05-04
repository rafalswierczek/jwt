<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Factory;

use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\Uuid4\Uuid4Factory;

final class JWSPayloadFactory
{
    public const VALID_MINUTES = 15;

    public static function create(string $userId, ?array $userInfo = null): JWSPayload
    {
        return new JWSPayload(
            id: (string) Uuid4Factory::createBinary(),
            issuer: 'Authentication server',
            subject: $userId,
            issuedAt: new \DateTimeImmutable(),
            expirationTime: new \DateTimeImmutable('+' . self::VALID_MINUTES . ' minutes'),
            data: $userInfo,
        );
    }
}
