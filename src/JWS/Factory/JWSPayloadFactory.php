<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Factory;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\Uuid4\Uuid4Factory;

final class JWSPayloadFactory
{
    public const VALID_MINUTES = 15;

    /**
     * @param array<string> $audience
     * @param array<mixed>|null $userInfo
     *
     * @throws InvalidJWSPayloadException
     */
    public static function create(string $userId, ?array $audience = null, ?array $userInfo = null): JWSPayload
    {
        return new JWSPayload(
            id: (string) Uuid4Factory::createBinary(),
            issuer: 'Authentication server',
            subject: $userId,
            issuedAt: new \DateTimeImmutable(),
            expirationTime: new \DateTimeImmutable('+' . self::VALID_MINUTES . ' minutes'),
            audience: $audience,
            data: $userInfo,
        );
    }
}
