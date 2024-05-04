<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Enum\Header;

enum Algorithm: string
{
    case HS256 = 'HMAC using SHA-256';
    case HS384 = 'HMAC using SHA-384';
    case HS512 = 'HMAC using SHA-512';
    case RS256 = 'RSASSA-PKCS1-v1_5 using SHA-256';
    case RS384 = 'RSASSA-PKCS1-v1_5 using SHA-384';
    case RS512 = 'RSASSA-PKCS1-v1_5 using SHA-512';
    case ES256 = 'ECDSA using P-256 and SHA-256';
    case ES384 = 'ECDSA using P-384 and SHA-384';
    case ES512 = 'ECDSA using P-512 and SHA-512';
    case PS256 = 'RSASSA-PSS using SHA-256 and MGF1 with SHA-256';
    case PS384 = 'RSASSA-PSS using SHA-384 and MGF1 with SHA-384';
    case PS512 = 'RSASSA-PSS using SHA-512 and MGF1 with SHA-512';

    public static function tryFromName(string $name): ?self
    {
        foreach (self::cases() as $case) {
            if ($name === $case->name) {
                return $case;
            }
        }

        return null;
    }
}
