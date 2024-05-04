<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Enum\Header;

enum Type: string
{
    case JWS = 'JWS';

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
