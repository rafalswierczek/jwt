<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Shared;

final class Value
{
    public static function string(mixed $value): string
    {
        if (false === is_string($value)) {
            throw new \TypeError();
        }

        return $value;
    }

    public static function int(mixed $value): int
    {
        if (false === is_int($value)) {
            throw new \TypeError();
        }

        return $value;
    }

    /**
     * @return array<string>
     */
    public static function arrayOfString(mixed $value): array
    {
        if (false === is_array($value)) {
            throw new \TypeError();
        }

        return $value;
    }

    /**
     * @return array<mixed>
     */
    public static function arrayOfMixed(mixed $value): array
    {
        if (false === is_array($value)) {
            throw new \TypeError();
        }

        return $value;
    }
}
