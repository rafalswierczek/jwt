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
     * @return list<string>
     */
    public static function listOfString(mixed $value): array
    {
        if (false === is_array($value)) {
            throw new \TypeError();
        }

        foreach ($value as $element) {
            if (false === is_string($element)) {
                throw new \TypeError();
            }
        }

        /** @var array<mixed, string> $list */
        $list = $value;

        return array_values($list);
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
