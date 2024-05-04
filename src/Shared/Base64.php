<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Shared;

use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class Base64
{
    public static function urlEncode(string $value): string
    {
        $base64 = base64_encode($value);

        return rtrim(strtr($base64, '+/', '-_'), '=');
    }

    public static function urlDecode(string $base64urlEncoded): string
    {
        $base64 = strtr($base64urlEncoded, '-_', '+/');

        $base64 .= match (strlen($base64) % 4) {
            2 => '==',
            3 => '=',
            default => '',
        };

        return base64_decode($base64, true) ?: throw new InvalidBase64InputException("Invalid input data for decoding: $base64urlEncoded");
    }
}
