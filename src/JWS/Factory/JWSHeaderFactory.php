<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Factory;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Enum\Header\TokenType;
use rafalswierczek\JWT\JWS\Model\JWSHeader;

final class JWSHeaderFactory
{
    public static function create(AlgorithmType $algorithmType = AlgorithmType::HS256): JWSHeader
    {
        return new JWSHeader(
            tokenType: TokenType::JWS,
            algorithmType: $algorithmType,
        );
    }
}
