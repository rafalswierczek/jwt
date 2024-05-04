<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Factory;

use rafalswierczek\JWT\JWS\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWS\Enum\Header\Type;
use rafalswierczek\JWT\JWS\Model\JWSHeader;

final class JWSHeaderFactory
{
    public static function create(Algorithm $algorithm = Algorithm::HS256): JWSHeader
    {
        return new JWSHeader(
            type: Type::JWS,
            algorithm: $algorithm,
        );
    }
}
