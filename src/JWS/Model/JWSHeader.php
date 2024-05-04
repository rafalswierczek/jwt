<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

use rafalswierczek\JWT\JWS\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWS\Enum\Header\Type;

final class JWSHeader
{
    public function __construct(
        private Type $type,
        private Algorithm $algorithm,
    ) {
    }

    public function getType(): Type
    {
        return $this->type;
    }

    public function getAlgorithm(): Algorithm
    {
        return $this->algorithm;
    }
}
