<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Enum\Header\TokenType;

final readonly class JWSHeader
{
    public function __construct(
        public TokenType $tokenType,
        public AlgorithmType $algorithmType,
    ) {
    }
}
