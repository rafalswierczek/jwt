<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Enum\Header\TokenType;

final class JWSHeader
{
    public function __construct(
        private TokenType $tokenType,
        private AlgorithmType $algorithmType,
    ) {
    }

    public function getTokenType(): TokenType
    {
        return $this->tokenType;
    }

    public function getAlgorithmType(): AlgorithmType
    {
        return $this->algorithmType;
    }
}
