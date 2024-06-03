<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWE\Model;

use rafalswierczek\JWT\JWE\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWE\Enum\Header\ContentType;
use rafalswierczek\JWT\JWE\Enum\Header\TokenType;

final readonly class JWEHeader
{
    public function __construct(
        public TokenType $tokenType,
        public ContentType $contentType,
        public AlgorithmType $algorithmType,
    ) {
    }
}
