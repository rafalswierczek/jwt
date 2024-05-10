<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWE\Model;

use rafalswierczek\JWT\JWE\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWE\Enum\Header\ContentType;
use rafalswierczek\JWT\JWE\Enum\Header\TokenType;

final class JWEHeader
{
    public function __construct(
        private TokenType $tokenType,
        private ContentType $contentType,
        private AlgorithmType $algorithmType,
    ) {
    }

    public function getType(): TokenType
    {
        return $this->tokenType;
    }

    public function getContentType(): ContentType
    {
        return $this->contentType;
    }

    public function getAlgorithm(): AlgorithmType
    {
        return $this->algorithmType;
    }
}
