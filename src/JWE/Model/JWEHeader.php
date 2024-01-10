<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWE\Model;

use rafalswierczek\JWT\JWE\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWE\Enum\Header\ContentType;
use rafalswierczek\JWT\JWE\Enum\Header\Type;

final class JWEHeader
{
    public function __construct(
        private Type $type,
        private ContentType $contentType,
        private Algorithm $algorithm,
    ) {
    }

    public function getType(): Type
    {
        return $this->type;
    }

    public function getContentType(): ContentType
    {
        return $this->contentType;
    }

    public function getAlgorithm(): Algorithm
    {
        return $this->algorithm;
    }
}
