<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

class JWSSignature
{
    public function __construct(private string $signature)
    {
    }

    public function __toString(): string
    {
        return $this->signature;
    }
}
