<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

final readonly class JWSSignature implements \Stringable
{
    public function __construct(public string $signature)
    {
    }

    public function __toString(): string
    {
        return $this->signature;
    }
}
