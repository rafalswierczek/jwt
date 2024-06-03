<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

final readonly class JWSUnprotectedHeader
{
    /**
     * @param array<string, string> $data
     */
    public function __construct(public array $data)
    {
    }
}
