<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

final class JWSUnprotectedHeader
{
    /**
     * @param array<string, string> $data
     */
    public function __construct(private array $data)
    {
    }

    /**
     * @return array<string, string>
     */
    public function getData(): array
    {
        return $this->data;
    }
}
