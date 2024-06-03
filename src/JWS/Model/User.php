<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

final readonly class User
{
    public function __construct(
        public string $id,
    ) {
    }
}
