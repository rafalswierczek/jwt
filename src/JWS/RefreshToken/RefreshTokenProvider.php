<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\RefreshToken;

final class RefreshTokenProvider implements RefreshTokenProviderInterface
{
    public function getRefreshToken(): string
    {
        return bin2hex(random_bytes(50));
    }
}
