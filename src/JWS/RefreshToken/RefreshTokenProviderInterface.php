<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\RefreshToken;

interface RefreshTokenProviderInterface
{
    public function getRefreshToken(): string;
}
