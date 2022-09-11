<?php

declare(strict_types=1);

namespace rafalswierczek\jwt;

interface JWTUserProviderInterface
{
    public function fetchUser(int|string $userIdentifier): object;
}
