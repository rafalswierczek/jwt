<?php

declare(strict_types=1);

namespace rafalswierczek\jwt;

interface JWTReceiverInterface
{
    public function getUserId(string $jwt): string;
}
