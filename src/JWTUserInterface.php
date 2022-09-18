<?php

declare(strict_types=1);

namespace rafalswierczek\JWT;

interface JWTUserInterface
{
    public function getId(): string;

    public function getJWT(): string;
}
