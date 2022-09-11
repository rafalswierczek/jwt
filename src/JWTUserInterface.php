<?php

declare(strict_types=1);

namespace rafalswierczek\jwt;

interface JWTUserInterface
{
    public function getId(): string;

    public function getJWT(): string;
}
