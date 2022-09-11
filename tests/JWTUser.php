<?php

declare(strict_types=1);

namespace rafalswierczek\jwt\tests;

use rafalswierczek\jwt\JWTUserInterface;

class JWTUser implements JWTUserInterface
{
    private string $id;

    private string $email;

    private string $jwt;

    public function getId(): string
    {
        return $this->id;
    }

    public function setId(string $id): self
    {
        $this->id = $id;

        return $this;
    }

    public function getJWT(): string
    {
        return $this->jwt;
    }

    public function setJWT(string $jwt): self
    {
        $this->jwt = $jwt;

        return $this;
    }
}
