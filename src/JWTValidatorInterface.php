<?php

declare(strict_types=1);

namespace rafalswierczek\JWT;

use rafalswierczek\JWT\Algorithm\AlgorithmFQCN;

interface JWTValidatorInterface
{
    public function isValid(string $jwt, string $jwtSecret, AlgorithmFQCN $algorithmFQCN): bool;
}
