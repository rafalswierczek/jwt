<?php

declare(strict_types=1);

namespace rafalswierczek\jwt;

use rafalswierczek\jwt\Algorithm\AlgorithmFQCN;

interface JWTValidatorInterface
{
    public function isValid(string $jwt, string $jwtSecret, AlgorithmFQCN $algorithmFQCN): bool;
}
