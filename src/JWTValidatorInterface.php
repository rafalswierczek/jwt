<?php

declare(strict_types=1);

namespace rafalswierczek\JWT;

use rafalswierczek\JWT\Algorithm\AlgorithmFQCN;
use rafalswierczek\JWT\Exception\{InvalidJWTSyntaxException, InvalidJWTException};

interface JWTValidatorInterface
{
    /**
     * @throws InvalidJWTException
     */
    public function validate(string $jwt, string $jwtSecret, AlgorithmFQCN $algorithmFQCN): void;

    /**
     * @throws InvalidJWTSyntaxException
     */
    public function validateSyntax(string $jwt): void;
}
