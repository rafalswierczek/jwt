<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Verifier;

use rafalswierczek\JWT\JWS\Exception\CannotMatchAudienceException;
use rafalswierczek\JWT\JWS\Exception\CompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\TokenHasExpiredException;
use rafalswierczek\JWT\JWS\Model\JWS;

interface JWSVerifierInterface
{
    /**
     * @throws CannotMatchAudienceException
     * @throws CompromisedSignatureException
     * @throws TokenHasExpiredException
     */
    public function verify(JWS $jws, string $secret, string $validAudience): void;
}
