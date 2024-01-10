<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Verifier;

use rafalswierczek\JWT\JWS\Exception\CompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\MissingAlgorithmImplementationException;
use rafalswierczek\JWT\JWS\Model\JWS;

interface JWSVerifierInterface
{
    /**
     * @throws MissingAlgorithmImplementationException 
     * @throws CompromisedSignatureException
     */
    public function verify(JWS $jws, string $secret): void;
}
