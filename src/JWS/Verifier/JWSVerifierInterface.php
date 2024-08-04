<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Verifier;

use rafalswierczek\JWT\JWS\Exception\CannotMatchAudienceException;
use rafalswierczek\JWT\JWS\Exception\JWSCompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSJsonException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Exception\JWSHasExpiredException;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

interface JWSVerifierInterface
{
    /**
     * @throws CannotMatchAudienceException
     * @throws JWSCompromisedSignatureException
     * @throws JWSHasExpiredException
     * @throws InvalidJWSCompactException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     * @throws InvalidBase64InputException
     */
    public function verifyCompactJWS(string $compactJWS, string $secret, string $validAudienceElement): void;

    /**
     * @throws CannotMatchAudienceException
     * @throws JWSCompromisedSignatureException
     * @throws JWSHasExpiredException
     * @throws InvalidJWSJsonException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     * @throws InvalidBase64InputException
     */
    public function verifyJsonJWS(string $jsonJWS, string $secret, string $validAudienceElement): void;

    /**
     * @throws CannotMatchAudienceException
     * @throws JWSCompromisedSignatureException
     * @throws JWSHasExpiredException
     */
    public function verify(JWS $jws, string $secret, string $validAudienceElement): void;
}
