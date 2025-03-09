<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Verifier;

use rafalswierczek\JWT\JWS\Exception\InvalidRefreshTokenCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidRefreshTokenException;
use rafalswierczek\JWT\JWS\Exception\RefreshTokenCompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\RefreshTokenHasExpiredException;
use rafalswierczek\JWT\JWS\Model\RefreshToken;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

interface RefreshTokenVerifierInterface
{
    /**
     * @param string $compactRefreshToken Compact refresh token with format: base64AlgorithmName.base64ExpireTimestamp.base64RandomBinary.base64Signature
     *
     * @throws RefreshTokenCompromisedSignatureException
     * @throws RefreshTokenHasExpiredException
     * @throws InvalidRefreshTokenCompactException
     * @throws InvalidRefreshTokenException
     * @throws InvalidBase64InputException
     */
    public function verifyCompactRefreshToken(string $compactRefreshToken, string $secret): void;

    /**
     * @throws RefreshTokenCompromisedSignatureException
     * @throws RefreshTokenHasExpiredException
     */
    public function verify(RefreshToken $refreshToken, string $secret): void;
}
