<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Verifier;

use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Exception\InvalidRefreshTokenCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidRefreshTokenException;
use rafalswierczek\JWT\JWS\Exception\RefreshTokenCompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\RefreshTokenHasExpiredException;
use rafalswierczek\JWT\JWS\Model\RefreshToken;
use rafalswierczek\JWT\JWS\Serializer\RefreshTokenSerializerInterface;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class RefreshTokenVerifier implements RefreshTokenVerifierInterface
{
    public function __construct(
        private RefreshTokenSerializerInterface $serializer,
        private AlgorithmProviderInterface $algorithmProvider,
    ) {
    }

    /**
     * @throws RefreshTokenCompromisedSignatureException
     * @throws RefreshTokenHasExpiredException
     * @throws InvalidRefreshTokenCompactException
     * @throws InvalidRefreshTokenException
     * @throws InvalidBase64InputException
     */
    public function verifyCompactRefreshToken(string $compactRefreshToken, string $secret): void
    {
        $refreshToken = $this->serializer->compactDeserializeRefreshToken($compactRefreshToken);

        $this->verify($refreshToken, $secret);
    }

    /**
     * @throws RefreshTokenCompromisedSignatureException
     * @throws RefreshTokenHasExpiredException
     */
    public function verify(RefreshToken $refreshToken, string $secret): void
    {
        $this->verifySignature($refreshToken, $secret);
        $this->verifyExpirationTime($refreshToken);
    }

    /**
     * @throws RefreshTokenCompromisedSignatureException
     */
    private function verifySignature(RefreshToken $refreshToken, string $secret): void
    {
        $algorithm = $this->algorithmProvider->getAlgorithm($refreshToken->algorithmType);

        $computedSignature = $algorithm->createRefreshTokenSignature($refreshToken->expiredAt, $refreshToken->randomBinary, $secret);

        if ($refreshToken->signature !== $computedSignature) {
            $compactRefreshToken = $this->serializer->compactSerializeRefreshToken($refreshToken);

            throw new RefreshTokenCompromisedSignatureException("Signature of following refresh token is compromised: $compactRefreshToken");
        }
    }

    /**
     * @throws RefreshTokenHasExpiredException
     */
    private function verifyExpirationTime(RefreshToken $refreshToken): void
    {
        if (new \DateTime() > $refreshToken->expiredAt) {
            $compactRefreshToken = $this->serializer->compactSerializeRefreshToken($refreshToken);

            throw new RefreshTokenHasExpiredException("This refresh token has expired: $compactRefreshToken");
        }
    }
}
