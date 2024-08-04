<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Verifier;

use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Exception\CannotMatchAudienceException;
use rafalswierczek\JWT\JWS\Exception\JWSCompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSJsonException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Exception\JWSHasExpiredException;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class JWSVerifier implements JWSVerifierInterface
{
    public function __construct(
        private AlgorithmProviderInterface $algorithmProvider,
        private JWSSerializerInterface $serializer,
    ) {
    }

    /**
     * @throws CannotMatchAudienceException
     * @throws JWSCompromisedSignatureException
     * @throws JWSHasExpiredException
     * @throws InvalidJWSCompactException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     * @throws InvalidBase64InputException
     */
    public function verifyCompactJWS(string $compactJWS, string $secret, string $validAudienceElement): void
    {
        $jws = $this->serializer->compactDeserializeJWS($compactJWS);

        $this->verify($jws, $secret, $validAudienceElement);
    }

    /**
     * @throws CannotMatchAudienceException
     * @throws JWSCompromisedSignatureException
     * @throws JWSHasExpiredException
     * @throws InvalidJWSJsonException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     * @throws InvalidBase64InputException
     */
    public function verifyJsonJWS(string $jsonJWS, string $secret, string $validAudienceElement): void
    {
        $jws = $this->serializer->jsonDeserializeJWS($jsonJWS);

        $this->verify($jws, $secret, $validAudienceElement);
    }

    /**
     * @throws CannotMatchAudienceException
     * @throws JWSCompromisedSignatureException
     * @throws JWSHasExpiredException
     */
    public function verify(JWS $jws, string $secret, string $validAudienceElement): void
    {
        $this->verifySignature($jws, $secret);
        $this->verifyExpirationTime($jws->payload);
        $this->verifyAudience($jws->payload, $validAudienceElement);
    }

    /**
     * @throws JWSCompromisedSignatureException
     */
    private function verifySignature(JWS $jws, string $secret): void
    {
        $algorithm = $this->algorithmProvider->getAlgorithm($jws->header->algorithmType);

        $computedSignature = $algorithm->createTokenSignature($jws->header, $jws->payload, $secret);

        if ((string) $jws->signature !== (string) $computedSignature) {
            $compactJWS = $this->serializer->compactSerializeJWS($jws);

            throw new JWSCompromisedSignatureException("Signature of following JWS is compromised: $compactJWS");
        }
    }

    /**
     * @throws JWSHasExpiredException
     */
    private function verifyExpirationTime(JWSPayload $payload): void
    {
        if (new \DateTime() > $payload->expirationTime) {
            throw new JWSHasExpiredException("JWS with id {$payload->id} has expired");
        }
    }

    /**
     * @throws CannotMatchAudienceException
     */
    private function verifyAudience(JWSPayload $payload, string $validAudienceElement): void
    {
        if (empty($audienceFromRequest = $payload->audience)) {
            return;
        }

        if (false === in_array($validAudienceElement, $audienceFromRequest)) {
            throw new CannotMatchAudienceException(sprintf('Cannot find %s in audience [%s]', $validAudienceElement, implode(', ', $audienceFromRequest)));
        }
    }
}
