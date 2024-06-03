<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Verifier;

use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Exception\CannotMatchAudienceException;
use rafalswierczek\JWT\JWS\Exception\CompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\TokenHasExpiredException;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;

final class JWSVerifier implements JWSVerifierInterface
{
    public function __construct(
        private AlgorithmProviderInterface $algorithmProvider,
        private JWSSerializerInterface $serializer,
    ) {
    }

    /**
     * @throws CannotMatchAudienceException
     * @throws CompromisedSignatureException
     * @throws TokenHasExpiredException
     */
    public function verify(JWS $jws, string $secret, string $validAudience): void
    {
        $header = $jws->header;
        $payload = $jws->payload;

        $algorithmInstance = $this->algorithmProvider->getAlgorithm($header->algorithmType);

        $computedSignature = $algorithmInstance->createSignature($header, $payload, $secret);

        $this->verifySignature($jws, $computedSignature);
        $this->verifyExpirationTime($payload);
        $this->verifyAudience($payload, $validAudience);
    }

    /**
     * @throws CompromisedSignatureException
     */
    private function verifySignature(JWS $jws, JWSSignature $computedSignature): void
    {
        if ((string) $jws->signature !== (string) $computedSignature) {
            $compactJWS = $this->serializer->compactSerializeJWS($jws);

            throw new CompromisedSignatureException('Signature of following JWS is compromised: ' . $compactJWS);
        }
    }

    /**
     * @throws TokenHasExpiredException
     */
    private function verifyExpirationTime(JWSPayload $payload): void
    {
        if (new \DateTime() > $payload->expirationTime) {
            throw new TokenHasExpiredException("JWS with id {$payload->id} has expired");
        }
    }

    /**
     * @throws CannotMatchAudienceException
     */
    private function verifyAudience(JWSPayload $payload, string $validAudience): void
    {
        if (empty($audienceFromRequest = $payload->audience)) {
            return;
        }

        if (false === in_array($validAudience, $audienceFromRequest)) {
            throw new CannotMatchAudienceException(sprintf('Cannot find %s in audience [%s]', $validAudience, implode(', ', $audienceFromRequest)));
        }
    }
}
