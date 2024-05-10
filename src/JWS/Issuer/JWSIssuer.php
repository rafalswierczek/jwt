<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Issuer;

use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Exception\MissingAlgorithmImplementationException;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;
use rafalswierczek\JWT\JWS\Model\JWSUnprotectedHeader;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;

final class JWSIssuer implements JWSIssuerInterface
{
    public function __construct(
        private AlgorithmProviderInterface $algorithmProvider,
        private JWSSerializerInterface $serializer,
    ) {
    }

    /**
     * @throws MissingAlgorithmImplementationException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function getCompactJWS(JWSHeader $header, JWSPayload $payload, string $secret): string
    {
        $jws = $this->getJWS($header, $payload, $secret);

        return $this->serializer->compactSerializeJWS($jws);
    }

    /**
     * @throws MissingAlgorithmImplementationException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function getJsonJWS(JWSHeader $header, JWSPayload $payload, string $secret, ?JWSUnprotectedHeader $unprotectedHeader = null): string
    {
        $jws = $this->getJWS($header, $payload, $secret, $unprotectedHeader);

        return $this->serializer->jsonSerializeJws($jws);
    }

    /**
     * @throws MissingAlgorithmImplementationException
     */
    public function getJWS(JWSHeader $header, JWSPayload $payload, string $secret, ?JWSUnprotectedHeader $unprotectedHeader = null): JWS
    {
        $signature = $this->getSignature($header, $payload, $secret);

        return new JWS($header, $payload, $signature, $unprotectedHeader);
    }

    /**
     * @throws MissingAlgorithmImplementationException
     */
    private function getSignature(JWSHeader $header, JWSPayload $payload, string $secret): JWSSignature
    {
        $algorithmInstance = $this->algorithmProvider->getAlgorithm($header->getAlgorithmType());

        return $algorithmInstance->createSignature($header, $payload, $secret);
    }
}
