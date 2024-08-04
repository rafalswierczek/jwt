<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Issuer;

use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
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

    public function generateCompactJWS(JWSHeader $header, JWSPayload $payload, string $secret): string
    {
        $jws = $this->generateJWS($header, $payload, $secret);

        return $this->serializer->compactSerializeJWS($jws);
    }

    public function generateJsonJWS(JWSHeader $header, JWSPayload $payload, string $secret, ?JWSUnprotectedHeader $unprotectedHeader = null): string
    {
        $jws = $this->generateJWS($header, $payload, $secret, $unprotectedHeader);

        return $this->serializer->jsonSerializeJWS($jws);
    }

    public function generateJWS(JWSHeader $header, JWSPayload $payload, string $secret, ?JWSUnprotectedHeader $unprotectedHeader = null): JWS
    {
        $signature = $this->generateSignature($header, $payload, $secret);

        return new JWS($header, $payload, $signature, $unprotectedHeader);
    }

    private function generateSignature(JWSHeader $header, JWSPayload $payload, string $secret): JWSSignature
    {
        $algorithm = $this->algorithmProvider->getAlgorithm($header->algorithmType);

        return $algorithm->createTokenSignature($header, $payload, $secret);
    }
}
