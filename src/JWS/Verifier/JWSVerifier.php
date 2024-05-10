<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Verifier;

use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Exception\CompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Exception\MissingAlgorithmImplementationException;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;

final class JWSVerifier implements JWSVerifierInterface
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
     * @throws CompromisedSignatureException
     */
    public function verify(JWS $jws, string $secret): void
    {
        $header = $jws->getHeader();
        $payload = $jws->getPayload();

        $algorithmInstance = $this->algorithmProvider->getAlgorithm($header->getAlgorithmType());

        $computedSignature = $algorithmInstance->createSignature($header, $payload, $secret);

        if ((string) $jws->getSignature() !== (string) $computedSignature) {
            $compactJws = $this->serializer->compactSerializeJws($jws);

            throw new CompromisedSignatureException('Signature of following JWS is compromised: ' . $compactJws);
        }
    }
}
