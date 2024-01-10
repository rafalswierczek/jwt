<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuer;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuerInterface;
use rafalswierczek\JWT\JWS\Verifier\JWSVerifier;
use rafalswierczek\JWT\JWS\Verifier\JWSVerifierInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;

class JWSVerifierTest extends TestCase
{
    private JWSVerifierInterface $verifier;

    private JWSIssuerInterface $issuer;

    private JWSSerializerInterface $serializer;

    protected function setUp(): void
    {
        $serializer = new JWSSerializer(new JWSHeaderSerializer(), new JWSPayloadSerializer());
        $algorithmProvider = new AlgorithmProvider($serializer);
        $verifier = new JWSVerifier($algorithmProvider, $serializer);
        $issuer = new JWSIssuer($algorithmProvider, $serializer);

        $this->issuer = $issuer;
        $this->verifier = $verifier;
        $this->serializer = $serializer;
    }

    public function testVerify(): void
    {
        $this->expectNotToPerformAssertions();

        $secret = JWSModel::getSecret();

        $compactJws = $this->issuer->getCompactJWS(JWSModel::getHeader(), JWSModel::getPayload(), $secret);

        $jws = $this->serializer->compactDeserializeJWS($compactJws);

        $this->verifier->verify($jws, $secret);
    }
}
