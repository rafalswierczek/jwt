<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\HS256;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuer;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;

class JWSIssuerTest extends TestCase
{
    private JWSIssuerInterface $issuer;

    private JWSSerializerInterface $serializer;

    protected function setUp(): void
    {
        $serializer = new JWSSerializer(new JWSHeaderSerializer(), new JWSPayloadSerializer());
        $algorithmProvider = new AlgorithmProvider($serializer);
        $issuer = new JWSIssuer($algorithmProvider, $serializer);

        $this->issuer = $issuer;
        $this->serializer = $serializer;
    }

    public function testGetCompactJWSUsingHS256(): void
    {
        $algorithmInstance = new HS256($this->serializer);
        $header = JWSModel::getHeader(Algorithm::HS256);
        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret();

        $expectedCompactJws = sprintf('%s.%s.%s',
            $this->serializer->base64EncodeHeader($header),
            $this->serializer->base64EncodePayload($payload),
            $this->serializer->base64EncodeSignature($algorithmInstance->createSignature($header, $payload, $secret)),
        );

        $compactJws = $this->issuer->getCompactJWS($header, $payload, $secret);

        $this->assertSame($expectedCompactJws, $compactJws);
    }

    public function testGetJsonJWSUsingHS256(): void
    {
        $algorithmInstance = new HS256($this->serializer);
        $header = JWSModel::getHeader(Algorithm::HS256);
        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret();
        $unprotectedHeader = JWSModel::getUnprotectedHeader();

        $expectedJsonJws = json_encode([
            'protected' => $this->serializer->base64EncodeHeader($header),
            'payload' => $this->serializer->base64EncodePayload($payload),
            'signature' => $this->serializer->base64EncodeSignature($algorithmInstance->createSignature($header, $payload, $secret)),
            'header' => $this->serializer->base64EncodeUnprotectedHeader($unprotectedHeader),
        ]);

        $jsonJws = $this->issuer->getJsonJWS($header, $payload, $secret, $unprotectedHeader);

        $this->assertSame($expectedJsonJws, $jsonJws);
    }
}
