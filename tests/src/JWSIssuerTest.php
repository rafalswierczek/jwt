<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\HS256;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuer;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuerInterface;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSSignatureSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSignatureSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSUnprotectedHeaderSerializer;

class JWSIssuerTest extends TestCase
{
    private JWSIssuerInterface $issuer;

    private JWSHeaderSerializerInterface $headerSerializer;

    private JWSPayloadSerializerInterface $payloadSerializer;

    private JWSSignatureSerializerInterface $signatureSerializer;

    private JWSUnprotectedHeaderSerializer $unprotectedHeaderSerializer;

    private JWSSerializerInterface $serializer;

    protected function setUp(): void
    {
        $headerSerializer = new JWSHeaderSerializer();
        $payloadSerializer = new JWSPayloadSerializer();
        $signatureSerializer = new JWSSignatureSerializer();
        $unprotectedHeaderSerializer = new JWSUnprotectedHeaderSerializer();
        $serializer = new JWSSerializer($headerSerializer, $payloadSerializer, $signatureSerializer, $unprotectedHeaderSerializer);
        $algorithmProvider = new AlgorithmProvider($headerSerializer, $payloadSerializer);
        $issuer = new JWSIssuer($algorithmProvider, $serializer);

        $this->headerSerializer = $headerSerializer;
        $this->payloadSerializer = $payloadSerializer;
        $this->signatureSerializer = $signatureSerializer;
        $this->unprotectedHeaderSerializer = $unprotectedHeaderSerializer;
        $this->serializer = $serializer;
        $this->issuer = $issuer;
    }

    public function testGetCompactJWSUsingHS256(): void
    {
        $algorithmInstance = new HS256($this->headerSerializer, $this->payloadSerializer);
        $header = JWSModel::getHeader();
        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret();
        $signature = $algorithmInstance->createSignature($header, $payload, $secret);

        $expectedCompactJWS = sprintf(
            '%s.%s.%s',
            $this->headerSerializer->base64Encode($header),
            $this->payloadSerializer->base64Encode($payload),
            $this->signatureSerializer->base64Encode($signature),
        );

        $compactJWS = $this->issuer->getCompactJWS($header, $payload, $secret);

        $this->assertSame($expectedCompactJWS, $compactJWS);
    }

    public function testGetJsonJWSUsingHS256(): void
    {
        $algorithmInstance = new HS256($this->headerSerializer, $this->payloadSerializer);
        $header = JWSModel::getHeader();
        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret();
        $unprotectedHeader = JWSModel::getUnprotectedHeader();
        $signature = $algorithmInstance->createSignature($header, $payload, $secret);

        $expectedJsonJWS = json_encode([
            'protected' => $this->headerSerializer->base64Encode($header),
            'payload' => $this->payloadSerializer->base64Encode($payload),
            'signature' => $this->signatureSerializer->base64Encode($signature),
            'header' => $this->unprotectedHeaderSerializer->base64Encode($unprotectedHeader),
        ]);

        $jsonJWS = $this->issuer->getJsonJWS($header, $payload, $secret, $unprotectedHeader);

        $this->assertSame($expectedJsonJWS, $jsonJWS);
    }

    public function testGetJWSUsingHS256(): void
    {
        $algorithmInstance = new HS256($this->headerSerializer, $this->payloadSerializer);
        $header = JWSModel::getHeader();
        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret();
        $signature = $algorithmInstance->createSignature($header, $payload, $secret);

        $expectedJWS = new JWS($header, $payload, $signature);

        $jws = $this->issuer->getJWS($header, $payload, $secret);

        $this->assertSame(
            $this->serializer->compactSerializeJWS($expectedJWS),
            $this->serializer->compactSerializeJWS($jws),
        );
    }
}
