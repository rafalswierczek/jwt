<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Model\JWSUnprotectedHeader;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;
use rafalswierczek\JWT\Shared\Base64;

class JWSSerializerTest extends TestCase
{
    private JWSSerializerInterface $serializer;

    protected function setUp(): void
    {
        $this->serializer = new JWSSerializer(new JWSHeaderSerializer(), new JWSPayloadSerializer());
    }

    public function testBase64EncodeHeader(): void
    {
        $header = JWSModel::getHeader();

        $base64UrlHeader = $this->serializer->base64EncodeHeader($header);

        $expectedBase64UrlHeader = Base64::UrlEncode((string) json_encode([
            'typ' => $header->getTokenType()->name,
            'alg' => $header->getAlgorithmType()->name,
        ]));

        $this->assertSame($expectedBase64UrlHeader, $base64UrlHeader);
    }

    public function testBase64DecodeHeader(): void
    {
        $expectedHeader = JWSModel::getHeader();

        $base64UrlHeader = $this->serializer->base64EncodeHeader($expectedHeader);

        $header = $this->serializer->base64DecodeHeader($base64UrlHeader);

        $this->assertSame($expectedHeader->getTokenType(), $header->getTokenType());
        $this->assertSame($expectedHeader->getAlgorithmType(), $header->getAlgorithmType());
    }

    public function testBase64EncodePayload(): void
    {
        $payload = JWSModel::getPayload();

        $base64UrlPayload = $this->serializer->base64EncodePayload($payload);

        $expectedBase64UrlPayload = Base64::UrlEncode((string) json_encode([
            'jti' => $payload->getId(),
            'iss' => $payload->getIssuer(),
            'sub' => $payload->getSubject(),
            'iat' => $payload->getIssuedAt()->getTimestamp(),
            'exp' => $payload->getExpirationTime()->getTimestamp(),
            'nbf' => $payload->getNotBefore()?->getTimestamp(),
            'aud' => $payload->getAudience(),
            'data' => $payload->getData(),
        ]));

        $this->assertSame($expectedBase64UrlPayload, $base64UrlPayload);
    }

    public function testBase64DecodePayload(): void
    {
        $expectedPayload = JWSModel::getPayload();

        $base64UrlPayload = $this->serializer->base64EncodePayload($expectedPayload);

        $payload = $this->serializer->base64DecodePayload($base64UrlPayload);

        $this->assertSame($expectedPayload->getId(), $payload->getId());
        $this->assertSame($expectedPayload->getIssuer(), $payload->getIssuer());
        $this->assertSame($expectedPayload->getSubject(), $payload->getSubject());
        $this->assertSame($expectedPayload->getIssuedAt()->getTimestamp(), $payload->getIssuedAt()->getTimestamp());
        $this->assertSame($expectedPayload->getExpirationTime()->getTimestamp(), $payload->getExpirationTime()->getTimestamp());
        $this->assertSame($expectedPayload->getNotBefore()?->getTimestamp(), $payload->getNotBefore()?->getTimestamp());
        $this->assertSame($expectedPayload->getAudience(), $payload->getAudience());
        $this->assertSame($expectedPayload->getData(), $payload->getData());
    }

    public function testBase64EncodeSignature(): void
    {
        $signature = JWSModel::getSignature();

        $base64UrlSignature = $this->serializer->base64EncodeSignature($signature);

        $expectedBase64UrlSignature = Base64::UrlEncode((string) $signature);

        $this->assertSame($expectedBase64UrlSignature, $base64UrlSignature);
    }

    public function testBase64DecodeSignature(): void
    {
        $expectedSignature = JWSModel::getSignature();

        $base64UrlSignature = $this->serializer->base64EncodeSignature($expectedSignature);

        $signature = $this->serializer->base64DecodeSignature($base64UrlSignature);

        $this->assertSame((string) $expectedSignature, (string) $signature);
    }

    public function testBase64EncodeUnprotectedHeader(): void
    {
        $header = JWSModel::getUnprotectedHeader();

        $base64UrlUnprotectedHeader = $this->serializer->base64EncodeUnprotectedHeader($header);

        $expectedBase64UrlUnprotectedHeader = Base64::urlEncode((string) json_encode($header->getData()));

        $this->assertSame($expectedBase64UrlUnprotectedHeader, $base64UrlUnprotectedHeader);
    }

    public function testBase64DecodeUnprotectedHeader(): void
    {
        $expectedHeader = JWSModel::getUnprotectedHeader();

        $base64UrlUnprotectedHeader = $this->serializer->base64EncodeUnprotectedHeader($expectedHeader);

        $unprotectedHeader = $this->serializer->base64DecodeUnprotectedHeader($base64UrlUnprotectedHeader);

        $this->assertSame($expectedHeader->getData(), $unprotectedHeader->getData());
    }

    public function testCompactSerializeJws(): void
    {
        $jws = JWSModel::getJws();

        $compactJws = $this->serializer->compactSerializeJws($jws);

        $expectedCompactJws = sprintf(
            '%s.%s.%s',
            $this->serializer->base64EncodeHeader($jws->getHeader()),
            $this->serializer->base64EncodePayload($jws->getPayload()),
            $this->serializer->base64EncodeSignature($jws->getSignature()),
        );

        $this->assertSame($expectedCompactJws, $compactJws);
    }

    public function testCompactDeserializeJWS(): void
    {
        $expectedJws = JWSModel::getJws();

        $compactJws = $this->serializer->compactSerializeJws($expectedJws);

        $jws = $this->serializer->compactDeserializeJWS($compactJws);

        $this->assertSame($expectedJws->getHeader()->getTokenType()->value, $jws->getHeader()->getTokenType()->value);
        $this->assertSame($expectedJws->getHeader()->getAlgorithmType()->value, $jws->getHeader()->getAlgorithmType()->value);

        $this->assertSame($expectedJws->getPayload()->getId(), $jws->getPayload()->getId());
        $this->assertSame($expectedJws->getPayload()->getIssuer(), $jws->getPayload()->getIssuer());
        $this->assertSame($expectedJws->getPayload()->getSubject(), $jws->getPayload()->getSubject());
        $this->assertSame($expectedJws->getPayload()->getIssuedAt()->getTimestamp(), $jws->getPayload()->getIssuedAt()->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getExpirationTime()->getTimestamp(), $jws->getPayload()->getExpirationTime()->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getNotBefore()?->getTimestamp(), $jws->getPayload()->getNotBefore()?->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getAudience(), $jws->getPayload()->getAudience());
        $this->assertSame($expectedJws->getPayload()->getData(), $jws->getPayload()->getData());

        $this->assertSame((string) $expectedJws->getSignature(), (string) $jws->getSignature());
    }

    public function testJsonSerializeJws(): void
    {
        $jws = JWSModel::getJws();

        $jsonJws = $this->serializer->jsonSerializeJws($jws);

        $expectedJsonJws = json_encode([
            'protected' => $this->serializer->base64EncodeHeader($jws->getHeader()),
            'payload' => $this->serializer->base64EncodePayload($jws->getPayload()),
            'signature' => $this->serializer->base64EncodeSignature($jws->getSignature()),
        ]);

        $this->assertSame($expectedJsonJws, $jsonJws);
    }

    public function testJsonSerializeJwsWithUnprotectedHeader(): void
    {
        $jws = JWSModel::getJws(includeUnprotectedHeader: true);

        $jsonJws = $this->serializer->jsonSerializeJws($jws);

        /** @var JWSUnprotectedHeader $unprotectedHeader */
        $unprotectedHeader = $jws->getUnprotectedHeader();

        $expectedJsonJws = json_encode([
            'protected' => $this->serializer->base64EncodeHeader($jws->getHeader()),
            'payload' => $this->serializer->base64EncodePayload($jws->getPayload()),
            'signature' => $this->serializer->base64EncodeSignature($jws->getSignature()),
            'header' => $this->serializer->base64EncodeUnprotectedHeader($unprotectedHeader),
        ]);

        $this->assertSame($expectedJsonJws, $jsonJws);
    }

    public function testJsonDeserializeJws(): void
    {
        $expectedJws = JWSModel::getJws();

        $jsonJws = $this->serializer->jsonSerializeJws($expectedJws);

        $jws = $this->serializer->jsonDeserializeJws($jsonJws);

        $this->assertSame($expectedJws->getHeader()->getTokenType()->value, $jws->getHeader()->getTokenType()->value);
        $this->assertSame($expectedJws->getHeader()->getAlgorithmType()->value, $jws->getHeader()->getAlgorithmType()->value);

        $this->assertSame($expectedJws->getPayload()->getId(), $jws->getPayload()->getId());
        $this->assertSame($expectedJws->getPayload()->getIssuer(), $jws->getPayload()->getIssuer());
        $this->assertSame($expectedJws->getPayload()->getSubject(), $jws->getPayload()->getSubject());
        $this->assertSame($expectedJws->getPayload()->getIssuedAt()->getTimestamp(), $jws->getPayload()->getIssuedAt()->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getExpirationTime()->getTimestamp(), $jws->getPayload()->getExpirationTime()->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getNotBefore()?->getTimestamp(), $jws->getPayload()->getNotBefore()?->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getAudience(), $jws->getPayload()->getAudience());
        $this->assertSame($expectedJws->getPayload()->getData(), $jws->getPayload()->getData());

        $this->assertSame((string) $expectedJws->getSignature(), (string) $jws->getSignature());
    }

    public function testJsonDeserializeJwsWithUnprotectedHeader(): void
    {
        $expectedJws = JWSModel::getJws(includeUnprotectedHeader: true);

        $jsonJws = $this->serializer->jsonSerializeJws($expectedJws);

        $jws = $this->serializer->jsonDeserializeJws($jsonJws);

        $this->assertSame($expectedJws->getHeader()->getTokenType()->value, $jws->getHeader()->getTokenType()->value);
        $this->assertSame($expectedJws->getHeader()->getAlgorithmType()->value, $jws->getHeader()->getAlgorithmType()->value);

        $this->assertSame($expectedJws->getPayload()->getId(), $jws->getPayload()->getId());
        $this->assertSame($expectedJws->getPayload()->getIssuer(), $jws->getPayload()->getIssuer());
        $this->assertSame($expectedJws->getPayload()->getSubject(), $jws->getPayload()->getSubject());
        $this->assertSame($expectedJws->getPayload()->getIssuedAt()->getTimestamp(), $jws->getPayload()->getIssuedAt()->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getExpirationTime()->getTimestamp(), $jws->getPayload()->getExpirationTime()->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getNotBefore()?->getTimestamp(), $jws->getPayload()->getNotBefore()?->getTimestamp());
        $this->assertSame($expectedJws->getPayload()->getAudience(), $jws->getPayload()->getAudience());
        $this->assertSame($expectedJws->getPayload()->getData(), $jws->getPayload()->getData());

        $this->assertSame((string) $expectedJws->getSignature(), (string) $jws->getSignature());

        $this->assertSame($expectedJws->getUnprotectedHeader()?->getData(), $jws->getUnprotectedHeader()?->getData());
    }
}
