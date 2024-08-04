<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSJsonException;
use rafalswierczek\JWT\JWS\Model\JWSUnprotectedHeader;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSSignatureSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSUnprotectedHeaderSerializer;

class JWSSerializerTest extends TestCase
{
    private JWSSerializerInterface $jwsSerializer;
    private JWSHeaderSerializer $jwsHeaderSerializer;
    private JWSPayloadSerializer $jwsPayloadSerializer;
    private JWSSignatureSerializer $jwsSignatureSerializer;
    private JWSUnprotectedHeaderSerializer $jwsUnprotectedHeaderSerializer;

    protected function setUp(): void
    {
        $this->jwsHeaderSerializer = new JWSHeaderSerializer();
        $this->jwsPayloadSerializer = new JWSPayloadSerializer();
        $this->jwsSignatureSerializer = new JWSSignatureSerializer();
        $this->jwsUnprotectedHeaderSerializer = new JWSUnprotectedHeaderSerializer();
        $this->jwsSerializer = new JWSSerializer($this->jwsHeaderSerializer, $this->jwsPayloadSerializer, $this->jwsSignatureSerializer, $this->jwsUnprotectedHeaderSerializer);
    }

    public function testCompactSerializeJWS(): void
    {
        $jws = JWSModel::getJWS();

        $expectedCompactJWS = sprintf(
            '%s.%s.%s',
            $this->jwsHeaderSerializer->base64Encode($jws->header),
            $this->jwsPayloadSerializer->base64Encode($jws->payload),
            $this->jwsSignatureSerializer->base64Encode($jws->signature),
        );

        $compactJWS = $this->jwsSerializer->compactSerializeJWS($jws);

        $this->assertSame($expectedCompactJWS, $compactJWS);
    }

    public function testCompactDeserializeJWS(): void
    {
        $expectedJWS = JWSModel::getJWS();

        $compactJWS = $this->jwsSerializer->compactSerializeJWS($expectedJWS);

        $jws = $this->jwsSerializer->compactDeserializeJWS($compactJWS);

        $this->assertSame($expectedJWS->header->tokenType->value, $jws->header->tokenType->value);
        $this->assertSame($expectedJWS->header->algorithmType->value, $jws->header->algorithmType->value);

        $this->assertSame($expectedJWS->payload->id, $jws->payload->id);
        $this->assertSame($expectedJWS->payload->issuer, $jws->payload->issuer);
        $this->assertSame($expectedJWS->payload->subject, $jws->payload->subject);
        $this->assertSame($expectedJWS->payload->issuedAt->getTimestamp(), $jws->payload->issuedAt->getTimestamp());
        $this->assertSame($expectedJWS->payload->expirationTime->getTimestamp(), $jws->payload->expirationTime->getTimestamp());
        $this->assertSame($expectedJWS->payload->notBefore?->getTimestamp(), $jws->payload->notBefore?->getTimestamp());
        $this->assertSame($expectedJWS->payload->audience, $jws->payload->audience);
        $this->assertSame($expectedJWS->payload->data, $jws->payload->data);

        $this->assertSame((string) $expectedJWS->signature, (string) $jws->signature);
    }

    public function testInvalidJWSCompactException(): void
    {
        $compactJWS = 'a.b.c.d';

        $this->expectException(InvalidJWSCompactException::class);
        $this->expectExceptionMessage('Compact serialized JWS must contain 3 elements. Invalid JWS: ' . $compactJWS);

        $this->jwsSerializer->compactDeserializeJWS($compactJWS);
    }

    public function testJsonSerializeJWS(): void
    {
        $jws = JWSModel::getJWS();

        $expectedJsonJWS = json_encode([
            'protected' => $this->jwsHeaderSerializer->base64Encode($jws->header),
            'payload' => $this->jwsPayloadSerializer->base64Encode($jws->payload),
            'signature' => $this->jwsSignatureSerializer->base64Encode($jws->signature),
        ]);

        $jsonJWS = $this->jwsSerializer->jsonSerializeJWS($jws);

        $this->assertSame($expectedJsonJWS, $jsonJWS);
    }

    public function testJsonSerializeJWSWithUnprotectedHeader(): void
    {
        $jws = JWSModel::getJWSWithUnprotectedHeader();

        $jsonJWS = $this->jwsSerializer->jsonSerializeJWS($jws);

        /** @var JWSUnprotectedHeader $unprotectedHeader */
        $unprotectedHeader = $jws->unprotectedHeader;

        $expectedJsonJWS = json_encode([
            'protected' => $this->jwsHeaderSerializer->base64Encode($jws->header),
            'payload' => $this->jwsPayloadSerializer->base64Encode($jws->payload),
            'signature' => $this->jwsSignatureSerializer->base64Encode($jws->signature),
            'header' => $this->jwsUnprotectedHeaderSerializer->base64Encode($unprotectedHeader),
        ]);

        $this->assertSame($expectedJsonJWS, $jsonJWS);
    }

    public function testJsonDeserializeJWS(): void
    {
        $expectedJWS = JWSModel::getJWS();

        $jsonJWS = $this->jwsSerializer->jsonSerializeJWS($expectedJWS);

        $jws = $this->jwsSerializer->jsonDeserializeJWS($jsonJWS);

        $this->assertSame($expectedJWS->header->tokenType->value, $jws->header->tokenType->value);
        $this->assertSame($expectedJWS->header->algorithmType->value, $jws->header->algorithmType->value);

        $this->assertSame($expectedJWS->payload->id, $jws->payload->id);
        $this->assertSame($expectedJWS->payload->issuer, $jws->payload->issuer);
        $this->assertSame($expectedJWS->payload->subject, $jws->payload->subject);
        $this->assertSame($expectedJWS->payload->issuedAt->getTimestamp(), $jws->payload->issuedAt->getTimestamp());
        $this->assertSame($expectedJWS->payload->expirationTime->getTimestamp(), $jws->payload->expirationTime->getTimestamp());
        $this->assertSame($expectedJWS->payload->notBefore?->getTimestamp(), $jws->payload->notBefore?->getTimestamp());
        $this->assertSame($expectedJWS->payload->audience, $jws->payload->audience);
        $this->assertSame($expectedJWS->payload->data, $jws->payload->data);

        $this->assertSame((string) $expectedJWS->signature, (string) $jws->signature);
    }

    public function testJsonDeserializeJWSWithUnprotectedHeader(): void
    {
        $expectedJWS = JWSModel::getJWSWithUnprotectedHeader();

        $jsonJWS = $this->jwsSerializer->jsonSerializeJWS($expectedJWS);

        $jws = $this->jwsSerializer->jsonDeserializeJWS($jsonJWS);

        $this->assertSame($expectedJWS->header->tokenType->value, $jws->header->tokenType->value);
        $this->assertSame($expectedJWS->header->algorithmType->value, $jws->header->algorithmType->value);

        $this->assertSame($expectedJWS->payload->id, $jws->payload->id);
        $this->assertSame($expectedJWS->payload->issuer, $jws->payload->issuer);
        $this->assertSame($expectedJWS->payload->subject, $jws->payload->subject);
        $this->assertSame($expectedJWS->payload->issuedAt->getTimestamp(), $jws->payload->issuedAt->getTimestamp());
        $this->assertSame($expectedJWS->payload->expirationTime->getTimestamp(), $jws->payload->expirationTime->getTimestamp());
        $this->assertSame($expectedJWS->payload->notBefore?->getTimestamp(), $jws->payload->notBefore?->getTimestamp());
        $this->assertSame($expectedJWS->payload->audience, $jws->payload->audience);
        $this->assertSame($expectedJWS->payload->data, $jws->payload->data);

        $this->assertSame((string) $expectedJWS->signature, (string) $jws->signature);

        $this->assertSame($expectedJWS->unprotectedHeader?->data, $jws->unprotectedHeader?->data);
    }

    #[DataProvider('invalidJsonJWSProvider')]
    public function testInvalidJWSJsonException(string $missingKey, string $jsonJWS): void
    {
        $this->expectException(InvalidJWSJsonException::class);
        $this->expectExceptionMessage(sprintf('There is a missing "%s" json key in JWS: %s', $missingKey, $jsonJWS));

        $this->jwsSerializer->jsonDeserializeJWS($jsonJWS);
    }

    /**
     * @return array<mixed>
     */
    public static function invalidJsonJWSProvider(): array
    {
        return [
            [
                'missingKey' => 'protected',
                'jsonJWS' => json_encode(['protecte' => '', 'payload' => '', 'signature' => '']),
            ],
            [
                'missingKey' => 'payload',
                'jsonJWS' => json_encode(['protected' => '', 'payloa' => '', 'signature' => '']),
            ],
            [
                'missingKey' => 'signature',
                'jsonJWS' => json_encode(['protected' => '', 'payload' => '', 'signatur' => '']),
            ],
        ];
    }
}
