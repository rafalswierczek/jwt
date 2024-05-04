<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;

class JWSPayloadSerializerTest extends TestCase
{
    private JWSPayloadSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new JWSPayloadSerializer();
    }

    public function testSerializePayload(): void
    {
        $payload = new JWSPayload(
            id: 'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            issuer: 'issuer',
            subject: 'ex123',
            issuedAt: new \DateTimeImmutable(),
            expirationTime: new \DateTimeImmutable('+30 minutes'),
            notBefore: new \DateTimeImmutable('+5 minutes'),
            audience: ['app1', 'app2'],
            data: ['user' => ['id' => 'userId', 'externalId' => 'ex123', 'name' => 'user123']],
        );

        $jsonPayload = $this->serializer->jsonSerialize($payload);

        $expectedJson = sprintf(
            '{"jti":"%s","iss":"%s","sub":"%s","iat":%s,"exp":%s,"nbf":%s,"aud":%s,"data":%s}',
            $payload->getId(),
            $payload->getIssuer(),
            $payload->getSubject(),
            $payload->getIssuedAt()->getTimestamp(),
            $payload->getExpirationTime()->getTimestamp(),
            $payload->getNotBefore()?->getTimestamp(),
            json_encode($payload->getAudience()),
            json_encode($payload->getData()),
        );

        $this->assertSame($expectedJson, $jsonPayload);
    }

    public function testDeserializePayload(): void
    {
        $issuedAt = new \DateTimeImmutable();
        $expirationTime = new \DateTimeImmutable('+30 minutes');
        $notBefore = new \DateTimeImmutable('+5 minutes');

        $jsonPayload = sprintf(
            '{"jti":"%s","iss":"%s","sub":"%s","iat":%s,"exp":%s,"nbf":%s,"aud":%s,"data":%s}',
            'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            'issuer',
            'ex123',
            $issuedAt->getTimestamp(),
            $expirationTime->getTimestamp(),
            $notBefore->getTimestamp(),
            '["app1","app2"]',
            '{"user":{"id":"userId","externalId":"ex123","name":"user123"}}',
        );

        $payload = $this->serializer->jsonDeserialize($jsonPayload);

        $expectedPayload = new JWSPayload(
            id: 'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            issuer: 'issuer',
            subject: 'ex123',
            issuedAt: $issuedAt,
            expirationTime: $expirationTime,
            notBefore: $notBefore,
            audience: ['app1', 'app2'],
            data: ['user' => ['id' => 'userId', 'externalId' => 'ex123', 'name' => 'user123']],
        );

        $this->assertSame($expectedPayload->getId(), $payload->getId());
        $this->assertSame($expectedPayload->getIssuer(), $payload->getIssuer());
        $this->assertSame($expectedPayload->getSubject(), $payload->getSubject());
        $this->assertSame($expectedPayload->getIssuedAt()->getTimestamp(), $payload->getIssuedAt()->getTimestamp());
        $this->assertSame($expectedPayload->getExpirationTime()->getTimestamp(), $payload->getExpirationTime()->getTimestamp());
        $this->assertSame($expectedPayload->getNotBefore()?->getTimestamp(), $payload->getNotBefore()?->getTimestamp());
        $this->assertSame($expectedPayload->getAudience(), $payload->getAudience());
        $this->assertSame($expectedPayload->getData(), $payload->getData());
    }

    public function testDeserializePayloadPartial(): void
    {
        $issuedAt = new \DateTimeImmutable();
        $expirationTime = new \DateTimeImmutable('+30 minutes');

        $jsonPayload = sprintf(
            '{"jti":"%s","iss":"%s","sub":"%s","iat":%s,"exp":%s,"aud":%s}',
            'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            'issuer',
            'ex123',
            $issuedAt->getTimestamp(),
            $expirationTime->getTimestamp(),
            '["app1","app2"]',
        );

        $payload = $this->serializer->jsonDeserialize($jsonPayload);

        $expectedPayload = new JWSPayload(
            id: 'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            issuer: 'issuer',
            subject: 'ex123',
            issuedAt: $issuedAt,
            expirationTime: $expirationTime,
            audience: ['app1', 'app2'],
        );

        $this->assertSame($expectedPayload->getId(), $payload->getId());
        $this->assertSame($expectedPayload->getIssuer(), $payload->getIssuer());
        $this->assertSame($expectedPayload->getSubject(), $payload->getSubject());
        $this->assertSame($expectedPayload->getIssuedAt()->getTimestamp(), $payload->getIssuedAt()->getTimestamp());
        $this->assertSame($expectedPayload->getExpirationTime()->getTimestamp(), $payload->getExpirationTime()->getTimestamp());
        $this->assertNull($payload->getNotBefore());
        $this->assertSame($expectedPayload->getAudience(), $payload->getAudience());
        $this->assertNull($payload->getData());
    }

    public function testDeserializePayloadMissingId(): void
    {
        $jsonPayload = sprintf(
            '{"iss":"%s","sub":"%s","iat":%s,"exp":%s,"nbf":%s,"aud":%s,"data":%s}',
            'issuer',
            'ex123',
            (new \DateTimeImmutable())->getTimestamp(),
            (new \DateTimeImmutable('-30 minutes'))->getTimestamp(),
            (new \DateTimeImmutable('+5 minutes'))->getTimestamp(),
            '["app1","app2"]',
            '{"user":{"id":"userId","externalId":"ex123","name":"user123"}}',
        );

        $this->expectException(InvalidJWSPayloadException::class);
        $this->expectExceptionMessage('Cannot find "jti" in json payload');

        $this->serializer->jsonDeserialize($jsonPayload);
    }

    public function testDeserializePayloadExpirationTimeBeforeIssuedAt(): void
    {
        $jsonPayload = sprintf(
            '{"jti":"%s","iss":"%s","sub":"%s","iat":%s,"exp":%s,"nbf":%s,"aud":%s,"data":%s}',
            'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            'issuer',
            'ex123',
            (new \DateTimeImmutable())->getTimestamp(),
            (new \DateTimeImmutable('-30 minutes'))->getTimestamp(),
            (new \DateTimeImmutable('+5 minutes'))->getTimestamp(),
            '["app1","app2"]',
            '{"user":{"id":"userId","externalId":"ex123","name":"user123"}}',
        );

        $this->expectException(InvalidJWSPayloadException::class);
        $this->expectExceptionMessage('Expiration Time must be after Issued At');

        $this->serializer->jsonDeserialize($jsonPayload);
    }

    public function testDeserializePayloadExpirationTimeBeforeNotBefore(): void
    {
        $jsonPayload = sprintf(
            '{"jti":"%s","iss":"%s","sub":"%s","iat":%s,"exp":%s,"nbf":%s,"aud":%s,"data":%s}',
            'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            'issuer',
            'ex123',
            (new \DateTimeImmutable())->getTimestamp(),
            (new \DateTimeImmutable('+2 minutes'))->getTimestamp(),
            (new \DateTimeImmutable('+5 minutes'))->getTimestamp(),
            '["app1","app2"]',
            '{"user":{"id":"userId","externalId":"ex123","name":"user123"}}',
        );

        $this->expectException(InvalidJWSPayloadException::class);
        $this->expectExceptionMessage('Expiration Time must be after Not Before');

        $this->serializer->jsonDeserialize($jsonPayload);
    }

    public function testDeserializePayloadMissingIssuer(): void
    {
        $jsonPayload = sprintf(
            '{"jti":"%s","sub":"%s","iat":%s,"exp":%s,"nbf":%s,"aud":%s,"data":%s}',
            'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            'ex123',
            (new \DateTimeImmutable())->getTimestamp(),
            (new \DateTimeImmutable('+30 minutes'))->getTimestamp(),
            (new \DateTimeImmutable('+5 minutes'))->getTimestamp(),
            '["app1","app2"]',
            '{"user":{"id":"userId","externalId":"ex123","name":"user123"}}',
        );

        $this->expectException(InvalidJWSPayloadException::class);
        $this->expectExceptionMessage('Cannot find "iss" in json payload');

        $this->serializer->jsonDeserialize($jsonPayload);
    }

    public function testDeserializePayloadMissingSubject(): void
    {
        $jsonPayload = sprintf(
            '{"jti":"%s","iss":"%s","iat":%s,"exp":%s,"nbf":%s,"aud":%s,"data":%s}',
            'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            'issuer',
            (new \DateTimeImmutable())->getTimestamp(),
            (new \DateTimeImmutable('+30 minutes'))->getTimestamp(),
            (new \DateTimeImmutable('+5 minutes'))->getTimestamp(),
            '["app1","app2"]',
            '{"user":{"id":"userId","externalId":"ex123","name":"user123"}}',
        );

        $this->expectException(InvalidJWSPayloadException::class);
        $this->expectExceptionMessage('Cannot find "sub" in json payload');

        $this->serializer->jsonDeserialize($jsonPayload);
    }

    public function testDeserializePayloadMissingExpirationTime(): void
    {
        $jsonPayload = sprintf(
            '{"jti":"%s","iss":"%s","sub":"%s","iat":%s,"nbf":%s,"aud":%s,"data":%s}',
            'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            'issuer',
            'ex123',
            (new \DateTimeImmutable())->getTimestamp(),
            (new \DateTimeImmutable('+5 minutes'))->getTimestamp(),
            '["app1","app2"]',
            '{"user":{"id":"userId","externalId":"ex123","name":"user123"}}',
        );

        $this->expectException(InvalidJWSPayloadException::class);
        $this->expectExceptionMessage('Cannot find "exp" in json payload');

        $this->serializer->jsonDeserialize($jsonPayload);
    }

    public function testDeserializePayloadMissingIssuedAt(): void
    {
        $jsonPayload = sprintf(
            '{"jti":"%s","iss":"%s","sub":"%s","exp":%s,"nbf":%s,"aud":%s,"data":%s}',
            'ZWFkMDA5OGQtMTc0My00YjhiLWI2NzItYzNkYzc1NWNjZGEz',
            'issuer',
            'ex123',
            (new \DateTimeImmutable('+30 minutes'))->getTimestamp(),
            (new \DateTimeImmutable('+5 minutes'))->getTimestamp(),
            '["app1","app2"]',
            '{"user":{"id":"userId","externalId":"ex123","name":"user123"}}',
        );

        $this->expectException(InvalidJWSPayloadException::class);
        $this->expectExceptionMessage('Cannot find "iat" in json payload');

        $this->serializer->jsonDeserialize($jsonPayload);
    }
}
