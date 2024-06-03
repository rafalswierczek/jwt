<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Exception\CannotMatchAudienceException;
use rafalswierczek\JWT\JWS\Exception\CompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\TokenHasExpiredException;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuer;
use rafalswierczek\JWT\JWS\Issuer\JWSIssuerInterface;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Serializer\JWSSignatureSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSUnprotectedHeaderSerializer;
use rafalswierczek\JWT\JWS\Verifier\JWSVerifier;
use rafalswierczek\JWT\JWS\Verifier\JWSVerifierInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;
use rafalswierczek\JWT\Shared\Base64;

class JWSVerifierTest extends TestCase
{
    private JWSVerifierInterface $verifier;

    private JWSIssuerInterface $issuer;

    private JWSSerializerInterface $serializer;

    protected function setUp(): void
    {
        $headerSerializer = new JWSHeaderSerializer();
        $payloadSerializer = new JWSPayloadSerializer();
        $signatureSerializer = new JWSSignatureSerializer();
        $unprotectedHeaderSerializer = new JWSUnprotectedHeaderSerializer();
        $serializer = new JWSSerializer($headerSerializer, $payloadSerializer, $signatureSerializer, $unprotectedHeaderSerializer);
        $algorithmProvider = new AlgorithmProvider($headerSerializer, $payloadSerializer);
        $verifier = new JWSVerifier($algorithmProvider, $serializer);
        $issuer = new JWSIssuer($algorithmProvider, $serializer);

        $this->issuer = $issuer;
        $this->verifier = $verifier;
        $this->serializer = $serializer;
    }

    public function testVerifySuccess(): void
    {
        $this->expectNotToPerformAssertions();

        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret();

        $jws = $this->issuer->getJWS(JWSModel::getHeader(), $payload, $secret);

        /** @var array<string> $audience */
        $audience = $payload->audience;

        $this->verifier->verify($jws, $secret, $audience[0]);
    }

    public function testCompromisedSignature(): void
    {
        $secret = JWSModel::getSecret();
        $payload = JWSModel::getPayload();

        $compactJWS = $this->issuer->getCompactJWS(JWSModel::getHeader(), $payload, $secret);
        $compactJWSHacked = $this->changeExpirationTime($compactJWS);

        $jws = $this->serializer->compactDeserializeJWS($compactJWS);
        $jwsHacked = $this->serializer->compactDeserializeJWS($compactJWSHacked);

        /** @var array<string> $audience */
        $audience = $payload->audience;

        $this->verifier->verify($jws, $secret, $audience[0]);

        $this->expectException(CompromisedSignatureException::class);

        $this->verifier->verify($jwsHacked, $secret, $audience[0]);
    }

    public function testTokenHasExpired(): void
    {
        $secret = JWSModel::getSecret();
        $payload = new JWSPayload(
            id: '0789d6cb-a511-4e23-a702-c1f5d3f02bf7',
            issuer: 'auth server',
            subject: 'user',
            issuedAt: new \DateTimeImmutable('-40 minutes'),
            expirationTime: new \DateTimeImmutable('-30 minutes'),
        );

        $jws = $this->issuer->getJWS(JWSModel::getHeader(), $payload, $secret);

        $this->expectException(TokenHasExpiredException::class);
        $this->expectExceptionMessage("JWS with id {$payload->id} has expired");

        $this->verifier->verify($jws, $secret, '');
    }

    public function testCannotMatchAudience(): void
    {
        $secret = JWSModel::getSecret();
        $payload = new JWSPayload(
            id: '0789d6cb-a511-4e23-a702-c1f5d3f02bf7',
            issuer: 'auth server',
            subject: 'user',
            issuedAt: new \DateTimeImmutable(),
            expirationTime: new \DateTimeImmutable('+15 minutes'),
            audience: ['Resource server 2', 'Resource server 3'],
        );
        $validAudience = 'Resource server 1';

        $jws = $this->issuer->getJWS(JWSModel::getHeader(), $payload, $secret);

        $this->expectException(CannotMatchAudienceException::class);

        $this->verifier->verify($jws, $secret, $validAudience);
    }

    private function changeExpirationTime(string $compactJWS): string
    {
        $compactJWSArray = explode('.', $compactJWS);

        $payloadArray = json_decode(Base64::urlDecode($compactJWSArray[1]), true);

        $payloadArray['exp'] = (new \DateTime('+99 days'))->getTimestamp();

        $compactJWSArray[1] = Base64::urlEncode((string) json_encode($payloadArray));

        return implode('.', $compactJWSArray);
    }
}
