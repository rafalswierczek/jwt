<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Exception\CannotMatchAudienceException;
use rafalswierczek\JWT\JWS\Exception\JWSCompromisedSignatureException;
use rafalswierczek\JWT\JWS\Exception\JWSHasExpiredException;
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
use rafalswierczek\JWT\Shared\Base64;

class JWSVerifierTest extends TestCase
{
    private JWSVerifierInterface $verifier;

    private JWSIssuerInterface $issuer;

    protected function setUp(): void
    {
        $headerSerializer = new JWSHeaderSerializer();
        $payloadSerializer = new JWSPayloadSerializer();
        $serializer = new JWSSerializer($headerSerializer, $payloadSerializer, new JWSSignatureSerializer(), new JWSUnprotectedHeaderSerializer());
        $algorithmProvider = new AlgorithmProvider($headerSerializer, $payloadSerializer);
        $verifier = new JWSVerifier($algorithmProvider, $serializer);
        $issuer = new JWSIssuer($algorithmProvider, $serializer);

        $this->issuer = $issuer;
        $this->verifier = $verifier;
    }

    public function testVerifySuccess(): void
    {
        $this->expectNotToPerformAssertions();

        $payload = JWSModel::getPayload();
        $secret = JWSModel::getSecret();

        $jws = $this->issuer->generateJWS(JWSModel::getHeader(), $payload, $secret);

        /** @var array<string> $audience */
        $audience = $payload->audience;

        $this->verifier->verify($jws, $secret, $audience[0]);
    }

    public function testCompromisedSignature(): void
    {
        $secret = JWSModel::getSecret();
        $payload = JWSModel::getPayload();

        $compactJWS = $this->issuer->generateCompactJWS(JWSModel::getHeader(), $payload, $secret);
        $compactJWSHacked = $this->changeExpirationTime($compactJWS);

        /** @var array<string> $audience */
        $audience = $payload->audience;

        $this->verifier->verifyCompactJWS($compactJWS, $secret, $audience[0]);

        $this->expectException(JWSCompromisedSignatureException::class);
        $this->expectExceptionMessage("Signature of following JWS is compromised: $compactJWSHacked");

        $this->verifier->verifyCompactJWS($compactJWSHacked, $secret, $audience[0]);
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

        $jws = $this->issuer->generateJWS(JWSModel::getHeader(), $payload, $secret);

        $this->expectException(JWSHasExpiredException::class);
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
        $validAudienceElement = 'Resource server 1';

        $jws = $this->issuer->generateJWS(JWSModel::getHeader(), $payload, $secret);

        $this->expectException(CannotMatchAudienceException::class);

        $this->verifier->verify($jws, $secret, $validAudienceElement);
    }

    private function changeExpirationTime(string $compactJWS): string
    {
        $compactJWSArray = explode('.', $compactJWS);

        /** @var array<string, mixed> $payloadArray */
        $payloadArray = json_decode(Base64::urlDecode($compactJWSArray[1]), true);

        $payloadArray['exp'] = (new \DateTime('+99 days'))->getTimestamp();

        $compactJWSArray[1] = Base64::urlEncode((string) json_encode($payloadArray));

        return implode('.', $compactJWSArray);
    }
}
