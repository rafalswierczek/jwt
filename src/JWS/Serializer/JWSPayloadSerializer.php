<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\Shared\Base64;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;
use rafalswierczek\JWT\Shared\Value;

final class JWSPayloadSerializer implements JWSPayloadSerializerInterface
{
    public function jsonSerialize(JWSPayload $payload): string
    {
        $payloadArray = [
            'jti' => $payload->id,
            'iss' => $payload->issuer,
            'sub' => $payload->subject,
            'iat' => $payload->issuedAt->getTimestamp(),
            'exp' => $payload->expirationTime->getTimestamp(),
        ];

        if (null !== $payload->notBefore) {
            $payloadArray['nbf'] = $payload->notBefore->getTimestamp();
        }

        if (!empty($payload->audience)) {
            $payloadArray['aud'] = $payload->audience;
        }

        if (!empty($payload->data)) {
            $payloadArray['data'] = $payload->data;
        }

        return json_encode($payloadArray) ?: throw new \ValueError('JWS payload JSON serialization failed due to usage of binary data');
    }

    /**
     * @throws InvalidJWSPayloadException
     */
    public function jsonDeserialize(string $jsonPayload): JWSPayload
    {
        /** @var array<mixed> $payloadArray */
        $payloadArray = json_decode($jsonPayload, true) ?? throw new InvalidJWSPayloadException('Invalid payload format');

        return new JWSPayload(
            id: Value::string($payloadArray['jti'] ?? throw new InvalidJWSPayloadException('Cannot find "jti" in json payload')),
            issuer: Value::string($payloadArray['iss'] ?? throw new InvalidJWSPayloadException('Cannot find "iss" in json payload')),
            subject: Value::string($payloadArray['sub'] ?? throw new InvalidJWSPayloadException('Cannot find "sub" in json payload')),
            issuedAt: (new \DateTimeImmutable())->setTimestamp(Value::int($payloadArray['iat'] ?? throw new InvalidJWSPayloadException('Cannot find "iat" in json payload'))),
            expirationTime: (new \DateTimeImmutable())->setTimestamp(Value::int($payloadArray['exp'] ?? throw new InvalidJWSPayloadException('Cannot find "exp" in json payload'))),
            notBefore: isset($payloadArray['nbf']) ? (new \DateTimeImmutable())->setTimestamp(Value::int($payloadArray['nbf'])) : null,
            audience: isset($payloadArray['aud']) ? Value::arrayOfString($payloadArray['aud']) : null,
            data: isset($payloadArray['data']) ? Value::arrayOfMixed($payloadArray['data']) : null,
        );
    }

    public function base64Encode(JWSPayload $payload): string
    {
        return Base64::UrlEncode($this->jsonSerialize($payload));
    }

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidJWSPayloadException
     */
    public function base64Decode(string $base64UrlPayload): JWSPayload
    {
        return $this->jsonDeserialize(Base64::UrlDecode($base64UrlPayload));
    }
}
