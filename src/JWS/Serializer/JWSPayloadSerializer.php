<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWSPayload;

final class JWSPayloadSerializer implements JWSPayloadSerializerInterface
{
    /**
     * @throws InvalidJWSPayloadException
     */
    public function jsonSerialize(JWSPayload $payload): string
    {
        $payloadArray = [
            'jti' => $payload->getId(),
            'iss' => $payload->getIssuer(),
            'sub' => $payload->getSubject(),
            'iat' => $payload->getIssuedAt()->getTimestamp(),
            'exp' => $payload->getExpirationTime()->getTimestamp(),
        ];

        if (null !== $payload->getNotBefore()) {
            $payloadArray['nbf'] = $payload->getNotBefore()->getTimestamp();
        }

        if (!empty($payload->getAudience())) {
            $payloadArray['aud'] = $payload->getAudience();
        }

        if (!empty($payload->getData())) {
            $payloadArray['data'] = $payload->getData();
        }

        return json_encode($payloadArray) ?: throw new InvalidJWSPayloadException('JWS payload JSON serialization failed due to binary data');
    }

    /**
     * @throws InvalidJWSPayloadException
     */
    public function jsonDeserialize(string $payload): JWSPayload
    {
        /** @var array<string, mixed> $payloadArray */
        $payloadArray = json_decode($payload, true) ?: throw new InvalidJWSPayloadException('JSON deserialization failed due to binary data or invalid format');

        return new JWSPayload(
            id: $payloadArray['jti'] ?? throw new InvalidJWSPayloadException('Cannot find "jti" in json payload'),
            issuer: $payloadArray['iss'] ?? throw new InvalidJWSPayloadException('Cannot find "iss" in json payload'),
            subject: $payloadArray['sub'] ?? throw new InvalidJWSPayloadException('Cannot find "sub" in json payload'),
            issuedAt: $this->getDateTime($payloadArray, 'iat'),
            expirationTime: $this->getDateTime($payloadArray, 'exp'),
            notBefore: $this->getDateTimeOptional($payloadArray, 'nbf'),
            audience: $payloadArray['aud'] ?? null,
            data: $payloadArray['data'] ?? null,
        );
    }

    /**
     * @param array<string, string|int> $payloadArray
     */
    private function getDateTime(array $payloadArray, string $headerKey): \DateTimeImmutable
    {
        if (false === is_int($payloadArray[$headerKey] ?? throw new InvalidJWSPayloadException(sprintf('Cannot find "%s" in json payload', $headerKey)))) {
            throw new InvalidJWSPayloadException(sprintf('Invalid "%s" value in json payload', $headerKey));
        }

        return (new \DateTimeImmutable())->setTimestamp((int) $payloadArray[$headerKey]);
    }

    /**
     * @param array<string, string|int> $payloadArray
     */
    private function getDateTimeOptional(array $payloadArray, string $headerKey): ?\DateTimeImmutable
    {
        if (false === isset($payloadArray[$headerKey])) {
            return null;
        }

        if (false === is_int($payloadArray[$headerKey])) {
            throw new InvalidJWSPayloadException(sprintf('Invalid "%s" value in json payload', $headerKey));
        }

        return (new \DateTimeImmutable())->setTimestamp($payloadArray[$headerKey]);
    }
}
