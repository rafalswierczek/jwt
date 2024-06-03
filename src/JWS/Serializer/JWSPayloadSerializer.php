<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\Shared\Base64;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

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
        /** @var array<string, mixed> $payloadArray */
        $payloadArray = json_decode($jsonPayload, true) ?? throw new InvalidJWSPayloadException('Invalid payload format');

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

    /**
     * @param array<string, string|int> $payloadArray
     *
     * @throws InvalidJWSPayloadException
     */
    private function getDateTime(array $payloadArray, string $headerKey): \DateTimeImmutable
    {
        $payloadTimestamp = $payloadArray[$headerKey] ?? throw new InvalidJWSPayloadException(sprintf('Cannot find "%s" in json payload', $headerKey));

        if (false === is_int($payloadTimestamp)) {
            throw new InvalidJWSPayloadException(sprintf('Invalid value of "%s" in json payload', $headerKey));
        }

        return (new \DateTimeImmutable())->setTimestamp((int) $payloadTimestamp);
    }

    /**
     * @param array<string, string|int> $payloadArray
     *
     * @throws InvalidJWSPayloadException
     */
    private function getDateTimeOptional(array $payloadArray, string $headerKey): ?\DateTimeImmutable
    {
        if (false === isset($payloadArray[$headerKey])) {
            return null;
        }

        if (false === is_int($payloadArray[$headerKey])) {
            throw new InvalidJWSPayloadException(sprintf('Invalid value of "%s" in json payload', $headerKey));
        }

        return (new \DateTimeImmutable())->setTimestamp($payloadArray[$headerKey]);
    }
}
