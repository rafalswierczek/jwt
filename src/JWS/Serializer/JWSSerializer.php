<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSJsonException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class JWSSerializer implements JWSSerializerInterface
{
    public function __construct(
        private JWSHeaderSerializerInterface $jwsHeaderSerializer,
        private JWSPayloadSerializerInterface $jwsPayloadSerializer,
        private JWSSignatureSerializerInterface $jwsSignatureSerializer,
        private JWSUnprotectedHeaderSerializerInterface $jwsUnprotectedHeaderSerializer,
    ) {
    }

    public function compactSerializeJWS(JWS $jws): string
    {
        $base64UrlHeader = $this->jwsHeaderSerializer->base64Encode($jws->header);
        $base64UrlPayload = $this->jwsPayloadSerializer->base64Encode($jws->payload);
        $base64UrlSignature = $this->jwsSignatureSerializer->base64Encode($jws->signature);

        return sprintf('%s.%s.%s', $base64UrlHeader, $base64UrlPayload, $base64UrlSignature);
    }

    /**
     * @throws InvalidJWSCompactException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     * @throws InvalidBase64InputException
     */
    public function compactDeserializeJWS(string $compactJWS): JWS
    {
        $base64UrlParts = explode('.', $compactJWS);

        if (3 !== count($base64UrlParts)) {
            throw new InvalidJWSCompactException('Compact serialized JWS must contain 3 elements. Invalid JWS: ' . $compactJWS);
        }

        $header = $this->jwsHeaderSerializer->base64Decode($base64UrlParts[0]);
        $payload = $this->jwsPayloadSerializer->base64Decode($base64UrlParts[1]);
        $signature = $this->jwsSignatureSerializer->base64Decode($base64UrlParts[2]);

        return new JWS($header, $payload, $signature);
    }

    public function jsonSerializeJWS(JWS $jws): string
    {
        $arrayJWS = [
            'protected' => $this->jwsHeaderSerializer->base64Encode($jws->header),
            'payload' => $this->jwsPayloadSerializer->base64Encode($jws->payload),
            'signature' => $this->jwsSignatureSerializer->base64Encode($jws->signature),
        ];

        if (null !== $jws->unprotectedHeader) {
            $arrayJWS['header'] = $this->jwsUnprotectedHeaderSerializer->base64Encode($jws->unprotectedHeader);
        }

        return (string) json_encode($arrayJWS);
    }

    /**
     * @throws InvalidJWSJsonException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     * @throws InvalidBase64InputException
     */
    public function jsonDeserializeJWS(string $jsonJWS): JWS
    {
        /** @var array<string, string> $arrayJWS */
        $arrayJWS = json_decode($jsonJWS, true);

        if (false === isset($arrayJWS['protected'])) {
            throw new InvalidJWSJsonException('There is a missing "protected" json key in JWS: ' . $jsonJWS);
        }

        if (false === isset($arrayJWS['payload'])) {
            throw new InvalidJWSJsonException('There is a missing "payload" json key in JWS: ' . $jsonJWS);
        }

        if (false === isset($arrayJWS['signature'])) {
            throw new InvalidJWSJsonException('There is a missing "signature" json key in JWS: ' . $jsonJWS);
        }

        $header = $this->jwsHeaderSerializer->base64Decode($arrayJWS['protected']);
        $payload = $this->jwsPayloadSerializer->base64Decode($arrayJWS['payload']);
        $signature = $this->jwsSignatureSerializer->base64Decode($arrayJWS['signature']);
        $unprotectedHeader = null;

        if (!empty($arrayJWS['header'])) {
            $unprotectedHeader = $this->jwsUnprotectedHeaderSerializer->base64Decode($arrayJWS['header']);
        }

        return new JWS($header, $payload, $signature, $unprotectedHeader);
    }
}
