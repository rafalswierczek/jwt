<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSJsonException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Model\JWSSignature;
use rafalswierczek\JWT\JWS\Model\JWSUnprotectedHeader;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializerInterface;
use rafalswierczek\JWT\Shared\Base64;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class JWSSerializer implements JWSSerializerInterface
{
    public function __construct(
        private JWSHeaderSerializerInterface $jwsHeaderSerializer,
        private JWSPayloadSerializerInterface $jwsPayloadSerializer,
    ) {
    }

    /**
     * @throws InvalidJWSHeaderException
     */    
    public function base64EncodeHeader(JWSHeader $header): string
    {
        return Base64::UrlEncode($this->jwsHeaderSerializer->jsonSerialize($header));
    }

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     */
    public function base64DecodeHeader(string $base64UrlHeader): JWSHeader
    {
        return $this->jwsHeaderSerializer->jsonDeserialize(Base64::UrlDecode($base64UrlHeader));
    }

    /**
     * @throws InvalidJWSPayloadException
     */
    public function base64EncodePayload(JWSPayload $payload): string
    {
        return Base64::UrlEncode($this->jwsPayloadSerializer->jsonSerialize($payload));
    }

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidJWSPayloadException
     */
    public function base64DecodePayload(string $base64UrlPayload): JWSPayload
    {
        return $this->jwsPayloadSerializer->jsonDeserialize(Base64::UrlDecode($base64UrlPayload));
    }

    public function base64EncodeSignature(JWSSignature $signature): string
    {
        return Base64::UrlEncode((string) $signature);
    }

    /**
     * @throws InvalidBase64InputException
     */
    public function base64DecodeSignature(string $base64UrlSignature): JWSSignature
    {
        return new JWSSignature(Base64::UrlDecode($base64UrlSignature));
    }

    public function base64EncodeUnprotectedHeader(JWSUnprotectedHeader $header): string
    {
        return Base64::urlEncode((string) json_encode($header->getData()));
    }

    /**
     * @throws InvalidBase64InputException
     */
    public function base64DecodeUnprotectedHeader(string $base64UrlUnprotectedHeader): JWSUnprotectedHeader
    {
        return new JWSUnprotectedHeader(json_decode(Base64::urlDecode($base64UrlUnprotectedHeader), true));
    }

    /**
     * @return string base64UrlEncodedHeader.base64UrlEncodedPayload.base64UrlEncodedSignature
     * 
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function compactSerializeJws(JWS $jws): string
    {
        $base64UrlHeader = $this->base64EncodeHeader($jws->getHeader());
        $base64UrlPayload = $this->base64EncodePayload($jws->getPayload());
        $base64UrlSignature = $this->base64EncodeSignature($jws->getSignature());

        return sprintf('%s.%s.%s', $base64UrlHeader, $base64UrlPayload, $base64UrlSignature);
    }
    
    /**
     * @throws InvalidJWSCompactException
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function compactDeserializeJWS(string $compactJws): JWS
    {
        $base64UrlParts = explode('.', $compactJws);

        if (3 !== count($base64UrlParts)) {
            throw new InvalidJWSCompactException('Compact serialized JWS must contain 3 members. Invalid JWS: '.$compactJws);
        }

        $header = $this->base64DecodeHeader($base64UrlParts[0]);
        $payload = $this->base64DecodePayload($base64UrlParts[1]);
        $signature = $this->base64DecodeSignature($base64UrlParts[2]);

        return new JWS($header, $payload, $signature);
    }

    /**
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function jsonSerializeJws(JWS $jws): string
    {
        $arrayJws = [
            'protected' => $this->base64EncodeHeader($jws->getHeader()),
            'payload' => $this->base64EncodePayload($jws->getPayload()),
            'signature' => $this->base64EncodeSignature($jws->getSignature()),
        ];

        if (null !== $jws->getUnprotectedHeader()) {
            $arrayJws['header'] = $this->base64EncodeUnprotectedHeader($jws->getUnprotectedHeader());
        }

        return (string) json_encode($arrayJws);
    }

    /**
     * @throws InvalidJWSJsonException
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function jsonDeserializeJws(string $jsonJws): JWS
    {
        /** @var array<string, string> $arrayJws */
        $arrayJws = json_decode($jsonJws, true);

        if (false === isset($arrayJws['protected'])) {
            throw new InvalidJWSJsonException('There is a missing "protected" json key in JWS: '.$jsonJws);
        }

        if (false === isset($arrayJws['payload'])) {
            throw new InvalidJWSJsonException('There is a missing "payload" json key in JWS: '.$jsonJws);
        }

        if (false === isset($arrayJws['signature'])) {
            throw new InvalidJWSJsonException('There is a missing "signature" json key in JWS: '.$jsonJws);
        }

        $header = $this->base64DecodeHeader($arrayJws['protected']);
        $payload = $this->base64DecodePayload($arrayJws['payload']);
        $signature = $this->base64DecodeSignature($arrayJws['signature']);
        $unprotectedHeader = null;

        if (!empty($arrayJws['header'])) {
            $unprotectedHeader = $this->base64DecodeUnprotectedHeader($arrayJws['header']);
        }

        return new JWS($header, $payload, $signature, $unprotectedHeader);
    }
}
