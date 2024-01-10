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
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

interface JWSSerializerInterface
{
    /**
     * @throws InvalidJWSHeaderException
     */    
    public function base64EncodeHeader(JWSHeader $header): string;

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     */
    public function base64DecodeHeader(string $base64UrlHeader): JWSHeader;

    /**
     * @throws InvalidJWSPayloadException
     */
    public function base64EncodePayload(JWSPayload $payload): string;

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidJWSPayloadException
     */
    public function base64DecodePayload(string $base64UrlPayload): JWSPayload;

    public function base64EncodeSignature(JWSSignature $signature): string;

    /**
     * @throws InvalidBase64InputException
     */
    public function base64DecodeSignature(string $base64UrlSignature): JWSSignature;

    public function base64EncodeUnprotectedHeader(JWSUnprotectedHeader $header): string;

    /**
     * @throws InvalidBase64InputException
     */
    public function base64DecodeUnprotectedHeader(string $base64UrlUnprotectedHeader): JWSUnprotectedHeader;

    /**
     * @return string base64UrlEncodedHeader.base64UrlEncodedPayload.base64UrlEncodedSignature
     * 
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function compactSerializeJws(JWS $jws): string;
    
    /**
     * @throws InvalidJWSCompactException
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function compactDeserializeJWS(string $compactJws): JWS;

    /**
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function jsonSerializeJws(JWS $jws): string;

    /**
     * @throws InvalidJWSJsonException
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function jsonDeserializeJws(string $jsonJws): JWS;
}
