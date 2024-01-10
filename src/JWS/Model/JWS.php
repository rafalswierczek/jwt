<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

final class JWS
{
    public function __construct(
        private JWSHeader $header,
        private JWSPayload $payload,
        private JWSSignature $signature,
        private ?JWSUnprotectedHeader $unprotectedHeader = null
    ) {
    }

    public function getHeader(): JWSHeader
    {
        return $this->header;
    }

    public function getPayload(): JWSPayload
    {
        return $this->payload;
    }

    public function getSignature(): JWSSignature
    {
        return $this->signature;
    }

    public function getUnprotectedHeader(): ?JWSUnprotectedHeader
    {
        return $this->unprotectedHeader;
    }
}
