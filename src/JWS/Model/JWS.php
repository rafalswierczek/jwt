<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

final readonly class JWS
{
    public function __construct(
        public JWSHeader $header,
        public JWSPayload $payload,
        public JWSSignature $signature,
        public ?JWSUnprotectedHeader $unprotectedHeader = null
    ) {
    }
}
