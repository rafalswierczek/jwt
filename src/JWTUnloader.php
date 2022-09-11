<?php

declare(strict_types=1);

namespace rafalswierczek\jwt;

final class JWTUnloader
{
    public function __construct(private string $jwt)
    {}

    public function getHeader(): array
    {
        return $this->getBody(0);
    }

    public function getPayload(): array
    {
        return $this->getBody(1);
    }

    public function getSignature(): string
    {
        $jwtBase64Parts = explode('.', $this->jwt);

        return base64_decode($jwtBase64Parts[2]);
    }

    public function getUserId(): string
    {
        $jsonPayload = $this->getPayload();

        return $jsonPayload['sub'];
    }

    private function getBody(int $partIndex): array
    {
        $jwtBase64Parts = explode('.', $this->jwt);

        $json = base64_decode($jwtBase64Parts[$partIndex]);

        return json_decode($json, true);
    }
}