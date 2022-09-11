<?php

declare(strict_types=1);

namespace rafalswierczek\jwt;

use rafalswierczek\jwt\Algorithm\{AlgorithmFQCN, AlgorithmInterface};

final class JWTIssuer
{
    private string $payload = "";
    
    public function __construct(
        private string $jwtSecret,
        private JWTUserInterface $jwtUser,
        private AlgorithmFQCN $algorithmFQCN
    ) {}

    public function getJWT(): string
    {
        $jsonHeader = $this->getHeader();

        $jsonPayload = $this->getPayload();
        
        /**
         * @var AlgorithmInterface
         */
        $algorithm = (new $this->algorithmFQCN->value(
            $this->jwtSecret,
            $jsonHeader,
            $jsonPayload
        ));
        
        $signature = $this->getSignature($algorithm);
        
        $token = sprintf(
            '%s.%s.%s',
            base64_encode($jsonHeader),
            base64_encode($jsonPayload),
            base64_encode($signature)
        );

        return $token;
    }

    public function addJsonToPayload(string $json): void
    {
        $this->payload = $json;
    }
    
    public function getHeader(): string
    {
        return json_encode([
            'alg' => $this->algorithmFQCN->value::getName(),
            'typ' => "JWT"
        ]);
    }

    public function getPayload(): string
    {
        $payloadArray = json_decode($this->payload, true) ?? [];
        $payloadArray['sub'] = $this->jwtUser->getId();

        return json_encode($payloadArray);
    }
    
    public function getSignature(AlgorithmInterface $algorithm): string
    {
        return $algorithm->hash();
    }
}
