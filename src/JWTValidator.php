<?php

declare(strict_types=1);

namespace rafalswierczek\JWT;

use rafalswierczek\JWT\Algorithm\AlgorithmFQCN;

final class JWTValidator implements JWTValidatorInterface
{
    public function isValid(string $jwt, string $jwtSecret, AlgorithmFQCN $algorithmFQCN): bool
    {
        $jwtBase64Parts = explode('.', $jwt);
        
        if (!$this->hasValidSyntax($jwtBase64Parts)) {
            return false;
        }
        
        $jsonHeader = base64_decode($jwtBase64Parts[0]);
        
        $jsonPayload = base64_decode($jwtBase64Parts[1]);

        $signatureToCheck = base64_decode($jwtBase64Parts[2]);

        /**
         * @var AlgorithmInterface
         */
        $algorithm = (new $algorithmFQCN->value(
            $jwtSecret,
            $jsonHeader,
            $jsonPayload
        ));
        
        $signature = $algorithm->hash();
        
        if ($signatureToCheck !== $signature) {
            return false;
        }
        
        return true;
    }
    
    private function hasValidSyntax(array $jwtBase64Parts): bool
    {
        if (count($jwtBase64Parts) !== 3) {
            return false;
        }

        foreach ($jwtBase64Parts as $jwtBase64Part) {
            if (empty($jwtBase64Part)) {
                return false;
            }
        }
        
        return true;
    }
}
