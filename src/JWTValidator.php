<?php

declare(strict_types=1);

namespace rafalswierczek\JWT;

use rafalswierczek\JWT\Algorithm\AlgorithmFQCN;
use rafalswierczek\JWT\Exception\{InvalidJWTSyntaxException, InvalidJWTException};

final class JWTValidator implements JWTValidatorInterface
{
    public function validate(string $jwt, string $jwtSecret, AlgorithmFQCN $algorithmFQCN): void
    {
        $this->validateSyntax($jwt);

        $jwtBase64Parts = explode('.', $jwt);
        
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
            throw new InvalidJWTException($jwt);
        }
    }
    
    public function validateSyntax(string $jwt): void
    {
        $jwtBase64Parts = explode('.', $jwt);

        if (count($jwtBase64Parts) !== 3) {
            throw new InvalidJWTSyntaxException($jwt);
        }

        foreach ($jwtBase64Parts as $jwtBase64Part) {
            if (empty($jwtBase64Part) || empty(base64_decode($jwtBase64Part))) {
                throw new InvalidJWTSyntaxException($jwt);
            }
        }
    }
}
