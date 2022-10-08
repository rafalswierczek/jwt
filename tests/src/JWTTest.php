<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\Algorithm\AlgorithmFQCN;

abstract class JWTTest extends TestCase
{
    protected const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC50ZXN0IiwiaWF0IjoxNjYyODgwNDI3LCJzdWIiOiJhLWItMyJ9.ODJmZTBmNzkyNjEzNDc5NjkyOGQ5MjZmZmM4ZTU3MGM0Zjg2NTRmOGNhN2NhOGU4NzE0Y2M5ZWYwYTYzOTFmYQ==';

    protected const JWT_SECRET = '123';

    protected const JWT_ALGORITHM = AlgorithmFQCN::HS256;

    protected const HEADER = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];

    protected const PAYLOAD = [
        'email' => "test@test.test",
        "iat" => 1662880427,
        "sub" => "a-b-3"
    ];

    protected const SIGNATURE = '82fe0f7926134796928d926ffc8e570c4f8654f8ca7ca8e8714cc9ef0a6391fa';
}
