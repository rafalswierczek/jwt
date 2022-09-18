<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

require dirname(__DIR__).'/vendor/autoload.php';

use rafalswierczek\JWT\JWTUnloader;

class JWTUnloaderTest
{
    private const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC50ZXN0IiwiaWF0IjoxNjYyODgwNDI3LCJzdWIiOiJhLWItMyJ9.ODJmZTBmNzkyNjEzNDc5NjkyOGQ5MjZmZmM4ZTU3MGM0Zjg2NTRmOGNhN2NhOGU4NzE0Y2M5ZWYwYTYzOTFmYQ==';

    public function testGetHeader(): self
    {
        $expectedHeader = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];

        $jwtUnloader = new JWTUnloader(self::JWT);

        $header = $jwtUnloader->getHeader();

        print_r(__FUNCTION__ . (($expectedHeader === $header) ? "| OK\n" : "| ERROR $header\n"));

        return $this;
    }

    public function testGetPayload(): self
    {
        $expectedPayload = [
            'email' => "test@test.test",
            "iat" => 1662880427,
            "sub" => "a-b-3"
        ];

        $jwtUnloader = new JWTUnloader(self::JWT);

        $payload = $jwtUnloader->getPayload();

        print_r(__FUNCTION__ . (($expectedPayload === $payload) ? "| OK\n" : "| ERROR $payload\n"));

        return $this;
    }

    public function testGetSignature(): self
    {
        $expectedSignature = '82fe0f7926134796928d926ffc8e570c4f8654f8ca7ca8e8714cc9ef0a6391fa';

        $jwtUnloader = new JWTUnloader(self::JWT);

        $signature = $jwtUnloader->getSignature();

        print_r(__FUNCTION__ . (($expectedSignature === $signature) ? "| OK\n" : "| ERROR $signature\n"));

        return $this;
    }

    public function testGetUserId(): self
    {
        $expectedUserId = 'a-b-3';

        $jwtUnloader = new JWTUnloader(self::JWT);

        $userId = $jwtUnloader->getUserId();

        print_r(__FUNCTION__ . (($expectedUserId === $userId) ? "| OK\n" : "| ERROR $userId\n"));

        return $this;
    }
}

(new JWTUnloaderTest())
    ->testGetHeader()
    ->testGetPayload()
    ->testGetSignature()
    ->testGetUserId()
;