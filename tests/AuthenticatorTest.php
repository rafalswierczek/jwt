<?php

declare(strict_types=1);

namespace rafalswierczek\jwt\tests;

require dirname(__DIR__).'/vendor/autoload.php';

use rafalswierczek\jwt\Algorithm\AlgorithmFQCN;
use rafalswierczek\jwt\{Authenticator, JWTValidator};
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class AuthenticatorTest
{
    private const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC50ZXN0IiwiaWF0IjoxNjYyODgwNDI3LCJzdWIiOiJhLWItMyJ9.ODJmZTBmNzkyNjEzNDc5NjkyOGQ5MjZmZmM4ZTU3MGM0Zjg2NTRmOGNhN2NhOGU4NzE0Y2M5ZWYwYTYzOTFmYQ==';

    public function testAuthenticate(): self
    {
        $request = new Request();
        $request->headers->set('Authorization', "Bearer ". self::JWT);

        putenv('JWT_SECRET=123');

        $authenticator = new Authenticator(new JWTValidator());
        $passport = $authenticator->authenticate($request);

        $badge = $passport->getBadge(UserBadge::class);

        $userToken = $badge->getUserIdentifier();

        print_r(__FUNCTION__ . ((self::JWT === $userToken) ? "| OK\n" : "| ERROR $userToken\n"));

        return $this;
    }
}

(new AuthenticatorTest())
    ->testAuthenticate()
;