<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use rafalswierczek\JWT\{Authenticator, JWTValidator};
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

class AuthenticatorTest extends JWTTest
{
    public function testAuthenticate(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', "Bearer ". static::JWT);

        putenv('JWT_SECRET=' . static::JWT_SECRET);

        $authenticator = new Authenticator(new JWTValidator());
        $passport = $authenticator->authenticate($request);

        /** @var UserBadge */
        $badge = $passport->getBadge(UserBadge::class);

        $userToken = $badge->getUserIdentifier();

        $this->assertSame(static::JWT, $userToken);
    }

    public function testAuthenticateWithInvalidJWT(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', "Bearer invalid.jwt.abc");

        putenv('JWT_SECRET=' . static::JWT_SECRET);

        $authenticator = new Authenticator(new JWTValidator());

        $this->expectException(AuthenticationException::class);

        $authenticator->authenticate($request);
    }
}
