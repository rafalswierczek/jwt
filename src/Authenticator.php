<?php

declare(strict_types=1);

namespace rafalswierczek\JWT;

use rafalswierczek\JWT\Algorithm\AlgorithmFQCN;
use Symfony\Component\HttpFoundation\{JsonResponse, Request, Response};
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class Authenticator implements AuthenticatorInterface
{
    public function __construct(private JWTValidatorInterface $jwtValidator)
    {}

    public function supports(Request $request): ?bool
    {
        return
            $request->headers->has('Authorization') &&
            0 === strpos($request->headers->get('Authorization'), 'Bearer ')
        ;
    }

    /**
     * @throws AuthenticationException
     */
    public function authenticate(Request $request): Passport
    {
        $authorizationHeader = $request->headers->get('Authorization');
        $jwt = explode(' ', $authorizationHeader)[1];

        $jwtSecret = getenv('JWT_SECRET') ?: throw new \RuntimeException('Cannot find JWT_SECRET in .env file');

        if(!$this->jwtValidator->isValid($jwt, $jwtSecret, AlgorithmFQCN::HS256)) {
            throw new AuthenticationException('JWT is not valid');
        }

        return new SelfValidatingPassport(new UserBadge($jwt));
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $user = $passport->getUser();

        return new PostAuthenticationToken($user, $firewallName, $user->getRoles());
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(['message' => 'Authentication failed - invalid JWT'], Response::HTTP_UNAUTHORIZED);
    }
}