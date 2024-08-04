# Simple JWS authentication codebase

[![Build](https://github.com/rafalswierczek/jwt/actions/workflows/php.yml/badge.svg)](https://github.com/rafalswierczek/jwt/actions/workflows/php.yml)

#### Take total control over JWS authentication with help of this repository.

## Installation:

> composer require rafalswierczek/jwt

## Usage

*Remember that this library is a code base so treat it as your source code. Be aware of exceptions defined in the contract, catch them.*

*Nothing will work unless you have 100% awareness of the whole architecture you want to implement.*

### SYMMETRIC SIGNATURE SYSTEM:
- Keep your JWS secret very safely and share it between applications to let one JWS be used to authenticate with multiple applications. This is pretty much the only reason to use JWT system at all.
- In authentication server or auth module in monolith:
    - Create your own endpoint that will check user credentials and return generated JWS in successful response.
    - Create your own instances of `JWSIssuerInterface`, `JWSHeader` and `JWSPayload` and generate new JWS that should be returned in auth endpoint.
    - Create your own instance of `RefreshTokenProviderInterface` and generate new refresh token that should be returned together with JWS.
    - You **MUST** have 1 unique secret key per 1 refresh token. Store both in a table as unique index. If refresh token get hacked or someone using it should be banned then you cannot do anything by definition of JWT system. The only way to handle this situation is to invalidate secret key associated with refresh token in such table to prevent user from generating new JWS that should be valid for 3~15 minutes depending on security measures.
    ```php
    // Issuer example:
    namespace YourApp\AuthServer\Infrastructure;

    use YourApp\AuthServer\Application\JWSIssuer;
    use YourApp\AuthServer\Domain\Header;
    use YourApp\AuthServer\Domain\Payload;
    use YourApp\AuthServer\Domain\User;
    use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
    use rafalswierczek\JWT\JWS\Enum\Header\TokenType;
    use rafalswierczek\JWT\JWS\Issuer\JWSIssuerInterface;
    use rafalswierczek\JWT\JWS\Model\JWSHeader;
    use rafalswierczek\JWT\JWS\Model\JWSPayload;
    use rafalswierczek\Uuid4\Uuid4Factory;

    final class RafalswierczekJWSIssuer implements JWSIssuer
    {
        public function __construct(private JWSIssuerInterface $issuer)
        {
        }

        public function issueToken(User $user): string
        {
            $header = Header::create();

            $payload = Payload::create(
                jwtId: Uuid4Factory::create()->toHex(),
                userId: $user->id,
            );

            return $this->issuer->generateCompactJWS(
                header: $this->mapHeader($header),
                payload: $this->mapPayload($payload, $user),
                secret: $_ENV['JWS_PRIVATE_KEY'],
            );
        }

        private function mapHeader(Header $header): JWSHeader
        {
            return new JWSHeader(
                tokenType: TokenType::from($header->typ),
                algorithmType: AlgorithmType::from($header->alg),
            );
        }

        private function mapPayload(Payload $payload, User $user): JWSPayload
        {
            return new JWSPayload(
                id: $payload->jti, // globally unique JWT id
                issuer: $payload->iss, // domain of auth server (might be the same as audience element)
                subject: $payload->sub, // user-uuid
                issuedAt: (new \DateTimeImmutable())->setTimestamp($payload->iat),
                expirationTime: (new \DateTimeImmutable())->setTimestamp($payload->exp),
                audience: $payload->aud, // ['yourdomain1.com', 'yourdomain2.com']
                data: ['user' => $user], // user metadata known to all audience applications
            );
        }
    }
    ```
- In every application that matches the audience:
    - Create your own authenticator and from there use your instance of `JWSVerifierInterface` to verify JWS from request header.
    - If JWS is expired (`JWSHasExpiredException`) try to request your auth server to generate new JWS using current refresh token. Return 403.
    - `JWSCompromisedSignatureException` is a red flag, most likely an attack or bug. Log it as error or alert and return 403.
    - `CannotMatchAudienceException` Might be the problem with old domain name or the JWS is just not meant to be used for this specific application. Log it as warning and return 403.
    - If the refresh token is not valid, log off the user and force him to log in (auth server endpoint) using whatever credentials you use.
