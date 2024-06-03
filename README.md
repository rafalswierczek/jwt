# Simple JWS authentication codebase

[![Build](https://github.com/rafalswierczek/jwt/actions/workflows/php.yml/badge.svg)](https://github.com/rafalswierczek/jwt/actions/workflows/php.yml)

#### Take total control over JWS authentication with help of this repository.

## Installation:

> composer require rafalswierczek/jwt

## Usage

*Remember that this library is a code base so treat it as your source code. Be aware of exceptions defined in the contract, catch them.*

### SYMMETRIC SIGNATURE SYSTEM:
- Keep your JWS secret very safely and share it between applications named as `my-app.com` and `api.my-app.com` to let one JWS be used to authenticate with multiple applications.
- In **_authentication server_**:
    - Create your own endpoint that will check user credentials and return generated JWS in successful response.
    - Create your own instances of `JWSIssuerInterface`, `JWSHeader` and `JWSPayload` and use it in token endpoint to get JWS.
    - (optional) Use the audience property (`aud` claim) in payload to specify which application the token is intended for.
    - (optional) Specify data of user that will be authenticated in each application.

    ```php
    $headerSerializer = new JWSHeaderSerializer();
    $payloadSerializer = new JWSPayloadSerializer();
    $signatureSerializer = new JWSSignatureSerializer();
    $unprotectedHeaderSerializer = new JWSUnprotectedHeaderSerializer();
    $serializer = new JWSSerializer($headerSerializer, $payloadSerializer, $signatureSerializer, $unprotectedHeaderSerializer);
    $algorithmProvider = new AlgorithmProvider($headerSerializer, $payloadSerializer);
    $issuer = new JWSIssuer($algorithmProvider, $serializer);
    $refreshTokenProvider  = new RefreshTokenProvider();

    $header = JWSHeaderFactory::create();
    $payload = JWSPayloadFactory::create(
        userId: 'user-id',
        audience: ['my-app.com', 'api.my-app.com'],
        userInfo: ['name' => 'John']
    );
    $secret = $yourSecretFromSharedVault;

    $compactJws = $issuer->getCompactJWS($header, $payload, $secret);
  
    $refreshToken = $refreshTokenProvider->getRefreshToken();

    return new JsonResponse(['jws' => $compactJws, 'refreshToken' => $refreshToken]);
    ```
- In all endpoints for each **_application_** that matches the audience:
    - Create your own authenticator and from there use your instance of `JWSVerifierInterface` to verify JWS from request header

    ```php
    $headerSerializer = new JWSHeaderSerializer();
    $payloadSerializer = new JWSPayloadSerializer();
    $signatureSerializer = new JWSSignatureSerializer();
    $unprotectedHeaderSerializer = new JWSUnprotectedHeaderSerializer();
    $serializer = new JWSSerializer($headerSerializer, $payloadSerializer, $signatureSerializer, $unprotectedHeaderSerializer);
    $algorithmProvider = new AlgorithmProvider($headerSerializer, $payloadSerializer);
    $issuer = new JWSIssuer($algorithmProvider, $serializer);
    $verifier = new JWSVerifier($algorithmProvider, $serializer);

    $authorizationHeader = $request->headers->get('Authorization'); // make sure you know it's compact or json JWS from your negotiation between each app and authentication server, if compact:
    $compactJws = explode(' ', $authorizationHeader)[1];

    $jws = $this->serializer->compactDeserializeJWS($compactJws);
    $secret = $yourSecretFromSharedVault;
    $validAudience = $_ENV['YOUR_APP_DOMAIN']; // something that matches the audience defined by authentication server in payload, for example: my-app.com
    
    try {
        $this->verifier->verify($jws, $secret, $validAudience);
    } catch (JWSAuthorizationException) {
        return new JsonResponse(status: 403);
    }

    // get user from valid JWS using additional data in payload:
    $data = $jws->payload->data; // any data added to the payload by the issuer, should be documented and well known amongst the audience
    $user = $yourUserFactory->createFromPayloadData($data['user'] ?? throw new YourException('Missing user in JWS'));

    // get minimal user from valid JWS using only user id defined in payload:
    $userId = $jws->payload->subject; // this should have standard format, for example uuid4
    $user = $yourUserFactory->createFromId($userId);
  
    // your HTTP processing after authentication was successful...
    ```
