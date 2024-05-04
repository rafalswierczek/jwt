# Simple JWS authentication codebase

[![Build](https://github.com/rafalswierczek/jwt/actions/workflows/php.yml/badge.svg)](https://github.com/rafalswierczek/jwt/actions/workflows/php.yml)

#### Take total control over JWS authentication with help of this repository.

## Installation:

> composer require rafalswierczek/jwt

## Usage

- Keep your JWS secret very safely and share it between applications to let one JWS be used to authenticate with multiple applications
- In authentication server:
    - Create your own token endpoint which will check user credentials and return generated JWS in successful response
    - Create your own settings for JWS header and payload
    - Create instances of `JWSIssuerInterface`, `JWSHeader` and `JWSPayload` and use it in token endpoint to get JWS

    ```php
    $serializer = new JWSSerializer(new JWSHeaderSerializer(), new JWSPayloadSerializer());
    $algorithmProvider = new AlgorithmProvider($serializer);
    $issuer = new JWSIssuer($algorithmProvider, $serializer);

    $header = $yourHeaderFactory::create();
    $payload = $yourPayloadFactory::create();
    $secret = $yourSecretProvider::get();

    $compactJws = $issuer->getCompactJWS($header, $payload, $secret);

    return new Response($compactJws);
    ```
- In all endpoints for each application with REST API:
    - Create your own authenticator and use your instance of `JWSVerifierInterface` there to verify JWS taken from request header

    ```php
    $serializer = new JWSSerializer(new JWSHeaderSerializer(), new JWSPayloadSerializer());
    $algorithmProvider = new AlgorithmProvider($serializer);
    $verifier = new JWSVerifier($algorithmProvider, $serializer);

    $authorizationHeader = $request->headers->get('Authorization');
    $jws = explode(' ', $authorizationHeader)[1]; // make sure you know it's compact or json JWS from your client-server negotiation, if compact:

    $jws = $this->serializer->compactDeserializeJWS($compactJws);
    $secret = $yourSecretProvider::get();
    
    try {
        $this->verifier->verify($jws, $secret);
    } catch (CompromisedSignatureException) {
        return new JsonResponse(['message' => 'Invalid JWS'], 401);
    }

    // your HTTP processing after authentication was successful...

    // get user from JWS:
    $payload = $jws->getPayload();
    $data = $payload->getData(); // any data added to payload
    $user = $yourUserDeserializer->deserialize($data['user'] ?? throw new YourException('Missing user in JWS'));

    // use available serializers and implement your own to manipulate JWS data
    ```
