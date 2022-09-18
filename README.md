# Simple JWT authenticator with Symfony Security

**This app is not production ready.**

## Installation:

> composer require rafalswierczek/jwt

### Symfony is used only in `Authenticator.php`. Create your own Authenticator so it's 100% framework independent.

## Usage

```PHP
$jwtSecret = '123'; // from .env
$algorithm = AlgorithmFQCN::HS256; // use HS256 or create your own that implements JWTUserInterface

#################################################

// ISSUER: front-end should request this to get JWT, keep in mind that $jwtUser should be taken from database:

// use your user that implements JWTUserInterface:
$jwtUser = (new JWTUser())->setId('a-b-3');

// set whatever is useful to you in payload:
$jsonPayload = '{"email": "test@test.test"}';

$jwtIssuer = new JWTIssuer($jwtSecret, $jwtUser, $algorithm);

// add your own payload before generating the token:
$jwtIssuer->addJsonToPayload($jsonPayload);

// issuer endpoint response body should have this token:
$jwtToken = $jwtIssuer->getJWT();

#################################################

// API RESOURCES: front-end requests should hit this code for every API endpoint that need to be protected by JWT:
// you need your own authenticator or rafalswierczek\jwt\Authenticator that uses code below:

$jwtValidator = new JWTValidator();

// get it from request header: Authorization: Bearer T-O-K-E-N:
$jwtToken = '';

// $jwtSecret makes us sure that $jwtToken is valid when it's verified using $algorithm:
$isValid = $jwtValidator->isValid($jwtToken, $jwtSecret, $algorithm); 

#################################################

// use JWTUnloader to get useful data from token:
$jwtUnloader = new JWTUnloader($jwtToken);

$payload = $jwtUnloader->getPayload();

// get an email or whatever you set up before JWTIssuer was used:
$email = $payload['email'];
```
