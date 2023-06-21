# Simple JWT authenticator with Symfony Security

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

// get it from request header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFp...:
$jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC50ZXN0IiwiaWF0IjoxNjYyODgwNDI3LCJzdWIiOiJhLWItMyJ9.ODJmZTBmNzkyNjEzNDc5NjkyOGQ5MjZmZmM4ZTU3MGM0Zjg2NTRmOGNhN2NhOGU4NzE0Y2M5ZWYwYTYzOTFmYQ==';

// $jwtSecret makes us sure that $jwtToken is valid when it's verified using $algorithm:
$jwtValidator->validate($jwtToken, $jwtSecret, $algorithm); 

#################################################

// use JWTUnloader to get useful data from token:
$jwtUnloader = new JWTUnloader($jwtToken, new JWTValidator());

$payload = $jwtUnloader->getPayload();

// get an email or whatever you set up before JWTIssuer was used:
$email = $payload['email'];
```
