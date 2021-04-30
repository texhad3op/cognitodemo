# Getting Started

* You have to register user in your cognito pool (ml-test-user-pool)
* Cognito will send to you email with temporary password
* You have to confirm your user using endpoint: /api/public/confirm
* Then you need to login using /api/public/login
* In the response you will get idToken and RefreshToken
* idToken you must use for secured links (/api/secured/check)
   Add header to each secured request: Authorization: Bearer **idToken**

* idToken is valid for specified time (1 hour for now)
* Then you need to get new idToken from endpoint (/api/public/refresh-jwt)
   passing refreshToken as a parameter
  
