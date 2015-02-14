# nxtlib-php

As suggested by Damelon, and required by another project I want to work on, I have created this library.

It is split up into three different classes -

class Curve25519:
There wasn't an implementation for a standalone curve25519 ECDH in PHP, so I ended up having to make my own :) ported from the js version in the nxt client

class Converters:
Conversion functions for changing between data types and creating public and private keys to use with curve25519

class Nxtlib:
Where the fun stuff happens, contains the objects curve, for curve25519, and convert, for converters, as well as some additional necesarry functions.
To initialize you need to include the ip of the node you want to connect to.
functions of Nxtlib:
- request($requestType, $params) 
- signBytes($message, $secretPhrase)
- verifyBytes($signature, $message, $publicKey)
- generateToken($websiteString, $secretPhrase)
- parseToken($tokenString, $website)

with node requests, signing and verifying bytes with curve25519, and generating and parsing tokens, nxt can be integrated into a web service fairly easily. 
Licensed with MIT licence, use however you'd like :)