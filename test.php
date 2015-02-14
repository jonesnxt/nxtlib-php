<?php 
// lets try this out

echo "<h1>Demo of nxtlib-php</h1>";

// initialize
include("nxtlib.php");
$nxt = new Nxtlib("jnxt.org");

// request
$req = $nxt->request("getBalance", json_decode('{"account": "NXT-MRCC-2YLS-8M54-3CMAJ"}'));
echo "<p>Balance of genesis request to jnxt.org server: </p><pre>" . json_encode($req) . "</pre>";

// public key
$pub = (new Converters())->secretPhraseToPublicKey("password");
echo "<p>Public key of account with secretPhrase of 'password': <pre>" . $pub . "</pre>";

// signBytes
$sig = $nxt->signBytes([0, 1, 2], "password");
echo "<p>Signature of bytes [0, 1, 2] signed with the passphrase 'password': </p><pre>" . $nxt->convert->byteArrayToHexString($sig) . "</pre>";

// verifyBytes
$valid = $nxt->verifyBytes($sig, [0,1,2], $pub);
echo "<p>Verification of the signed bytes: </p><pre>";
var_dump($valid);
echo "</pre>";

// generateToken
$token = $nxt->generateToken("php", "password");
echo "<p>Token of text 'php' signed with account of passPhrase 'password': </p><pre>" . $token . "</pre>";

// parseToken
$parse = $nxt->parseToken($token, "php");
echo "<p>Data given by parsing the token generated above: </p><pre>" . json_encode($parse) . "</pre>";

?>