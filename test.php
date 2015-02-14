<?php 
// test everything out...
include("nxtlib.php");
$nxt = new Nxtlib("jnxt.org");
//echo $nxt->sign("test", "test");

$passphrase = "test";
$pub = (new Converters())->secretPhraseToPublicKey($passphrase);
echo json_encode($pub);
$sig = $nxt->generateToken("huh", $passphrase);
echo "<br/>" . json_encode($sig);

var_dump($nxt->parseToken($sig, "huh"));


//$that = $nxt->sign("test", "test");
echo "<br/><br/>";
//echo json_encode((new Converters())->hexStringToByteArray($that));

?>
<script src="curve25519.js"></script>
<script src="converters.js"></script>
<script src="jssha256.js"></script>
<script>

var _hash = {
		init: SHA256_init,
		update: SHA256_write,
		getBytes: SHA256_finalize
	};

function simpleHash(message) {
		_hash.init();
		_hash.update(message);
		return _hash.getBytes();
	}


    function secretPhraseToPublicKey(secretPhrase) {
            secretPhraseBytes = converters.stringToByteArray(secretPhrase);
            digest = simpleHash(secretPhrase);
            return converters.byteArrayToHexString(curve25519.keygen(digest).p);
        }


function sign (message, secretPhrase) {
		var messageBytes = (message);
		var secretPhraseBytes = converters.stringToByteArray(secretPhrase);
		var digest = simpleHash(secretPhraseBytes);

		var s = curve25519.keygen(digest).s;


		var m = simpleHash(messageBytes);
		_hash.init();
		_hash.update(m);
		_hash.update(s);
		var x = _hash.getBytes();

		var y = curve25519.keygen(x).p;

		_hash.init();
		_hash.update(m);
		_hash.update(y);
		var h = _hash.getBytes();


		var v = curve25519.sign(h, x, s);


		return v.concat(h);
	}

		function areByteArraysEqual(bytes1, bytes2) {
		if (bytes1.length !== bytes2.length)
			return false;

		for (var i = 0; i < bytes1.length; ++i) {
			if (bytes1[i] !== bytes2[i])
				return false;
		}

		return true;
	}

		function verifyBytes(signature, message, publicKey) {
		var signatureBytes = signature;
		var messageBytes = message;
		var publicKeyBytes = publicKey;
		var v = signatureBytes.slice(0, 32);
		var h = signatureBytes.slice(32);
		var y = curve25519.verify(v, h, publicKeyBytes);

		var m = simpleHash(messageBytes);

		_hash.init();
		_hash.update(m);
		_hash.update(y);
		var h2 = _hash.getBytes();

		return areByteArraysEqual(h, h2);
	}

var pub = secretPhraseToPublicKey("test");
//alert(pub);
var sig = sign([0,1,2], "test");
//alert(sig);

//alert(verifyBytes(sig, [0,1,2], converters.hexStringToByteArray(pub)));


</script>