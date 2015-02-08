<?php 
// test everything out...
include("nxtlib.php");
$nxt = new Nxtlib("jnxt.org");
//echo $nxt->sign("test", "test");

$that = $nxt->sign("test", "test");
echo "<br/><br/>";
echo json_encode((new Converters())->hexStringToByteArray($that));

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


function sign (message, secretPhrase) {
		var messageBytes = converters.stringToByteArray(message);
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


alert(sign("test", "test"));

</script>