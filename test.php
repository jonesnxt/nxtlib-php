<?php 
// test everything out...
include("nxtlib.php");

$nxt = new Nxtlib("jnxt.org");
//echo $nxt->sign("test", "test");
$that = curve25519_keygen([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);

echo "<br/><br/>";
var_dump($that);

?>
<script src="curve25519.js"></script>
<script>
document.write(JSON.stringify(curve25519.keygen([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])));
</script>