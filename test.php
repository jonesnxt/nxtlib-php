<?php 
// test everything out...
include("nxtlib.php");

$nxt = new Nxtlib("jnxt.org");
echo $nxt->sign("test", "test");
?>