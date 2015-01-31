<?php 
// test everything out...
include("nxtlib.php");

$nxt = new Nxtlib("jnxt.org");
$nxt->sign("test", "test");
?>