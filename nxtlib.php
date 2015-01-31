<?php 
	// nxtlib-php
	// created by Alex Jones
	// MIT licenced, use how you'd like (:
    include("curve25519.php");
    include("converters.php");

	class Nxtlib
	{
		private $nodeAddress;
		function __construct($nodeAddr)
		{
			$nodeAddress = $nodeAddr;
		}

		function request($requestType, $params)
		{
			$reqString = "http://".$nodeAddress.":7876/nxt?requestType=".$requestType."&".http_build_query($params);
			$rawtext = file_get_contents($reqString);
			return json_decode($rawtext);
		}

		function sign($message, $secretPhrase) {

        $P = array();
        $s = array();
        $dt = curve25519_keygen(hash("sha256", $secretPhrase));

        $P = $dt->P;
        $s = $dt->s;

        $m = hash("sha256", $message);
        var_dump($s);
        $x = hash("sha256", byteArrayToBin($s).hexStringToBin($m));

        $Y = curve25519_keygen($x)->P;

        $h = hash("sha256", hexStringToBin($m).byteArrayToBin($Y));

        $v = curve25519_sign($h, $x, $s);

        $signature = byteArrayToHexString($v).$h;

        /*
            if (!Curve25519.isCanonicalSignature(signature)) {
                throw new RuntimeException("Signature not canonical");
            }
            */
        return $signature;

    }


	}

?>