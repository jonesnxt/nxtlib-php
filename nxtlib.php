<?php 
	// nxtlib-php
	// created by Alex Jones
	// MIT licenced, use how you'd like (:

	class nxtlib
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

		function sign($message, $passphrase)
		{
			$priv = hash("sha256", $passphrase);
        	$P = curve25519_public($private);
        	$s = curve25519_shared($private, $public);

        	$m = hash("sha256", $message);

        	$x = hash("sha256", $m.$s);

        	$Y = curve25519_public($x);

        	$h = hash("sha256", $m.$Y);

        	$v = 

        digest.update(m);
        byte[] x = digest.digest(s);

        byte[] Y = new byte[32];
        Curve25519.keygen(Y, null, x);

        digest.update(m);
        byte[] h = digest.digest(Y);

        byte[] v = new byte[32];
        Curve25519.sign(v, h, x, s);

        byte[] signature = new byte[64];
        System.arraycopy(v, 0, signature, 0, 32);
        System.arraycopy(h, 0, signature, 32, 32);

        /*
            if (!Curve25519.isCanonicalSignature(signature)) {
                throw new RuntimeException("Signature not canonical");
            }
            */
        return signature;

    }

		}
	}

?>