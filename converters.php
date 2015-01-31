<?php
function hexStringToByteArray($hex)
{
	return unpack("*i", pack("H"));
}

function byteArrayToHexString($bytes)
{


}

function hexStringToBin($hex)
{
	return pack("H", $hex);
}

function byteArrayToBin($bytes)
{
	return pack("i", $bytes);
}

?>