<?php

namespace test;

use Phore\App\Mod\OAuth\PublicKeyConverter;
use PHPUnit\Framework\TestCase;

class PublicKeyConverterTest extends TestCase
{
    private function generateKey($config) {
        $res = openssl_pkey_new($config);
        return openssl_pkey_get_details($res);
    }

    public function testRsa4096()
    {
        $config = array(
            "private_key_bits" => 4096,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $keyDetails = $this->generateKey($config);

        $conv = new PublicKeyConverter();
        $mod =  base64_encode($keyDetails['rsa']['n']);
        $exp =  base64_encode($keyDetails['rsa']['e']);
        $pubKey = $conv->getPemPublicKeyFromModExp($mod,$exp);

        $this->assertEquals($keyDetails['key'],$pubKey);
    }

    public function testRsa2048()
    {
        $config = array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $keyDetails = $this->generateKey($config);

        $conv = new PublicKeyConverter();
        $mod =  base64_encode($keyDetails['rsa']['n']);
        $exp =  base64_encode($keyDetails['rsa']['e']);
        $pubKey = $conv->getPemPublicKeyFromModExp($mod,$exp);

        $this->assertEquals($keyDetails['key'],$pubKey);
    }

    public function testRsa1024()
    {
        $config = array(
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $keyDetails = $this->generateKey($config);

        $conv = new PublicKeyConverter();
        $mod =  base64_encode($keyDetails['rsa']['n']);
        $exp =  base64_encode($keyDetails['rsa']['e']);
        $pubKey = $conv->getPemPublicKeyFromModExp($mod,$exp);

        $this->assertEquals($keyDetails['key'],$pubKey);
    }

    public function testAbc() {

    }
}
