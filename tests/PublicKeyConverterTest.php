<?php

namespace test;

use Phore\App\Mod\OAuth\PublicKeyConverter;
use PHPUnit\Framework\TestCase;

class PublicKeyConverterTest extends TestCase
{
    /**
     * @var $publicKexConverter PublicKeyConverter
     */
    private $publicKexConverter;

    protected function setUp(): void
    {
        $this->publicKexConverter = new PublicKeyConverter();
    }

    protected function tearDown(): void
    {
        $this->publicKexConverter = null;
    }

    private function _generateKey($config) {
        return openssl_pkey_get_details(openssl_pkey_new($config));
    }

    private function _getConfig($bits){
        return array(
            "private_key_bits" => $bits,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
    }

    private function _getPublicKeyConverter($keyDetails){
        $comp["mod"] =  base64_encode($keyDetails['rsa']['n']);
        $comp["exp"] =  base64_encode($keyDetails['rsa']['e']);
        return $comp;
    }

    private static function _getMethod($name)
    {
        $class = new \ReflectionClass('Phore\App\Mod\OAuth\PublicKeyConverter');
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method;
    }

    public function testRsa4096()
    {
        //Arrange
        $keyDetails = $this->_generateKey($this->_getConfig(4096));
        $comp = $this->_getPublicKeyConverter($keyDetails);
        //Act
        $pubKey = $this->publicKexConverter->getPemPublicKeyFromModExp($comp["mod"],$comp["exp"]);
        //Assert
        $this->assertEquals($keyDetails['key'],$pubKey);
    }

    public function testRsa2048()
    {
        //Arrange
        $keyDetails = $this->_generateKey($this->_getConfig(2048));
        $comp = $this->_getPublicKeyConverter($keyDetails);
        //Act
        $pubKey = $this->publicKexConverter->getPemPublicKeyFromModExp($comp["mod"],$comp["exp"]);
        //Assert
        $this->assertEquals($keyDetails['key'],$pubKey);
    }

    public function testRsa1024()
    {
        //Arrange
        $keyDetails = $this->_generateKey($this->_getConfig(1024));
        $comp = $this->_getPublicKeyConverter($keyDetails);
        //Act
        $pubKey = $this->publicKexConverter->getPemPublicKeyFromModExp($comp["mod"],$comp["exp"]);
        //Assert
        $this->assertEquals($keyDetails['key'],$pubKey);
    }

    public function testPrepadSigned()
    {
        $method = $this->_getMethod('prepadSigned');
        $result = $method->invokeArgs($this->publicKexConverter, array("0ab4"));
        $this->assertEquals("0ab4", $result);
        $result = $method->invokeArgs($this->publicKexConverter, array("7ab4"));
        $this->assertEquals("7ab4", $result);
        $result = $method->invokeArgs($this->publicKexConverter, array("8ab4"));
        $this->assertEquals("008ab4", $result);
        $result = $method->invokeArgs($this->publicKexConverter, array("aab4"));
        $this->assertEquals("00aab4", $result);
    }

    public function testIntToHex()
    {
        $method = $this->_getMethod('intToHex');
        $result = $method->invokeArgs($this->publicKexConverter, array("1"));
        $this->assertEquals("01", $result);
        $result = $method->invokeArgs($this->publicKexConverter, array("128"));
        $this->assertEquals("80", $result);
    }

    public function testEncodeLengthHex()
    {
        $method = $this->_getMethod('encodeLengthHex');
        $result = $method->invokeArgs($this->publicKexConverter, array("127"));
        $this->assertEquals("7f", $result);
        $result = $method->invokeArgs($this->publicKexConverter, array("128"));
        $this->assertEquals("8180", $result);
    }

    public function testGetOidSequenz()
    {
        $method = $this->_getMethod('getOidSequence');
        $result = $method->invokeArgs($this->publicKexConverter, array());
        $this->assertEquals("300d06092a864886f70d0101010500", $result);
        $result = $method->invokeArgs($this->publicKexConverter, array("RSA"));
        $this->assertEquals("300d06092a864886f70d0101010500", $result);
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage("unsupported algorithm");
        $method->invokeArgs($this->publicKexConverter, array("DSA"));
    }

    public function testEncodeAsn1()
    {
        $method = $this->_getMethod('encodeAsn1');
        $result = $method->invokeArgs($this->publicKexConverter, array("30", "4444"));
        $this->assertEquals("30024444", $result);
        $result = $method->invokeArgs($this->publicKexConverter, array("30", "6ab7def"));
        $this->assertEquals("30036ab7def", $result);
    }
}
