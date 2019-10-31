<?php


namespace Phore\App\Mod\OAuth;

class PublicKeyConverter
{

    /**
     * @param $modulo string base64_encoded
     * @param $exponent string base64_encoded
     * @return string
     * @throws \Exception
     */
    public function getPemPublicKeyFromModExp($modulo, $exponent) : string
    {
        $modHex = $this->base64toHex($modulo);
        $modHexPadded = $this->prepadSigned($modHex);

        $modInteger = $this->encodeAsn1("02", $modHexPadded);

        $expHex = $this->base64toHex($exponent);
        $expHexPadded = $this->prepadSigned($expHex);

        $expInteger = $this->encodeAsn1("02", $expHexPadded);

        $neSequence = $this->encodeAsn1("30", $modInteger.$expInteger);

        $bitString = $this->encodeAsn1("03", "00".$neSequence);

        $oidSequence = $this->getOidSequence();

        $key = $this->encodeAsn1("30", $oidSequence.$bitString);

        $base64Key = $this->hexToBase64($key);

        $pemKey = "-----BEGIN PUBLIC KEY-----\n".chunk_split($base64Key,64,"\n")."-----END PUBLIC KEY-----\n";

        return $pemKey;
    }

    private function base64toHex(string $base64String) : String
    {
        return bin2hex(base64_decode($base64String));
    }

    private function hexToBase64(string $hexString) : String
    {
        return base64_encode(hex2bin($hexString));
    }

    /**
     * @param $type string 30:Sequence, 03:BitString, 02:Integer
     * @param $content
     * @return string
     */
    private function encodeAsn1(string $type, string $content) :  string
    {
        $length = strlen($content)/2;
        $encodedLength = $this->encodeLengthHex($length);
        return $type.$encodedLength.$content;
    }

    private function getOidSequence(string $algo = 'RSA') : string
    {
        switch ($algo) {
            case 'RSA':
                return "300d06092a864886f70d0101010500";
            default:
                throw new \Exception("unsupported algorithm");
        }
    }

    private function encodeLengthHex(int $n) {
        if($n < 128) {
            return $this->intToHex($n);
        } else {
            $nHex = $this->intToHex($n);
            $lengthOfLengthByte = 128 + strlen($nHex)/2;
            return $this->intToHex($lengthOfLengthByte) . $nHex;
        }
    }

    private function intToHex(int $n) {
        $hex = dechex($n);
        if(strlen($hex)%2 === 1) {
            return "0".$hex;
        }
        return $hex;
    }

    private function prepadSigned(string $hex) {
        $msb = substr($hex, 0, 1);
        if($msb > "7") {
            return "00".$hex;
        } else {
            return $hex;
        }
    }

}
