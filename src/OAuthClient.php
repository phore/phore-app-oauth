<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 28.05.19
 * Time: 14:29
 */

namespace Phore\App\Mod\OAuth;


use Phore\Core\Exception\InvalidDataException;

class OAuthClient
{

    private $clientId;
    private $clientSecret;
    private $alg = "RS256";
    private $scopes = [];

    private $config;

    public function __construct(string $clientId, string $clientSecret)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    public function loadOpenIdConfig(string $host) : self
    {
        $this->config = phore_http_request($host . "/.well-known/openid-configuration")->send()->getBodyJson();
        return $this;
    }

    public function getAuthorizeUrl() : string
    {
        return phore_pluck("authorization_endpoint", $this->config, new \InvalidArgumentException("authorization_endpoint missing"));
    }

    public function getUserInfoUrl() : string
    {
        return phore_pluck("userinfo_endpoint", $this->config, new \InvalidArgumentException("authorization_endpoint missing"));
    }


    public function getLogoutUrl(string $backlinkUrl) : string
    {
        return phore_pluck("logout_endpoint", $this->config, new \InvalidArgumentException("authorization_endpoint missing")) . "?returnTo=$backlinkUrl";
    }

    public function getToken(string $code, string $lastRedirectUri)
    {
        $tokenUrl = phore_pluck("token_endpoint", $this->config, new \InvalidArgumentException("token_endpoint missing"));
        $ret = phore_http_request($tokenUrl)->withPostFormBody([
            "grant_type" => "authorization_code",
            "client_id" => $this->clientId,
            "client_secret" => $this->clientSecret,
            "redirect_uri" => $lastRedirectUri,
            "code" => $code,
            "alg" =>$this->alg
        ])->send()->getBodyJson();

        return $ret;
    }

    /**
     * @param string $token
     * @return bool
     * @throws InvalidDataException
     * @throws \Exception
     */
    public function validateToken(string $token) {
        $tokenComponents = explode(".", $token);
        if(count($tokenComponents) !== 3) {
            throw new \InvalidArgumentException("Malformed or unsupported JWT");
        }
        $header = phore_json_decode(base64_decode($tokenComponents[0]));
        $data = $tokenComponents[0].".".$tokenComponents[1];
        $signature = base64_decode(str_replace(['-', '_', ''], ['+', '/', '='], $tokenComponents[2]));

        $headerAlg = phore_pluck('alg', $header, new \InvalidArgumentException("Invalid token header: alg missing."));

        switch ($headerAlg) {
            case "HS256":
                $hash = hash_hmac("sha256", $data, $this->clientSecret, true);
                if(hash_equals($signature, hash_hmac("sha256", $data, $this->clientSecret, true))) {
                    return true;
                }
                return false;
            case "HS512":
                if(hash_equals($signature, hash_hmac("sha512", $data, $this->clientSecret, true))) {
                    return true;
                }
                return false;
            case "RS256":
                $rsaSignatureAlg = OPENSSL_ALGO_SHA256;
                break;
            case "RS512":
                $rsaSignatureAlg = OPENSSL_ALGO_SHA512;
                break;
            default:
                throw new \InvalidArgumentException("Unsupported signing method: $headerAlg");
        }

        $jwks = phore_http_request($this->config['jwks_uri'])->send()->getBodyJson();

        if(!array_key_exists('keys', $jwks)) {
            $jwks = ['keys' => $jwks];
        }

        $keyFound = false;
        foreach ($jwks['keys'] as $index => $key) {
            $kid = phore_pluck('kid', $key);
            if($kid === $header['kid']) {
                $keyFound = true;
                break;
            }
        }

        if(!$keyFound) {
            throw new InvalidDataException("No matching kid found in JWKS");
        }

        $jwk = $jwks['keys'][$index];

        if(phore_pluck('alg', $jwk, new \InvalidArgumentException("Invalid jwk: alg missing.")) !== $headerAlg) {
            throw new InvalidDataException("Signing Algorithms jwks: {$jwks['keys'][$index]['alg']} and jwt: $headerAlg don't match.");
        }

        $modulo = phore_pluck('n',$jwk, new \InvalidArgumentException("Invalid jwk: n missing."));
        $exponent = phore_pluck('e',$jwk, new \InvalidArgumentException("Invalid jwk: e missing."));

        $converter = new PublicKeyConverter();
        $pubKey = $converter->getPemPublicKeyFromModExp($modulo, $exponent);
        $pub = openssl_pkey_get_public($pubKey);
        $verify = openssl_verify($data, $signature, $pub, $rsaSignatureAlg);
        if ($verify === 1)
            return true; // Signature correct
        if ($verify === 0);
            return false; // Signature invalid
        if ($verify === -1)
            throw new \InvalidArgumentException("Openssl error on verifying signature: " . openssl_error_string());
    }

    public function getScopes() {
        return implode(" ", $this->scopes);
    }

    public function addScopes(array $scopes) {
        $this->scopes = array_unique(array_merge($this->scopes, $scopes));
    }


    public function getUserInfo(string $token)
    {
        return phore_http_request($this->getUserInfoUrl())->withBearerAuth($token)->send()->getBodyJson();
    }

}
