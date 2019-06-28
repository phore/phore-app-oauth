<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 28.05.19
 * Time: 14:29
 */

namespace Phore\App\Mod\OAuth;


class OAuthClient
{

    private $clientId;
    private $clientSecret;

    private $config;

    public function __construct(string $clientId, string $clientKey)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientKey;
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
            "code" => $code
        ])->send()->getBodyJson();

        return $ret;
    }


    public function getUserInfo(string $token)
    {
        return phore_http_request($this->getUserInfoUrl())->withBearerAuth($token)->send()->getBodyJson();
    }

}
