<?php

namespace test;

use Phore\App\Mod\OAuth\OAuthClient;
use PHPUnit\Framework\TestCase;

class OAuthClientTest extends TestCase
{

    private $client;

    protected function setUp(): void
    {
        $this->client = new OAuthClient("test_client", "test_secret");
        $this->client->loadOpenIdConfig("http://localhost/oAuthServer");
    }

    protected function tearDown(): void
    {
        $this->client=null;
    }

    public function testGetToken()
    {
        $token = $this->client->getToken("testCode", "testURL");

        $this->assertEquals("accessTokenTest", $token["access_token"]);
        $this->assertEquals("Bearer", $token["token_type"]);
        $this->assertEquals(10, $token["expires_in"]);
        $this->assertArrayHasKey("id_token", $token);

    }

    public function testGetAuthorizeUrl()
    {
        $url = $this->client->getAuthorizeUrl();
        $this->assertEquals("http://localhost/oAuthServer/authorize", $url);
    }

    public function testGetUserInfoUrl()
    {
        $url = $this->client->getUserInfoUrl();
        $this->assertEquals("http://localhost/oAuthServer/userinfo", $url);

    }

    public function testGetLogoutUrl()
    {
        $url = $this->client->getLogoutUrl("returnAfterLogoutUrl");
        $this->assertEquals("http://localhost/oAuthServer/logout?returnTo=returnAfterLogoutUrl", $url);
    }

    public function testValidateToken()
    {
        $token = $this->client->getToken("testCode", "testURL");
        $this->assertTrue($this->client->validateToken($token['id_token']));
    }

    public function testValidateSymmetricToken()
    {
        $token = $this->client->getToken("testCode", "testURL");
        $this->assertTrue($this->client->validateToken($token['symmetric_token']));
    }

    public function testAddAndGetScopes()
    {
        $this->client->addScopes(["openid", "profile", "profile"]);
        $this->assertEquals("openid profile",$this->client->getScopes());
    }
}
