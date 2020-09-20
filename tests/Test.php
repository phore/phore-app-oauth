<?php

namespace test;

use PHPUnit\Framework\TestCase;

class Test extends TestCase
{

    private $clientURL = "http://localhost/test";
    private $authURL = "http://localhost/oAuthServer";

    public function testAuthorizationFlow() {
        // call test client
        $result = phore_http_request($this->clientURL, [], [CURLOPT_FOLLOWLOCATION => false])->send();
        $location = $result->getHeaders()['location'];
        $this->assertStringContainsString("http://localhost/oAuthServer/authorize?client_id=test_client&response_type=code&scope=openid+admin&redirect_uri=http%3A%2F%2Flocalhost%2Ftest&state=", $location[0]);

        //redirect to signin
        $state = substr($location[0], -12);
        $psid = $result->getCookies()['PSID'][0];
        $result = phore_http_request($location[0], [], [CURLOPT_FOLLOWLOCATION => false])->send();
        $location = $result->getHeaders()['location'];
        $this->assertEquals("/oAuthServer/signin", $location[0]);

        //sign in
        $result = phore_http_request($this->authURL."/signin", [], [CURLOPT_FOLLOWLOCATION => false])
            ->withHeaders(["Cookie" => "PSID=$psid"])
            ->withPostFormBody(["user" => "testuser", "passwd" => "test"])
            ->send();
        $location = $result->getHeaders()['location'];
        $this->assertEquals("/oAuthServer/authorize?__login_ok", $location[0]);

        //login ok redirects to redirect Uri with token and state
        $result = phore_http_request("http://localhost".$location[0], [], [CURLOPT_FOLLOWLOCATION => false])->send();
        $location = $result->getHeaders()['location'];
        $this->assertEquals("/test?code=token123&state=state123", $location[0]);

        $result = phore_http_request("http://localhost/test?code=token123&state=$state", [], [CURLOPT_FOLLOWLOCATION => false])
            ->withHeaders(["Cookie" => "PSID=$psid"])
            ->send();

        $location = $result->getHeaders()['location'];
        $this->assertEquals("http://localhost/test", $location[0]);

        $result = phore_http_request($location[0])->withHeaders(["Cookie" => "PSID=$psid"])->send()->getBodyJson();
        $this->assertTrue($result["success"]);
    }

    public function testBearerRsaAvailable() {
        $result = phore_http_request($this->authURL."/token")->withMethod('POST')->send()->getBodyJson();
        $result = phore_http_request($this->clientURL)->withBearerAuth($result['id_token'])->send()->getBodyJson();
        $this->assertTrue($result["success"]);
    }

}
