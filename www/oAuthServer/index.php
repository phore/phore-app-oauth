<?php

namespace App;

use App\JWK\JwkManager;
use Phore\App\Mod\OAuth\OAuthModule;
use Phore\MicroApp\App;
use Phore\MicroApp\Auth\HttpBasicAuthMech;
use Phore\MicroApp\Handler\JsonExceptionHandler;
use Phore\MicroApp\Handler\JsonResponseHandler;
use Phore\MicroApp\Type\Params;
use Phore\MicroApp\Type\Request;
use Phore\Session\SessionHandler;


require __DIR__ . "/../../vendor/autoload.php";

$app = new App();
$app->activateExceptionErrorHandlers();
$app->setOnExceptionHandler(new JsonExceptionHandler());
$app->setResponseHandler(new JsonResponseHandler());

/**
 ** Configure Access Control Lists
 **/
$app->acl->addRule(\aclRule()->route("/*")->ALLOW());


/**
 ** Configure Dependency Injection
 **/



/**
 ** Define Routes
 **/

$app->router->onGet("/oAuthServer/", function (Request $request) {
    $code = $request->GET->get("code", "");
    $state = $request->GET->get("state", "");
    echo "oAuthServer";
    return true;
});


$app->router->onGet("/oAuthServer/.well-known/openid-configuration", function (Request $request) {
    $host = $request->requestScheme . "://" . $request->httpHost;
    return [
        "issuer" => $host,
        "authorization_endpoint" => $host . "/oAuthServer/authorize",
        "token_endpoint" => $host . "/oAuthServer/token",
        "userinfo_endpoint" => $host . "/oAuthServer/userinfo",
        "logout_endpoint" => $host . "/oAuthServer/logout",
        "jwks_uri" => $host . "/oAuthServer/.well-known/jwks.json"
    ];
});

$app->router->onGet("/oAuthServer/authorize", function (Params $params) {
    if ( ! $params->has("__login_ok")) {
        header("Location: /oAuthServer/signin");
    } else {
        $redirect_uri = "/test";
        $token = "token123";
        $state = "state123";
        header("Location: $redirect_uri?code=$token&state=$state");
    }
    return true;
});

$app->router->onPost("/oAuthServer/token", function () {
    return [
        "access_token" => "accessTokenTest",
        "token_type" => "Bearer",
        "expires_in" => 10,
        "id_token" => "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3RLaWQifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ep8Q8NpC8gy6R7lmI_bRZXrZRQGI0ABtUprH9bB_eAEp5evxG7ps_0VkVqB8suRE6sWt3Kt4TRVc-_Easna78RXxdOFjvLipELk8MIM3PdWSVXMTRwkf6fkuXa3BkJkCztYFN81uvnZyIdO1t1BoXwcB9ERrsGpnsNWGgnB5F1jLRSrre6ji-GYq5Zwns16EXwrz3rRpN9QinbSZsP2lb0KBUymf3fNu7sT7R7y68lvKd62yzLEU4iTBiiLDKBMH4Nlk2wqt1bmvSeJBNfC7kGZU22er6Ny65itlKgi9xEb7KXQ1FKsd-o3wULWId7HgV1Hucq-TfIUz1QvT_HUtpA"
    ];
});

$app->router->onGet("/oAuthServer/signin", function () {
    echo "signin";
    return true;
});

$app->router->onPost("/oAuthServer/signin", function (Request $request) {
    $user = $request->POST->get("user");
    $password = $request->POST->get("passwd");
    if( $user == "testuser" && $password == "test") {
        header("Location: /oAuthServer/authorize?__login_ok");
    } else {
        echo "incorrect user/password";
    }
    return true;
});

$app->router->onGet("/oAuthServer/.well-known/jwks.json", function () {
    $privateKey = openssl_pkey_get_private("file://private-key-rsa.pem");
    $keyDetails = openssl_pkey_get_details($privateKey);
    $jwks[] = $key = [
        "kty" => "RSA",
        "alg" => "RS512",
        "kid" => "testKid",
        "use" => "sig",
        "n" => base64_encode($keyDetails["rsa"]["n"]),
        "e" => base64_encode($keyDetails["rsa"]["e"]),
        "cert" => $keyDetails["key"]
    ];
    return $jwks;
});


/**
 ** Run the application
 **/
$app->serve();
