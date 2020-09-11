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
        "id_token" => "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3RLaWQifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0L29BdXRoU2VydmVyIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjUzNDAyMzAwNzk5LCJhdWQiOiJ0ZXN0X2NsaWVudCJ9.gQEuplrLFxqlkLF6EVqNdJg0IR1qFI820dosPMg15IM32mlUs5yuZYkQHbtj3WUUFfV12FpZs7dcoA_ZZnPAOsHTlt2dmbqDUKHClsuSa8p7FpqkSBMrh0wZN3KvUpqcuqr42FZGfB49Xdg5nlUM2iIBO9MMU7VRFoe-doh0Cx1WkIg6HfUoth7_mCycdC5YRazMEskY7B2u0meIK7XJmQWLB6iCHgx1E6EC_Vwmh0odEy9XBFo4kCR9_iSBt5i97L3VikVYsXOeYj3Xs5TR0xxODvswkqtdx78EGB18Xo0B4ksSaEkguFqFAKLUgfFOFWeMFJ5yxdz3kGoRjiuo5A",
        "symmetric_token" => "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.UC-Hj59_0b7KRPDqlh9zSO4TdXx0CMUE7TIHy9jng8c"
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
        "n" => base64urlEncode($keyDetails["rsa"]["n"]),
        "e" => base64urlEncode($keyDetails["rsa"]["e"]),
        "cert" => $keyDetails["key"]
    ];
    return ['keys' => $jwks];
});


/**
 ** Run the application
 **/
$app->serve();
