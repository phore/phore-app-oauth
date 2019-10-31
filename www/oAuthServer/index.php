<?php

namespace App;

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
        "logout_endpoint" => $host . "/oAuthServer/logout"
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
        "id_token" => "jwtTest"
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


/**
 ** Run the application
 **/
$app->serve();
