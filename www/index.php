<?php

namespace App;

use Phore\App\Mod\OAuth\OAuthModule;
use Phore\MicroApp\App;
use Phore\MicroApp\Auth\HttpBasicAuthMech;
use Phore\MicroApp\Handler\JsonExceptionHandler;
use Phore\MicroApp\Handler\JsonResponseHandler;
use Phore\MicroApp\Type\Request;
use Phore\Session\SessionHandler;


require __DIR__ . "/../vendor/autoload.php";

$app = new App();
$app->activateExceptionErrorHandlers();
$app->setOnExceptionHandler(new JsonExceptionHandler());
$app->setResponseHandler(new JsonResponseHandler());

/**
 ** Configure Access Control Lists
 **/
$app->acl->addRule(\aclRule()->route("/*")->ALLOW());

$app->define("sessionHandler", function() {
    return new SessionHandler("redis://redis");
});

/**
 ** Configure Dependency Injection
 **/
$app->define("session", function (SessionHandler $sessionHandler) {
    $session = $sessionHandler->loadSession();
    return $session;
});

$app->addModule(new OAuthModule("test_client", "test_secret", "http://localhost/oAuthServer"));

/**
 ** Define Routes
 **/

$app->router->onGet("/", function () {
    echo "hallo";
    return true;
});

$app->router->onGet("/test", function (Request $request) {
    return ["success" => true];
});

/**
 ** Run the application
 **/
$app->serve();
