<?php
/**
 * Created by PhpStorm.
 * User: matthias
 * Date: 28.05.19
 * Time: 15:42
 */

namespace Phore\App\Mod\OAuth;



use Phore\Core\Exception\InvalidDataException;
use Phore\MicroApp\App;
use Phore\MicroApp\AppModule;
use Phore\App\Mod\OAuth\OAuthClient;
use Phore\MicroApp\Response\RedirectResponse;
use Phore\MicroApp\Type\Request;
use Phore\Session\Session;

class OAuthModule implements AppModule
{

    private $clientId;
    private $clientKey;
    private $openIdHost;
    private $clientScopes;
    private $requiredClaims;



    const SESS_LAST_BACKLINK_KEY = "_oauth_last_backlink_url";
    const SESS_TOKEN = "_oauth_token";
    const SESS_TOKEN_TIMEOUT = "_oauth_token_timeout";
    const SESS_REQ_STATE = "_oauth_req_state";

    public function __construct($clientId, $clientKey, $openIdHost, array $clientScopes=["openid"], array $requiredClaims = [])
    {
        $this->clientId = $clientId;
        $this->clientKey = $clientKey;
        $this->openIdHost = $openIdHost;
        $this->clientScopes = $clientScopes;
        $this->requiredClaims = $requiredClaims;
    }

    /**
     * Called just after adding this to a app by calling
     * `$app->addModule(new SomeModule());`
     *
     * Here is the right place to add Routes, etc.
     *
     * @param App $app
     *
     * @return mixed
     */
    public function register(App $app)
    {
        $app->define("oAuthClient", function () {
            $client = new OAuthClient($this->clientId, $this->clientKey);
            $client->addScopes($this->clientScopes);
            $client->loadOpenIdConfig($this->openIdHost);
            return $client;
        });

        $app->onEvent(App::EVENT_ON_REQUEST, function (Request $request, Session $session) use ($app) {
            /* @var $oAuthClient \Phore\App\Mod\OAuth\OAuthClient */
            $oAuthClient = $app->oAuthClient;

            // Request has an authorization token
            if($request->authorizationMethod === "bearer") {
                $token = $request->authorization;
                if($oAuthClient->validateToken($token) === true && $oAuthClient->validateClaims($this->requiredClaims) === true) {
                    return true;
                }
            }

            // user returned from login with a code
            if ($request->GET->has("code") && $request->GET->has("state") && $request->requestMethod == "GET") {
                /* @var $session Session */
                $session = $app->session;

                if ($request->GET->get("state") !== $session->get(self::SESS_REQ_STATE))
                    throw new \InvalidArgumentException("Session stkick ate invalid: {$request->GET->get("state")} !== '{$session->get(self::SESS_REQ_STATE)}'");

                $token = $oAuthClient->getToken($request->GET->get("code"), $session->get(self::SESS_LAST_BACKLINK_KEY));

                if(!$oAuthClient->validateToken($token['id_token'])) {
                    throw new InvalidDataException("token signature doesnt match public key.");
                }
                if(!$oAuthClient->validateClaims($this->requiredClaims)) {
                    throw new InvalidDataException("Required claims missing");
                }
                //TODO: Check access rights, issuer
                $session->set("id_token", $token['id_token']);
                $session->setOauthToken($token["access_token"]);
                $session->set(self::SESS_TOKEN_TIMEOUT, time() + $token["expires_in"]);
                $session->update();

                return new RedirectResponse($session->get(self::SESS_LAST_BACKLINK_KEY));
            }

            // unknown user, initiate login process
            ignore_user_abort(true);
            if ($session->get(self::SESS_TOKEN_TIMEOUT, 0) > time())
                return true;

            /* @var $oAuthClient \Phore\App\Mod\OAuth\OAuthClient */
            $oAuthClient = $app->oAuthClient;
            if ( ! $oAuthClient instanceof OAuthClient)
                throw new \InvalidArgumentException("No oAuthClient registered in di.");


            $backlinkUrl = $request->requestScheme . "://" . $request->httpHost . $request->requestPath;
            $session->set(self::SESS_LAST_BACKLINK_KEY, $backlinkUrl);

            $state = phore_random_str(12);
            $session->set(self::SESS_REQ_STATE, $state);
            $session->update();

            return new RedirectResponse($oAuthClient->getAuthorizeUrl(), [
                "client_id" => $this->clientId,
                "response_type" => "code",
                "scope" => $oAuthClient->getScopes(),
                "redirect_uri" => $request->requestScheme . "://" . $request->httpHost . $request->requestPath,
                "state" => $state
            ]);
        });
    }
}
