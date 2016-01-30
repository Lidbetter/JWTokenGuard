<?php

namespace App\JWTokenGuard;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Illuminate\Auth\Events;
use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;

class JwtGuard implements Guard
{
    use GuardHelpers;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * @var \Lcobucci\JWT\Builder
     */
    private $builder;

    /**
     * @var \Lcobucci\JWT\Parser
     */
    private $parser;

    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string|null
     */
    protected $tokenStr;

    /**
     * @var \Lcobucci\JWT\Token|null
     */
    protected $token;

    /**
     * JwtGuard constructor.
     *
     * @param \Illuminate\Http\Request                $request
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Lcobucci\JWT\Builder                   $builder
     * @param \Lcobucci\JWT\Parser                    $parser
     * @param string                                  $secret
     */
    public function __construct(Request $request, UserProvider $provider, Builder $builder, Parser $parser, $secret)
    {
        $this->request = $request;
        $this->provider = $provider;
        $this->builder = $builder;
        $this->parser = $parser;
        $this->secret = $secret;

        $this->tokenStr = $this->getTokenForRequest();
        $this->token = $this->validTokenFromStr($this->tokenStr);

    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        if (! empty($this->token)) {
            // after verifying that the token has not been tampered with
            // get the identifiable info from it and pass it in to get the user
            $creds = $this->getTokenCredentials();
            $user = $this->provider->retrieveByCredentials($creds);
        }

        return $this->user = $user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        // TODO: Implement validate() method.
        return false;
    }

    protected function getTokenCredentials()
    {
        return array_filter([
            'id' => $this->token->getClaim('id', ''),
            'email' => $this->token->getClaim('email', ''),
            'username' => $this->token->getClaim('username', ''),
        ]);
    }

    /**
     * Get the token for the current request.
     *
     * @return string
     */
    protected function getTokenForRequest()
    {
        $token = $this->request->input('api_token');

        if (empty($token)) {
            $token = $this->request->bearerToken();
        }

        if (empty($token)) {
            $token = $this->request->getPassword();
        }

        return $token;
    }

    protected function validTokenFromStr($tokenStr)
    {
        if(! empty($tokenStr)) {
            $token = $this->parser->parse($tokenStr);
            if($token->verify(new Sha256(), $this->secret)) {
                return $token;
            }
        }
        return null;
    }

    // making tokens

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool   $remember
     * @param  bool   $login
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false, $login = true)
    {
        // don't care what was passed in this is always false (stateless auth)
        $remember = false;
        $this->fireAttemptEvent($credentials, $remember, $login);

        $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            if ($login) {
                $this->login($user, $remember);
            }
            return true;
        }

        return false;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Log a user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    public function login(AuthenticatableContract $user, $remember = false)
    {

        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->fireLoginEvent($user, $remember);

        $this->setUser($user);

        $this->createTokenForceNew($user);
    }

    protected function token(AuthenticatableContract $user, $force = false)
    {
        if(!$force && $this->token) {
            return $this->token;
        }

        if($force) {
            $this->builder->unsign();
        }

        $authIdentifierName = $user->getAuthIdentifierName();
        $authIdentifierValue = $user->{$authIdentifierName};

        return $this->token = $this->builder
            ->setIssuedAt(time()) // Configures the time that the token was issue (iat claim)
            ->setNotBefore(time() + 60) // Configures the time that the token can be used (nbf claim)
            ->setExpiration(time() + 3600) // Configures the expiration time of the token (exp claim)
            ->set($authIdentifierName, $authIdentifierValue) // Configures a new claim, called "id"
            ->sign(new Sha256(), $this->secret) // creates a signature using app key as secret
            ->getToken(); // Retrieves the generated token
    }

    public function createToken(AuthenticatableContract $user)
    {
        return $this->token($user, $force = false);
    }

    public function createTokenForceNew(AuthenticatableContract $user)
    {
        return $this->token($user, $force = true);
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param  array  $credentials
     * @param  bool  $remember
     * @param  bool  $login
     * @return void
     */
    protected function fireAttemptEvent(array $credentials, $remember, $login)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Attempting(
                $credentials, $remember, $login
            ));
        }
    }

    /**
     * Fire the login event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    protected function fireLoginEvent($user, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Login($user, $remember));
        }
    }
}