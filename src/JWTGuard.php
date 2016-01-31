<?php

namespace Lidbetter\JWTokenGuard;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Illuminate\Auth\Events;
use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;

class JWTGuard implements Guard
{
    use GuardHelpers;

    /**
     * @var array
     */
    protected $config;

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
     * @var string class name, subclass of (\Lcobucci\JWT\Signer\BaseSigner)
     */
    protected $signer;

    /**
     * @var string|null
     */
    protected $tokenStr;


    /**
     * JwtGuard constructor.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Lcobucci\JWT\Builder $builder
     * @param \Lcobucci\JWT\Parser $parser
     * @param array $guardConfig
     */
    public function __construct(Request $request, UserProvider $provider, Builder $builder, Parser $parser, $guardConfig)
    {
        $this->config = $guardConfig;
        $this->request = $request;
        $this->provider = $provider;
        $this->builder = $builder;
        $this->parser = $parser;
        $this->secret = empty($this->config['key']) ? config('app.key') : $this->config['key'];
        $this->signer = '\\'.ltrim($this->config['signer'], '\\');

        $this->tokenStr = $this->getTokenForRequest();
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


        // after verifying that the token has not been tampered with
        // get the identifiable info from it and pass it in to get the user
        $token = $this->validTokenFromStr($this->tokenStr);
        if($token) {
            $creds = $this->getTokenCredentials($token);
            $user = $this->provider->retrieveByCredentials($creds);
            if (!$this->hasValidTokenHashForUser($token, $user)) {
                $user = null;
            }
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

        $this->createToken($user);
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
            if($token->verify(new $this->signer, $this->secret)) {
                return $token;
            }
        }

        return null;
    }

    protected function hasValidTokenHashForUser(Token $token, AuthenticatableContract $user = null)
    {
        if(!$user) {
            return false;
        }

        return ($token->getClaim('hash') === $this->buildTokenPayloadHash($user));
    }

    public function createToken(AuthenticatableContract $user)
    {
        $payload = $this->buildTokenPayload($user);

        $this->builder->unsign();

        // set additional payload data
        foreach($payload as $key => $value) {
            $this->builder->set($key, $value);
        }

        $now = time();
        $lifespanSecs = $this->config['lifespan'] * 60;

        return $this->builder
            ->setIssuedAt($now) // Configures the time that the token was issue (iat claim)
            ->setExpiration($now + $lifespanSecs) // Configures the expiration time of the token (exp claim)
            ->sign(new $this->signer, $this->secret) // creates a signature using app key as secret
            ->getToken(); // Retrieves the generated token
    }

    protected function buildTokenPayload(AuthenticatableContract $user)
    {
        $payload = [];
        $payload['hash'] = $this->buildTokenPayloadHash($user);

        foreach($this->config['payload'] as $property) {
            $payload[$property] = $user->{$property};
        }

        return $payload;
    }

    protected function buildTokenPayloadHash(AuthenticatableContract $user)
    {
        $hashableString = '';
        foreach($this->config['hash'] as $property) {
            $hashableString .= $user->{$property};
        }
        return sha1($hashableString);
    }


    protected function getTokenCredentialsWithHash(Token $token) {
        $payload = $this->getTokenCredentials($token);
        $payload['hash'] = $token->getClaim('hash');

        return $payload;
    }

    protected function getTokenCredentials(Token $token)
    {
        $creds = [];
        foreach($this->config['payload'] as $property) {
            $creds[$property] = $token->getClaim($property);
        }

        return $creds;
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