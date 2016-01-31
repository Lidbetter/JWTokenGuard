<?php

namespace App\JWTokenGuard;

use App\JWTokenGuard;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Illuminate\Support\ServiceProvider;

class JWTokenGuardServiceProvider extends ServiceProvider
{
    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot()
    {
        /** \Illuminate\Auth\AuthManager */
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            // Return an instance of Illuminate\Contracts\Auth\Guard...
            return new JWTGuard(
                $app['request'],
                $app['auth']->createUserProvider($config['provider']),
                new Builder(),
                new Parser(),
                $app->config['app']['key']
            );
        });
    }

    /**
     * Register bindings in the container.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}