<?php

namespace Lidbetter\JWTokenGuard;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Lidbetter\JWTokenGuard;
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
        // publish the config file with:
        // php artisan vendor:publish --provider="Lidbetter\JWTokenGuard\JWTokenGuardServiceProvider"
        $this->publishes([__DIR__.'/config.php' => config_path('jwtguard.php')]);

        // load the default config if the user has not published it
        if(!$this->app['config']['jwtguard']) {

            $this->app['config']->set('jwtguard', require __DIR__.'/config.php');
        }

        /** \Illuminate\Auth\AuthManager */
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            // Return an instance of Illuminate\Contracts\Auth\Guard...
            return new JWTGuard(
                $app['request'],
                $app['auth']->createUserProvider($config['provider']),
                new Builder(),
                new Parser(),
                $this->app['config']['jwtguard']
            );
        });
    }
}
