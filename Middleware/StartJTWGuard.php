<?php

namespace Lidbetter\JWTokenGuard\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;

class StartJTWGuard
{
    protected $container;

    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  \Closure                 $next
     * @param string                    $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = 'api')
    {
        // override the default guard (probably 'web') to 'api'
        // this allows subsequent auth checks to function as
        // expected without any other code changes!
        $this->container->make('config')->set(['auth.defaults.guard' => $guard]);

        return $next($request);
    }
}