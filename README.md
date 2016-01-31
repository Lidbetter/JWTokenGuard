## JWTokenGuard
A Json Web Token Guard adaptor for the Laravel Framework.

The goal is for a dropin replacement to the session guard which is shipped by default, most existing middleware which relies on `Auth::` should work.

### Installation 

`composer require lidbetter/jw-token-guard`

1) Add the following to `config/app.php` in the **providers** array

    `Lidbetter\JWTokenGuard\JWTokenGuardServiceProvider::class,`

2) In `config/auth.php ` change your api driver to `jwt` - should look something like

    ```php
	    ...
        'guards' => [
            'web' => [
                'driver' => 'session',
                'provider' => 'users',
            ],

            'api' => [
                'driver' => 'jwt',
                'provider' => 'users',
            ],
        ],
        ...   
    ```


3) In `app/Http/Controllers/Auth/AuthController.php` 
  
   replace: `use Illuminate\Foundation\Auth\AuthenticatesAndRegistersUsers;`

    with: `use Lidbetter\JWTokenGuard\Traits\AuthenticatesAndRegistersUsersAndJWT;`

    Don't forget to swap the use statment inside the class too. This will make the post login method return a token, if credentials are valid.
    

4) Optional but advisable, add the middleware to set the default auth driver to the JWT implementation
   in `app/Http/Kernel.php` add the middle ware to the api route, should now look something like:
   
   ```php
    protected $middlewareGroups = [
        'web' => [
            \App\Http\Middleware\EncryptCookies::class,
            \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
            \Illuminate\Session\Middleware\StartSession::class,
            \Illuminate\View\Middleware\ShareErrorsFromSession::class,
            \App\Http\Middleware\VerifyCsrfToken::class,
        ],

        'api' => [
            'throttle:60,1',
            \Lidbetter\JWTokenGuard\Middleware\StartJTWGuard::class,
        ],
    ];
    ```
    
You should now be able to use `Auth::check`, `Auth::guest()`, `Auth::user()` etc. anywhere inside your app and if accessed via a route protected via the `api` middle group get the `JWTGuard` and the default guard if you access non api grouped middleware routes.
