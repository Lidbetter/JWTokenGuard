<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Secret Key
    |--------------------------------------------------------------------------
    |
    | This is the key that your tokens will be encrypted with, it should be a
    | 32 character string if this option is empty or not defined, the app
    | key is used.
    |
    */
    'key' => env('JWT_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Signing algorithm
    |--------------------------------------------------------------------------
    |
    | You probably don't need to change this, for options look in vendor or:
    | https://github.com/lcobucci/jwt/tree/3.1.0/src/Signer
    |
    */
    'signer' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,


    /*
    |--------------------------------------------------------------------------
    | Hash
    |--------------------------------------------------------------------------
    |
    | This option controls early token invalidation. The list should contain
    | Authenticatable model properties which, when changed invalidate the
    | token, regardless of the expiry date.
    |
    */
    'hash' => [ 'id', 'email', 'password' ],

    /*
    |--------------------------------------------------------------------------
    | Payload
    |--------------------------------------------------------------------------
    |
    | This option controls the which items are included in the token payload.
    | This cannot be empty. You should include the model ID, or some other
    | information which does not change and is unique to a single user
    | (maybe email or username). This information can be retrieved
    | by the Guard and used without consulting the database.
    |
    */
    'payload' => [ 'id' ],


    /*
    |--------------------------------------------------------------------------
    | Token Lifetime
    |--------------------------------------------------------------------------
    |
    | Here you may specify the number of minutes a token should be valid for.
    | If you are using a combination of sessions and stateless api for web
    | users, it would be a good idea to set this slightly longer than the
    | session lifetime. If your'e tokens are long lived (more than a few
    | hours/days) it is very important to be able to invalidate them
    | when the user changes their password (see hash option)
    |
    */
    'lifespan' => 125
];
