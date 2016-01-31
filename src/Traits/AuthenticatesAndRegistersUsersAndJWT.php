<?php

namespace Lidbetter\JWTokenGuard\Traits;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\AuthenticatesAndRegistersUsers;

trait AuthenticatesAndRegistersUsersAndJWT
{

    use AuthenticatesAndRegistersUsers;

    /**
     * Send the response after the user was authenticated.
     * The response from this is returned instead of the
     * response from handleUserWasAuthenticated
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return \Illuminate\Http\Response
     */
    public function authenticated(Request $request, Authenticatable $user)
    {
        if($request->wantsJson() || $request->isJson()) {
            return response(Auth::createToken($user), 200);
        }

        return redirect()->intended($this->redirectPath());
    }

    /**
     * Get the failed login response instance.
     *
     * @param \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    protected function sendFailedLoginResponse(Request $request)
    {
        if($request->wantsJson() || $request->isJson()) {
            return response($this->getFailedLoginMessage(), 401);
        }

        return redirect()->back()
            ->withInput($request->only($this->loginUsername(), 'remember'))
            ->withErrors([
                $this->loginUsername() => $this->getFailedLoginMessage(),
            ]);
    }
}
