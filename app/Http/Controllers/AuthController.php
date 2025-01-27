<?php

namespace App\Http\Controllers;

use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name'=>'required',
            'email'=>'required|email|unique:users',
            'password'=>'required',
        ]);
        $user = User::create($fields);
        event(new Registered($user));
        return [
            'user'=>$user,
        ];

    }
    public function login(Request $request){
      $request->validate([
            'email'=>'required|email|exists:users',
            'password'=>'required',
        ]);

      $user = User::where('email', $request->email)->first();

        if (!$user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Please verify your email before logging in.'
            ], 403);
        }

      if(!$user || !Hash::check($request->password, $user->password)){
          return [
              'message'=>'Incorrect credentials'
          ];
      }
        $token = $user->createToken($user->name);
        return [
            'user'=>$user,
            'token'=>$token
        ];
    }
    public function logout(Request $request){
        $request->user()->currentAccessToken()->delete();
        return [
            'message'=>'Logged out.'
        ];
    }

    public function verifyEmail(EmailVerificationRequest $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email already verified.'
            ], 200);
        }

        $request->user()->markEmailAsVerified();

        return response()->json([
            'message' => 'Email verified successfully.'
        ], 200);
    }

    public function resendVerificationEmail(Request $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email already verified.'
            ], 400);
        }

        $request->user()->sendEmailVerificationNotification();

        return response()->json([
            'message' => 'Verification email resent.'
        ], 200);
    }

}
