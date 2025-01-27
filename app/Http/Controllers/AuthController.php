<?php

namespace App\Http\Controllers;

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
        $token = $user->createToken($request->name);
        return [
            'user'=>$user,
            'token'=>$token
        ];

    }
    public function login(Request $request){
      $request->validate([
            'email'=>'required|email|exists:users',
            'password'=>'required',
        ]);

      $user = User::where('email', $request->email)->first();

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
}
