<?php

namespace App\Http\Controllers;

use App\Mail\VerifyEmailOtpMail;
use Carbon\Carbon;
use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        // ✅ Validate only user inputs (excluding OTP)
        $fields = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|min:6',
        ]);

        // ✅ Generate OTP and expiry time separately
        $otp = rand(100000, 999999);
        $otpExpiresAt = Carbon::now()->addMinutes(10);

        // ✅ Create the user with hashed password
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => Hash::make($fields['password']),
            'email_otp' => $otp,
            'otp_expires_at' => $otpExpiresAt
        ]);

        // ✅ Send OTP Email
        Mail::to($user->email)->send(new VerifyEmailOtpMail($otp));

        return response()->json([
            'message' => 'User registered! Please check your email for the OTP.',
            'user' => $user
        ], 201);
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

    public function verifyOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
            'otp' => 'required|integer',
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || $user->email_otp !== $request->otp || Carbon::now()->greaterThan($user->otp_expires_at)) {
            return response()->json([
                'message' => 'Invalid or expired OTP.'
            ], 400);
        }

        // ✅ Mark email as verified
        $user->email_verified_at = now();
        $user->email_otp = null;
        $user->otp_expires_at = null;
        $user->save();

        return response()->json([
            'message' => 'Email verified successfully.'
        ], 200);
    }


    public function resendOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
        ]);

        $user = User::where('email', $request->email)->first();

        if ($user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email already verified.'
            ], 400);
        }

        // ✅ Generate new OTP
        $otp = rand(100000, 999999);
        $user->email_otp = $otp;
        $user->otp_expires_at = Carbon::now()->addMinutes(10);
        $user->save();

        // ✅ Send OTP Email
        Mail::to($user->email)->send(new VerifyEmailOtpMail($otp));

        return response()->json([
            'message' => 'OTP resent successfully.'
        ], 200);
    }

}
